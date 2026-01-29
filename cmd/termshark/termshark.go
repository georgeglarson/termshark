// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/adrg/xdg"
	"github.com/blang/semver"
	"github.com/flytam/filenamify"
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/cli"
	"github.com/gcla/termshark/v2/pkg/confwatcher"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/pkg/lifecycle"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/pkg/state"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/pkg/tailfile"
	"github.com/gcla/termshark/v2/pkg/tty"
	"github.com/gcla/termshark/v2/pkg/web"
	"github.com/gcla/termshark/v2/ui"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gdamore/tcell/v2"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	log "github.com/sirupsen/logrus"

	"net/http"
	_ "net/http/pprof"
)

//======================================================================

// Run cmain() and afterwards make sure all goroutines stop, then exit with
// the correct exit code. Go's main() prototype does not provide for returning
// a value.
func main() {
	// Create a central lifecycle tracker for all goroutines.
	// The tracker provides both a WaitGroup for goroutine tracking and
	// a context for shutdown signaling.
	tracker := lifecycle.New()
	termshark.SetTracker(tracker)

	res := cmain()
	tracker.Wait()

	if !termshark.ShouldSwitchTerminal && !termshark.ShouldSwitchBack {
		os.Exit(res)
	}

	os.Clearenv()
	for _, e := range termshark.OriginalEnv {
		ks := strings.SplitN(e, "=", 2)
		if len(ks) == 2 {
			os.Setenv(ks[0], ks[1])
		}
	}

	exe, err := os.Executable()
	if err != nil {
		log.Warnf("Unexpected error determining termshark executable: %v", err)
		os.Exit(1)
	}

	switch {
	case termshark.ShouldSwitchTerminal:
		os.Setenv("TERMSHARK_ORIGINAL_TERM", os.Getenv("TERM"))
		os.Setenv("TERM", fmt.Sprintf("%s-256color", os.Getenv("TERM")))
	case termshark.ShouldSwitchBack:
		os.Setenv("TERM", os.Getenv("TERMSHARK_ORIGINAL_TERM"))
		os.Setenv("TERMSHARK_ORIGINAL_TERM", "")
	}

	// Need exec because we really need to re-initialize everything, including have
	// all init() functions be called again
	err = syscall.Exec(exe, os.Args, os.Environ())
	if err != nil {
		log.Warnf("Unexpected error exec-ing termshark %s: %v", exe, err)
		res = 1
	}

	os.Exit(res)
}

func cmain() int {
	// Initialize application state
	state := newAppState()
	defer state.cleanup()
	defer state.printPcapSaveMessage()
	defer state.printInterfaceError()

	// Preserve environment in case we need to re-exec (e.g., user switches TERM)
	termshark.OriginalEnv = os.Environ()

	// Set up signal handling for job control (ctrl-z) and termination
	sigChan := make(chan os.Signal, 100)
	system.RegisterForSignals(sigChan)

	// Initialize configuration
	state.configDir = setupConfigDirs()
	if err := profiles.ReadDefaultConfig(state.configDir); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	}

	// Parse tshark-compatible flags first to check for passthrough mode
	var tsopts cli.Tshark
	tsFlags := flags.NewParser(&tsopts, flags.IgnoreUnknown|flags.HelpFlag)
	_, err := tsFlags.ParseArgs(os.Args)

	passthru := true
	if err != nil {
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			passthru = false
		} else {
			return 1
		}
	}

	// Handle special modes (tail, capture) - these exit early
	if exitCode, continueNormal := handleSpecialModes(&tsopts); !continueNormal {
		return exitCode
	}

	// Load profile if specified
	if tsopts.Profile != "" {
		sanitized, ferr := filenamify.Filenamify(tsopts.Profile, filenamify.Options{})
		if ferr != nil || sanitized != tsopts.Profile {
			fmt.Fprintf(os.Stderr, "Error: Invalid profile name %q. Profile names must be valid directory names.\n", tsopts.Profile)
			return 1
		}
		if err = profiles.Use(tsopts.Profile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
	}

	// Handle tshark passthrough mode
	if exitCode, continueNormal := handleTsharkPassthrough(&tsopts, passthru); !continueNormal {
		return exitCode
	}

	// Parse termshark's own command line arguments
	tmFlags := flags.NewParser(&state.opts, flags.PassDoubleDash)
	filterArgs, err := tmFlags.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Command-line error: %v\n\n", err)
		ui.WriteHelp(tmFlags, os.Stderr)
		return 1
	}

	// Handle help and version flags
	if exitCode, continueNormal := handleHelpAndVersion(&state.opts, tmFlags); !continueNormal {
		return exitCode
	}

	// Handle web UI mode early - before source validation
	// This allows starting the web server without specifying a pcap file
	if state.opts.Web {
		// Setup logging first
		if err := setupLogging(state.opts.LogTty); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		// Resolve pcap file if provided via -r flag
		var psrcs []pcap.IPacketSource
		if state.opts.Pcap != "" {
			psrcs = append(psrcs, pcap.FileSource{Filename: string(state.opts.Pcap)})
		}
		return runWebServer(state.opts.WebAddr, psrcs)
	}

	// Validate TTY
	state.usetty, err = validateTTY(state.opts.TtyValue())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v.\n", err)
		return 1
	}

	applyTermOverride()

	// Resolve packet sources
	state.psrcs, filterArgs, err = resolvePacketSources(&state.opts, filterArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Validate and transform sources (stdin, fifos)
	state.psrcs, err = validateAndTransformSources(state.psrcs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Validate source combinations
	if err = validateSourceCombinations(state.psrcs); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Resolve filters
	state.captureFilter, state.displayFilter, err = resolveFilters(&state.opts, state.psrcs, filterArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Validate write target
	if err = validateWriteTarget(&state.opts, state.psrcs); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Helpful to use logging when enumerating interfaces below, so do it first
	if err := setupLogging(state.opts.LogTty); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	debug := false
	if (state.opts.Debug.Set && state.opts.Debug.Val == true) || (!state.opts.Debug.Set && profiles.ConfBool("main.debug", false)) {
		debug = true
	}

	if debug {
		for _, addr := range termshark.LocalIPs() {
			log.Infof("Starting debug web server at http://%s:6060/debug/pprof/", addr)
		}
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}

	if err = createCacheDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	tsharkBin, err := validateTsharkBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ui.SetPacketColorsSupportedState(checkTsharkColorSupport(tsharkBin))

	// Resolve interface names (convert numeric indices to canonical names)
	state.psrcs, err = resolveInterfaceNames(state.psrcs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	state.watcher, err = confwatcher.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Problem constructing config file watcher: %v", err)
		return 1
	}

	//======================================================================

	// Initialize application state from configuration
	initUIState()
	pdmlArgs, psmlArgs, tsharkArgs := loadTsharkArgs(state.opts.TimestampFormat)
	if ui.IsPacketColorsEnabled() && !ui.IsPacketColorsSupported() {
		log.Warnf("Packet coloring is enabled, but %s does not support --color", tsharkBin)
		ui.InitPacketColors(false)
	}
	cacheSize, bundleSize := loadCacheSettings()

	var ifaceTmpFile string

	// no file sources - so interface or fifo
	if len(pcap.FileSystemSources(state.psrcs)) == 0 {
		if state.opts.WriteTo != "" {
			ifaceTmpFile = string(state.opts.WriteTo)
			ui.SetWriteToSelected(true)
		} else {
			srcNames := make([]string, 0, len(state.psrcs))
			for _, psrc := range state.psrcs {
				srcNames = append(srcNames, psrc.Name())
			}
			ifaceTmpFile = pcap.TempPcapFile(srcNames...)
		}
		state.waitingForPackets = true
	} else {
		// Note: StartUIChan will be closed after ui.Build() to ensure we close the right channel
		state.waitingForPackets = false // Mark that we should start UI immediately after build
	}

	// Configure base16 color handling before creating the tcell screen
	configureBase16Colors()

	// Build the UI - cleanup is handled by state.cleanup() deferred at the top
	if state.app, err = ui.Build(state.usetty); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// Tcell returns ExitError now because if its internal terminfo DB does not have
		// a matching entry, it tries to build one with infocmp.
		if _, ok := termshark.RootCause(err).(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "Termshark could not recognize your terminal. Try changing $TERM.\n")
		}
		return 1
	}

	// Close StartUIChan here (after ui.Build) for file loading so we close the right channel
	if !state.waitingForPackets {
		close(ui.GetStartUIChan())
	}

	state.appRunner = state.app.Runner()

	pcap.PcapCmds = pcap.MakeCommands(state.opts.DecodeAs, tsharkArgs, pdmlArgs, psmlArgs, ui.IsPacketColorsEnabled())
	pcap.PcapOpts = pcap.Options{
		CacheSize:      cacheSize,
		PacketsPerLoad: bundleSize,
	}

	// This is a global. The type supports swapping out the real loader by embedding it via
	// pointer, but I assume this only happens in the main goroutine.
	ui.SetLoader(&pcap.PacketLoader{ParentLoader: pcap.NewPcapLoader(pcap.PcapCmds, &pcap.Runner{IApp: state.app}, pcap.PcapOpts)})

	// Populate the filter widget initially - runs asynchronously
	go ui.GetFilterWidget().UpdateCompletions(state.app)

	ui.SetRunning(false)

	validator := filter.DisplayFilterValidator{
		Invalid: &filter.ValidateCB{
			App: state.app,
			Fn: func(app gowid.IApp) {
				if !ui.IsRunning() {
					fmt.Fprintf(os.Stderr, "Invalid filter: %s\n", state.displayFilter)
					ui.RequestQuit()
				} else {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						ui.OpenError(fmt.Sprintf("Invalid filter: %s", state.displayFilter), app)
					}))
				}
			},
		},
	}

	// Do this before the load starts, so that the PSML process has a guaranteed safe
	// PSML column format to use when it begins. The call to RequestLoadPcapWithCheck,
	// for example, will access the setting for preferred PSML columns.
	//
	// Init a global variable with the list of all valid tshark columns and
	// their formats. This might start a tshark process if the data isn't
	// cached. If so, print a message to console - "initializing". I'm not doing
	// anything smarter or async - it's not worth it, this should take a fraction
	// of a second.
	err = shark.InitValidColumns()

	// If this message is needed, we want it to appear after the init message for the packet
	// columns - after InitValidColumns
	if state.waitingForPackets {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("(The termshark UI will start when packets are detected on %s...)\n",
			strings.Join(pcap.SourcesNames(state.psrcs), " or ")))
	}

	// Refresh
	fileSrcs := pcap.FileSystemSources(state.psrcs)
	if len(fileSrcs) > 0 {
		psrc := fileSrcs[0]
		absfile, err := filepath.Abs(psrc.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not determine working directory: %v\n", err)
			return 1
		}

		doit := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.GetFilterWidget().SetValue(state.displayFilter, app)
			}))
			ui.RequestLoadPcap(absfile, state.displayFilter, ui.NoGlobalJump, app)
		}
		validator.Valid = &filter.ValidateCB{Fn: doit, App: state.app}
		validator.EmptyCB = &filter.ValidateCB{Fn: doit, App: state.app}
		validator.Validate(state.displayFilter)
	} else {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		state.ifaceExitCode = 0
		for _, psrc := range state.psrcs {
			if psrc.IsInterface() {
				if state.ifaceExitCode, state.ifaceErr = termshark.RunForStderr(
					termshark.CaptureBin(),
					[]string{"-i", psrc.Name(), "-a", "duration:1"},
					append(os.Environ(), "TERMSHARK_CAPTURE_MODE=1"),
					state.stderr,
				); state.ifaceExitCode != 0 {
					return 1
				}
			} else {
				// We only test one - the assumption is that if dumpcap can read from eth0, it can also read from eth1, ... And
				// this lets termshark start up more quickly.
				break
			}
		}

		doLoad := func(app gowid.IApp) {
			state.ifacePcapFilename = ifaceTmpFile
			ui.RequestLoadInterfaces(state.psrcs, state.captureFilter, state.displayFilter, ifaceTmpFile, app)
		}

		ifValid := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.GetFilterWidget().SetValue(state.displayFilter, app)
			}))
			doLoad(app)
		}

		validator.Valid = &filter.ValidateCB{Fn: ifValid, App: state.app}
		validator.EmptyCB = &filter.ValidateCB{Fn: doLoad, App: state.app}
		validator.Validate(state.displayFilter)
	}

	// Initialize event loop state
	state.wasLoadingPdmlLastTime = ui.GetLoader().PdmlLoader.IsLoading()
	state.wasLoadingAnythingLastTime = ui.GetLoader().LoadingAnything()

	// This is used to stop iface load and any stream reassembly. Make sure to
	// avoid any stream reassembly errors, since this is a controlled shutdown
	// but the tshark processes reading data for stream reassembly may still
	// complain about interruptions
	stopLoaders := func() {
		if ui.GetStreamLoader() != nil {
			ui.GetStreamLoader().SuppressErrors = true
		}
		ui.GetLoader().CloseMain()
	}

	inactiveDuration := 60 * time.Second
	checkPcapCacheDuration := 5 * time.Second

Loop:
	for {
		var finChan <-chan time.Time
		var tickChan <-chan time.Time
		var inactivityChan <-chan time.Time
		var checkPcapCacheChan <-chan time.Time
		var tcellEvents <-chan tcell.Event
		var opsChan <-chan gowid.RunFunction
		var afterRenderEvents <-chan gowid.IAfterRenderEvent
		// For setting struct views empty. This isn't done as soon as a load is initiated because
		// in the case we are loading from an interface and following new packets, we get an ugly
		// blinking effect where the loading message is displayed, shortly followed by the struct or
		// hex view which comes back from the pdml process (because the pdml process can only read
		// up to the end of the currently seen packets, each time it has to start afresh from the
		// beginning to get new packets). Waiting 500ms to display loading gives enough time, in
		// practice,

		// On change of state - check for new pdml requests
		if ui.GetLoader().PdmlLoader.IsLoading() != state.wasLoadingPdmlLastTime {
			ui.GetCacheRequestsChan() <- struct{}{}
		}

		// This should really be moved to a handler...
		if !ui.GetLoader().LoadingAnything() {
			if state.wasLoadingAnythingLastTime {
				// If the state has just switched to 0, it means no interface-reading process is
				// running. That means we will no longer be reading from an interface or a fifo, so
				// we point the loader at the file we wrote to the cache, and redirect all
				// loads/filters to that now.
				ui.GetLoader().TurnOffPipe()
				state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.ClearProgressWidgetFor(app, ui.LoaderOwns)
					ui.SetProgressDeterminateFor(app, ui.LoaderOwns) // always switch back - for pdml (partial) loads of later data.
				}))

				// When the progress bar is enabled, track the previous percentage reached. This is
				// so that I don't go "backwards" if I generate a progress value less than the last
				// one, using the current algorithm (because it would be confusing to see it go
				// backwards)
				state.prevProgPercentage = 0.0
			}

			// EnableOpsVar will be enabled when all the handlers have run, which happen in the main goroutine.
			// I need them to run because the loader channel is closed in one, and the ticker goroutines
			// don't terminate until these goroutines stop
			if ui.IsQuitRequested() {
				if ui.IsRunning() {
					if !state.quitIssuedToApp {
						state.app.Quit()
						state.quitIssuedToApp = true // Avoid closing app twice - doubly-closed channel
					}
				} else {
					// No UI so exit loop immediately
					break Loop
				}
			}
		}

		// Only display the progress bar if PSML is loading or if PDML is loading that is needed
		// by the UI. If the PDML is an optimistic load out of the display, then no need for
		// progress.
		doprog := false
		if ui.GetLoader().PsmlLoader.IsLoading() || (ui.GetLoader().PdmlLoader.IsLoading() && ui.GetLoader().PdmlLoader.LoadIsVisible()) {
			if state.prevProgPercentage >= 1.0 {
				if state.progCancelTimer != nil {
					state.progCancelTimer.Reset(time.Duration(500) * time.Millisecond)
					state.progCancelTimer = nil
				}
			} else {
				ui.SetProgressWidget(state.app)
				if state.progCancelTimer == nil {
					state.progCancelTimer = time.AfterFunc(time.Duration(100000)*time.Hour, func() {
						state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
							ui.ClearProgressWidgetFor(app, ui.LoaderOwns)
							state.progCancelTimer = nil
						}))
					})
				}
			}

			tickChan = state.progTicker.C // progress is only enabled when a pcap may be loading

			// Rule:
			// - prefer progress if we can apply it to psml only (not pdml)
			// - otherwise use a spinner if interface load or fifo load in operation
			// - otherwise use progress for pdml
			if system.HaveFdinfo {
				// Prefer progress, if the OS supports it.
				doprog = true
				if ui.GetLoader().ReadingFromFifo() {
					// But if we are have an interface load (or a pipe load), then we can't
					// predict when the data will run out, so use a spinner. That's because we
					// feed the data to tshark -T psml with a tail command which reads from
					// the tmp file being created by the pipe/interface source.
					doprog = false
					if !ui.GetLoader().InterfaceLoader.IsLoading() && !ui.GetLoader().PsmlLoader.IsLoading() {
						// Unless those loads are finished, and the only loading activity is now
						// PDML/pcap, which is loaded on demand in blocks of 1000. Then we can
						// use the progress bar.
						doprog = true
					}
				}
			}
		}

		if ui.GetLoader().InterfaceLoader.IsLoading() && !state.currentlyInactive {
			inactivityChan = state.inactivityTimer.C
		}

		if !state.checkedPcapCache {
			checkPcapCacheChan = state.checkPcapCacheTimer.C
		}

		// Only process tcell and gowid events if the UI is running.
		if ui.IsRunning() {
			tcellEvents = state.app.TCellEvents
		}

		if ui.GetFin() != nil && ui.GetFin().Active() {
			finChan = ui.GetFin().C()
		}

		// For operations like ClearPcap - need previous loads to be fully finished first. The operations
		// channel is enabled until an operation starts, then disabled until the operation re-enables it
		// via a handler.
		//
		// Make sure state doesn't change until all handlers have been run
		if !ui.GetLoader().PdmlLoader.IsLoading() && !ui.GetLoader().PsmlLoader.IsLoading() {
			opsChan = pcap.OpsChan
		}

		afterRenderEvents = state.app.AfterRenderEvents

		state.wasLoadingPdmlLastTime = ui.GetLoader().PdmlLoader.IsLoading()
		state.wasLoadingAnythingLastTime = ui.GetLoader().LoadingAnything()

		select {

		case <-checkPcapCacheChan:
			// Only check the cache dir if we own it; don't want to delete pcap files
			// that might be shared with wireshark
			if profiles.ConfBool("main.use-tshark-temp-for-pcap-cache", false) {
				log.Infof("Termshark does not own the pcap temp dir %s; skipping size check", termshark.PcapDir())
			} else {
				termshark.PrunePcapCache()
			}
			state.checkedPcapCache = true

		case <-inactivityChan:
			if ui.GetFin() != nil {
				ui.GetFin().Activate()
			}
			state.currentlyInactive = true

		case <-finChan:
			ui.GetFin().Advance()
			state.app.Redraw()

		case <-ui.GetStartUIChan():
			if err = activateUI(state); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				return 1
			}

			handleTerminalColorSuggestions(state)

			defer func() {
				// Do this to make sure the program quits quickly if quit is invoked
				// mid-load. It's safe to call this if a pcap isn't being loaded.
				//
				// The regular stopLoadPcap will send a signal to pcapChan. But if app.quit
				// is called, the main select{} loop will be broken, and nothing will listen
				// to that channel. As a result, nothing stops a pcap load. This calls the
				// context cancellation function right away
				stopLoaders()

				state.appRunner.Stop()
				state.app.Close()
				ui.SetRunning(false)
			}()

		case fn := <-opsChan:
			state.app.Run(fn)

		case <-ui.GetQuitRequestedChan():
			ui.SetQuitRequested(true)
			// Without this, a quit during a pcap load won't happen until the load is finished
			if ui.GetLoader().LoadingAnything() {
				// We know we're not idle, so stop any load so the quit op happens quickly for the user. Quit
				// will happen next time round because the quitRequested flag is checked.
				stopLoaders()
			}

		case sig := <-sigChan:
			if exitCode, shouldExit := handleSignal(state, sig, debug); shouldExit {
				return exitCode
			}

		case <-ui.GetCacheRequestsChan():
			ui.SetCacheRequests(pcap.ProcessPdmlRequests(ui.GetCacheRequests(),
				ui.GetLoader().ParentLoader, ui.GetLoader().PdmlLoader, ui.SetStructWidgets{Ld: ui.GetLoader()}, state.app))

		case <-tickChan:
			// We already know that we are LoadingPdml|LoadingPsml
			if doprog {
				state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
					state.prevProgPercentage = ui.UpdateProgressBarForFile(ui.GetLoader(), state.prevProgPercentage, app)
				}))
			} else {
				state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.UpdateProgressBarForInterface(ui.GetLoader().InterfaceLoader, app)
				}))
			}

		case ev := <-tcellEvents:
			state.app.HandleTCellEvent(ev, gowid.IgnoreUnhandledInput)
			state.inactivityTimer.Reset(inactiveDuration)
			state.currentlyInactive = false
			state.checkPcapCacheTimer.Reset(checkPcapCacheDuration)

		case ev, ok := <-afterRenderEvents:
			// This means app.Quit() has been called, which closes the AfterRenderEvents
			// channel - and then will accept no more events. select will then return
			// nil on this channel - which we then use to break the loop
			if !ok {
				break Loop
			}
			ev.RunThenRenderEvent(state.app)
			if ui.IsRunning() {
				state.app.RedrawTerminal()
			}

		case <-state.watcher.ConfigChanged():
			// Re-read so changes that can take effect immediately do so
			if err := profiles.ReadDefaultConfig(state.configDir); err != nil {
				log.Warnf("Unexpected error re-reading toml config: %v", err)
			}
			ui.UpdateRecentMenu(state.app)
		}

	}

	return 0
}

//======================================================================
// Helper functions extracted from cmain() for better readability
//======================================================================

// setupConfigDirs creates the necessary configuration and cache directories.
// Returns the global config folder path for use in config loading.
func setupConfigDirs() string {
	cacheDir := filepath.Join(xdg.CacheHome, "termshark")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create cache dir: %v\n", err)
	}
	configDir := filepath.Join(xdg.ConfigHome, "termshark")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create config dir: %v\n", err)
	} else {
		if err = os.MkdirAll(filepath.Join(configDir, "profiles"), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create profiles dir: %v\n", err)
		}
	}
	return configDir
}

// setupLogging configures the logging output, either to a file or to stderr.
func setupLogging(logToTty bool) error {
	if !logToTty {
		logfile := termshark.CacheFile("termshark.log")
		logfd, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("could not create log file %s: %w", logfile, err)
		}
		// Don't close it - just let the descriptor be closed at exit. logrus is used
		// in many places, some outside of this main function, and closing results in
		// an error often on freebsd.
		log.SetOutput(logfd)
	}
	return nil
}

// validateTsharkBinary checks that the tshark binary exists and is a supported version.
// Returns the path to the tshark binary.
func validateTsharkBinary() (string, error) {
	tsharkBin, kverr := termshark.TSharkPath()
	if kverr != nil {
		return "", fmt.Errorf(kverr.KeyVals["msg"].(string))
	}

	valids := profiles.ConfStrings("main.validated-tsharks")

	if !slices.Contains(valids, tsharkBin) {
		tver, err := termshark.TSharkVersion(tsharkBin)
		if err != nil {
			return "", fmt.Errorf("could not determine tshark version: %w", err)
		}
		// This is the earliest version that gives reliable results in termshark.
		mver, _ := semver.Make("1.10.2")
		if tver.LT(mver) {
			return "", fmt.Errorf("termshark will not operate correctly with a tshark older than %v (found %v)", mver, tver)
		}

		valids = append(valids, tsharkBin)
		profiles.SetConf("main.validated-tsharks", valids)
	}

	// If the last tshark we used isn't the same as the current one, then remove the cached fields
	// data structure so it can be regenerated.
	if tsharkBin != profiles.ConfString("main.last-used-tshark", "") {
		fields.DeleteCachedFields()
	}

	// Write out the last-used tshark path.
	profiles.SetConf("main.last-used-tshark", tsharkBin)

	return tsharkBin, nil
}

// checkTsharkColorSupport determines if the current tshark binary supports color output.
func checkTsharkColorSupport(tsharkBin string) bool {
	colorTsharks := profiles.ConfStrings("main.color-tsharks")

	if slices.Contains(colorTsharks, tsharkBin) {
		return true
	}

	supported, err := termshark.TSharkSupportsColor(tsharkBin)
	if err != nil {
		return false
	}

	if supported {
		colorTsharks = append(colorTsharks, tsharkBin)
		profiles.SetConf("main.color-tsharks", colorTsharks)
	}

	return supported
}

// createCacheDirs creates the necessary cache directories for termshark.
func createCacheDirs() error {
	for _, dir := range []string{termshark.CacheDir(), termshark.DefaultPcapDir(), termshark.PcapDir()} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("unexpected error making dir %s: %w", dir, err)
		}
	}

	// Write the empty pcap file used for color validation
	emptyPcap := termshark.CacheFile("empty.pcap")
	if _, err := os.Stat(emptyPcap); os.IsNotExist(err) {
		if err = termshark.WriteEmptyPcap(emptyPcap); err != nil {
			return fmt.Errorf("could not create dummy pcap %s: %w", emptyPcap, err)
		}
	}

	return nil
}

// validateTTY validates the specified TTY device, returning the path to use.
// If ttyPath is empty, returns the default "/dev/tty".
func validateTTY(ttyPath string) (string, error) {
	if ttyPath != "" {
		ttyf, err := os.Open(ttyPath)
		if err != nil {
			return "", fmt.Errorf("could not open terminal %s: %w", ttyPath, err)
		}
		defer ttyf.Close()

		if !isatty.IsTerminal(ttyf.Fd()) {
			return "", fmt.Errorf("%s is not a terminal", ttyPath)
		}
		return ttyPath, nil
	}
	// Always override - in case the user has GOWID_TTY in a shell script
	return "/dev/tty", nil
}

// applyTermOverride applies the TERM environment variable override from config.
func applyTermOverride() {
	termVar := profiles.ConfString("main.term", "")
	if termVar != "" {
		fmt.Fprintf(os.Stderr, "Configuration file overrides TERM setting, using TERM=%s\n", termVar)
		os.Setenv("TERM", termVar)
	}
}

// initUIState initializes the UI state from configuration settings.
func initUIState() {
	ui.InitDarkMode(profiles.ConfBool("main.dark-mode", true))
	ui.InitAutoScroll(profiles.ConfBool("main.auto-scroll", true))
	ui.InitPacketColors(profiles.ConfBool("main.packet-colors", true))
}

// loadTsharkArgs loads the tshark command-line arguments from configuration.
func loadTsharkArgs(timestampFormat string) (pdmlArgs, psmlArgs, tsharkArgs []string) {
	pdmlArgs = profiles.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs = profiles.ConfStringSlice("main.psml-args", []string{})
	if timestampFormat != "" {
		psmlArgs = append(psmlArgs, "-t", timestampFormat)
	}
	tsharkArgs = profiles.ConfStringSlice("main.tshark-args", []string{})
	return
}

// loadCacheSettings loads pcap cache configuration settings.
func loadCacheSettings() (cacheSize, bundleSize int) {
	cacheSize = profiles.ConfInt("main.pcap-cache-size", 64)
	bundleSize = profiles.ConfInt("main.pcap-bundle-size", 1000)
	if bundleSize <= 0 {
		maxBundleSize := 100000
		log.Infof("Config specifies pcap-bundle-size as %d - setting to max (%d)", bundleSize, maxBundleSize)
		bundleSize = maxBundleSize
	}
	return
}

// configureBase16Colors configures color handling for base16-shell compatibility.
// This must be called before creating the tcell screen.
//======================================================================
// Application State and Event Loop Types
//======================================================================

// appState holds the runtime state for the main application loop.
// This centralizes state that was previously scattered across local variables.
type appState struct {
	// Configuration
	configDir     string
	opts          cli.Termshark
	displayFilter string
	captureFilter string

	// Packet sources
	psrcs             []pcap.IPacketSource
	ifacePcapFilename string

	// UI state
	app                 *gowid.App
	appRunner           *gowid.AppRunner
	startedSuccessfully bool
	uiSuspended         bool

	// Loading state
	wasLoadingPdmlLastTime     bool
	wasLoadingAnythingLastTime bool
	prevProgPercentage         float64

	// Interface capture state
	ifaceExitCode int
	ifaceErr      error
	stderr        *bytes.Buffer

	// Timers
	progTicker          *time.Ticker
	inactivityTimer     *time.Timer
	checkPcapCacheTimer *time.Timer
	progCancelTimer     *time.Timer

	// Flags
	currentlyInactive bool
	checkedPcapCache  bool
	quitIssuedToApp   bool
	waitingForPackets bool

	// Terminal state
	ctrlzLineDisc tty.TerminalSignals
	usetty        string

	// Config watcher
	watcher *confwatcher.ConfigWatcher
}

// newAppState creates a new appState with default values.
func newAppState() *appState {
	return &appState{
		stderr:              &bytes.Buffer{},
		progTicker:          time.NewTicker(200 * time.Millisecond),
		inactivityTimer:     time.NewTimer(60 * time.Second),
		checkPcapCacheTimer: time.NewTimer(5 * time.Second),
	}
}

// cleanup performs cleanup operations when the application exits.
func (s *appState) cleanup() {
	// Clean up packet sources
	for _, psrc := range s.psrcs {
		if psrc != nil {
			if remover, ok := psrc.(pcap.ISourceRemover); ok {
				remover.Remove()
			}
		}
	}

	// Close widgets
	ui.CloseWidgets(s.app)

	// Close config watcher
	if s.watcher != nil {
		s.watcher.Close()
	}
}

// printInterfaceError prints interface capture errors after the UI closes.
func (s *appState) printInterfaceError() {
	if s.ifaceExitCode != 0 {
		fmt.Fprintf(os.Stderr, "Cannot capture on device %s", pcap.SourcesString(s.psrcs))
		if s.ifaceErr != nil {
			fmt.Fprintf(os.Stderr, ": %v", s.ifaceErr)
		}
		fmt.Fprintf(os.Stderr, " (exit code %d)\n", s.ifaceExitCode)
		if s.stderr.Len() != 0 {
			cbin, err1 := filepath.Abs(filepath.FromSlash(termshark.CaptureBin()))
			def, err2 := filepath.Abs("termshark")
			if err1 == nil && err2 == nil && cbin == def {
				cbin = "the capture process"
			}
			fmt.Fprintf(os.Stderr, "Standard error stream from %s:\n", cbin)
			fmt.Fprintf(os.Stderr, "------\n%s\n------\n", s.stderr.String())
		}
		if runtime.GOOS == "linux" && os.Geteuid() != 0 {
			fmt.Fprintf(os.Stderr, "You might need: sudo setcap cap_net_raw,cap_net_admin+eip %s\n", termshark.PrivilegedBin())
			fmt.Fprintf(os.Stderr, "Or try running with sudo or as root.\n")
		}
		fmt.Fprintf(os.Stderr, "See https://termshark.io/no-root for more info.\n")
	}
}

// printPcapSaveMessage prints the message about where packets were saved.
func (s *appState) printPcapSaveMessage() {
	if len(pcap.FileSystemSources(s.psrcs)) == 0 && s.startedSuccessfully && !ui.GetWriteToSelected() && !ui.GetWriteToDeleted() {
		fmt.Fprintf(os.Stderr, "Packets read from %s have been saved in %s\n",
			pcap.SourcesString(s.psrcs), s.ifacePcapFilename)
	}
}

//======================================================================
// Input Source Resolution
//======================================================================

// resolvePacketSources determines the packet sources from CLI arguments.
// Returns the sources and any error encountered.
func resolvePacketSources(opts *cli.Termshark, filterArgs []string) ([]pcap.IPacketSource, []string, error) {
	var psrcs []pcap.IPacketSource
	pcapf := string(opts.Pcap)

	// If no interface specified, and no pcap specified via -r, then we assume the first
	// argument is a pcap file e.g. termshark foo.pcap
	if pcapf == "" && len(opts.Ifaces) == 0 {
		pcapf = string(opts.Args.FilterOrPcap)
		if pcapf == "" {
			if termshark.IsTerminal(os.Stdin.Fd()) {
				pfile, err := system.PickFile()
				switch err {
				case nil:
					psrcs = append(psrcs, pcap.TemporaryFileSource{FileSource: pcap.FileSource{Filename: pfile}})
				case system.NoPicker:
					psrcs = append(psrcs, pcap.InterfaceSource{Iface: "1"})
				default:
					if err = system.PickFileError(err.Error()); err != nil {
						fmt.Fprintf(os.Stderr, err.Error())
					}
					return nil, nil, fmt.Errorf("file picker error")
				}
			} else {
				psrcs = append(psrcs, pcap.FileSource{Filename: "-"})
			}
		}
	} else {
		filterArgs = append(filterArgs, opts.Args.FilterOrPcap)
	}

	if pcapf != "" && len(opts.Ifaces) > 0 {
		return nil, nil, fmt.Errorf("please supply either a pcap or one or more live captures")
	}

	if len(psrcs) == 0 {
		switch {
		case pcapf != "":
			psrcs = append(psrcs, pcap.FileSource{Filename: pcapf})
		case len(opts.Ifaces) > 0:
			for _, iface := range opts.Ifaces {
				psrcs = append(psrcs, pcap.InterfaceSource{Iface: iface})
			}
		}
	}

	return psrcs, filterArgs, nil
}

// validateAndTransformSources validates packet sources and transforms stdin/fifo sources.
func validateAndTransformSources(psrcs []pcap.IPacketSource) ([]pcap.IPacketSource, error) {
	haveStdin := false
	for pi, psrc := range psrcs {
		switch {
		case psrc.Name() == "-":
			if haveStdin {
				return nil, fmt.Errorf("requested live capture %v (\"stdin\") cannot be supplied more than once", psrc.Name())
			}
			if termshark.IsTerminal(os.Stdin.Fd()) {
				return nil, fmt.Errorf("requested live capture is %v (\"stdin\") but stdin is a tty", psrc.Name())
			}
			if runtime.GOOS != "windows" {
				psrcs[pi] = pcap.PipeSource{Descriptor: "/dev/fd/0", Fd: int(os.Stdin.Fd())}
				haveStdin = true
			} else {
				return nil, fmt.Errorf("termshark does not yet support piped input on Windows")
			}
		default:
			stat, err := os.Stat(psrc.Name())
			if err != nil {
				if psrc.IsFile() || psrc.IsFifo() {
					return nil, fmt.Errorf("error reading file %s: %v", psrc.Name(), err)
				}
				continue
			}
			if stat.Mode()&os.ModeNamedPipe != 0 {
				psrcs[pi] = pcap.FifoSource{Filename: psrc.Name()}
			} else {
				if pcapffile, err := os.Open(psrc.Name()); err != nil {
					return nil, fmt.Errorf("error reading file %s: %v", psrc.Name(), err)
				} else {
					pcapffile.Close()
				}
			}
		}
	}
	return psrcs, nil
}

// validateSourceCombinations ensures valid combinations of file and interface sources.
func validateSourceCombinations(psrcs []pcap.IPacketSource) error {
	fileSrcs := pcap.FileSystemSources(psrcs)
	if len(fileSrcs) == 1 {
		if len(psrcs) > 1 {
			return fmt.Errorf("you can't specify both a pcap and a live capture")
		}
	} else if len(fileSrcs) > 1 {
		return fmt.Errorf("you can't specify more than one pcap")
	}
	return nil
}

// resolveFilters determines capture and display filters from arguments.
func resolveFilters(opts *cli.Termshark, psrcs []pcap.IPacketSource, filterArgs []string) (captureFilter, displayFilter string, err error) {
	fileSrcs := pcap.FileSystemSources(psrcs)

	termshark.ReverseStringSlice(filterArgs)
	argsFilter := strings.Join(filterArgs, " ")

	captureFilter = opts.CaptureFilter
	displayFilter = opts.DisplayFilter

	// If only live captures and filter args provided, use as capture filter
	if len(fileSrcs) == 0 && argsFilter != "" {
		if opts.CaptureFilter != "" {
			return "", "", fmt.Errorf("two capture filters provided - '%s' and '%s' - please supply one only",
				opts.CaptureFilter, argsFilter)
		}
		captureFilter = argsFilter
	}

	// Validate filters for file sources
	if len(fileSrcs) > 0 {
		if captureFilter != "" {
			return "", "", fmt.Errorf("cannot use a capture filter when reading from a pcap file")
		}
		if argsFilter != "" {
			if opts.DisplayFilter != "" {
				return "", "", fmt.Errorf("two display filters provided - '%s' and '%s' - please supply one only",
					opts.DisplayFilter, argsFilter)
			}
			displayFilter = argsFilter
		}
	}

	return captureFilter, displayFilter, nil
}

// validateWriteTarget validates the -w flag target.
func validateWriteTarget(opts *cli.Termshark, psrcs []pcap.IPacketSource) error {
	if opts.WriteTo == "" {
		return nil
	}

	fileSrcs := pcap.FileSystemSources(psrcs)
	if len(fileSrcs) > 0 {
		return fmt.Errorf("the -w flag is incompatible with regular capture sources %v", fileSrcs)
	}
	if opts.WriteTo == "-" {
		return fmt.Errorf("cannot set -w to stdout. Target file must be regular or a symlink")
	}
	if _, err := os.Stat(string(opts.WriteTo)); err == nil || !os.IsNotExist(err) {
		if !system.FileRegularOrLink(string(opts.WriteTo)) {
			return fmt.Errorf("cannot set -w to %s. Target file must be regular or a symlink", opts.WriteTo)
		}
	}
	return nil
}

// resolveInterfaceNames resolves numeric interface indices to canonical names.
func resolveInterfaceNames(psrcs []pcap.IPacketSource) ([]pcap.IPacketSource, error) {
	var systemInterfaces map[int][]string
	var err error

	for pi, psrc := range psrcs {
		checkInterfaceName := false
		ifaceIdx := -1
		if psrc.IsInterface() {
			if i, err := strconv.Atoi(psrc.Name()); err == nil {
				ifaceIdx = i
			}
			if ifaceIdx != -1 {
				checkInterfaceName = true
			} else if runtime.GOOS == "windows" {
				checkInterfaceName = true
			}
		}

		if checkInterfaceName {
			if systemInterfaces == nil {
				systemInterfaces, err = termshark.Interfaces()
				if err != nil {
					return nil, fmt.Errorf("could not enumerate network interfaces: %v\n\nTo capture packets, run with sudo:\n  sudo termshark -i <interface>\n\nOr analyze an existing pcap file:\n  termshark -r <file.pcap>", err)
				}
			}

			gotit := false
			var canonicalName string
		iLoop:
			for n, i := range systemInterfaces {
				if n == ifaceIdx {
					gotit = true
					canonicalName = i[0]
					break
				} else {
					for _, iname := range i {
						if iname == psrc.Name() {
							gotit = true
							canonicalName = i[0]
							break iLoop
						}
					}
				}
			}
			if gotit {
				psrcs[pi] = pcap.InterfaceSource{Iface: canonicalName}
			} else {
				return nil, fmt.Errorf("could not find network interface %s", psrc.Name())
			}
		}
	}
	return psrcs, nil
}

//======================================================================
// CLI Processing
//======================================================================

// handleSpecialModes handles special termshark modes (tail, capture, passthru).
// Returns exit code and whether to continue with normal operation.
func handleSpecialModes(tsopts *cli.Tshark) (exitCode int, continueNormal bool) {
	// Windows tail mode
	if tsopts.TailFileValue() != "" {
		err := tailfile.Tail(tsopts.TailFileValue())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)
			return 1, false
		}
		return 0, false
	}

	// Internal capture mode
	if os.Getenv("TERMSHARK_CAPTURE_MODE") == "1" {
		err := system.DumpcapExt(termshark.DumpcapBin(), termshark.TSharkBin(), os.Args[1:]...)
		if err != nil {
			return 1, false
		}
		return 0, false
	}

	return 0, true
}

// handleTsharkPassthrough checks if we should pass through to tshark.
// Returns exit code and whether to continue with normal operation.
func handleTsharkPassthrough(tsopts *cli.Tshark, passthru bool) (exitCode int, continueNormal bool) {
	// Don't pass through to tshark if --web mode is requested
	for _, arg := range os.Args[1:] {
		if arg == "--web" || strings.HasPrefix(arg, "--web=") {
			return 0, true
		}
	}

	if passthru &&
		(cli.FlagIsTrue(tsopts.PassThru) ||
			(tsopts.PassThru == "auto" && !isatty.IsTerminal(os.Stdout.Fd())) ||
			tsopts.PrintIfaces) {

		tsharkBin, kverr := termshark.TSharkPath()
		if kverr != nil {
			fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
			return 1, false
		}

		args := []string{}
		for _, arg := range os.Args[1:] {
			if !slices.Contains(cli.TermsharkOnly, arg) && !termshark.StringIsArgPrefixOf(arg, cli.TermsharkOnly) {
				args = append(args, arg)
			}
		}
		args = append([]string{tsharkBin}, args...)

		if runtime.GOOS != "windows" {
			err := syscall.Exec(tsharkBin, args, os.Environ())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error execing tshark binary: %v\n", err)
				return 1, false
			}
		} else {
			c := exec.Command(args[0], args[1:]...)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err := c.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error starting tshark: %v\n", err)
				return 1, false
			}

			err = c.Wait()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error waiting for tshark: %v\n", err)
				return 1, false
			}

			return 0, false
		}
	}
	return 0, true
}

// handleHelpAndVersion handles --help and --version flags.
// Returns exit code and whether to continue with normal operation.
func handleHelpAndVersion(opts *cli.Termshark, tmFlags *flags.Parser) (exitCode int, continueNormal bool) {
	if opts.Help {
		ui.WriteHelp(tmFlags, os.Stdout)
		return 0, false
	}

	if len(opts.Version) > 0 {
		res := 0
		ui.WriteVersion(tmFlags, os.Stdout)
		if len(opts.Version) > 1 {
			if tsharkBin, kverr := termshark.TSharkPath(); kverr != nil {
				fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
				res = 1
			} else {
				if ver, err := termshark.TSharkVersion(tsharkBin); err != nil {
					fmt.Fprintf(os.Stderr, "Could not determine version of tshark from binary %s\n", tsharkBin)
					res = 1
				} else {
					ui.WriteTsharkVersion(tmFlags, tsharkBin, ver, os.Stdout)
				}
			}
		}
		return res, false
	}

	return 0, true
}

func configureBase16Colors() {
	// Determine whether to ignore base16 color remapping
	if profiles.ConfKeyExists("main.ignore-base16-colors") {
		gowid.IgnoreBase16 = profiles.ConfBool("main.ignore-base16-colors", false)
	} else {
		// Try to auto-detect whether or not base16-shell is installed and in-use
		gowid.IgnoreBase16 = (os.Getenv("BASE16_SHELL") != "")
	}

	if gowid.IgnoreBase16 {
		log.Infof("Will not consider colors 0-21 from the terminal 256-color-space when interpolating theme colors")
		// If main.respect-colorterm=true then termshark will leave COLORTERM set and use
		// 24-bit color if possible. The problem with this, in the presence of base16, is that
		// some terminal-emulators still map RGB ANSI codes to colors 0-21 in the 256-color space.
		// Termshark will fall back to 256-colors if base16 is detected.
		if os.Getenv("COLORTERM") != "" && !profiles.ConfBool("main.respect-colorterm", false) {
			log.Infof("Pessimistically disabling 24-bit color to avoid conflicts with base16")
			os.Unsetenv("COLORTERM")
		}
	}
}

// handleTerminalColorSuggestions checks if the terminal supports more colors
// and suggests switching to a better terminal mode if available.
func handleTerminalColorSuggestions(state *appState) {
	if runtime.GOOS == "windows" {
		return
	}

	if state.app.GetColorMode() == gowid.Mode8Colors {
		// If exists is true, it means we already tried and then reverted back, so
		// just load up termshark normally with no further interruption.
		if _, exists := os.LookupEnv("TERMSHARK_ORIGINAL_TERM"); !exists {
			if !profiles.ConfBool("main.disable-term-helper", false) {
				err := termshark.Does256ColorTermExist()
				if err != nil {
					log.Infof("Must use 8-color mode because 256-color version of TERM=%s unavailable - %v.", os.Getenv("TERM"), err)
				} else {
					time.AfterFunc(time.Duration(3)*time.Second, func() {
						state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
							ui.SuggestSwitchingTerm(app)
						}))
					})
				}
			}
		}
	} else if os.Getenv("TERMSHARK_ORIGINAL_TERM") != "" {
		time.AfterFunc(time.Duration(3)*time.Second, func() {
			state.app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.IsTerminalLegible(app)
			}))
		})
	}
}

// handleSignal processes system signals and returns whether the main loop should exit.
// Returns (exitCode, shouldExit). If shouldExit is true, cmain should return exitCode.
func handleSignal(state *appState, sig os.Signal, debug bool) (int, bool) {
	if system.IsSigTSTP(sig) {
		if ui.IsRunning() {
			// Remove our terminal overrides that allow ctrl-z
			state.ctrlzLineDisc.Restore()
			// Stop tcell/gowid events for keys, etc
			state.appRunner.Stop()
			// Go back to terminal view
			state.app.DeactivateScreen()

			ui.SetRunning(false)
			state.uiSuspended = true
		} else {
			log.Infof("UI not active - no terminal changes required.")
		}

		// This is not synchronous, but some time after calling this, we'll be suspended.
		if err := system.StopMyself(); err != nil {
			fmt.Fprintf(os.Stderr, "Unexpected error issuing SIGSTOP: %v\n", err)
			return 1, true
		}

	} else if system.IsSigCont(sig) {
		if state.uiSuspended {
			// Go to termshark UI view
			if err := state.app.ActivateScreen(); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting UI: %v\n", err)
				return 1, true
			}

			// Start tcell/gowid events for keys, etc
			state.appRunner.Start()

			// Reinstate our terminal overrides that allow ctrl-z
			if err := state.ctrlzLineDisc.Set(state.usetty); err != nil {
				ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), state.app)
			}

			ui.SetRunning(true)
			state.uiSuspended = false
		}
	} else if system.IsSigUSR1(sig) {
		if debug {
			termshark.ProfileCPUFor(20)
		} else {
			log.Infof("SIGUSR1 ignored by termshark - see the --debug flag")
		}

	} else if system.IsSigUSR2(sig) {
		if debug {
			termshark.ProfileHeap()
		} else {
			log.Infof("SIGUSR2 ignored by termshark - see the --debug flag")
		}

	} else {
		log.Infof("Starting termination via signal %v", sig)
		ui.RequestQuit()
	}

	return 0, false
}

// activateUI activates the terminal UI and returns any error encountered.
func activateUI(state *appState) error {
	log.Infof("Launching termshark UI")

	// Go to termshark UI view
	if err := state.app.ActivateScreen(); err != nil {
		return fmt.Errorf("error starting UI: %w", err)
	}

	// Need to do that here because the app won't know how many colors the screen
	// has (and therefore which variant of the theme to load) until the screen is
	// activated.
	ui.ApplyCurrentTheme(state.app)

	// This needs to run after the toml config file is loaded.
	ui.SetupColors()

	// Start tcell/gowid events for keys, etc
	state.appRunner.Start()

	// Reinstate our terminal overrides that allow ctrl-z
	if err := state.ctrlzLineDisc.Set(state.usetty); err != nil {
		ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), state.app)
	}

	ui.SetRunning(true)
	state.startedSuccessfully = true

	ui.SetStartUIChan(nil) // make sure it's not triggered again

	return nil
}

// runWebServer starts the web UI server instead of the terminal UI.
func runWebServer(addr string, psrcs []pcap.IPacketSource) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		cancel()
	}()

	// Create sharkd backend using the unified state package
	backend, err := state.NewSharkdBackend(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start sharkd: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure sharkd is installed (usually part of wireshark-common).")
		return 1
	}
	defer backend.Close()

	// Create state manager
	manager := state.NewManager(backend)
	defer manager.Close()

	// Load pcap file if provided
	if len(psrcs) > 0 {
		for _, src := range psrcs {
			if fs, ok := src.(pcap.FileSource); ok {
				if err := manager.LoadFile(fs.Filename); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to load pcap file: %v\n", err)
					return 1
				}
				fmt.Printf("Loaded: %s\n", fs.Filename)
			}
		}
	}

	// Start web server with state manager
	server := web.NewServerWithManager(addr, manager)
	fmt.Printf("Web UI available at http://%s\n", addr)
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		return 1
	}

	return 0
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
