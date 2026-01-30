// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main


import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/ui"
	log "github.com/sirupsen/logrus"
)

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

