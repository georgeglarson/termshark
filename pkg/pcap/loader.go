// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var PcapCmds ILoaderCmds
var PcapOpts Options

var OpsChan chan gowid.RunFunction

var hexByteRe = regexp.MustCompile(`([0-9a-f][0-9a-f] )`)
var filenameInvalidRe = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

func init() {
	OpsChan = make(chan gowid.RunFunction, 100)
}

//======================================================================

type LoaderState bool

const (
	NotLoading LoaderState = false
	Loading    LoaderState = true
)

func (t LoaderState) String() string {
	if t {
		return "loading"
	} else {
		return "not-loading"
	}
}

//======================================================================

// PacketLoader supports swapping out loaders
type PacketLoader struct {
	*ParentLoader
}

// Renew is called when a new pcap is loaded from an open termshark session i.e. termshark
// was started with one packet source, then a new one is selected. This ensures that all
// connected loaders that might still be doing work are cancelled.
func (c *PacketLoader) Renew() {
	if c.ParentLoader == nil {
		return
	}
	c.ParentLoader.CloseMain()
	c.ParentLoader = NewPcapLoader(c.ParentLoader.cmds, c.runner, c.ParentLoader.opt)
}

type ParentLoader struct {
	// Note that a nil InterfaceLoader implies this loader is not handling a "live" packet source
	*InterfaceLoader // these are only replaced from the main goroutine, so no lock needed
	*PsmlLoader
	*PdmlLoader

	cmds ILoaderCmds

	tailStoppedDeliberately atomic.Bool // true if tail is stopped because its packet feed has run out

	psrcs         []IPacketSource // The canonical struct for the loader's current packet source.
	displayFilter string
	captureFilter string

	ifaceFile string // shared between InterfaceLoader and PsmlLoader - to preserve and feed packets

	mainCtx      context.Context // cancelling this cancels the dependent contexts - used to close whole loader.
	mainCancelFn context.CancelFunc

	loadWasCancelled atomic.Bool // True if the last load (iface or file) was halted by the stop button or ctrl-c

	runner IMainRunner
	opt    Options // held only to pass to the PDML and PSML loaders when renewed
}

type Options struct {
	CacheSize      int
	PacketsPerLoad int
}

type iLoaderEnv interface {
	Commands() ILoaderCmds
	MainRun(fn gowid.RunFunction)
	Context() context.Context
}

// IMainRunner is implemented by a type that runs a closure on termshark's main loop
// (via gowid's App.Run)
type IMainRunner interface {
	Run(fn gowid.RunFunction)
}

type Runner struct {
	gowid.IApp
}

var _ IMainRunner = (*Runner)(nil)

func (a *Runner) Run(fn gowid.RunFunction) {
	a.IApp.Run(fn)
}

//======================================================================

func NewPcapLoader(cmds ILoaderCmds, runner IMainRunner, opts ...Options) *ParentLoader {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.CacheSize == 0 {
		opt.CacheSize = 32
	}
	if opt.PacketsPerLoad == 0 {
		opt.PacketsPerLoad = 1000 // default
	} else if opt.PacketsPerLoad < 100 {
		opt.PacketsPerLoad = 100 // minimum
	}

	res := &ParentLoader{
		PsmlLoader: &PsmlLoader{}, // so default fields are set and XmlLoader is not nil
		PdmlLoader: &PdmlLoader{
			opt: opt,
		},
		cmds:   cmds,
		runner: runner,
		opt:    opt,
	}

	res.mainCtx, res.mainCancelFn = context.WithCancel(context.Background())

	res.RenewPsmlLoader()
	res.RenewPdmlLoader()

	return res
}

func (c *ParentLoader) RenewPsmlLoader() {
	c.PsmlLoader = &PsmlLoader{
		PcapPsml:            c.PsmlLoader.PcapPsml,
		tailCmd:             c.PsmlLoader.tailCmd,
		PsmlCmd:             c.PsmlLoader.PsmlCmd,
		packetAverageLength: make([]averageTracker, 64),
		packetMaxLength:     make([]maxTracker, 64),
		packetPsmlData:      make([][]string, 0),
		packetPsmlColors:    make([]PacketColors, 0),
		packetPsmlHeaders:   make([]string, 0, 10),
		PacketNumberMap:     make(map[int]int),
		PacketNumberOrder:   make(map[int]int),
		startStage2Chan:     make(chan struct{}), // do this before signalling start
		PsmlFinishedChan:    make(chan struct{}),
		opt:                 c.opt,
	}
	packetCache, err := lru.New(c.opt.CacheSize)
	if err != nil {
		log.Fatal(err)
	}
	c.PacketCache = packetCache
}

func (c *ParentLoader) RenewPdmlLoader() {
	pdml := &PdmlLoader{
		PcapPdml:            c.PcapPdml,
		PcapPcap:            c.PcapPcap,
		rowCurrentlyLoading: -1,
		opt:                 c.opt,
	}
	pdml.highestCachedRow.Store(-1)
	c.PdmlLoader = pdml
}

func (c *ParentLoader) RenewIfaceLoader() {
	c.InterfaceLoader = &InterfaceLoader{}
}

func (p *ParentLoader) LoadingAnything() bool {
	return p.PsmlLoader.IsLoading() || p.PdmlLoader.IsLoading() || p.InterfaceLoader.IsLoading()
}

func (p *ParentLoader) InterfaceFile() string {
	return p.ifaceFile
}

func (p *ParentLoader) DisplayFilter() string {
	return p.displayFilter
}

func (p *ParentLoader) CaptureFilter() string {
	return p.captureFilter
}

func (p *ParentLoader) TurnOffPipe() {
	// Switch over to  the temp pcap file. If a new filter is applied
	// after stopping, we should read from the temp file and not the fifo
	// because nothing will be feeding the fifo.
	if p.PsmlLoader.PcapPsml != p.PdmlLoader.PcapPdml {
		log.Infof("Switching from interface/fifo mode to file mode")
		p.PsmlLoader.PcapPsml = p.PdmlLoader.PcapPdml
	}
}

func (p *ParentLoader) PacketSources() []IPacketSource {
	return p.psrcs
}

func (p *ParentLoader) PsmlStoppedDeliberately() bool {
	return p.psmlStoppedDeliberately_.Load()
}

func (p *ParentLoader) TailStoppedDeliberately() bool {
	return p.tailStoppedDeliberately.Load()
}

func (p *ParentLoader) LoadWasCancelled() bool {
	return p.loadWasCancelled.Load()
}

func (p *ParentLoader) Commands() ILoaderCmds {
	return p.cmds
}

func (p *ParentLoader) Context() context.Context {
	return p.mainCtx
}

func (p *ParentLoader) MainRun(fn gowid.RunFunction) {
	p.runner.Run(fn)
}

// CloseMain shuts down the whole loader, including progress monitoring goroutines. Use this only
// when about to load a new pcap (use a new loader)
func (c *ParentLoader) CloseMain() {
	c.psmlStoppedDeliberately_.Store(true)
	c.pdmlStoppedDeliberately_.Store(true)
	if c.mainCancelFn != nil {
		c.mainCancelFn()
		c.mainCancelFn = nil
	}
}

func (c *ParentLoader) StopLoadPsmlAndIface(cb Callback) {
	log.Infof("Requested stop psml + iface")

	c.psmlStoppedDeliberately_.Store(true)
	c.loadWasCancelled.Store(true)

	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadIface()
}

//======================================================================

func (c *PacketLoader) Reload(filter string, cb Callback, app gowid.IApp) {
	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadPdml()

	OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
		c.RenewPsmlLoader()
		c.RenewPdmlLoader()

		// This is not ideal. I'm clearing the views, but I'm about to
		// restart. It's not really a new source, so called the new source
		// handler is an untidy way of updating the current capture in the
		// title bar again
		handleClear(NoneCode, app, cb)

		c.displayFilter = filter

		log.Infof("Applying display filter '%s'", filter)

		c.loadPsmlSync(c.InterfaceLoader, c, cb, app)
	})
}

func (c *PacketLoader) LoadPcap(pcap string, displayFilter string, cb Callback, app gowid.IApp) {
	log.Infof("Requested pcap file load for '%v'", pcap)

	curDisplayFilter := displayFilter
	// The channel is unbuffered, and monitored from the same goroutine, so this would block
	// unless we start a new goroutine

	if c.Pcap() == pcap && c.DisplayFilter() == curDisplayFilter {
		log.Infof("No operation - same pcap and filter.")
		HandleError(NoneCode, app, fmt.Errorf("Same pcap and filter - nothing to do."), cb)
	} else {

		c.stopTail()
		c.stopLoadPsml()
		c.stopLoadPdml()
		c.stopLoadIface()

		OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
			c.Renew()

			// This will enable the operation when clear completes
			handleClear(NoneCode, app, cb)

			c.psrcs = []IPacketSource{FileSource{Filename: pcap}}
			c.ifaceFile = ""

			c.PcapPsml = pcap
			c.PcapPdml = pcap
			c.PcapPcap = pcap
			c.displayFilter = displayFilter

			// call from main goroutine - when new filename is established
			handleNewSource(NoneCode, app, cb)

			log.Infof("Starting new pcap file load '%s'", pcap)
			c.loadPsmlSync(nil, c.ParentLoader, cb, app)
		})
	}
}

// Clears the currently loaded data. If the loader is currently reading from an
// interface, the loading continues after the current data has been discarded. If
// the loader is currently reading from a file, the loading *stops*.

// Intended to restart iface loader - since a clear will discard all data up to here.
func (c *PacketLoader) ClearPcap(cb Callback) {
	startIfaceAgain := false

	if c.InterfaceLoader != nil {
		// Don't restart if the previous interface load was deliberately cancelled
		if !c.loadWasCancelled.Load() {
			startIfaceAgain = true
			for _, psrc := range c.psrcs {
				startIfaceAgain = startIfaceAgain && CanRestart(psrc) // Only try to restart if the packet source allows
			}
		}
		c.stopLoadIface()
	}

	// Don't close main context, it's used by interface process.
	// We may not have anything running, but it's ok - then the op channel
	// will be enabled
	if !startIfaceAgain {
		c.loadWasCancelled.Store(true)
	}
	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadPdml()

	// When stop is done, launch the clear and restart
	OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
		// Don't CloseMain - that will stop the interface process too
		c.loadWasCancelled.Store(false)
		c.RenewPsmlLoader()
		c.RenewPdmlLoader()

		handleClear(NoneCode, app, cb)

		if !startIfaceAgain {
			c.psrcs = c.psrcs[:0]
			c.ifaceFile = ""
			c.PcapPsml = ""
			c.PcapPdml = ""
			c.PcapPcap = ""
			c.displayFilter = ""
		} else {
			c.RenewIfaceLoader()

			if err := c.loadInterfaces(c.psrcs, c.CaptureFilter(), c.DisplayFilter(), c.InterfaceFile(), cb, app); err != nil {
				HandleError(NoneCode, app, err, cb)
			}
		}
	})
}

// Always called from app goroutine context - so don't need to protect for race on cancelfn
// Assumes gstate is ready
// iface can be a number, or a fifo, or a pipe...
func (c *PacketLoader) LoadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb Callback, app gowid.IApp) error {
	c.RenewIfaceLoader()

	return c.loadInterfaces(psrcs, captureFilter, displayFilter, tmpfile, cb, app)
}

func (c *ParentLoader) loadPsmlForInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb Callback, app gowid.IApp) error {
	// It's a temporary unique file, and no processes are started yet, so either
	// (a) it doesn't exist, OR
	// (b) it does exist in which case this load is a result of a restart.
	// In ths second case, we need to discard existing packets before starting
	// tail in case it catches this file with existing data.
	err := os.Remove(tmpfile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	c.PcapPsml = nil
	c.PcapPdml = tmpfile
	c.PcapPcap = tmpfile

	c.psrcs = psrcs // dpm't know if it's fifo (tfifo), pipe (/dev/fd/3) or iface (eth0). Treated same way

	c.ifaceFile = tmpfile
	c.displayFilter = displayFilter
	c.captureFilter = captureFilter

	handleNewSource(NoneCode, app, cb)

	log.Infof("Starting new interface/fifo load '%v'", SourcesString(psrcs))
	c.PsmlLoader.loadPsmlSync(c.InterfaceLoader, c, cb, app)

	return nil
}

// intended for internal use
func (c *ParentLoader) loadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb Callback, app gowid.IApp) error {

	if err := c.loadPsmlForInterfaces(psrcs, captureFilter, displayFilter, tmpfile, cb, app); err != nil {
		return err
	}

	// Deliberately use only HandleEnd handler once, in the PSML load - when it finishes,
	// we'll reenable ops
	c.InterfaceLoader.loadIfacesSync(c, cb, app)

	return nil
}

func (c *ParentLoader) String() string {
	names := make([]string, 0, len(c.psrcs))
	for _, psrc := range c.psrcs {
		switch {
		case psrc.IsFile() || psrc.IsFifo():
			names = append(names, filepath.Base(psrc.Name()))
		case psrc.IsPipe():
			names = append(names, "<stdin>")
		case psrc.IsInterface():
			names = append(names, psrc.Name())
		default:
			names = append(names, "(no packet source)")
		}
	}
	return strings.Join(names, " + ")
}

func (c *ParentLoader) Empty() bool {
	return len(c.psrcs) == 0
}

func (c *ParentLoader) Pcap() string {
	for _, psrc := range c.psrcs {
		if psrc != nil && psrc.IsFile() {
			return psrc.Name()
		}
	}
	return ""
}

func (c *ParentLoader) Interfaces() []string {
	names := make([]string, 0, len(c.psrcs))
	for _, psrc := range c.psrcs {
		if psrc != nil && !psrc.IsFile() {
			names = append(names, psrc.Name())
		}
	}
	return names
}

func (c *ParentLoader) loadIsNecessary(ev LoadPcapSlice) bool {
	res := true
	if ev.Row > c.NumLoaded() {
		res = false
	} else if ce, ok := c.CacheAt((ev.Row / c.opt.PacketsPerLoad) * c.opt.PacketsPerLoad); ok && ce.Complete() {
		// Might be less because a cache load might've been interrupted - if it's not truncated then
		// we're set
		res = false

		// I can't conclude that a load based at row 0 is sufficient to ignore this one.
		// The previous load might've started when only 10 packets were available (via the
		// the PSML data), so the PDML end idx would be frame.number < 10. This load might
		// be for a rocus position of 20, which would map via rounding to row 0. But we
		// don't have the data.

		// Hang on - this is for a load that has finished. If it was a live load, the cache
		// will not be marked complete for this batch of data - so a live load that is loading
		// this batch, but started earlier in the load (so frame.number < X where X < row)
		// will not be marked complete in the cache, so the load will be redone if needed. If
		// we get here, the load is still underway, so let it complete.
	} else if c.LoadingRow() == ev.Row {
		res = false
	}
	return res
}

// Assumes this is a clean stop, not an error
func (p *ParentLoader) stopTail() {
	p.tailStoppedDeliberately.Store(true)
	if p.tailCancelFn != nil {
		p.tailCancelFn()
	}
}

//======================================================================

type LoadPcapSlice struct {
	Row           int
	CancelCurrent bool
	Jump          int // 0 means no jump
}

func (m LoadPcapSlice) String() string {
	pieces := make([]string, 0, 3)
	pieces = append(pieces, fmt.Sprintf("loadslice: %d", m.Row))
	if m.CancelCurrent {
		pieces = append(pieces, fmt.Sprintf("cancelcurrent: %v", m.CancelCurrent))
	}
	if m.Jump != 0 {
		pieces = append(pieces, fmt.Sprintf("jumpto: %d", m.Jump))
	}
	return fmt.Sprintf("[%s]", strings.Join(pieces, ", "))
}

//======================================================================

func ProcessPdmlRequests(requests []LoadPcapSlice, mloader *ParentLoader,
	loader *PdmlLoader, cb Callback, app gowid.IApp) []LoadPcapSlice {
Loop:
	for {
		if len(requests) == 0 {
			break
		} else {
			ev := requests[0]

			if !mloader.loadIsNecessary(ev) {
				requests = requests[1:]
			} else {
				if loader.state.Load() {
					if ev.CancelCurrent {
						loader.stopLoadPdml()
					}
				} else {
					mloader.RenewPdmlLoader()
					mloader.loadPcapSync(ev.Row, true, mloader, cb, app)
					requests = requests[1:]
				}
				break Loop
			}
		}
	}
	return requests
}

//======================================================================

// https://stackoverflow.com/a/28005931/784226
func TempPcapFile(tokens ...string) string {
	tokensClean := make([]string, 0, len(tokens))
	for _, token := range tokens {
		tokensClean = append(tokensClean, filenameInvalidRe.ReplaceAllString(token, "_"))
	}

	tokenClean := strings.Join(tokensClean, "-")

	return filepath.Join(termshark.PcapDir(), fmt.Sprintf("%s--%s.pcap",
		tokenClean,
		termshark.DateStringForFilename(),
	))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
