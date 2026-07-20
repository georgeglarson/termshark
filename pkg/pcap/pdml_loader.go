// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type PdmlLoader struct {
	state atomic.Bool // true = loading

	PcapPdml string // Pcap file source for the pdml reader - tmpfile if iface; pcap otherwise
	PcapPcap string // Pcap file source for the pcap reader - tmpfile if iface; pcap otherwise

	pdmlStoppedDeliberately_ atomic.Bool // true if loader is in a transient state due to a user operation e.g. stop, reload, etc

	stage2Ctx      context.Context // cancels the pcap/pdml loading process
	stage2CancelFn context.CancelFunc

	stage2Wg sync.WaitGroup

	startChan chan struct{}

	Stage2FinishedChan chan struct{} // closed when entire pdml+pcap load process is done

	pdmlPid atomic.Int32 // 0 if process not started
	pcapPid atomic.Int32 // 0 if process not started

	sync.Mutex
	visible                  bool         // true if this pdml load is needed right now by the UI
	rowCurrentlyLoading      int          // set by the pdml loading stage - main goroutine only
	highestCachedRow         atomic.Int32 // accessed from pdml and pcap goroutines
	killAfterReadingThisMany atomic.Int32 // A shortcut - tell pcap/pdml to read one

	opt Options
}

func (c *PdmlLoader) PdmlPid() int {
	return int(c.pdmlPid.Load())
}

func (c *PdmlLoader) PcapPid() int {
	return int(c.pcapPid.Load())
}

type iPdmlLoaderEnv interface {
	iLoaderEnv
	DisplayFilter() string
	ReadingFromFifo() bool
	StartStage2ChanFn() chan struct{}
	PacketCacheFn() *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)]
	updateCacheEntryWithPdml(row int, pdml []IPdmlPacket, done bool)
	updateCacheEntryWithPcap(row int, pcap [][]byte, done bool)
	LengthOfPdmlCacheEntry(row int) (int, error)
	LengthOfPcapCacheEntry(row int) (int, error)
	CacheAt(row int) (CacheEntry, bool)
	DoWithPsmlData(func([][]string))
}

func (c *PdmlLoader) loadPcapSync(row int, visible bool, ps iPdmlLoaderEnv, cb Callback, app gowid.IApp) {

	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	c.stage2Ctx, c.stage2CancelFn = context.WithCancel(ps.Context())

	c.state.Store(true)
	c.rowCurrentlyLoading = row
	c.visible = visible

	// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
	var pdmlCancelled int32
	var pcapCancelled int32
	c.startChan = make(chan struct{})

	c.Stage2FinishedChan = make(chan struct{}) // gcla later todo - suspect

	// Returns true if it's an error we should bring to user's attention
	unexpectedPdmlError := func(err error) bool {
		cancelled := atomic.LoadInt32(&pdmlCancelled)
		if cancelled == 0 {
			if err != io.EOF {
				if err, ok := err.(*xml.SyntaxError); !ok || err.Msg != "unexpected EOF" {
					return true
				}
			}
		}
		return false
	}

	unexpectedPcapError := func(err error) bool {
		cancelled := atomic.LoadInt32(&pcapCancelled)
		if cancelled == 0 {
			if err != io.EOF {
				if err, ok := err.(*xml.SyntaxError); !ok || err.Msg != "unexpected EOF" {
					return true
				}
			}
		}
		return false
	}

	setPcapCancelled := func() {
		atomic.CompareAndSwapInt32(&pcapCancelled, 0, 1)
	}

	setPdmlCancelled := func() {
		atomic.CompareAndSwapInt32(&pdmlCancelled, 0, 1)
	}

	//======================================================================

	var displayFilterStr string

	sidx := -1
	eidx := -1

	// Determine this in main goroutine
	termshark.Go(func() {

		ps.MainRun(gowid.RunFunction(func(app gowid.IApp) {
			HandleBegin(PdmlCode, app, cb)
		}))

		// This should correctly wait for all resources, no matter where in the process of creating them
		// an interruption or error occurs
		defer func(p *PdmlLoader) {
			// Wait for all other goroutines to complete
			p.stage2Wg.Wait()

			// The process Wait() goroutine will always expect a stage2 cancel at some point. It can
			// come early, if the user interrupts the load. If not, then we send it now, to let
			// that goroutine terminate.
			p.stage2CancelFn()

			ps.MainRun(gowid.RunFunction(func(app gowid.IApp) {
				close(p.Stage2FinishedChan)
				HandleEnd(PdmlCode, app, cb)

				p.state.Store(false)
				p.rowCurrentlyLoading = -1
				p.stage2CancelFn = nil
			}))
		}(c)

		// Set these before starting the pcap and pdml process goroutines so that
		// at the beginning, PdmlCmd and PcapCmd are definitely not nil. These
		// values are saved by the goroutine, and used to access the pid of these
		// processes, if they are started.
		var pdmlCmd IPcapCommand
		var pcapCmd IPcapCommand

		//
		// Goroutine to set mapping between table rows and frame numbers
		//
		c.stage2Wg.Add(1)
		termshark.Go(func() {
			defer c.stage2Wg.Done()
			select {
			case <-ps.StartStage2ChanFn():
				break
			case <-c.stage2Ctx.Done():
				return
			}

			// Do this - but if we're cancelled first (stage2Ctx.Done), then they
			// don't need to be signalled because the other selects waiting on these
			// channels will be cancelled too.
			// This has to wait until the PsmlCmd and PcapCmd are set - because next stages depend
			// on those
			defer func() {
				// Signal the pdml and pcap reader to start.
				select {
				case <-c.startChan: // it will be closed if the psml has loaded already, and this e.g. a cached load
				default:
					close(c.startChan)
				}
			}()

			// If there's no filter, psml, pdml and pcap run concurrently for speed. Therefore the pdml and pcap
			// don't know how large the psml will be. So we set numToRead to 1000. This might be too high, but
			// we only use this to determine when we can kill the reading processes early. The result will be
			// correct if we don't kill the processes, it just might load for longer.
			c.killAfterReadingThisMany.Store(int32(c.opt.PacketsPerLoad))
			var err error
			if ps.DisplayFilter() == "" {
				sidx = row + 1
				// +1 for frame.number being 1-based; +1 to read past the end so that
				// the XML decoder doesn't stall and I can kill after abcdex
				eidx = row + c.opt.PacketsPerLoad + 1 + 1
			} else {
				ps.DoWithPsmlData(func(psmlData [][]string) {
					if len(psmlData) > row {
						sidx, err = strconv.Atoi(psmlData[row][0])
						if err != nil {
							log.Errorf("Failed to parse PSML packet number: %v", err)
							return
						}
						if len(psmlData) > row+c.opt.PacketsPerLoad+1 {
							// If we have enough packets to request one more than the amount to
							// cache, then requesting one more will mean the XML decoder won't
							// block at packet 999 waiting for </pdml> - so this is a hack to
							// let me promptly kill tshark when I've read enough.
							eidx, err = strconv.Atoi(psmlData[row+c.opt.PacketsPerLoad+1][0])
							if err != nil {
								log.Errorf("Failed to parse PSML packet number: %v", err)
								return
							}
						} else {
							eidx, err = strconv.Atoi(psmlData[len(psmlData)-1][0])
							if err != nil {
								log.Errorf("Failed to parse PSML packet number: %v", err)
								return
							}
							eidx += 1 // beyond end of last frame
							c.killAfterReadingThisMany.Store(int32(len(psmlData) - row))
						}
					}
				})
			}

			if ps.DisplayFilter() != "" {
				displayFilterStr = fmt.Sprintf("(%s) and (frame.number >= %d) and (frame.number < %d)", ps.DisplayFilter(), sidx, eidx)
			} else {
				displayFilterStr = fmt.Sprintf("(frame.number >= %d) and (frame.number < %d)", sidx, eidx)
			}

			// These need to be set after displayFilterStr is set but before stage 2 is started
			pdmlCmd = ps.Commands().Pdml(c.PcapPdml, displayFilterStr)
			pcapCmd = ps.Commands().Pcap(c.PcapPcap, displayFilterStr)

		})

		//======================================================================

		pdmlPidChan := make(chan int)
		pcapPidChan := make(chan int)

		pdmlTermChan := make(chan error)
		pcapTermChan := make(chan error)

		pdmlCtx, pdmlCancelFn := context.WithCancel(c.stage2Ctx)
		pcapCtx, pcapCancelFn := context.WithCancel(c.stage2Ctx)

		//
		// Goroutine to track pdml and pcap process lifetimes
		//
		termshark.Go(func() {
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				return
			}

			var err error
			stage2CtxChan := c.stage2Ctx.Done()
			pdmlPidChan := pdmlPidChan
			pcapPidChan := pcapPidChan

			pdmlCancelledChan := pdmlCtx.Done()
			pcapCancelledChan := pcapCtx.Done()

			pdmlState := NotStarted
			pcapState := NotStarted

			killPcap := func() {
				err := termshark.KillIfPossible(pcapCmd)
				if err != nil {
					log.Infof("Did not kill pcap process: %v", err)
				}
			}

			killPdml := func() {
				err = termshark.KillIfPossible(pdmlCmd)
				if err != nil {
					log.Infof("Did not kill pdml process: %v", err)
				}
			}

		loop:
			for {
				select {

				case err = <-pdmlTermChan:
					pdmlState = Terminated

				case err = <-pcapTermChan:
					pcapState = Terminated

				case pid := <-pdmlPidChan:
					// this channel can be closed on a stage2 cancel, before the
					// pdml process has been started, meaning we get nil for the
					// pid. If that's the case, don't save the cmd, so we know not
					// to try to kill anything later.
					pdmlPidChan = nil // don't select on this channel again
					if pid != 0 {
						pdmlState = Started
						c.pdmlPid.Store(int32(pid))
						if stage2CtxChan == nil || pdmlCancelledChan == nil {
							// means that stage2 has been cancelled (so stop the load), and
							// pdmlCmd != nil => for sure a process was started. So kill it.
							// It won't have been cleaned up anywhere else because Wait() is
							// only called below, in this goroutine.
							killPdml()
						}
					}

				case pid := <-pcapPidChan:
					pcapPidChan = nil // don't select on this channel again
					if pid != 0 {
						pcapState = Started
						c.pcapPid.Store(int32(pid))
						if stage2CtxChan == nil || pcapCancelledChan == nil {
							killPcap()
						}
					}

				case <-pdmlCancelledChan:
					pdmlCancelledChan = nil // don't select on this channel again
					setPdmlCancelled()
					if pdmlState == Started {
						killPdml()
					}

				case <-pcapCancelledChan:
					pcapCancelledChan = nil // don't select on this channel again
					setPcapCancelled()
					if pcapState == Started {
						// means that for sure, a process was started
						killPcap()
					}

				case <-stage2CtxChan:
					// This will automatically signal pdmlCtx.Done and pcapCtx.Done()

					// Once the pcap/pdml load is initiated, we guarantee we get a stage2 cancel
					// once all the stage2 goroutines are finished. So we don't quit the select loop
					// until this channel (as well as the others) has received a signal
					stage2CtxChan = nil
				}

				// if pdmlpidchan is nil, it means the the channel has been closed or we've received a message
				// a message means the proc has started
				// closed means it won't be started
				// if closed, then pdmlCmd == nil
				// 04/11/21: I can't take a shortcut here and condition on Terminated || (cancelledChan == nil && NotStarted)
				// See the pcap or pdml goroutines below. I block at the beginning, checking on the stage2 cancellation.
				// If I get past that point, and there are no errors in the process invocation, I am guaranteed to start both
				// the pdml and pcap processes. If there are errors, I am guaranteed to close the pcapPidChan with a defer.
				// If I take a shortcut and end this goroutine via a stage2 cancellation before waiting for the pcap pid,
				// then I'll block in that goroutine, trying to send to the pcapPidChan, but with nothing here to receive
				// the value. In the pcap process goroutine, if I get past the stage2 cancellation check, then I need to
				// have something to receive the pid - this goroutine. It needs to stay alive until it gets the pid, or a
				// zero.
				if (pdmlState == Terminated || (pdmlPidChan == nil && c.pdmlPid.Load() == 0)) &&
					(pcapState == Terminated || (pcapPidChan == nil && c.pcapPid.Load() == 0)) {
					// nothing to select on so break
					break loop
				}
			}
		})

		//======================================================================

		//
		// Goroutine to run pdml process
		//
		c.stage2Wg.Add(1)
		termshark.Go(func() {
			defer c.stage2Wg.Done()
			// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
			// quit if that happens first
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				close(pdmlPidChan)
				return
			}

			// We didn't get a stage2 cancel yet. We could now, but for now we've been told to continue
			// now we'll guarantee either:
			// - we'll send the pdml pid on pdmlPidChan if it starts
			// - we'll close the channel if it doesn't start

			pid := 0

			defer func() {
				// Guarantee that at the end of this goroutine, if we didn't start a process (pid == 0)
				// we will close the channel to signal the Wait() goroutine above.
				if pid == 0 {
					close(pdmlPidChan)
				}
			}()

			pdmlOut, err := pdmlCmd.StdoutReader()
			if err != nil {
				HandleError(PdmlCode, app, err, cb)
				return
			}

			err = pdmlCmd.Start()
			if err != nil {
				err = fmt.Errorf("Error starting PDML process %v: %w", pdmlCmd, err)
				HandleError(PdmlCode, app, err, cb)
				return
			}

			log.Infof("Started PDML command %v with pid %d", pdmlCmd, pdmlCmd.Pid())

			pid = pdmlCmd.Pid()
			pdmlPidChan <- pid

			d := xml.NewDecoder(pdmlOut)
			packets := make([]IPdmlPacket, 0, c.opt.PacketsPerLoad)
			issuedKill := false
			readAllRequiredPdml := false
			var packet PdmlPacket
			var cpacket IPdmlPacket
		Loop:
			for {
				tok, err := d.Token()
				if err != nil {
					if !issuedKill && unexpectedPdmlError(err) {
						err = fmt.Errorf("Could not read PDML data: %w", err)
						issuedKill = true
						pdmlCancelFn()
						HandleError(PdmlCode, app, err, cb)
					}
					if errors.Is(err, io.EOF) {
						readAllRequiredPdml = true
					}
					break
				}
				switch tok := tok.(type) {
				case xml.StartElement:
					switch tok.Name.Local {
					case "packet":
						err := d.DecodeElement(&packet, &tok)
						if err != nil {
							if !issuedKill && unexpectedPdmlError(err) {
								err = fmt.Errorf("Could not decode PDML data: %w", err)
								issuedKill = true
								pdmlCancelFn()
								HandleError(PdmlCode, app, err, cb)
							}
							break Loop
						}
						cpacket = SnappyPdmlPacket(packet)
						packets = append(packets, cpacket)
						ps.updateCacheEntryWithPdml(row, packets, false)
						if len(packets) == int(c.killAfterReadingThisMany.Load()) {
							// Shortcut - we never take more than abcdex - so just kill here
							issuedKill = true
							readAllRequiredPdml = true
							c.pdmlStoppedDeliberately_.Store(true)
							pdmlCancelFn()
						}
					}

				}

			}

			// The Wait has to come after the last read, which is above.
			// Use a goroutine with timeout to prevent indefinite blocking
			// if the child process is unkillable.
			waitDone := make(chan error, 1)
			go func() {
				waitDone <- pdmlCmd.Wait()
			}()
			select {
			case waitErr := <-waitDone:
				pdmlTermChan <- waitErr
			case <-time.After(30 * time.Second):
				log.Warnf("Timed out waiting for pdml process to exit")
				pdmlTermChan <- fmt.Errorf("pdml process wait timed out")
			}

			// Want to preserve invariant - for simplicity - that we only add full loads
			// to the cache

			ps.MainRun(gowid.RunFunction(func(gowid.IApp) {
				// never evict row 0
				ps.PacketCacheFn().Get(0)
				if c.highestCachedRow.Load() != -1 {
					// try not to evict "end"
					ps.PacketCacheFn().Get(int(c.highestCachedRow.Load()))
				}

				// the cache entry is marked complete if we are not reading from a fifo, which implies
				// the source of packets will not grow larger. If it could grow larger, we want to ensure
				// that termshark doesn't think that there are only 900 packets, because that's what's
				// in the cache from a previous request - now there might be 950 packets.
				//
				// If the PDML routine was stopped programmatically, that implies the load was not complete
				// so we don't mark the cache as complete then either.
				markComplete := false
				if !ps.ReadingFromFifo() && readAllRequiredPdml {
					markComplete = true
				}
				ps.updateCacheEntryWithPdml(row, packets, markComplete)
				if int32(row) > c.highestCachedRow.Load() {
					c.highestCachedRow.Store(int32(row))
				}
			}))
		})

		//======================================================================

		//
		// Goroutine to run pcap process
		//
		c.stage2Wg.Add(1)
		termshark.Go(func() {
			defer c.stage2Wg.Done()
			// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
			// quit if that happens first
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				close(pcapPidChan)
				return
			}

			pid := 0

			defer func() {
				if pid == 0 {
					close(pcapPidChan)
				}
			}()

			pcapOut, err := pcapCmd.StdoutReader()
			if err != nil {
				HandleError(PdmlCode, app, err, cb)
				return
			}

			err = pcapCmd.Start()
			if err != nil {
				// e.g. on the pi
				err = fmt.Errorf("Error starting PCAP process %v: %w", pcapCmd, err)
				HandleError(PdmlCode, app, err, cb)
				return
			}

			log.Infof("Started pcap command %v with pid %d", pcapCmd, pcapCmd.Pid())

			pid = pcapCmd.Pid()
			pcapPidChan <- pid

			packets := make([][]byte, 0, c.opt.PacketsPerLoad)
			issuedKill := false
			readAllRequiredPcap := false
			rd := bufio.NewReader(pcapOut)
			packet := make([]byte, 0)

			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					if !issuedKill && unexpectedPcapError(err) {
						err = fmt.Errorf("Could not read PCAP packet: %w", err)
						HandleError(PdmlCode, app, err, cb)
					}
					if errors.Is(err, io.EOF) {
						readAllRequiredPcap = true
					}
					break
				}

				parseResults := hexByteRe.FindAllStringSubmatch(string(line), -1)

				if len(parseResults) < 1 {
					packets = append(packets, packet)
					packet = make([]byte, 0)

					readEnough := (len(packets) >= int(c.killAfterReadingThisMany.Load()))
					ps.updateCacheEntryWithPcap(row, packets, false)

					if readEnough && !issuedKill {
						// Shortcut - we never take more than abcdex - so just kill here
						issuedKill = true
						readAllRequiredPcap = true
						pcapCancelFn()
					}
				} else {
					// Ignore line number
					for _, parsedByte := range parseResults[1:] {
						b, err := strconv.ParseUint(string(parsedByte[0][0:2]), 16, 8)
						if err != nil {
							err = fmt.Errorf("Could not read PCAP packet: %w", err)
							if !issuedKill {
								HandleError(PdmlCode, app, err, cb)
							}
							break
						}
						packet = append(packet, byte(b))
					}
				}
			}

			// The Wait has to come after the last read, which is above.
			// Use a goroutine with timeout to prevent indefinite blocking
			// if the child process is unkillable.
			waitDone := make(chan error, 1)
			go func() {
				waitDone <- pcapCmd.Wait()
			}()
			select {
			case waitErr := <-waitDone:
				pcapTermChan <- waitErr
			case <-time.After(30 * time.Second):
				log.Warnf("Timed out waiting for pcap process to exit")
				pcapTermChan <- fmt.Errorf("pcap process wait timed out")
			}

			// I just want to ensure I read it from ram, obviously this is racey
			// never evict row 0
			ps.PacketCacheFn().Get(0)
			if c.highestCachedRow.Load() != -1 {
				// try not to evict "end"
				ps.PacketCacheFn().Get(int(c.highestCachedRow.Load()))
			}
			markComplete := false
			if !ps.ReadingFromFifo() && readAllRequiredPcap {
				markComplete = true
			}
			ps.updateCacheEntryWithPcap(row, packets, markComplete)

		})

	})

}

//======================================================================

func (c *PdmlLoader) IsLoading() bool {
	return c.state.Load()
}

func (c *PdmlLoader) LoadIsVisible() bool {
	return c.visible
}

// Only call from main goroutine
func (c *PdmlLoader) LoadingRow() int {
	return c.rowCurrentlyLoading
}

// KillAfterReadingThisMany returns the number of packets to read before killing tshark.
func (c *PdmlLoader) KillAfterReadingThisMany() int {
	return int(c.killAfterReadingThisMany.Load())
}

func (p *PdmlLoader) stopLoadPdml() {
	p.pdmlStoppedDeliberately_.Store(true)
	if p.stage2CancelFn != nil {
		p.stage2CancelFn()
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
