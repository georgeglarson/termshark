// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/format"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type PsmlLoader struct {
	state atomic.Bool // true = loading

	PcapPsml any // Pcap file source for the psml reader - fifo if iface+!stopped; tmpfile if iface+stopped; pcap otherwise

	psmlStoppedDeliberately_ atomic.Bool // true if loader is in a transient state due to a user operation e.g. stop, reload, etc

	psmlCtx      context.Context // cancels the psml loading process
	psmlCancelFn context.CancelFunc
	tailCtx      context.Context // cancels the tail reader process (if iface in operation)
	tailCancelFn context.CancelFunc

	// Signalled when the psml is fully loaded (or already loaded) - to tell
	// the pdml and pcap reader goroutines to start - they can then map table
	// row -> frame number
	startStage2Chan chan struct{}

	PsmlFinishedChan chan struct{} // closed when entire psml load process is done

	tailCmd ITailCommand
	PsmlCmd IPcapCommand // gcla later todo - change to pid like PdmlPid

	sync.Mutex
	packetAverageLength []averageTracker // length of num columns
	packetMaxLength     []maxTracker     // length of num columns
	packetPsmlData      [][]string
	packetPsmlColors    []PacketColors
	packetPsmlHeaders   []string
	PacketNumberMap     map[int]int // map from actual packet row <packet>12</packet> to pos in unsorted table
	// This would be affected by a display filter e.g. packet 12 might be the 1st packet in the table.
	// I need this so that if the user jumps to a mark stored as "packet 12", I can find the right table row.
	PacketNumberOrder map[int]int // e.g. {12->44, 44->71, 71->72,...} - the packet numbers, in order, affected by a filter.
	// If I use a generic ordered map, I could avoid this separate structure

	PacketCache *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)] - accessed from any goroutine

	opt Options
}

type PacketColors struct {
	FG gowid.IColor
	BG gowid.IColor
}

type iPsmlLoaderEnv interface {
	iLoaderEnv
	iTailCommand
	PsmlStoppedDeliberately() bool
	TailStoppedDeliberately() bool
	LoadWasCancelled() bool
	DisplayFilter() string
	InterfaceFile() string
	PacketSources() []IPacketSource
}

//======================================================================

// Holds a reference to the loader, and wraps Read() around the tail process's
// Read(). Count the bytes, and when they are equal to the final total of bytes
// written by the tshark -i process (spooling to a tmp file), a function is called
// which stops the PSML process.
type tailReadTracker struct {
	tailReader io.Reader
	loader     *InterfaceLoader
	tail       iTailCommand
	callback   Callback
	app        gowid.IApp
}

func (r *tailReadTracker) Read(p []byte) (int, error) {
	n, err := r.tailReader.Read(p)

	r.loader.Lock()
	if r.loader.totalFifoBytesRead.IsNone() {
		r.loader.totalFifoBytesRead = gwutil.SomeInt64(int64(n))
	} else {
		r.loader.totalFifoBytesRead = gwutil.SomeInt64(int64(n) + r.loader.totalFifoBytesRead.Val())
	}
	// err == ErrClosed if the pipe (tailReader) that is wrapped in this tracker is closed.
	// This can happen because this call to Read() and the deferred closepipe() function run
	// at the same time.
	if err != nil && r.loader.fifoError == nil && err != io.EOF && !errIsAlreadyClosed(err) {
		r.loader.fifoError = err
	}
	r.loader.Unlock()

	r.loader.checkAllBytesRead(r.tail, r.callback, r.app)

	return n, err
}

func errIsAlreadyClosed(err error) bool {
	if err == os.ErrClosed {
		return true
	} else if err, ok := err.(*os.PathError); ok {
		return errIsAlreadyClosed(err.Err)
	} else {
		return false
	}
}

//======================================================================

// waitForFileData sets an inotify watch on filename, and returns when a WRITE
// event is seen.  There is special logic for the case where the file is
// removed; then the watcher is deleted and reinstated. This is to handle a
// specific loading bug in termshark due to an optimized packet capture
// process. To capture packets, termshark runs itself with a special env var
// set.  It detects this at startup, then launches dumpcap as the first
// capture method. If this fails (e.g. the source is an extcap), it launches
// tshark instead. Dumpcap is more efficient, but tshark is needed for the
// extcap sources. The problem is that termshark needs a heuristic for when
// packets have actually been detected - this is so it can wait to launch the
// UI (in case a password is needed at the terminal, I don't want to obscure
// that with the UI). So termshark waits for a WRITE to the pcap generated by
// the capture process, and then launches tail. BUT - if dumpcap fails, it
// will delete (unlink) the capture file passed to it with the -w argument
// before tshark starts. If we don't watch for WRITE, this triggers the
// notifier; then tail starts; then tail fails because depending on timing,
// tshark may not have started yet and so the tail target pcap does not exist.
// The fix is to monitor for inotify REMOVE too, and if seen, recreate the
// pcap file (empty), and restart the watcher. And importantly, don't let
// the tail process start until the WRITE event is seen.
func waitForFileData(ctx context.Context, filename string, errFn func(error)) {
	for {
		// this set up is so that I can detect when there are actually packets to read (e.g
		// maybe there's no traffic on the interface). When there's something to read, the
		// rest of the procedure can spring into action. Why not spring into action right away?
		// Because the tail command needs a file to exist to watch it with -f. Can I rely on
		// tail -F across all supported platforms? (e.g. Windows)
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			err = fmt.Errorf("Could not create FS watch: %w", err)
			errFn(err)
			return
		}

		file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			watcher.Close()
			err = fmt.Errorf("Could not touch temporary pcap file %s: %w", filename, err)
			errFn(err)
			return
		}
		file.Close()

		if err := watcher.Add(filename); err != nil {
			watcher.Close()
			err = fmt.Errorf("Could not set up watcher for %s: %w", filename, err)
			errFn(err)
			return
		}

		retry := false
	NotifyLoop:
		for {
			select {
			case fe := <-watcher.Events:
				if fe.Name == filename {
					switch fe.Op {
					case fsnotify.Remove:
						retry = true
						break NotifyLoop
					default:
						break NotifyLoop
					}
				}
			case err := <-watcher.Errors:
				watcher.Close()
				err = fmt.Errorf("Unexpected watcher error for %s: %w", filename, err)
				errFn(err)
				return
			case <-ctx.Done():
				watcher.Close()
				return
			}
		}

		// Close the watcher explicitly before potentially looping to avoid FD leak
		watcher.Close()

		if !retry {
			return
		}
	}
}

// loadPsmlSync starts tshark processes, and other processes, to generate PSML
// data. There is coordination with the PDML loader via a channel,
// startStage2Chan. If a filter is set, then we might need to read far more
// than a block of 1000 PDML packets (via frame.number <= 4000, for example),
// and we don't know how many to read until the PSML is loaded. We don't want
// to only load one PDML packet at a time, and reload as the user hits arrow
// down through the PSML (in the case the packets selected by the filter are
// very spaced out).
//
// The flow is as follows:
// - if the source of packets is a fifo/interface then
//   - create a pipe
//   - set PcapPsml to a Reader object that tracks bytes read from the pipe
//
// - start the PSML tshark command and get its stdout
// - if the source of packets is a fifo/interface then
//   - use inotify to wait for the tmp pcap file to appear
//   - start the tail command to read the tmp file created by the interface loader
//
// - read the PSML and add to data structures
//
// Goroutines are started to track the process lifetimes of both processes.
func (p *PsmlLoader) loadPsmlSync(iloader *InterfaceLoader, e iPsmlLoaderEnv, cb Callback, app gowid.IApp) {
	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	p.psmlCtx, p.psmlCancelFn = context.WithCancel(e.Context())
	p.tailCtx, p.tailCancelFn = context.WithCancel(e.Context())

	intPsmlCtx, intPsmlCancelFn := context.WithCancel(context.Background())

	p.state.Store(true)

	//======================================================================

	var psmlOut io.ReadCloser

	// Only start this process if we are in interface mode
	var err error
	var fifoPipeReader *os.File
	var fifoPipeWriter *os.File

	//======================================================================

	// Make sure we start the goroutine that monitors for shutdown early - so if/when
	// a shutdown happens, and we get blocked in the XML parser, this will be able to
	// respond
	psmlPidChan := make(chan int)
	tailPidChan := make(chan int)
	psmlTermChan := make(chan error)
	tailTermChan := make(chan error)
	psmlPid := 0 // 0 means not running
	tailPid := 0

	//======================================================================

	termshark.Go(func() {

		e.MainRun(gowid.RunFunction(func(app gowid.IApp) {
			HandleBegin(PsmlCode, app, cb)
		}))

		defer func(ch chan struct{}) {
			// This will signal goroutines using select on this channel to terminate - like
			// ticker routines that update the packet list UI with new data every second.
			close(p.PsmlFinishedChan)

			e.MainRun(gowid.RunFunction(func(gowid.IApp) {
				HandleEnd(PsmlCode, app, cb)
				p.state.Store(false)
				p.psmlCancelFn = nil
			}))
		}(p.PsmlFinishedChan)

		//======================================================================

		// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
		if e.DisplayFilter() == "" || p.ReadingFromFifo() {
			// don't hold up pdml and pcap generators. If the filter is "", then the frame numbers
			// equal the row numbers, so we don't need the psml to map from row -> frame.
			//
			// And, if we are in interface mode, we won't reach the end of the psml anyway.
			//
			close(p.startStage2Chan)
		}

		//======================================================================

		var closePipeOnce sync.Once
		closePipe := func() {
			closePipeOnce.Do(func() {
				fifoPipeWriter.Close()
				fifoPipeReader.Close()
			})
		}

		if p.ReadingFromFifo() {
			// PcapPsml will be nil if here

			// Build a pipe - the side to be read from will be given to the PSML process
			// and the side to be written to is given to the tail process, which feeds in
			// data from the pcap source.
			//
			fifoPipeReader, fifoPipeWriter, err = os.Pipe()
			if err != nil {
				err = fmt.Errorf("Could not create pipe: %w", err)
				HandleError(PsmlCode, app, err, cb)
				intPsmlCancelFn()
				return
			}
			// pw is used as Stdout for the tail command, which unwinds in this
			// goroutine - so we can close at this point in the unwinding. pr
			// is used as stdin for the psml command, which also runs in this
			// goroutine.
			defer func() {
				closePipe()
			}()

			// wrap the read end of the pipe with a Read() function that counts
			// bytes. If they are equal to the total bytes written to the tmpfile by
			// the tshark -i process, then that means the source is exhausted, and
			// the tail + psml processes are stopped.
			p.PcapPsml = &tailReadTracker{
				tailReader: fifoPipeReader,
				loader:     iloader,
				tail:       e,
				callback:   cb,
				app:        app,
			}
		}

		// Set c.PsmlCmd before it's referenced in the goroutine below. We want to be
		// sure that if if psmlCmd is nil then that means the process has finished (not
		// has not yet started)
		p.PsmlCmd = e.Commands().Psml(p.PcapPsml, e.DisplayFilter())

		// this channel always needs to be signalled or else the goroutine below won't terminate.
		// Closing it will pass a zero-value int (pid) to the goroutine which will understand that
		// means the psml process is NOT running, so it won't call cmd.Wait() on it.
		defer func() {
			if psmlPid == 0 {
				close(psmlPidChan)
			}
		}()

		//======================================================================
		// Goroutine to track process state changes
		termshark.Go(func() {
			cancelledChan := p.psmlCtx.Done()
			intCancelledChan := intPsmlCtx.Done()

			var err error
			psmlCmd := p.PsmlCmd
			pidChan := psmlPidChan
			state := NotStarted

			kill := func() {
				err := termshark.KillIfPossible(psmlCmd)
				if err != nil {
					log.Infof("Did not kill tshark psml process: %v", err)
				}

				if p.ReadingFromFifo() {
					closePipe()
				}
			}

		loop:
			for {
				select {
				case err = <-psmlTermChan:
					state = Terminated
					if !p.psmlStoppedDeliberately_.Load() {
						if err != nil {
							var exerr *exec.ExitError
							if errors.As(err, &exerr) {
								HandleError(PsmlCode, app, MakeUsefulError(psmlCmd, err), cb)
							}
						}
					}

				case <-cancelledChan:
					intPsmlCancelFn() // start internal shutdown
					cancelledChan = nil

				case <-intCancelledChan:
					intCancelledChan = nil
					if state == Started {
						kill()
					}

				case pid := <-pidChan:
					pidChan = nil
					if pid != 0 {
						state = Started
						if intCancelledChan == nil {
							kill()
						}
					}
				}

				if state == Terminated || (pidChan == nil && state == NotStarted) {
					break loop
				}
			}

		})

		//======================================================================

		psmlOut, err = p.PsmlCmd.StdoutReader()
		if err != nil {
			err = fmt.Errorf("Could not access pipe output: %w", err)
			HandleError(PsmlCode, app, err, cb)
			intPsmlCancelFn()
			return
		}

		err = p.PsmlCmd.Start()
		if err != nil {
			err = fmt.Errorf("Error starting PSML command %v: %w", p.PsmlCmd, err)
			HandleError(PsmlCode, app, err, cb)
			intPsmlCancelFn()
			return
		}

		log.Infof("Started PSML command %v with pid %d", p.PsmlCmd, p.PsmlCmd.Pid())

		// Do this here because code later can return early - e.g. the watcher fails to be
		// set up - and then we'll never issue a Wait
		waitedForPsml := false

		// Prefer a defer rather than a goroutine here. That's because otherwise, this goroutine
		// and the XML processing routine reading the process's StdoutPipe are running in parallel,
		// and the XML routine should not issue a Read() (which it does behind the scenes) after
		// Wait() has been called.
		waitForPsml := func() {
			if !waitedForPsml {
				psmlTermChan <- p.PsmlCmd.Wait()
				waitedForPsml = true
			}
		}

		defer waitForPsml()

		psmlPid = p.PsmlCmd.Pid()
		psmlPidChan <- psmlPid

		//======================================================================

		// If it was cancelled, then we don't need to start the tail process because
		// psml will read from the tmp pcap file generated by the interface reading
		// process.

		p.tailCmd = nil

		// Need to run dumpcap -i eth0 -w <tmppcapfile>
		if p.ReadingFromFifo() {
			p.tailCmd = e.Commands().Tail(e.InterfaceFile())

			defer func() {
				if tailPid == 0 {
					close(tailPidChan)
				}
			}()

			//======================================================================
			// process lifetime goroutine for the tail process:
			// tshark -i > tmp
			// tail -f tmp | tshark -i - -t psml
			// ^^^^^^^^^^^
			termshark.Go(func() {
				cancelledChan := p.tailCtx.Done()

				var err error
				tailCmd := p.tailCmd
				pidChan := tailPidChan
				state := NotStarted

				kill := func() {
					err := termshark.KillIfPossible(tailCmd)
					if err != nil {
						log.Infof("Did not kill tshark tail process: %v", err)
					}
				}

			loop:
				for {
					select {
					case err = <-tailTermChan:
						state = Terminated
						// Don't close the pipe - the psml might not have finished reading yet
						// gcla later todo - is this right or wrong

						// Close the pipe so that the psml reader gets EOF and will also terminate;
						// otherwise the PSML reader will block waiting for more data from the pipe
						fifoPipeWriter.Close()
						if !p.psmlStoppedDeliberately_.Load() && !e.TailStoppedDeliberately() {
							if err != nil {
								var exerr *exec.ExitError
								if errors.As(err, &exerr) {
									HandleError(PsmlCode, app, MakeUsefulError(tailCmd, err), cb)
								}
							}
						}

					case <-cancelledChan:
						cancelledChan = nil
						if state == Started {
							kill()
						}

					case pid := <-pidChan:
						pidChan = nil
						if pid != 0 {
							state = Started
							if cancelledChan == nil {
								kill()
							}
						}
					}

					// successfully started then died/kill, OR
					// was never started, won't be started, and cancelled
					if state == Terminated || (pidChan == nil && state == NotStarted) {
						break loop
					}
				}
			})

			//======================================================================

			p.tailCmd.SetStdout(fifoPipeWriter)

			waitForFileData(intPsmlCtx,
				e.InterfaceFile(),
				func(err error) {
					HandleError(PsmlCode, app, err, cb)
					intPsmlCancelFn()
					p.tailCancelFn() // needed to end the goroutine, end if tailcmd has not started
				},
			)

			log.Infof("Starting Tail command: %v", p.tailCmd)

			err = p.tailCmd.Start()
			if err != nil {
				err = fmt.Errorf("Could not start tail command %v: %w", p.tailCmd, err)
				HandleError(PsmlCode, app, err, cb)
				intPsmlCancelFn()
				p.tailCancelFn() // needed to end the goroutine, end if tailcmd has not started
				return
			}

			termshark.Go(func() {
				tailTermChan <- p.tailCmd.Wait()
			})

			tailPid = p.tailCmd.Pid()
			tailPidChan <- tailPid
		} // end of reading from fifo

		//======================================================================

		//
		// Goroutine to read psml xml and update data structures
		//
		defer func(ch chan struct{}) {
			select {
			case <-ch:
				// already done/closed, do nothing
			default:
				close(ch)
			}

			// This will kill the tail process if there is one
			intPsmlCancelFn() // stop the ticker
		}(p.startStage2Chan)

		d := xml.NewDecoder(psmlOut)

		// <packet>
		// <section>1</section>
		// <section>0.000000</section>
		// <section>192.168.44.123</section>
		// <section>192.168.44.213</section>
		// <section>TFTP</section>
		// <section>77</section>
		// <section>Read Request, File: C:\IBMTCPIP\lccm.1, Transfer type: octet</section>
		// </packet>

		var curPsml []string
		var curCounts []int
		var fg string
		var bg string
		var pidx int
		ppidx := 0 // the previous packet number read; 0 means no packet. I can use 0 because
		// the psml I read will start at packet 1 so - map[0] => 1st packet
		ready := false
		empty := true
		structure := false
		for {
			if intPsmlCtx.Err() != nil {
				break
			}
			tok, err := d.Token()
			if err != nil {
				// gcla later todo - LoadWasCancelled is checked outside of the main goroutine here
				if err != io.EOF && !e.LoadWasCancelled() {
					err = fmt.Errorf("Could not read PSML data: %w", err)
					HandleError(PsmlCode, app, err, cb)
				}
				break
			}
			switch tok := tok.(type) {
			case xml.EndElement:
				switch tok.Name.Local {
				case "structure":
					structure = false
					p.Lock()
					// Don't keep the first column - we add on column number to all PSML
					// loads whether or not the user wants it to track table number -> packet
					// number. This is then stripped from the columns shown to the user.
					p.packetPsmlHeaders = p.packetPsmlHeaders[1:]
					p.Unlock()
				case "packet":
					p.Lock()

					// Validate curPsml has at least one element before accessing
					if len(curPsml) == 0 {
						p.Unlock()
						continue
					}

					// Track the mapping of packet number <section>12</section> to position
					// in the table e.g. 5th element. This is so that I can jump to the correct
					// row with marks even if a filter is currently applied.
					pidx, err = strconv.Atoi(curPsml[0])
					if err != nil {
						log.Errorf("Failed to parse PSML packet number: %v", err)
						p.Unlock()
						continue
					}
					p.PacketNumberMap[pidx] = len(p.packetPsmlData)
					p.PacketNumberOrder[ppidx] = pidx
					ppidx = pidx

					p.packetPsmlData = append(p.packetPsmlData, curPsml[1:])

					if len(curPsml) > 1 && len(p.packetAverageLength) > len(curPsml)-1 {
						p.packetAverageLength = p.packetAverageLength[0 : len(curPsml)-1]
					}
					if len(curPsml) > 1 && len(p.packetMaxLength) > len(curPsml)-1 {
						p.packetMaxLength = p.packetMaxLength[0 : len(curPsml)-1]
					}

					if len(curCounts) > 1 {
						for i, ct := range curCounts[1:] {
							if i >= len(p.packetAverageLength) || i >= len(p.packetMaxLength) {
								break
							}
							// skip the first one - that's not displayed in the UI. We always have element 0 as No.
							p.packetAverageLength[i].update(ct)
							p.packetMaxLength[i].update(ct)
						}
					}

					p.packetPsmlColors = append(p.packetPsmlColors, PacketColors{
						FG: psmlColorToIColor(fg),
						BG: psmlColorToIColor(bg),
					})
					p.Unlock()

				case "section":
					ready = false
					// Means we got </section> without any char data i.e. empty <section>
					if empty {
						curCounts = append(curCounts, 0)
						curPsml = append(curPsml, "")
					}
				}
			case xml.StartElement:
				switch tok.Name.Local {
				case "structure":
					structure = true
				case "packet":
					curPsml = make([]string, 0, 10)
					curCounts = make([]int, 0, 10)
					fg = ""
					bg = ""
					for _, attr := range tok.Attr {
						switch attr.Name.Local {
						case "foreground":
							fg = attr.Value
						case "background":
							bg = attr.Value
						}
					}
				case "section":
					ready = true
					empty = true
				}
			case xml.CharData:
				if ready {
					if structure {
						p.Lock()
						p.packetPsmlHeaders = append(p.packetPsmlHeaders, string(tok))
						p.Unlock()
						e.MainRun(gowid.RunFunction(func(app gowid.IApp) {
							handlePsmlHeader(PsmlCode, app, cb)
						}))
					} else {
						curPsml = append(curPsml, string(format.TranslateHexCodes(tok)))
						curCounts = append(curCounts, len(curPsml[len(curPsml)-1]))
						empty = false
					}
				}
			}
		}

	})

}

func (c *PsmlLoader) DoWithPsmlData(fn func([][]string)) {
	c.Lock()
	defer c.Unlock()
	fn(c.packetPsmlData)
}

func (c *PsmlLoader) ReadingFromFifo() bool {
	// If it's a string it means that it's a filename, so it's not a fifo. Other values
	// in practise are the empty interface, or the read end of a fifo
	_, ok := c.PcapPsml.(string)
	return !ok
}

func (c *PsmlLoader) IsLoading() bool {
	return c.state.Load()
}

func (c *PsmlLoader) StartStage2ChanFn() chan struct{} {
	return c.startStage2Chan
}

func (c *PsmlLoader) PacketCacheFn() *lru.Cache { // i -> [pdml(i * 1000)..pdml(i+1*1000)]
	return c.PacketCache
}

func (p *PsmlLoader) PacketsPerLoad() int {
	p.Lock()
	defer p.Unlock()
	return p.opt.PacketsPerLoad
}

func (p *PsmlLoader) stopLoadPsml() {
	p.psmlStoppedDeliberately_.Store(true)
	if p.psmlCancelFn != nil {
		p.psmlCancelFn()
	}
}

// PsmlData returns a copy of the packet PSML data. The caller must NOT hold p.Lock().
// Use PsmlDataLocked if the lock is already held.
func (p *PsmlLoader) PsmlData() [][]string {
	p.Lock()
	defer p.Unlock()
	result := make([][]string, len(p.packetPsmlData))
	copy(result, p.packetPsmlData)
	return result
}

// PsmlDataLocked returns the packet PSML data. The caller MUST already hold p.Lock().
func (p *PsmlLoader) PsmlDataLocked() [][]string {
	return p.packetPsmlData
}

// PsmlHeaders returns a copy of the PSML column headers. The caller must NOT hold p.Lock().
func (p *PsmlLoader) PsmlHeaders() []string {
	p.Lock()
	defer p.Unlock()
	result := make([]string, len(p.packetPsmlHeaders))
	copy(result, p.packetPsmlHeaders)
	return result
}

func (p *PsmlLoader) PsmlColors() []PacketColors {
	p.Lock()
	defer p.Unlock()
	result := make([]PacketColors, len(p.packetPsmlColors))
	copy(result, p.packetPsmlColors)
	return result
}

func (p *PsmlLoader) PsmlAverageLengths() []gwutil.IntOption {
	p.Lock()
	defer p.Unlock()
	res := make([]gwutil.IntOption, 0, len(p.packetAverageLength))
	for _, avg := range p.packetAverageLength {
		res = append(res, avg.average())
	}
	return res
}

func (p *PsmlLoader) PsmlMaxLengths() []int {
	p.Lock()
	defer p.Unlock()
	res := make([]int, 0, len(p.packetMaxLength))
	for _, maxer := range p.packetMaxLength {
		res = append(res, int(maxer.max()))
	}
	return res
}

// if done==true, then this cache entry is complete
func (p *PsmlLoader) updateCacheEntryWithPdml(row int, pdml []IPdmlPacket, done bool) {
	var ce CacheEntry
	p.Lock()
	defer p.Unlock()
	if ce2, ok := p.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pdml = pdml
	ce.PdmlComplete = done
	p.PacketCache.Add(row, ce)
}

func (p *PsmlLoader) updateCacheEntryWithPcap(row int, pcap [][]byte, done bool) {
	var ce CacheEntry
	p.Lock()
	defer p.Unlock()
	if ce2, ok := p.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pcap = pcap
	ce.PcapComplete = done
	p.PacketCache.Add(row, ce)
}

func (p *PsmlLoader) LengthOfPdmlCacheEntry(row int) (int, error) {
	p.Lock()
	defer p.Unlock()
	if ce, ok := p.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pdml), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

func (p *PsmlLoader) LengthOfPcapCacheEntry(row int) (int, error) {
	p.Lock()
	defer p.Unlock()
	if ce, ok := p.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pcap), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

func (c *PsmlLoader) CacheAt(row int) (CacheEntry, bool) {
	if ce, ok := c.PacketCache.Get(row); ok {
		return ce.(CacheEntry), ok
	}
	return CacheEntry{}, false
}

func (c *PsmlLoader) NumLoaded() int {
	c.Lock()
	defer c.Unlock()
	return len(c.packetPsmlData)
}

//======================================================================

func psmlColorToIColor(col string) gowid.IColor {
	if res, err := gowid.MakeRGBColorSafe(col); err != nil {
		return nil
	} else {
		return res
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
