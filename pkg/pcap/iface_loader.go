// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type InterfaceLoader struct {
	state atomic.Bool // true = loading

	ifaceCtx      context.Context // cancels the iface reader process
	ifaceCancelFn context.CancelFunc

	ifaceCmd IBasicCommand

	sync.Mutex
	// set by the iface procedure when it has finished e.g. the pipe to the fifo has finished, the
	// iface process has been killed, etc. This tells the psml-reading procedure when it should stop i.e.
	// when this many bytes have passed through.
	totalFifoBytesWritten gwutil.Int64Option
	totalFifoBytesRead    gwutil.Int64Option
	fifoError             error
}

type iTailCommand interface {
	stopTail()
}

type iIfaceLoaderEnv interface {
	iLoaderEnv
	iTailCommand
	PsmlStoppedDeliberately() bool
	InterfaceFile() string
	PacketSources() []IPacketSource
	CaptureFilter() string
}

// dumpcap -i eth0 -w /tmp/foo.pcap
// dumpcap -i /dev/fd/3 -w /tmp/foo.pcap
func (i *InterfaceLoader) loadIfacesSync(e iIfaceLoaderEnv, cb Callback, app gowid.IApp) {
	i.totalFifoBytesWritten = gwutil.NoneInt64()

	i.ifaceCtx, i.ifaceCancelFn = context.WithCancel(e.Context())

	log.Infof("Starting Iface command: %v", i.ifaceCmd)

	pid := 0
	ifacePidChan := make(chan int)

	defer func() {
		if pid == 0 {
			close(ifacePidChan)
		}
	}()

	// tshark -i eth0 -w foo.pcap
	i.ifaceCmd = e.Commands().Iface(SourcesNames(e.PacketSources()), e.CaptureFilter(), e.InterfaceFile())

	err := i.ifaceCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting interface reader %v: %w", i.ifaceCmd, err)
		HandleError(IfaceCode, app, err, cb)
		return
	}

	ifaceTermChan := make(chan error)

	i.state.Store(true)

	log.Infof("Started Iface command %v with pid %d", i.ifaceCmd, i.ifaceCmd.Pid())

	// Do this in a goroutine because the function is expected to return quickly
	termshark.Go(func() {
		ifaceTermChan <- i.ifaceCmd.Wait()
	})

	//======================================================================
	// Process goroutine

	termshark.Go(func() {
		defer func() {
			// if psrc is a PipeSource, then we open /dev/fd/3 in termshark, and reroute descriptor
			// stdin to number 3 when termshark starts. So to kill the process writing in, we need
			// to close our side of the pipe.
			for _, psrc := range e.PacketSources() {
				if cl, ok := psrc.(io.Closer); ok {
					cl.Close()
				}
			}

			e.MainRun(gowid.RunFunction(func(gowid.IApp) {
				i.state.Store(false)
				i.ifaceCancelFn = nil
			}))

		}()

		cancelledChan := i.ifaceCtx.Done()
		state := NotStarted

		var err error
		pidChan := ifacePidChan

		ifaceCmd := i.ifaceCmd

		killIface := func() {
			err = termshark.KillIfPossible(i.ifaceCmd)
			if err != nil {
				log.Infof("Did not kill iface process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-ifaceTermChan:
				state = Terminated
				if !e.PsmlStoppedDeliberately() && err != nil {
					var exerr *exec.ExitError
					if errors.As(err, &exerr) {
						// This could be if termshark is started like this: cat nosuchfile.pcap | termshark -i -
						// Then dumpcap will be started with /dev/fd/3 as its stdin, but will fail with EOF and
						// exit status 1.
						HandleError(IfaceCode, app, MakeUsefulError(ifaceCmd, err), cb)
					}
				}

			case pid := <-pidChan:
				// this channel can be closed on a stage2 cancel, before the
				// pdml process has been started, meaning we get nil for the
				// pid. If that's the case, don't save the cmd, so we know not
				// to try to kill anything later.
				pidChan = nil
				if pid != 0 {
					state = Started
					if cancelledChan == nil {
						killIface()
					}
				}

			case <-cancelledChan:
				cancelledChan = nil
				if state == Started {
					killIface()
				}
			}

			// if pdmlpidchan is nil, it means the the channel has been closed or we've received a message
			// a message means the proc has started
			// closed means it won't be started
			// if closed, then pdmlCmd == nil
			if state == Terminated || (pidChan == nil && state == NotStarted) {
				// nothing to select on so break
				break loop
			}
		}

		// Calculate the final size of the tmp file we wrote with packets read from the
		// interface/pipe. This runs after the dumpcap command finishes.
		fi, err := os.Stat(e.InterfaceFile())
		i.Lock()
		if err != nil {
			log.Warn(err)
			// Deliberately not a fatal error - it can happen if the source of packets to tshark -i
			// is corrupt, resulting in a tshark error. Setting zero here will line up with the
			// reading end which will read zero, and so terminate the tshark -T psml procedure.

			if i.fifoError == nil && !os.IsNotExist(err) {
				// Ignore ENOENT because it means there was an error before dumpcap even wrote
				// anything to disk
				i.fifoError = err
			}
		} else {
			i.totalFifoBytesWritten = gwutil.SomeInt64(fi.Size())
		}
		i.Unlock()

		i.checkAllBytesRead(e, cb, app)
	})

	//======================================================================

	pid = i.ifaceCmd.Pid()
	ifacePidChan <- pid
}

// checkAllBytesRead is called (a) when the tshark -i process is finished
// writing to the tmp file and (b) every time the tmpfile tail process reads
// bytes. totalFifoBytesWrite is set to non-nil only when the tail process
// completes. totalFifoBytesRead is updated every read. If they are every
// found to be equal, it means that (1) the tail process has finished, meaning
// killed or has reached EOF with its packet source (e.g. stdin, fifo) and (2)
// the tail process has read all those bytes - so no packets will be
// missed. In that case, the tail process is killed and its stdout closed,
// which will trigger the psml reading process to shut down, and termshark
// will turn off its loading UI.
func (i *InterfaceLoader) checkAllBytesRead(e iTailCommand, cb Callback, app gowid.IApp) {
	i.Lock()
	cancel := false
	if !i.totalFifoBytesWritten.IsNone() && !i.totalFifoBytesRead.IsNone() {
		if i.totalFifoBytesRead.Val() == i.totalFifoBytesWritten.Val() {
			cancel = true
		}
	}
	if i.fifoError != nil {
		cancel = true
	}
	fifoErr := i.fifoError
	i.Unlock()

	// if there was a fifo error, OR we have read all the bytes that were written, then
	// we need to stop the tail command
	if cancel {
		if fifoErr != nil {
			err := fmt.Errorf("Fifo error: %v", fifoErr)
			HandleError(IfaceCode, app, err, cb)
		}

		e.stopTail()
	}
}

func (i *InterfaceLoader) stopLoadIface() {
	if i != nil && i.ifaceCancelFn != nil {
		i.ifaceCancelFn()
	}
}

func (c *InterfaceLoader) IsLoading() bool {
	return c != nil && c.state.Load()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
