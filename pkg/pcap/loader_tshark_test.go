// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

//go:build tshark
// +build tshark

package pcap

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/lifecycle"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func init() {
	// Set up lifecycle tracker for tests so that termshark.Go() works
	termshark.SetTracker(lifecycle.New())
}

//======================================================================
// Test callback handler
//======================================================================

type testCallbacks struct {
	errors []error
}

var _ IOnError = (*testCallbacks)(nil)

func (c *testCallbacks) OnError(_ HandlerCode, _ gowid.IApp, err error) {
	c.errors = append(c.errors, err)
}

//======================================================================
// iStopLoop - controls when fake packet generation stops
//======================================================================

type iStopLoop interface {
	shouldStop() error
}

//======================================================================
// loopReader - reads from a maker function, looping up to `loops` times
//======================================================================

type bodyMakerFn func() io.ReadCloser

type loopReader struct {
	maker   bodyMakerFn
	loops   int
	stopper iStopLoop
	body    io.ReadCloser
	numdone int
}

var _ io.Reader = (*loopReader)(nil)

func newLoopReader(maker bodyMakerFn, loops int, stopper iStopLoop) *loopReader {
	res := &loopReader{
		maker:   maker,
		loops:   loops,
		stopper: stopper,
	}
	res.body = maker()
	return res
}

func (r *loopReader) Read(p []byte) (int, error) {
	read := 0
	for read < len(p) {
		if r.numdone == r.loops {
			return read, io.EOF
		}
		req := len(p[read:])
		n, err := r.body.Read(p[read:])
		read += n
		if err != nil {
			if err != io.EOF {
				return read, err
			}
			r.numdone += 1 // EOF
			r.body.Close()
			r.body = r.maker()
			if r.stopper != nil {
				err = r.stopper.shouldStop()
				if err != nil {
					return read, err
				}
			}
		} else if n < req {
			break
		}
	}

	return read, nil
}

//======================================================================
// pcapLooper - an io.Reader that loops pcap body data forever (until stopper)
//======================================================================

type pcapLooper struct {
	io.Reader
}

var _ io.Reader = (*pcapLooper)(nil)

func newPcapLooper(prefix string, suffix string, stopper iStopLoop) *pcapLooper {
	looper := newLoopReader(func() io.ReadCloser {
		file, err := os.Open(fmt.Sprintf("testdata/%s.%s-body", prefix, suffix))
		if err != nil {
			panic(err)
		}
		return file
	}, 100000, stopper)

	fileh, err := os.Open(fmt.Sprintf("testdata/%s.%s-header", prefix, suffix))
	if err != nil {
		panic(err)
	}

	res := &pcapLooper{
		Reader: io.MultiReader(fileh, looper),
	}

	return res
}

//======================================================================
// hackedPacket - a packet with a controllable source port
//======================================================================

var hdr []byte = []byte{
	0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
}

var pkt []byte = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x39, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00,
	//
	0x30, 0xfd, 0x38, 0xd2, 0x76, 0x12, 0xe8, 0xde,
	0x27, 0x19, 0xde, 0x6c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2b, 0x93, 0x80, 0x40, 0x00, 0x40, 0x11,
	0xdc, 0x5d, 0xc0, 0xa8, 0x56, 0xf6, 0x45, 0xae,
	0x00, 0x00,
	0xb6, 0x87,
	0x22, 0x61, 0x00, 0x17,
	0xb0, 0xd4, 0x05, 0x0a, 0x06, 0xae, 0x1a, 0xae,
	0x1a, 0xae, 0x1a, 0xae, 0x1a, 0xae, 0x1a, 0xae,
	0x1a,
}

type portfn func() int

type hackedPacket struct {
	idx      int
	port     portfn
	actual   io.Reader
	stopper  iStopLoop
	foocount int
}

var _ io.Reader = (*hackedPacket)(nil)

func (r *hackedPacket) Read(p []byte) (int, error) {
	if r.actual == nil {
		if r.stopper != nil {
			err := r.stopper.shouldStop()
			if err != nil {
				return 0, err
			}
		}

		data := make([]byte, len(pkt))
		copy(data, pkt)
		port := r.port()
		data[r.idx+1] = byte(port & 0xff)
		data[r.idx+0] = byte((port & 0xff00) >> 8)
		r.actual = bytes.NewReader(data)
	}
	resi, rese := r.actual.Read(p)
	return resi, rese
}

func newPortLooper(pfn portfn, stopper iStopLoop) io.Reader {
	readers := make([]io.Reader, 65536)
	for i := range len(readers) {
		readers[i] = &hackedPacket{idx: 34 + 16, port: pfn, stopper: stopper, foocount: i}
	}
	readers = append([]io.Reader{strings.NewReader(string(hdr))}, readers...)
	return io.MultiReader(readers...)
}

//======================================================================
// fakeIfaceCmd - writes pcap data from an io.Reader to a tmpfile
//======================================================================

type fakeIfaceCmd struct {
	input   io.Reader
	tmpfile string
	waitCh  chan error
}

var _ IBasicCommand = (*fakeIfaceCmd)(nil)

func (f *fakeIfaceCmd) String() string          { return "fake-dumpcap" }
func (f *fakeIfaceCmd) Pid() int                { return 12345 }
func (f *fakeIfaceCmd) StderrSummary() []string { return nil }

func (f *fakeIfaceCmd) Start() error {
	f.waitCh = make(chan error, 1)
	termshark.Go(func() {
		// Give waitForFileData time to set up the inotify watcher
		time.Sleep(200 * time.Millisecond)
		file, err := os.OpenFile(f.tmpfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			f.waitCh <- err
			return
		}
		defer file.Close()
		_, _ = io.Copy(file, f.input)
		f.waitCh <- nil
	})
	return nil
}

func (f *fakeIfaceCmd) Wait() error {
	return <-f.waitCh
}

func (f *fakeIfaceCmd) Kill() error {
	return nil
}

//======================================================================
// Fake interface command factories
//======================================================================

type IIface interface {
	Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand
}

type fakeIface struct {
	prefix  string
	stopper iStopLoop
}

func (f *fakeIface) Iface(_ []string, _ string, tmpfile string) IBasicCommand {
	return &fakeIfaceCmd{
		input:   newPcapLooper(f.prefix, "pcap", f.stopper),
		tmpfile: tmpfile,
	}
}

type hackedIface struct {
	stopper iStopLoop
	pfn     portfn
}

func (f *hackedIface) Iface(_ []string, _ string, tmpfile string) IBasicCommand {
	return &fakeIfaceCmd{
		input:   newPortLooper(f.pfn, f.stopper),
		tmpfile: tmpfile,
	}
}

type fakeIfaceCommands struct {
	fake IIface
	Commands
}

var _ ILoaderCmds = fakeIfaceCommands{}

func (c fakeIfaceCommands) Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand {
	return c.fake.Iface(ifaces, captureFilter, tmpfile)
}

//======================================================================
// Stopper types for controlling packet generation
//======================================================================

type inputStoppedError struct{}

func (e inputStoppedError) Error() string {
	return "Test stopped input"
}

type chanerr struct {
	err   error
	valid bool
}

type chanfn func() <-chan chanerr

type waitForAnswer struct {
	ch chanfn
}

var _ iStopLoop = (*waitForAnswer)(nil)

func (s *waitForAnswer) shouldStop() error {
	errv := <-s.ch()
	if errv.valid {
		return errv.err
	} else {
		return inputStoppedError{}
	}
}

//======================================================================

// Test using real tshark commands - load testdata/1.pcap, verify PSML and
// PDML data. Also tests re-use of a loader across multiple loads.
func TestRealProcs(t *testing.T) {
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(Commands{}, runner)

	// Make sure we can re-use the same loader, because that's what termshark does
	for range 3 {
		assert.NotNil(t, loader)

		psmlFinChan := loader.PsmlLoader.PsmlFinishedChan

		// Set up state like LoadPcap does internally
		loader.psrcs = []IPacketSource{FileSource{Filename: "testdata/1.pcap"}}
		loader.PcapPsml = "testdata/1.pcap"
		loader.PcapPdml = "testdata/1.pcap"
		loader.PcapPcap = "testdata/1.pcap"
		loader.displayFilter = ""

		fmt.Printf("about to load real pcap\n")
		cb := &testCallbacks{}

		loader.PsmlLoader.loadPsmlSync(nil, loader, cb, nil)

		<-psmlFinChan
		fmt.Printf("done loading real pcap\n")

		assert.Empty(t, cb.errors, "unexpected errors during PSML load: %v", cb.errors)
		assert.False(t, loader.PsmlLoader.IsLoading())

		data := loader.PsmlLoader.PsmlData()
		assert.Equal(t, 18, len(data))
		assert.Equal(t, "192.168.86.246", data[0][2])

		// No pdml yet
		_, ok := loader.PsmlLoader.PacketCache.Get(0)
		assert.Equal(t, false, ok)

		// Load first 1000 rows of pcap as pdml+pcap
		cb2 := &testCallbacks{}
		instructions := []LoadPcapSlice{{Row: 0}}

		instructionsAfter := ProcessPdmlRequests(instructions, loader, loader.PdmlLoader, cb2, nil)
		assert.Equal(t, 0, len(instructionsAfter))

		<-loader.PdmlLoader.Stage2FinishedChan
		fmt.Printf("done loading PDML\n")

		assert.Empty(t, cb2.errors, "unexpected errors during PDML load: %v", cb2.errors)
		assert.False(t, loader.PdmlLoader.IsLoading())

		cei, ok := loader.PsmlLoader.PacketCache.Get(0)
		assert.Equal(t, true, ok)
		ce := cei.(CacheEntry)
		assert.Equal(t, true, ce.PdmlComplete)
		assert.Equal(t, true, ce.PcapComplete)
		assert.Equal(t, 18, len(ce.Pdml))
		assert.Equal(t, 18, len(ce.Pcap))

		// Now clear for next run
		fmt.Printf("ABOUT TO CLEAR\n")
		loader.RenewPsmlLoader()
		loader.RenewPdmlLoader()
		loader.psrcs = nil
		loader.displayFilter = ""

		_, ok = loader.PsmlLoader.PacketCache.Get(0)
		assert.Equal(t, false, ok)
	}
}

//======================================================================

func TestIface1(t *testing.T) {
	answerChan := make(chan chanerr)
	getChan := func() <-chan chanerr {
		return answerChan
	}

	fakeIfaceCmd := &fakeIface{
		prefix: "2",
		stopper: &waitForAnswer{
			ch: getChan,
		},
	}
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(fakeIfaceCommands{
		fake: fakeIfaceCmd,
	}, runner)

	psmlFinChan := loader.PsmlLoader.PsmlFinishedChan

	cb := &testCallbacks{}

	tmpfile := filepath.Join(t.TempDir(), "test-iface1.pcap")
	psrcs := []IPacketSource{InterfaceSource{Iface: "dummy"}}

	loader.RenewIfaceLoader()

	// Start the packet generation and reading process
	err := loader.loadInterfaces(psrcs, "", "", tmpfile, cb, nil)
	assert.NoError(t, err)

	fmt.Printf("fake sleep\n")
	time.Sleep(1 * time.Second)

	read := 10000
	fmt.Printf("reading %d packets from looper\n", read)
	for i := 0; i < read-1; i++ { // otherwise it reads one too many
		answerChan <- chanerr{err: nil, valid: true}
	}

	fmt.Printf("giving processes time to catch up\n")
	time.Sleep(2 * time.Second)

	fmt.Printf("stopping iface read\n")
	// Close answerChan to stop packet production; the pipeline will
	// drain naturally: iface finishes writing → tail reads all bytes →
	// checkAllBytesRead triggers stopTail → tshark finishes → PSML done
	close(answerChan)

	fmt.Printf("waiting for loader to signal end\n")
	<-psmlFinChan

	fmt.Printf("done loading interface pcap\n")

	data := loader.PsmlLoader.PsmlData()
	assert.NotEqual(t, 0, len(data))
	assert.Equal(t, read, len(data))
	assert.Equal(t, "192.168.44.123", data[0][2])

	assert.False(t, loader.PsmlLoader.IsLoading())

	// Now clear
	fmt.Printf("about to clear\n")
	loader.RenewPsmlLoader()
	loader.RenewPdmlLoader()
	loader.psrcs = nil
	loader.displayFilter = ""

	data = loader.PsmlLoader.PsmlData()
	assert.Equal(t, 0, len(data))
}

//======================================================================

func TestIfaceNewFilter(t *testing.T) {
	port := 0

	pfn := func() int {
		res := port
		port++
		return res
	}

	answerChan := make(chan chanerr)
	getChan := func() <-chan chanerr {
		return answerChan
	}

	hackedIfaceCmd := &hackedIface{
		stopper: &waitForAnswer{
			ch: getChan,
		},
		pfn: pfn,
	}
	cmds := fakeIfaceCommands{
		fake: hackedIfaceCmd,
	}
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	psmlFinChan := loader.PsmlLoader.PsmlFinishedChan

	filtcount := 1000
	cb := &testCallbacks{}

	tmpfile := filepath.Join(t.TempDir(), "test-iface-filter.pcap")
	psrcs := []IPacketSource{InterfaceSource{Iface: "dummy"}}

	loader.RenewIfaceLoader()

	fmt.Printf("doing load interface op with filter\n")
	err := loader.loadInterfaces(psrcs, "", fmt.Sprintf("frame.number <= %d", filtcount), tmpfile, cb, nil)
	assert.NoError(t, err)

	fmt.Printf("fake sleep\n")
	time.Sleep(1 * time.Second)

	read := 30000
	fmt.Printf("fake reading %d packets from looper\n", read)
	for i := 0; i < read; i++ {
		answerChan <- chanerr{err: nil, valid: true}
	}

	fmt.Printf("fake giving processes time to catch up\n")
	time.Sleep(2 * time.Second)

	fmt.Printf("fake stopping iface read\n")
	close(answerChan)

	fmt.Printf("fake waiting for loader to signal end\n")
	<-psmlFinChan

	fmt.Printf("fake done loading interface pcap\n")

	data := loader.PsmlLoader.PsmlData()
	fmt.Printf("fake num packets was %d\n", len(data))
	assert.NotEqual(t, 0, len(data))
	assert.Equal(t, filtcount, len(data))
	assert.Equal(t, "192.168.86.246", data[0][2])

	re, _ := regexp.Compile("^[0-9]+ ")

	// Check the source port is correct for each packet read
	for i := 0; i < filtcount; i++ {
		s := data[i][6]
		if re.MatchString(s) { // rule out those where tshark converts port to name
			pref := fmt.Sprintf("%d", i)
			res := strings.HasPrefix(s, pref)
			assert.True(t, res)
		}
	}

	assert.False(t, loader.PsmlLoader.IsLoading())

	//======================================================================
	// Second pass: reload from tmpfile with a new display filter.
	// The first pass captured packets to tmpfile. We now re-read that
	// file with a different filter to test filter reapplication.
	//======================================================================

	// Reset for second pass - reload from the captured tmpfile as a pcap file
	loader.RenewPsmlLoader()
	loader.RenewPdmlLoader()
	psmlFinChan = loader.PsmlLoader.PsmlFinishedChan

	// Read from the tmpfile created by the first pass (it has 30000 packets)
	loader.psrcs = []IPacketSource{FileSource{Filename: tmpfile}}
	loader.PcapPsml = tmpfile
	loader.PcapPdml = tmpfile
	loader.PcapPcap = tmpfile
	loader.displayFilter = fmt.Sprintf("frame.number > 500 && frame.number <= %d", filtcount+500)

	cb2 := &testCallbacks{}
	loader.PsmlLoader.loadPsmlSync(nil, loader, cb2, nil)

	fmt.Printf("loop 2: waiting for loader to signal end\n")
	<-psmlFinChan

	data = loader.PsmlLoader.PsmlData()
	fmt.Printf("fake num packets was %d\n", len(data))
	assert.NotEqual(t, 0, len(data))
	assert.Equal(t, filtcount, len(data))

	// Check the source port is correct for each packet read
	for i := 0; i < filtcount; i++ {
		s := data[i][6]
		if re.MatchString(s) { // rule out those where tshark converts port to name
			pref := fmt.Sprintf("%d", i+500)
			res := strings.HasPrefix(s, pref)
			assert.True(t, res)
		}
	}

	assert.False(t, loader.PsmlLoader.IsLoading())

	// Final cleanup
	loader.RenewPsmlLoader()
	loader.RenewPdmlLoader()
	loader.psrcs = nil
	loader.displayFilter = ""

	data = loader.PsmlLoader.PsmlData()
	assert.Equal(t, 0, len(data))
}

//======================================================================

func TestKeepThisLast(t *testing.T) {
	fmt.Printf("Waiting for test goroutines to stop\n")
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-time.After(10 * time.Second):
			assert.FailNow(t, "Not all test goroutines terminated in 10s")
		}
	}()
	termshark.Tracker().Wait()
	close(done)
	fmt.Printf("Done waiting for test goroutines to stop\n")
}

func TestKeepThisLast2(t *testing.T) {
	TestKeepThisLast(t)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
