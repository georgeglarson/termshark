// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/gcla/gowid"
)

//======================================================================
// Mock IBasicCommand
//======================================================================

// MockBasicCommand implements IBasicCommand for testing
type MockBasicCommand struct {
	name          string
	pid           int
	startErr      error
	waitErr       error
	killErr       error
	stderrSummary []string
	started       bool
	waited        bool
	killed        bool
	mu            sync.Mutex
}

func NewMockBasicCommand(name string, pid int) *MockBasicCommand {
	return &MockBasicCommand{
		name:          name,
		pid:           pid,
		stderrSummary: []string{},
	}
}

func (m *MockBasicCommand) String() string {
	return m.name
}

func (m *MockBasicCommand) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = true
	return m.startErr
}

func (m *MockBasicCommand) Wait() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.waited = true
	return m.waitErr
}

func (m *MockBasicCommand) Pid() int {
	return m.pid
}

func (m *MockBasicCommand) Kill() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killed = true
	return m.killErr
}

func (m *MockBasicCommand) StderrSummary() []string {
	return m.stderrSummary
}

func (m *MockBasicCommand) WasStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

func (m *MockBasicCommand) WasKilled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.killed
}

//======================================================================
// Mock IPcapCommand
//======================================================================

// MockPcapCommand implements IPcapCommand for testing
type MockPcapCommand struct {
	*MockBasicCommand
	stdoutData    []byte
	stdoutReadErr error
	reader        *mockReadCloser
}

type mockReadCloser struct {
	*bytes.Reader
	closed bool
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

func NewMockPcapCommand(name string, pid int, stdoutData []byte) *MockPcapCommand {
	return &MockPcapCommand{
		MockBasicCommand: NewMockBasicCommand(name, pid),
		stdoutData:       stdoutData,
	}
}

func (m *MockPcapCommand) StdoutReader() (io.ReadCloser, error) {
	if m.stdoutReadErr != nil {
		return nil, m.stdoutReadErr
	}
	m.reader = &mockReadCloser{Reader: bytes.NewReader(m.stdoutData)}
	return m.reader, nil
}

//======================================================================
// Mock ITailCommand
//======================================================================

// MockTailCommand implements ITailCommand for testing
type MockTailCommand struct {
	*MockBasicCommand
	stdout   io.Writer
	closeErr error
}

func NewMockTailCommand(name string, pid int) *MockTailCommand {
	return &MockTailCommand{
		MockBasicCommand: NewMockBasicCommand(name, pid),
	}
}

func (m *MockTailCommand) SetStdout(w io.Writer) {
	m.stdout = w
}

func (m *MockTailCommand) Close() error {
	return m.closeErr
}

// WriteToStdout simulates tail writing data to its stdout
func (m *MockTailCommand) WriteToStdout(data []byte) (int, error) {
	if m.stdout == nil {
		return 0, nil
	}
	return m.stdout.Write(data)
}

//======================================================================
// Mock ILoaderCmds
//======================================================================

// MockLoaderCmds implements ILoaderCmds for testing
type MockLoaderCmds struct {
	// Pre-configured responses
	PsmlData []byte // PSML XML data to return
	PdmlData []byte // PDML XML data to return
	PcapData []byte // Hex dump data to return

	// Track calls
	PsmlCalls  []mockPsmlCall
	PdmlCalls  []mockPdmlCall
	PcapCalls  []mockPcapCall
	IfaceCalls []mockIfaceCall
	TailCalls  []mockTailCall

	// Commands to return (for inspection)
	LastPsmlCmd  *MockPcapCommand
	LastPdmlCmd  *MockPcapCommand
	LastPcapCmd  *MockPcapCommand
	LastIfaceCmd *MockBasicCommand
	LastTailCmd  *MockTailCommand

	// Error injection
	PsmlStartErr  error
	PdmlStartErr  error
	PcapStartErr  error
	IfaceStartErr error
	TailStartErr  error

	mu      sync.Mutex
	nextPid int
}

type mockPsmlCall struct {
	Pcap          any
	DisplayFilter string
}

type mockPdmlCall struct {
	Pcap          string
	DisplayFilter string
}

type mockPcapCall struct {
	Pcap          string
	DisplayFilter string
}

type mockIfaceCall struct {
	Ifaces        []string
	CaptureFilter string
	Tmpfile       string
}

type mockTailCall struct {
	Tmpfile string
}

func NewMockLoaderCmds() *MockLoaderCmds {
	return &MockLoaderCmds{
		nextPid: 1000,
	}
}

func (m *MockLoaderCmds) getNextPid() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	pid := m.nextPid
	m.nextPid++
	return pid
}

func (m *MockLoaderCmds) Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IfaceCalls = append(m.IfaceCalls, mockIfaceCall{
		Ifaces:        ifaces,
		CaptureFilter: captureFilter,
		Tmpfile:       tmpfile,
	})
	cmd := NewMockBasicCommand("mock-dumpcap", m.nextPid)
	m.nextPid++
	cmd.startErr = m.IfaceStartErr
	m.LastIfaceCmd = cmd
	return cmd
}

func (m *MockLoaderCmds) Tail(tmpfile string) ITailCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TailCalls = append(m.TailCalls, mockTailCall{Tmpfile: tmpfile})
	cmd := NewMockTailCommand("mock-tail", m.nextPid)
	m.nextPid++
	cmd.startErr = m.TailStartErr
	m.LastTailCmd = cmd
	return cmd
}

func (m *MockLoaderCmds) Psml(pcap any, displayFilter string) IPcapCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PsmlCalls = append(m.PsmlCalls, mockPsmlCall{
		Pcap:          pcap,
		DisplayFilter: displayFilter,
	})
	cmd := NewMockPcapCommand("mock-tshark-psml", m.nextPid, m.PsmlData)
	m.nextPid++
	cmd.startErr = m.PsmlStartErr
	m.LastPsmlCmd = cmd
	return cmd
}

func (m *MockLoaderCmds) Pcap(pcap string, displayFilter string) IPcapCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PcapCalls = append(m.PcapCalls, mockPcapCall{
		Pcap:          pcap,
		DisplayFilter: displayFilter,
	})
	cmd := NewMockPcapCommand("mock-tshark-pcap", m.nextPid, m.PcapData)
	m.nextPid++
	cmd.startErr = m.PcapStartErr
	m.LastPcapCmd = cmd
	return cmd
}

func (m *MockLoaderCmds) Pdml(pcap string, displayFilter string) IPcapCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PdmlCalls = append(m.PdmlCalls, mockPdmlCall{
		Pcap:          pcap,
		DisplayFilter: displayFilter,
	})
	cmd := NewMockPcapCommand("mock-tshark-pdml", m.nextPid, m.PdmlData)
	m.nextPid++
	cmd.startErr = m.PdmlStartErr
	m.LastPdmlCmd = cmd
	return cmd
}

//======================================================================
// Mock IMainRunner
//======================================================================

// MockMainRunner implements IMainRunner for testing
type MockMainRunner struct {
	mu        sync.Mutex
	functions []gowid.RunFunction
	runSync   bool // If true, run functions immediately
}

func NewMockMainRunner(runSync bool) *MockMainRunner {
	return &MockMainRunner{
		functions: make([]gowid.RunFunction, 0),
		runSync:   runSync,
	}
}

func (m *MockMainRunner) Run(fn gowid.RunFunction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runSync {
		// Run immediately with nil app (for simple tests)
		fn(nil)
	} else {
		m.functions = append(m.functions, fn)
	}
}

func (m *MockMainRunner) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.functions)
}

func (m *MockMainRunner) RunPending(app gowid.IApp) {
	m.mu.Lock()
	fns := m.functions
	m.functions = make([]gowid.RunFunction, 0)
	m.mu.Unlock()

	for _, fn := range fns {
		fn(app)
	}
}

//======================================================================
// Mock callback handlers
//======================================================================

// MockCallbacks tracks all handler callbacks for testing
type MockCallbacks struct {
	mu sync.Mutex

	BeginCalls     []HandlerCode
	EndCalls       []HandlerCode
	ErrorCalls     []mockErrorCall
	ClearCalls     []HandlerCode
	NewSourceCalls []HandlerCode
	PsmlHeaderCalls []HandlerCode
}

type mockErrorCall struct {
	Code HandlerCode
	Err  error
}

func NewMockCallbacks() *MockCallbacks {
	return &MockCallbacks{}
}

func (m *MockCallbacks) BeforeBegin(code HandlerCode, app gowid.IApp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BeginCalls = append(m.BeginCalls, code)
}

func (m *MockCallbacks) AfterEnd(code HandlerCode, app gowid.IApp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EndCalls = append(m.EndCalls, code)
}

func (m *MockCallbacks) OnError(code HandlerCode, app gowid.IApp, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ErrorCalls = append(m.ErrorCalls, mockErrorCall{Code: code, Err: err})
}

func (m *MockCallbacks) OnClear(code HandlerCode, app gowid.IApp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ClearCalls = append(m.ClearCalls, code)
}

func (m *MockCallbacks) OnNewSource(code HandlerCode, app gowid.IApp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NewSourceCalls = append(m.NewSourceCalls, code)
}

func (m *MockCallbacks) OnPsmlHeader(code HandlerCode, app gowid.IApp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PsmlHeaderCalls = append(m.PsmlHeaderCalls, code)
}

//======================================================================
// Test helpers
//======================================================================

// generatePsmlXML creates valid PSML XML for testing
func generatePsmlXML(packets [][]string) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0"?>` + "\n")
	buf.WriteString(`<psml>` + "\n")
	buf.WriteString(`<structure>` + "\n")
	buf.WriteString(`<section>No.</section>` + "\n")
	buf.WriteString(`<section>Time</section>` + "\n")
	buf.WriteString(`<section>Source</section>` + "\n")
	buf.WriteString(`<section>Destination</section>` + "\n")
	buf.WriteString(`<section>Protocol</section>` + "\n")
	buf.WriteString(`<section>Length</section>` + "\n")
	buf.WriteString(`<section>Info</section>` + "\n")
	buf.WriteString(`</structure>` + "\n")

	for _, pkt := range packets {
		buf.WriteString(`<packet>` + "\n")
		for _, field := range pkt {
			buf.WriteString(`<section>` + field + `</section>` + "\n")
		}
		buf.WriteString(`</packet>` + "\n")
	}

	buf.WriteString(`</psml>` + "\n")
	return buf.String()
}

// generatePdmlXML creates valid PDML XML for testing
func generatePdmlXML(packetCount int) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0"?>` + "\n")
	buf.WriteString(`<pdml>` + "\n")

	for i := 1; i <= packetCount; i++ {
		buf.WriteString(`<packet>` + "\n")
		buf.WriteString(`<proto name="geninfo"><field name="num" show="`)
		buf.WriteString(string(rune('0' + i)))
		buf.WriteString(`"/></proto>` + "\n")
		buf.WriteString(`</packet>` + "\n")
	}

	buf.WriteString(`</pdml>` + "\n")
	return buf.String()
}

// generateHexDump creates valid hex dump output for testing
func generateHexDump(packetCount int) string {
	var buf bytes.Buffer
	for i := 0; i < packetCount; i++ {
		// Simple 14-byte ethernet frame header
		buf.WriteString("0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 \n")
		buf.WriteString("\n") // Packet separator
	}
	return buf.String()
}

//======================================================================
// Context helpers for testing
//======================================================================

type testContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newTestContext() *testContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &testContext{ctx: ctx, cancel: cancel}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
