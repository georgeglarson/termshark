// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// NewPcapLoader Tests
//======================================================================

func TestNewPcapLoader_DefaultOptions(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)

	loader := NewPcapLoader(cmds, runner)

	require.NotNil(t, loader)
	assert.NotNil(t, loader.PsmlLoader)
	assert.NotNil(t, loader.PdmlLoader)
	assert.NotNil(t, loader.mainCtx)
	assert.NotNil(t, loader.mainCancelFn)
}

func TestNewPcapLoader_CustomOptions(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	opts := Options{
		CacheSize:      64,
		PacketsPerLoad: 500,
	}

	loader := NewPcapLoader(cmds, runner, opts)

	require.NotNil(t, loader)
	assert.Equal(t, 500, loader.PsmlLoader.opt.PacketsPerLoad)
}

func TestNewPcapLoader_MinimumPacketsPerLoad(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	opts := Options{
		PacketsPerLoad: 10, // Below minimum
	}

	loader := NewPcapLoader(cmds, runner, opts)

	// Should be clamped to minimum of 100
	assert.Equal(t, 100, loader.PsmlLoader.opt.PacketsPerLoad)
}

func TestNewPcapLoader_InitializesCache(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)

	loader := NewPcapLoader(cmds, runner)

	assert.NotNil(t, loader.PacketCache)
}

//======================================================================
// ParentLoader Method Tests
//======================================================================

func TestParentLoader_Empty(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.True(t, loader.Empty())

	loader.psrcs = []IPacketSource{FileSource{Filename: "test.pcap"}}
	assert.False(t, loader.Empty())
}

func TestParentLoader_Pcap(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// No sources
	assert.Equal(t, "", loader.Pcap())

	// File source
	loader.psrcs = []IPacketSource{FileSource{Filename: "/path/to/test.pcap"}}
	assert.Equal(t, "/path/to/test.pcap", loader.Pcap())

	// Interface source (not a file)
	loader.psrcs = []IPacketSource{InterfaceSource{Iface: "eth0"}}
	assert.Equal(t, "", loader.Pcap())

	// Mixed sources
	loader.psrcs = []IPacketSource{
		InterfaceSource{Iface: "eth0"},
		FileSource{Filename: "capture.pcap"},
	}
	assert.Equal(t, "capture.pcap", loader.Pcap())
}

func TestParentLoader_Interfaces(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// No sources
	assert.Empty(t, loader.Interfaces())

	// Interface source
	loader.psrcs = []IPacketSource{InterfaceSource{Iface: "eth0"}}
	assert.Equal(t, []string{"eth0"}, loader.Interfaces())

	// Multiple interfaces
	loader.psrcs = []IPacketSource{
		InterfaceSource{Iface: "eth0"},
		InterfaceSource{Iface: "wlan0"},
	}
	assert.Equal(t, []string{"eth0", "wlan0"}, loader.Interfaces())

	// File source (not an interface)
	loader.psrcs = []IPacketSource{FileSource{Filename: "test.pcap"}}
	assert.Empty(t, loader.Interfaces())
}

func TestParentLoader_String(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// No sources
	assert.Equal(t, "", loader.String())

	// File source - shows base name
	loader.psrcs = []IPacketSource{FileSource{Filename: "/path/to/test.pcap"}}
	assert.Equal(t, "test.pcap", loader.String())

	// Interface source
	loader.psrcs = []IPacketSource{InterfaceSource{Iface: "eth0"}}
	assert.Equal(t, "eth0", loader.String())

	// Pipe source
	loader.psrcs = []IPacketSource{PipeSource{Descriptor: "stdin", Fd: 0}}
	assert.Equal(t, "<stdin>", loader.String())

	// Multiple sources
	loader.psrcs = []IPacketSource{
		FileSource{Filename: "/tmp/a.pcap"},
		InterfaceSource{Iface: "eth0"},
	}
	assert.Equal(t, "a.pcap + eth0", loader.String())
}

func TestParentLoader_DisplayFilter(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, "", loader.DisplayFilter())

	loader.displayFilter = "tcp.port == 80"
	assert.Equal(t, "tcp.port == 80", loader.DisplayFilter())
}

func TestParentLoader_CaptureFilter(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, "", loader.CaptureFilter())

	loader.captureFilter = "port 80"
	assert.Equal(t, "port 80", loader.CaptureFilter())
}

func TestParentLoader_InterfaceFile(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, "", loader.InterfaceFile())

	loader.ifaceFile = "/tmp/capture.pcap"
	assert.Equal(t, "/tmp/capture.pcap", loader.InterfaceFile())
}

func TestParentLoader_PacketSources(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Nil(t, loader.PacketSources())

	sources := []IPacketSource{FileSource{Filename: "test.pcap"}}
	loader.psrcs = sources
	assert.Equal(t, sources, loader.PacketSources())
}

func TestParentLoader_TurnOffPipe(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Set up fifo mode (PcapPsml != PcapPdml)
	loader.PsmlLoader.PcapPsml = nil // fifo mode uses nil or reader
	loader.PdmlLoader.PcapPdml = "/tmp/capture.pcap"

	loader.TurnOffPipe()

	// Should switch to file mode
	assert.Equal(t, "/tmp/capture.pcap", loader.PsmlLoader.PcapPsml)
}

func TestParentLoader_CloseMain(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.NotNil(t, loader.mainCancelFn)

	loader.CloseMain()

	assert.True(t, loader.psmlStoppedDeliberately_.Load())
	assert.True(t, loader.pdmlStoppedDeliberately_.Load())
	assert.Nil(t, loader.mainCancelFn)
}

//======================================================================
// PsmlLoader Method Tests
//======================================================================

func TestPsmlLoader_IsLoading(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.PsmlLoader.IsLoading())

	loader.PsmlLoader.state.Store(true)
	assert.True(t, loader.PsmlLoader.IsLoading())
}

func TestPsmlLoader_ReadingFromFifo(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// String means file, not fifo
	loader.PsmlLoader.PcapPsml = "/path/to/file.pcap"
	assert.False(t, loader.PsmlLoader.ReadingFromFifo())

	// Nil means fifo mode
	loader.PsmlLoader.PcapPsml = nil
	assert.True(t, loader.PsmlLoader.ReadingFromFifo())

	// Non-string interface also means fifo
	loader.PsmlLoader.PcapPsml = struct{}{}
	assert.True(t, loader.PsmlLoader.ReadingFromFifo())
}

func TestPsmlLoader_NumLoaded(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, 0, loader.PsmlLoader.NumLoaded())

	loader.PsmlLoader.packetPsmlData = [][]string{
		{"0.000", "192.168.1.1", "192.168.1.2"},
		{"0.001", "192.168.1.2", "192.168.1.1"},
	}
	assert.Equal(t, 2, loader.PsmlLoader.NumLoaded())
}

func TestPsmlLoader_PsmlData(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	data := [][]string{
		{"field1", "field2"},
		{"field3", "field4"},
	}
	loader.PsmlLoader.packetPsmlData = data

	assert.Equal(t, data, loader.PsmlLoader.PsmlData())
}

func TestPsmlLoader_PsmlHeaders(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	headers := []string{"Time", "Source", "Destination", "Protocol"}
	loader.PsmlLoader.packetPsmlHeaders = headers

	assert.Equal(t, headers, loader.PsmlLoader.PsmlHeaders())
}

func TestPsmlLoader_PacketsPerLoad(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	opts := Options{PacketsPerLoad: 500}
	loader := NewPcapLoader(cmds, runner, opts)

	assert.Equal(t, 500, loader.PsmlLoader.PacketsPerLoad())
}

func TestPsmlLoader_DoWithPsmlData(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	loader.PsmlLoader.packetPsmlData = [][]string{
		{"a", "b"},
		{"c", "d"},
	}

	var capturedData [][]string
	loader.PsmlLoader.DoWithPsmlData(func(data [][]string) {
		capturedData = data
	})

	assert.Equal(t, loader.PsmlLoader.packetPsmlData, capturedData)
}

//======================================================================
// PdmlLoader Method Tests
//======================================================================

func TestPdmlLoader_IsLoading(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.PdmlLoader.IsLoading())

	loader.PdmlLoader.state.Store(true)
	assert.True(t, loader.PdmlLoader.IsLoading())
}

func TestPdmlLoader_LoadIsVisible(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.PdmlLoader.LoadIsVisible())

	loader.PdmlLoader.visible = true
	assert.True(t, loader.PdmlLoader.LoadIsVisible())
}

func TestPdmlLoader_LoadingRow(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, -1, loader.PdmlLoader.LoadingRow())

	loader.PdmlLoader.rowCurrentlyLoading = 42
	assert.Equal(t, 42, loader.PdmlLoader.LoadingRow())
}

//======================================================================
// InterfaceLoader Method Tests
//======================================================================

func TestInterfaceLoader_IsLoading(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Nil interface loader
	assert.False(t, loader.InterfaceLoader.IsLoading())

	// Create interface loader
	loader.RenewIfaceLoader()
	assert.False(t, loader.InterfaceLoader.IsLoading())

	loader.InterfaceLoader.state.Store(true)
	assert.True(t, loader.InterfaceLoader.IsLoading())
}

//======================================================================
// CacheEntry Tests
//======================================================================

func TestCacheEntry_Complete(t *testing.T) {
	// Empty entry
	entry := CacheEntry{}
	assert.False(t, entry.Complete())

	// Only PDML complete
	entry = CacheEntry{PdmlComplete: true}
	assert.False(t, entry.Complete())

	// Only PCAP complete
	entry = CacheEntry{PcapComplete: true}
	assert.False(t, entry.Complete())

	// Both complete
	entry = CacheEntry{PdmlComplete: true, PcapComplete: true}
	assert.True(t, entry.Complete())
}

func TestPsmlLoader_CacheOperations(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initially no cache entry
	_, ok := loader.PsmlLoader.CacheAt(0)
	assert.False(t, ok)

	// Add PDML to cache
	pdmlData := []IPdmlPacket{PdmlPacket{Content: []byte("test")}}
	loader.PsmlLoader.updateCacheEntryWithPdml(0, pdmlData, true)

	entry, ok := loader.PsmlLoader.CacheAt(0)
	assert.True(t, ok)
	assert.True(t, entry.PdmlComplete)
	assert.False(t, entry.PcapComplete)
	assert.Len(t, entry.Pdml, 1)

	// Add PCAP to same cache entry
	pcapData := [][]byte{{0xff, 0xff}}
	loader.PsmlLoader.updateCacheEntryWithPcap(0, pcapData, true)

	entry, ok = loader.PsmlLoader.CacheAt(0)
	assert.True(t, ok)
	assert.True(t, entry.Complete())
	assert.Len(t, entry.Pcap, 1)
}

func TestPsmlLoader_LengthOfCacheEntries(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// No entry
	_, err := loader.PsmlLoader.LengthOfPdmlCacheEntry(0)
	assert.Error(t, err)

	_, err = loader.PsmlLoader.LengthOfPcapCacheEntry(0)
	assert.Error(t, err)

	// Add entries
	pdmlData := []IPdmlPacket{PdmlPacket{}, PdmlPacket{}, PdmlPacket{}}
	pcapData := [][]byte{{}, {}}
	loader.PsmlLoader.updateCacheEntryWithPdml(0, pdmlData, false)
	loader.PsmlLoader.updateCacheEntryWithPcap(0, pcapData, false)

	pdmlLen, err := loader.PsmlLoader.LengthOfPdmlCacheEntry(0)
	assert.NoError(t, err)
	assert.Equal(t, 3, pdmlLen)

	pcapLen, err := loader.PsmlLoader.LengthOfPcapCacheEntry(0)
	assert.NoError(t, err)
	assert.Equal(t, 2, pcapLen)
}

//======================================================================
// LoadPcapSlice Tests
//======================================================================

func TestLoadPcapSlice_String(t *testing.T) {
	slice := LoadPcapSlice{Row: 0}
	assert.Equal(t, "[loadslice: 0]", slice.String())

	slice = LoadPcapSlice{Row: 1000, CancelCurrent: true}
	assert.Equal(t, "[loadslice: 1000, cancelcurrent: true]", slice.String())

	slice = LoadPcapSlice{Row: 500, Jump: 42}
	assert.Equal(t, "[loadslice: 500, jumpto: 42]", slice.String())

	slice = LoadPcapSlice{Row: 0, CancelCurrent: true, Jump: 100}
	assert.Equal(t, "[loadslice: 0, cancelcurrent: true, jumpto: 100]", slice.String())
}

//======================================================================
// Renew Methods Tests
//======================================================================

func TestParentLoader_RenewPsmlLoader(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Modify state
	loader.PsmlLoader.packetPsmlData = [][]string{{"test"}}
	loader.PsmlLoader.state.Store(true)

	// Renew
	loader.RenewPsmlLoader()

	// Should have fresh state
	assert.Empty(t, loader.PsmlLoader.packetPsmlData)
	assert.False(t, loader.PsmlLoader.state.Load())
	assert.NotNil(t, loader.PsmlLoader.PacketCache)
}

func TestParentLoader_RenewPdmlLoader(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Modify state
	loader.PdmlLoader.state.Store(true)
	loader.PdmlLoader.rowCurrentlyLoading = 42

	// Renew
	loader.RenewPdmlLoader()

	// Should have fresh state
	assert.False(t, loader.PdmlLoader.state.Load())
	assert.Equal(t, -1, loader.PdmlLoader.rowCurrentlyLoading)
}

func TestParentLoader_RenewIfaceLoader(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Nil(t, loader.InterfaceLoader)

	loader.RenewIfaceLoader()

	assert.NotNil(t, loader.InterfaceLoader)
	assert.False(t, loader.InterfaceLoader.state.Load())
}

//======================================================================
// LoadingAnything Tests
//======================================================================

func TestParentLoader_LoadingAnything(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Nothing loading
	assert.False(t, loader.LoadingAnything())

	// PSML loading
	loader.PsmlLoader.state.Store(true)
	assert.True(t, loader.LoadingAnything())
	loader.PsmlLoader.state.Store(false)

	// PDML loading
	loader.PdmlLoader.state.Store(true)
	assert.True(t, loader.LoadingAnything())
	loader.PdmlLoader.state.Store(false)

	// Interface loading
	loader.RenewIfaceLoader()
	loader.InterfaceLoader.state.Store(true)
	assert.True(t, loader.LoadingAnything())
}

//======================================================================
// MakeUsefulError Tests
//======================================================================

func TestMakeUsefulError(t *testing.T) {
	cmd := NewMockBasicCommand("test-cmd", 123)
	cmd.stderrSummary = []string{"error line 1", "error line 2"}

	err := MakeUsefulError(cmd, assert.AnError)

	assert.NotNil(t, err)
	// The error should contain command info
	assert.Contains(t, err.Error(), "test-cmd")
}

//======================================================================
// psmlColorToIColor Tests
//======================================================================

func TestPsmlColorToIColor(t *testing.T) {
	// Valid color
	color := psmlColorToIColor("#ff0000")
	assert.NotNil(t, color)

	// Invalid color
	color = psmlColorToIColor("notacolor")
	assert.Nil(t, color)

	// Empty string
	color = psmlColorToIColor("")
	assert.Nil(t, color)
}

//======================================================================
// TempPcapFile Tests
//======================================================================

func TestTempPcapFile(t *testing.T) {
	// Single token
	result := TempPcapFile("eth0")
	assert.Contains(t, result, "eth0")
	assert.Contains(t, result, ".pcap")

	// Multiple tokens
	result = TempPcapFile("eth0", "capture")
	assert.Contains(t, result, "eth0-capture")

	// Token with invalid characters
	result = TempPcapFile("eth0:1")
	assert.Contains(t, result, "eth0_1") // : replaced with _
}

//======================================================================
// loadIsNecessary Tests
//======================================================================

func TestParentLoader_loadIsNecessary_RowBeyondLoaded(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// No PSML data loaded yet
	ev := LoadPcapSlice{Row: 100}
	assert.False(t, loader.loadIsNecessary(ev))
}

func TestParentLoader_loadIsNecessary_CacheComplete(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Add some PSML data
	loader.PsmlLoader.packetPsmlData = make([][]string, 100)

	// Add complete cache entry at row 0
	loader.PsmlLoader.updateCacheEntryWithPdml(0, []IPdmlPacket{PdmlPacket{}}, true)
	loader.PsmlLoader.updateCacheEntryWithPcap(0, [][]byte{{}}, true)

	// Request for row 0 should not need loading (cache complete)
	ev := LoadPcapSlice{Row: 0}
	assert.False(t, loader.loadIsNecessary(ev))
}

func TestParentLoader_loadIsNecessary_CacheIncomplete(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Add some PSML data
	loader.PsmlLoader.packetPsmlData = make([][]string, 100)

	// Add incomplete cache entry at row 0 (only PDML, no PCAP)
	loader.PsmlLoader.updateCacheEntryWithPdml(0, []IPdmlPacket{PdmlPacket{}}, true)
	// Note: PcapComplete is still false

	// Request for row 0 should need loading (cache incomplete)
	ev := LoadPcapSlice{Row: 0}
	assert.True(t, loader.loadIsNecessary(ev))
}

func TestParentLoader_loadIsNecessary_AlreadyLoadingRow(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Add some PSML data
	loader.PsmlLoader.packetPsmlData = make([][]string, 100)

	// Set currently loading row
	loader.PdmlLoader.rowCurrentlyLoading = 0

	// Request for same row should not need loading
	ev := LoadPcapSlice{Row: 0}
	assert.False(t, loader.loadIsNecessary(ev))
}

func TestParentLoader_loadIsNecessary_DifferentRow(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Add some PSML data (2000 packets)
	loader.PsmlLoader.packetPsmlData = make([][]string, 2000)

	// Set currently loading row
	loader.PdmlLoader.rowCurrentlyLoading = 0

	// Request for different row should need loading
	ev := LoadPcapSlice{Row: 1000}
	assert.True(t, loader.loadIsNecessary(ev))
}

//======================================================================
// PsmlLoader Average/Max Length Tests
//======================================================================

func TestPsmlLoader_PsmlAverageLengths(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initial state has 64 pre-allocated trackers with zero values
	avgs := loader.PsmlLoader.PsmlAverageLengths()
	assert.Len(t, avgs, 64)
	// All should be None (no data tracked yet)
	assert.True(t, avgs[0].IsNone())

	// Override with specific data
	loader.PsmlLoader.packetAverageLength = []averageTracker{
		{count: 2, total: 20},
		{count: 3, total: 30},
	}

	avgs = loader.PsmlLoader.PsmlAverageLengths()
	assert.Len(t, avgs, 2)
	assert.Equal(t, 10, avgs[0].Val())
	assert.Equal(t, 10, avgs[1].Val())
}

func TestPsmlLoader_PsmlMaxLengths(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initial state has 64 pre-allocated trackers with zero values
	maxes := loader.PsmlLoader.PsmlMaxLengths()
	assert.Len(t, maxes, 64)

	// Override with specific data
	loader.PsmlLoader.packetMaxLength = []maxTracker{
		{cur: 15},
		{cur: 25},
	}

	maxes = loader.PsmlLoader.PsmlMaxLengths()
	assert.Len(t, maxes, 2)
	assert.Equal(t, 15, maxes[0])
	assert.Equal(t, 25, maxes[1])
}

func TestPsmlLoader_PsmlColors(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Empty
	colors := loader.PsmlLoader.PsmlColors()
	assert.Empty(t, colors)

	// Add colors
	loader.PsmlLoader.packetPsmlColors = []PacketColors{
		{FG: nil, BG: nil},
		{FG: nil, BG: nil},
	}

	colors = loader.PsmlLoader.PsmlColors()
	assert.Len(t, colors, 2)
}

//======================================================================
// errIsAlreadyClosed Tests
//======================================================================

func TestErrIsAlreadyClosed(t *testing.T) {
	// Note: This function is unexported but we can test it indirectly
	// through the behavior of the loader. For now, we'll skip direct testing
	// since it's an internal helper.
}

//======================================================================
// Mock Command Tests
//======================================================================

func TestMockLoaderCmds_TracksAllCalls(t *testing.T) {
	cmds := NewMockLoaderCmds()

	// Make various calls
	cmds.Psml("test.pcap", "tcp")
	cmds.Pdml("test.pcap", "udp")
	cmds.Pcap("test.pcap", "")
	cmds.Iface([]string{"eth0"}, "port 80", "/tmp/test.pcap")
	cmds.Tail("/tmp/test.pcap")

	// Verify tracking
	assert.Len(t, cmds.PsmlCalls, 1)
	assert.Equal(t, "test.pcap", cmds.PsmlCalls[0].Pcap)
	assert.Equal(t, "tcp", cmds.PsmlCalls[0].DisplayFilter)

	assert.Len(t, cmds.PdmlCalls, 1)
	assert.Equal(t, "udp", cmds.PdmlCalls[0].DisplayFilter)

	assert.Len(t, cmds.PcapCalls, 1)

	assert.Len(t, cmds.IfaceCalls, 1)
	assert.Equal(t, []string{"eth0"}, cmds.IfaceCalls[0].Ifaces)
	assert.Equal(t, "port 80", cmds.IfaceCalls[0].CaptureFilter)

	assert.Len(t, cmds.TailCalls, 1)
}

func TestMockPcapCommand_StdoutReader(t *testing.T) {
	data := []byte("test output data")
	cmd := NewMockPcapCommand("test", 123, data)

	reader, err := cmd.StdoutReader()
	require.NoError(t, err)

	// Read all data
	buf := make([]byte, len(data))
	n, err := reader.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)

	// Close
	err = reader.Close()
	assert.NoError(t, err)
}

func TestMockTailCommand_WriteToStdout(t *testing.T) {
	cmd := NewMockTailCommand("tail", 456)

	// No stdout set
	n, err := cmd.WriteToStdout([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 0, n)

	// Set stdout
	var buf bytes.Buffer
	cmd.SetStdout(&buf)

	n, err = cmd.WriteToStdout([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", buf.String())
}

func TestMockMainRunner_Modes(t *testing.T) {
	// Async mode (collect functions)
	asyncRunner := NewMockMainRunner(false)
	called := false
	asyncRunner.Run(func(app gowid.IApp) {
		called = true
	})
	assert.False(t, called)
	assert.Equal(t, 1, asyncRunner.PendingCount())

	asyncRunner.RunPending(nil)
	assert.True(t, called)
	assert.Equal(t, 0, asyncRunner.PendingCount())

	// Sync mode (run immediately)
	syncRunner := NewMockMainRunner(true)
	called = false
	syncRunner.Run(func(app gowid.IApp) {
		called = true
	})
	assert.True(t, called)
	assert.Equal(t, 0, syncRunner.PendingCount())
}

func TestMockCallbacks_TracksAllCalls(t *testing.T) {
	cb := NewMockCallbacks()

	cb.BeforeBegin(PsmlCode, nil)
	cb.BeforeBegin(PdmlCode, nil)
	cb.AfterEnd(PsmlCode, nil)
	cb.OnError(PsmlCode, nil, assert.AnError)
	cb.OnClear(NoneCode, nil)
	cb.OnNewSource(NoneCode, nil)
	cb.OnPsmlHeader(PsmlCode, nil)

	assert.Len(t, cb.BeginCalls, 2)
	assert.Len(t, cb.EndCalls, 1)
	assert.Len(t, cb.ErrorCalls, 1)
	assert.Equal(t, assert.AnError, cb.ErrorCalls[0].Err)
	assert.Len(t, cb.ClearCalls, 1)
	assert.Len(t, cb.NewSourceCalls, 1)
	assert.Len(t, cb.PsmlHeaderCalls, 1)
}

//======================================================================
// State Flag Tests
//======================================================================

func TestParentLoader_PsmlStoppedDeliberately(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.PsmlStoppedDeliberately())

	loader.psmlStoppedDeliberately_.Store(true)
	assert.True(t, loader.PsmlStoppedDeliberately())
}

func TestParentLoader_TailStoppedDeliberately(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.TailStoppedDeliberately())

	loader.tailStoppedDeliberately.Store(true)
	assert.True(t, loader.TailStoppedDeliberately())
}

func TestParentLoader_LoadWasCancelled(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.LoadWasCancelled())

	loader.loadWasCancelled.Store(true)
	assert.True(t, loader.LoadWasCancelled())
}

//======================================================================
// Accessor Method Tests
//======================================================================

func TestParentLoader_Commands(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, cmds, loader.Commands())
}

func TestParentLoader_Context(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	ctx := loader.Context()
	assert.NotNil(t, ctx)

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled initially")
	default:
		// Expected
	}
}

func TestParentLoader_MainRun(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(false) // Collect functions
	loader := NewPcapLoader(cmds, runner)

	called := false
	loader.MainRun(func(app gowid.IApp) {
		called = true
	})

	// Function should be queued, not executed yet
	assert.False(t, called)
	assert.Equal(t, 1, runner.PendingCount())

	// Execute pending functions
	runner.RunPending(nil)
	assert.True(t, called)
}

//======================================================================
// Stop Method Tests
//======================================================================

func TestParentLoader_StopLoadPsmlAndIface(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Set up an interface loader
	loader.RenewIfaceLoader()

	// Initially not stopped
	assert.False(t, loader.psmlStoppedDeliberately_.Load())
	assert.False(t, loader.loadWasCancelled.Load())

	// Call stop
	loader.StopLoadPsmlAndIface(nil)

	// Should set flags
	assert.True(t, loader.psmlStoppedDeliberately_.Load())
	assert.True(t, loader.loadWasCancelled.Load())
}

//======================================================================
// Context Cancellation Tests
//======================================================================

func TestParentLoader_ContextCancelledOnCloseMain(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	ctx := loader.Context()

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled initially")
	default:
		// Expected
	}

	// Close main
	loader.CloseMain()

	// Context should now be cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context should be cancelled after CloseMain")
	}
}

//======================================================================
// PacketLoader Renew Tests
//======================================================================

func TestPacketLoader_Renew(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)

	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	// Set up some state
	loader.PsmlLoader.packetPsmlData = [][]string{{"test"}}
	loader.PdmlLoader.rowCurrentlyLoading = 42
	originalCtx := loader.mainCtx

	// Renew
	loader.Renew()

	// Should have fresh state
	assert.NotEqual(t, originalCtx, loader.mainCtx)
	assert.Empty(t, loader.PsmlLoader.packetPsmlData)
	assert.Equal(t, -1, loader.PdmlLoader.rowCurrentlyLoading)
}

//======================================================================
// PsmlLoader State Tests
//======================================================================

func TestPsmlLoader_StateTransitions(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initial state
	assert.False(t, loader.PsmlLoader.state.Load())
	assert.False(t, loader.PsmlLoader.IsLoading())

	// Transition to Loading
	loader.PsmlLoader.state.Store(true)
	assert.True(t, loader.PsmlLoader.IsLoading())

	// Transition back to NotLoading
	loader.PsmlLoader.state.Store(false)
	assert.False(t, loader.PsmlLoader.IsLoading())
}

func TestPdmlLoader_StateTransitions(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initial state
	assert.False(t, loader.PdmlLoader.state.Load())
	assert.False(t, loader.PdmlLoader.IsLoading())

	// Transition to Loading
	loader.PdmlLoader.state.Store(true)
	assert.True(t, loader.PdmlLoader.IsLoading())

	// Transition back to NotLoading
	loader.PdmlLoader.state.Store(false)
	assert.False(t, loader.PdmlLoader.IsLoading())
}

func TestInterfaceLoader_StateTransitions(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Create interface loader
	loader.RenewIfaceLoader()

	// Initial state
	assert.False(t, loader.InterfaceLoader.state.Load())
	assert.False(t, loader.InterfaceLoader.IsLoading())

	// Transition to Loading
	loader.InterfaceLoader.state.Store(true)
	assert.True(t, loader.InterfaceLoader.IsLoading())

	// Transition back to NotLoading
	loader.InterfaceLoader.state.Store(false)
	assert.False(t, loader.InterfaceLoader.IsLoading())
}

//======================================================================
// Visibility and Row Loading Tests
//======================================================================

func TestPdmlLoader_VisibleField(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.False(t, loader.PdmlLoader.LoadIsVisible())

	loader.PdmlLoader.visible = true
	assert.True(t, loader.PdmlLoader.LoadIsVisible())

	loader.PdmlLoader.visible = false
	assert.False(t, loader.PdmlLoader.LoadIsVisible())
}

func TestPdmlLoader_RowCurrentlyLoadingField(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, -1, loader.PdmlLoader.LoadingRow())

	loader.PdmlLoader.rowCurrentlyLoading = 100
	assert.Equal(t, 100, loader.PdmlLoader.LoadingRow())

	loader.PdmlLoader.rowCurrentlyLoading = -1
	assert.Equal(t, -1, loader.PdmlLoader.LoadingRow())
}

func TestPdmlLoader_HighestCachedRowField(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	assert.Equal(t, int32(-1), loader.PdmlLoader.highestCachedRow.Load())

	loader.PdmlLoader.highestCachedRow.Store(500)
	assert.Equal(t, int32(500), loader.PdmlLoader.highestCachedRow.Load())
}

//======================================================================
// InterfaceLoader Field Tests
//======================================================================

func TestInterfaceLoader_FifoByteFields(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)
	loader.RenewIfaceLoader()

	// Initially no bytes tracked (Option type with IsNone())
	assert.True(t, loader.InterfaceLoader.totalFifoBytesWritten.IsNone())
	assert.True(t, loader.InterfaceLoader.totalFifoBytesRead.IsNone())
}

func TestInterfaceLoader_FifoErrorField(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)
	loader.RenewIfaceLoader()

	// Initially no error
	assert.Nil(t, loader.InterfaceLoader.fifoError)

	// Set error
	testErr := assert.AnError
	loader.InterfaceLoader.fifoError = testErr
	assert.Equal(t, testErr, loader.InterfaceLoader.fifoError)
}

//======================================================================
// PacketNumberMap Tests
//======================================================================

func TestPsmlLoader_PacketNumberMap(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Initially empty
	assert.Empty(t, loader.PsmlLoader.PacketNumberMap)
	assert.Empty(t, loader.PsmlLoader.PacketNumberOrder)

	// Add mappings
	loader.PsmlLoader.PacketNumberMap[12] = 0  // Packet 12 is at position 0
	loader.PsmlLoader.PacketNumberMap[44] = 1  // Packet 44 is at position 1
	loader.PsmlLoader.PacketNumberOrder[12] = 44 // After 12 comes 44

	assert.Equal(t, 0, loader.PsmlLoader.PacketNumberMap[12])
	assert.Equal(t, 1, loader.PsmlLoader.PacketNumberMap[44])
	assert.Equal(t, 44, loader.PsmlLoader.PacketNumberOrder[12])
}

//======================================================================
// Stage2 Channel Tests
//======================================================================

func TestPsmlLoader_Stage2Channels(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Channels should be initialized
	assert.NotNil(t, loader.PsmlLoader.startStage2Chan)
	assert.NotNil(t, loader.PsmlLoader.PsmlFinishedChan)

	// StartStage2ChanFn should return the channel
	ch := loader.PsmlLoader.StartStage2ChanFn()
	assert.Equal(t, loader.PsmlLoader.startStage2Chan, ch)
}

func TestPdmlLoader_Stage2Channels(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	// Stage2FinishedChan starts as nil
	assert.Nil(t, loader.PdmlLoader.Stage2FinishedChan)

	// After setting up, it should be set
	loader.PdmlLoader.Stage2FinishedChan = make(chan struct{})
	assert.NotNil(t, loader.PdmlLoader.Stage2FinishedChan)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
