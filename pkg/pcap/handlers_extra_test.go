// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"errors"
	"os"
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// HandleError with HandlerList containing mixed types
//======================================================================

func TestHandleError_HandlerList_MixedTypes(t *testing.T) {
	errHandler := &mockOnError{}
	nonH := &nonHandler{}
	list := HandlerList{nonH, errHandler}

	testErr := errors.New("mixed list error")
	result := HandleError(PsmlCode, nil, testErr, list)

	// Returns false for list dispatch
	assert.False(t, result)
	assert.True(t, errHandler.called)
	assert.Equal(t, PsmlCode, errHandler.code)
	assert.Equal(t, testErr, errHandler.err)
}

//======================================================================
// HandleError with nested HandlerList
//======================================================================

func TestHandleError_NestedHandlerList(t *testing.T) {
	h1 := &mockOnError{}
	h2 := &mockOnError{}
	innerList := HandlerList{h2}
	outerList := HandlerList{h1, innerList}
	testErr := errors.New("nested error")

	HandleError(ConvCode, nil, testErr, outerList)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, ConvCode, h1.code)
	assert.Equal(t, ConvCode, h2.code)
	assert.Equal(t, testErr, h1.err)
	assert.Equal(t, testErr, h2.err)
}

//======================================================================
// handleClear with HandlerList containing mixed types
//======================================================================

func TestHandleClear_HandlerList_MixedTypes(t *testing.T) {
	clearHandler := &mockClear{}
	nonH := &nonHandler{}
	list := HandlerList{nonH, clearHandler}

	result := handleClear(PdmlCode, nil, list)

	assert.False(t, result)
	assert.True(t, clearHandler.called)
	assert.Equal(t, PdmlCode, clearHandler.code)
}

//======================================================================
// handleNewSource with HandlerList
//======================================================================

func TestHandleNewSource_HandlerList(t *testing.T) {
	h1 := &mockNewSource{}
	h2 := &mockNewSource{}
	list := HandlerList{h1, h2}

	result := handleNewSource(IfaceCode, nil, list)

	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, IfaceCode, h1.code)
	assert.Equal(t, IfaceCode, h2.code)
}

func TestHandleNewSource_HandlerList_MixedTypes(t *testing.T) {
	h1 := &mockNewSource{}
	nonH := &nonHandler{}
	list := HandlerList{nonH, h1}

	result := handleNewSource(TailCode, nil, list)

	assert.False(t, result)
	assert.True(t, h1.called)
}

//======================================================================
// handlePsmlHeader with HandlerList
//======================================================================

func TestHandlePsmlHeader_HandlerList(t *testing.T) {
	h1 := &mockPsmlHeader{}
	h2 := &mockPsmlHeader{}
	list := HandlerList{h1, h2}

	result := handlePsmlHeader(PsmlCode, nil, list)

	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, PsmlCode, h1.code)
	assert.Equal(t, PsmlCode, h2.code)
}

func TestHandlePsmlHeader_HandlerList_MixedTypes(t *testing.T) {
	h1 := &mockPsmlHeader{}
	nonH := &nonHandler{}
	list := HandlerList{nonH, h1}

	result := handlePsmlHeader(PsmlCode, nil, list)

	assert.False(t, result)
	assert.True(t, h1.called)
}

//======================================================================
// handleClear with nested HandlerList
//======================================================================

func TestHandleClear_NestedHandlerList(t *testing.T) {
	h1 := &mockClear{}
	h2 := &mockClear{}
	innerList := HandlerList{h2}
	outerList := HandlerList{h1, innerList}

	handleClear(ConvCode, nil, outerList)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, ConvCode, h1.code)
	assert.Equal(t, ConvCode, h2.code)
}

//======================================================================
// HandleEnd with HandlerList containing mixed types
//======================================================================

func TestHandleEnd_HandlerList_MixedTypes(t *testing.T) {
	endHandler := &mockAfterEnd{}
	nonH := &nonHandler{}
	list := HandlerList{nonH, endHandler}

	result := HandleEnd(StreamCode, nil, list)

	assert.False(t, result)
	assert.True(t, endHandler.called)
	assert.Equal(t, StreamCode, endHandler.code)
}

//======================================================================
// HandleBegin with empty HandlerList
//======================================================================

func TestHandleBegin_EmptyHandlerList(t *testing.T) {
	list := HandlerList{}

	result := HandleBegin(PsmlCode, nil, list)

	assert.False(t, result)
}

func TestHandleEnd_EmptyHandlerList(t *testing.T) {
	list := HandlerList{}

	result := HandleEnd(PsmlCode, nil, list)

	assert.False(t, result)
}

func TestHandleError_EmptyHandlerList(t *testing.T) {
	list := HandlerList{}

	result := HandleError(PsmlCode, nil, errors.New("err"), list)

	assert.False(t, result)
}

//======================================================================
// TypedHandlerList with various types
//======================================================================

func TestTypedHandlerList_WithAfterEnd(t *testing.T) {
	h1 := &mockAfterEnd{}
	h2 := &mockAfterEnd{}
	list := TypedHandlerList[*mockAfterEnd]{h1, h2}

	HandleEnd(ConvCode, nil, list)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, ConvCode, h1.code)
	assert.Equal(t, ConvCode, h2.code)
}

func TestTypedHandlerList_WithOnError(t *testing.T) {
	h1 := &mockOnError{}
	h2 := &mockOnError{}
	list := TypedHandlerList[*mockOnError]{h1, h2}
	testErr := errors.New("typed list error")

	HandleError(CapinfoCode, nil, testErr, list)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, testErr, h1.err)
	assert.Equal(t, testErr, h2.err)
}

func TestTypedHandlerList_WithClear(t *testing.T) {
	h1 := &mockClear{}
	h2 := &mockClear{}
	list := TypedHandlerList[*mockClear]{h1, h2}

	handleClear(NoneCode, nil, list)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, NoneCode, h1.code)
}

func TestTypedHandlerList_WithNewSource(t *testing.T) {
	h1 := &mockNewSource{}
	list := TypedHandlerList[*mockNewSource]{h1}

	handleNewSource(IfaceCode, nil, list)

	assert.True(t, h1.called)
	assert.Equal(t, IfaceCode, h1.code)
}

func TestTypedHandlerList_WithPsmlHeader(t *testing.T) {
	h1 := &mockPsmlHeader{}
	list := TypedHandlerList[*mockPsmlHeader]{h1}

	handlePsmlHeader(PsmlCode, nil, list)

	assert.True(t, h1.called)
	assert.Equal(t, PsmlCode, h1.code)
}

//======================================================================
// HandleUnpack with various patterns
//======================================================================

func TestHandleUnpack_EmptyList(t *testing.T) {
	list := HandlerList{}
	called := false

	result := HandleUnpack(PsmlCode, list, func(code HandlerCode, app gowid.IApp, cb any) bool {
		called = true
		return true
	}, nil)

	assert.True(t, result)
	assert.False(t, called) // No items to iterate
}

func TestHandleUnpack_NestedUnpackable(t *testing.T) {
	h1 := &mockBeforeBegin{}
	innerList := HandlerList{h1}
	outerList := HandlerList{innerList}
	callCount := 0

	HandleUnpack(PsmlCode, outerList, func(code HandlerCode, app gowid.IApp, cb any) bool {
		callCount++
		// The inner item is also a list, so it will be unpacked
		HandleUnpack(code, cb, func(code HandlerCode, app gowid.IApp, cb2 any) bool {
			callCount++
			return true
		}, app)
		return true
	}, nil)

	assert.Equal(t, 2, callCount) // Once for innerList, once for h1
}

//======================================================================
// Handler code bitmask operations
//======================================================================

func TestHandlerCode_BitwiseOperations(t *testing.T) {
	// Verify codes can be combined as bitmask
	combined := PsmlCode | PdmlCode
	assert.Equal(t, HandlerCode(6), combined)

	// Check individual flags
	assert.True(t, combined&PsmlCode != 0)
	assert.True(t, combined&PdmlCode != 0)
	assert.False(t, combined&TailCode != 0)

	// All codes combined
	all := NoneCode | PdmlCode | PsmlCode | TailCode | IfaceCode | ConvCode | StreamCode | CapinfoCode
	assert.Equal(t, HandlerCode(255), all)
}

//======================================================================
// Multiple callback interfaces on the same struct
//======================================================================

type multiHandler struct {
	beginCalled      bool
	endCalled        bool
	errorCalled      bool
	clearCalled      bool
	newSourceCalled  bool
	psmlHeaderCalled bool
	beginCode        HandlerCode
	endCode          HandlerCode
	errorCode        HandlerCode
	clearCode        HandlerCode
	newSourceCode    HandlerCode
	psmlHeaderCode   HandlerCode
	lastErr          error
}

func (m *multiHandler) BeforeBegin(code HandlerCode, app gowid.IApp) {
	m.beginCalled = true
	m.beginCode = code
}

func (m *multiHandler) AfterEnd(code HandlerCode, app gowid.IApp) {
	m.endCalled = true
	m.endCode = code
}

func (m *multiHandler) OnError(code HandlerCode, app gowid.IApp, err error) {
	m.errorCalled = true
	m.errorCode = code
	m.lastErr = err
}

func (m *multiHandler) OnClear(code HandlerCode, app gowid.IApp) {
	m.clearCalled = true
	m.clearCode = code
}

func (m *multiHandler) OnNewSource(code HandlerCode, app gowid.IApp) {
	m.newSourceCalled = true
	m.newSourceCode = code
}

func (m *multiHandler) OnPsmlHeader(code HandlerCode, app gowid.IApp) {
	m.psmlHeaderCalled = true
	m.psmlHeaderCode = code
}

func TestMultiHandler_HandleBegin(t *testing.T) {
	h := &multiHandler{}

	result := HandleBegin(PsmlCode, nil, h)
	assert.True(t, result)
	assert.True(t, h.beginCalled)
	assert.Equal(t, PsmlCode, h.beginCode)
}

func TestMultiHandler_HandleEnd(t *testing.T) {
	h := &multiHandler{}

	result := HandleEnd(PdmlCode, nil, h)
	assert.True(t, result)
	assert.True(t, h.endCalled)
	assert.Equal(t, PdmlCode, h.endCode)
}

func TestMultiHandler_HandleError(t *testing.T) {
	h := &multiHandler{}
	testErr := errors.New("multi handler error")

	result := HandleError(TailCode, nil, testErr, h)
	assert.True(t, result)
	assert.True(t, h.errorCalled)
	assert.Equal(t, TailCode, h.errorCode)
	assert.Equal(t, testErr, h.lastErr)
}

func TestMultiHandler_HandleClear(t *testing.T) {
	h := &multiHandler{}

	result := handleClear(IfaceCode, nil, h)
	assert.True(t, result)
	assert.True(t, h.clearCalled)
	assert.Equal(t, IfaceCode, h.clearCode)
}

func TestMultiHandler_HandleNewSource(t *testing.T) {
	h := &multiHandler{}

	result := handleNewSource(ConvCode, nil, h)
	assert.True(t, result)
	assert.True(t, h.newSourceCalled)
	assert.Equal(t, ConvCode, h.newSourceCode)
}

func TestMultiHandler_HandlePsmlHeader(t *testing.T) {
	h := &multiHandler{}

	result := handlePsmlHeader(StreamCode, nil, h)
	assert.True(t, result)
	assert.True(t, h.psmlHeaderCalled)
	assert.Equal(t, StreamCode, h.psmlHeaderCode)
}

func TestMultiHandler_AllCallbacks(t *testing.T) {
	h := &multiHandler{}
	testErr := errors.New("all callbacks error")

	HandleBegin(PsmlCode, nil, h)
	HandleEnd(PdmlCode, nil, h)
	HandleError(TailCode, nil, testErr, h)
	handleClear(IfaceCode, nil, h)
	handleNewSource(ConvCode, nil, h)
	handlePsmlHeader(StreamCode, nil, h)

	assert.True(t, h.beginCalled)
	assert.True(t, h.endCalled)
	assert.True(t, h.errorCalled)
	assert.True(t, h.clearCalled)
	assert.True(t, h.newSourceCalled)
	assert.True(t, h.psmlHeaderCalled)
	assert.Equal(t, PsmlCode, h.beginCode)
	assert.Equal(t, PdmlCode, h.endCode)
	assert.Equal(t, TailCode, h.errorCode)
	assert.Equal(t, IfaceCode, h.clearCode)
	assert.Equal(t, ConvCode, h.newSourceCode)
	assert.Equal(t, StreamCode, h.psmlHeaderCode)
	assert.Equal(t, testErr, h.lastErr)
}

//======================================================================
// PacketLoaderAdapter Tests
//======================================================================

func TestPacketLoaderAdapter_NilLoader(t *testing.T) {
	adapter := NewPacketLoaderAdapter(nil)

	assert.Nil(t, adapter.PsmlData())
	assert.Nil(t, adapter.PsmlHeaders())
	assert.Nil(t, adapter.PsmlColors())
	assert.Nil(t, adapter.PacketNumberMap())
	assert.Equal(t, "", adapter.DisplayFilter())
	assert.Equal(t, "", adapter.Pcap())
	assert.False(t, adapter.IsLoading())
}

func TestPacketLoaderAdapter_WithLoader(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	adapter := NewPacketLoaderAdapter(loader)
	require.NotNil(t, adapter)

	// Test with empty loader state
	assert.Empty(t, adapter.PsmlData())
	assert.Empty(t, adapter.PsmlHeaders())
	assert.Empty(t, adapter.PsmlColors())
	assert.Empty(t, adapter.PacketNumberMap())
	assert.Equal(t, "", adapter.DisplayFilter())
	assert.Equal(t, "", adapter.Pcap())
	assert.False(t, adapter.IsLoading())
}

func TestPacketLoaderAdapter_PsmlData(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.PsmlLoader.packetPsmlData = [][]string{
		{"0.000", "192.168.1.1", "192.168.1.2", "TCP", "66", "SYN"},
		{"0.001", "192.168.1.2", "192.168.1.1", "TCP", "66", "SYN-ACK"},
	}

	adapter := NewPacketLoaderAdapter(loader)
	data := adapter.PsmlData()

	assert.Len(t, data, 2)
	assert.Equal(t, "192.168.1.1", data[0][1])
}

func TestPacketLoaderAdapter_PsmlHeaders(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.PsmlLoader.packetPsmlHeaders = []string{"Time", "Source", "Destination", "Protocol", "Length", "Info"}

	adapter := NewPacketLoaderAdapter(loader)
	headers := adapter.PsmlHeaders()

	assert.Equal(t, []string{"Time", "Source", "Destination", "Protocol", "Length", "Info"}, headers)
}

func TestPacketLoaderAdapter_PsmlColors(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.PsmlLoader.packetPsmlColors = []PacketColors{
		{FG: nil, BG: nil},
		{FG: nil, BG: nil},
	}

	adapter := NewPacketLoaderAdapter(loader)
	colors := adapter.PsmlColors()

	assert.Len(t, colors, 2)
}

func TestPacketLoaderAdapter_PacketNumberMap(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.PsmlLoader.PacketNumberMap[10] = 0
	loader.PsmlLoader.PacketNumberMap[20] = 1
	loader.PsmlLoader.PacketNumberMap[30] = 2

	adapter := NewPacketLoaderAdapter(loader)
	pnm := adapter.PacketNumberMap()

	assert.Equal(t, 3, len(pnm))
	assert.Equal(t, 0, pnm[10])
	assert.Equal(t, 1, pnm[20])
	assert.Equal(t, 2, pnm[30])

	// Verify it's a copy, not the same map
	pnm[99] = 99
	assert.Equal(t, 3, len(loader.PsmlLoader.PacketNumberMap))
}

func TestPacketLoaderAdapter_DisplayFilter(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.displayFilter = "tcp.port == 443"

	adapter := NewPacketLoaderAdapter(loader)
	assert.Equal(t, "tcp.port == 443", adapter.DisplayFilter())
}

func TestPacketLoaderAdapter_Pcap(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	loader.psrcs = []IPacketSource{FileSource{Filename: "/tmp/capture.pcap"}}

	adapter := NewPacketLoaderAdapter(loader)
	assert.Equal(t, "/tmp/capture.pcap", adapter.Pcap())
}

func TestPacketLoaderAdapter_IsLoading(t *testing.T) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	parentLoader := NewPcapLoader(cmds, runner)
	loader := &PacketLoader{ParentLoader: parentLoader}

	adapter := NewPacketLoaderAdapter(loader)
	assert.False(t, adapter.IsLoading())

	loader.PsmlLoader.state.Store(true)
	assert.True(t, adapter.IsLoading())

	loader.PsmlLoader.state.Store(false)
	assert.False(t, adapter.IsLoading())
}

func TestPacketLoaderAdapter_ImplementsLoaderAdapter(t *testing.T) {
	// Compilation-time check is already done via var assertion
	// This test confirms the adapter can be created for a nil loader
	adapter := NewPacketLoaderAdapter(nil)
	assert.NotNil(t, adapter)
}

//======================================================================
// errIsAlreadyClosed Tests
//======================================================================

func TestErrIsAlreadyClosed_WithErrClosed(t *testing.T) {
	assert.True(t, errIsAlreadyClosed(os.ErrClosed))
}

func TestErrIsAlreadyClosed_WithPathError(t *testing.T) {
	err := &os.PathError{Op: "read", Path: "/tmp/test", Err: os.ErrClosed}
	assert.True(t, errIsAlreadyClosed(err))
}

func TestErrIsAlreadyClosed_WithNestedPathError(t *testing.T) {
	inner := &os.PathError{Op: "read", Path: "/tmp/inner", Err: os.ErrClosed}
	outer := &os.PathError{Op: "write", Path: "/tmp/outer", Err: inner}
	assert.True(t, errIsAlreadyClosed(outer))
}

func TestErrIsAlreadyClosed_WithOtherError(t *testing.T) {
	assert.False(t, errIsAlreadyClosed(errors.New("some other error")))
}

func TestErrIsAlreadyClosed_WithPathErrorContainingOtherErr(t *testing.T) {
	err := &os.PathError{Op: "read", Path: "/tmp/test", Err: errors.New("not closed")}
	assert.False(t, errIsAlreadyClosed(err))
}

//======================================================================
// CacheEntry Tests (additional)
//======================================================================

func TestCacheEntry_Complete_AllCombinations(t *testing.T) {
	tests := []struct {
		name     string
		pdml     bool
		pcap     bool
		expected bool
	}{
		{"neither complete", false, false, false},
		{"only pdml", true, false, false},
		{"only pcap", false, true, false},
		{"both complete", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := CacheEntry{
				PdmlComplete: tt.pdml,
				PcapComplete: tt.pcap,
			}
			assert.Equal(t, tt.expected, entry.Complete())
		})
	}
}

func TestCacheEntry_WithData(t *testing.T) {
	entry := CacheEntry{
		Pdml:         []IPdmlPacket{PdmlPacket{Content: []byte("<packet>test</packet>")}},
		Pcap:         [][]byte{{0x00, 0x01, 0x02}},
		PdmlComplete: true,
		PcapComplete: true,
	}

	assert.True(t, entry.Complete())
	assert.Len(t, entry.Pdml, 1)
	assert.Len(t, entry.Pcap, 1)
	assert.Equal(t, []byte{0x00, 0x01, 0x02}, entry.Pcap[0])
}

//======================================================================
// ParsePsmlColors Tests
//======================================================================

func TestParsePsmlColors_ValidColors(t *testing.T) {
	colors := ParsePsmlColors("#ff0000", "#00ff00")

	assert.NotNil(t, colors.FG)
	assert.NotNil(t, colors.BG)
}

func TestParsePsmlColors_EmptyStrings(t *testing.T) {
	colors := ParsePsmlColors("", "")

	assert.Nil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

func TestParsePsmlColors_InvalidStrings(t *testing.T) {
	colors := ParsePsmlColors("notacolor", "alsonotacolor")

	assert.Nil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

func TestParsePsmlColors_OneFGValid(t *testing.T) {
	colors := ParsePsmlColors("#000000", "")

	assert.NotNil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

func TestParsePsmlColors_OneBGValid(t *testing.T) {
	colors := ParsePsmlColors("", "#ffffff")

	assert.Nil(t, colors.FG)
	assert.NotNil(t, colors.BG)
}

//======================================================================
// HandleUnpack handler function signature test
//======================================================================

func TestHandleUnpack_HandlerFuncCalledWithCorrectCode(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockAfterEnd{}
	list := HandlerList{h1, h2}

	var receivedCodes []HandlerCode
	HandleUnpack(ConvCode, list, func(code HandlerCode, app gowid.IApp, cb any) bool {
		receivedCodes = append(receivedCodes, code)
		return true
	}, nil)

	assert.Len(t, receivedCodes, 2)
	assert.Equal(t, ConvCode, receivedCodes[0])
	assert.Equal(t, ConvCode, receivedCodes[1])
}

//======================================================================
// Nil Handler Tests (ensuring no panics)
//======================================================================

func TestHandleBegin_NilCallback(t *testing.T) {
	// Passing nil should not panic; it just won't match any interface
	result := HandleBegin(PsmlCode, nil, nil)
	assert.False(t, result)
}

func TestHandleEnd_NilCallback(t *testing.T) {
	result := HandleEnd(PsmlCode, nil, nil)
	assert.False(t, result)
}

func TestHandleError_NilCallback(t *testing.T) {
	result := HandleError(PsmlCode, nil, errors.New("err"), nil)
	assert.False(t, result)
}

func TestHandleClear_NilCallback(t *testing.T) {
	result := handleClear(PsmlCode, nil, nil)
	assert.False(t, result)
}

func TestHandleNewSource_NilCallback(t *testing.T) {
	result := handleNewSource(PsmlCode, nil, nil)
	assert.False(t, result)
}

func TestHandlePsmlHeader_NilCallback(t *testing.T) {
	result := handlePsmlHeader(PsmlCode, nil, nil)
	assert.False(t, result)
}

//======================================================================
// Callback type alias test
//======================================================================

func TestCallbackTypeAlias(t *testing.T) {
	// Callback is an alias for `any`, so any type should be assignable
	var cb Callback

	cb = &mockBeforeBegin{}
	assert.NotNil(t, cb)

	cb = &mockAfterEnd{}
	assert.NotNil(t, cb)

	cb = &multiHandler{}
	assert.NotNil(t, cb)

	cb = HandlerList{&mockBeforeBegin{}, &mockAfterEnd{}}
	assert.NotNil(t, cb)

	cb = "a string"
	assert.NotNil(t, cb)

	cb = 42
	assert.NotNil(t, cb)
}

//======================================================================
// MockCallbacks integration test (using as a handler)
//======================================================================

func TestMockCallbacks_AsHandlerWithDispatch(t *testing.T) {
	cb := NewMockCallbacks()

	// MockCallbacks implements all handler interfaces
	HandleBegin(PsmlCode, nil, cb)
	HandleEnd(PdmlCode, nil, cb)
	HandleError(TailCode, nil, errors.New("test"), cb)
	handleClear(NoneCode, nil, cb)
	handleNewSource(IfaceCode, nil, cb)
	handlePsmlHeader(PsmlCode, nil, cb)

	assert.Len(t, cb.BeginCalls, 1)
	assert.Equal(t, PsmlCode, cb.BeginCalls[0])
	assert.Len(t, cb.EndCalls, 1)
	assert.Equal(t, PdmlCode, cb.EndCalls[0])
	assert.Len(t, cb.ErrorCalls, 1)
	assert.Equal(t, TailCode, cb.ErrorCalls[0].Code)
	assert.Len(t, cb.ClearCalls, 1)
	assert.Equal(t, NoneCode, cb.ClearCalls[0])
	assert.Len(t, cb.NewSourceCalls, 1)
	assert.Equal(t, IfaceCode, cb.NewSourceCalls[0])
	assert.Len(t, cb.PsmlHeaderCalls, 1)
	assert.Equal(t, PsmlCode, cb.PsmlHeaderCalls[0])
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
