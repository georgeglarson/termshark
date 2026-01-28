// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"errors"
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
)

//======================================================================

// Mock implementations for testing

type mockBeforeBegin struct {
	called bool
	code   HandlerCode
}

func (m *mockBeforeBegin) BeforeBegin(code HandlerCode, app gowid.IApp) {
	m.called = true
	m.code = code
}

type mockAfterEnd struct {
	called bool
	code   HandlerCode
}

func (m *mockAfterEnd) AfterEnd(code HandlerCode, app gowid.IApp) {
	m.called = true
	m.code = code
}

type mockOnError struct {
	called bool
	code   HandlerCode
	err    error
}

func (m *mockOnError) OnError(code HandlerCode, app gowid.IApp, err error) {
	m.called = true
	m.code = code
	m.err = err
}

type mockClear struct {
	called bool
	code   HandlerCode
}

func (m *mockClear) OnClear(code HandlerCode, app gowid.IApp) {
	m.called = true
	m.code = code
}

type mockNewSource struct {
	called bool
	code   HandlerCode
}

func (m *mockNewSource) OnNewSource(code HandlerCode, app gowid.IApp) {
	m.called = true
	m.code = code
}

type mockPsmlHeader struct {
	called bool
	code   HandlerCode
}

func (m *mockPsmlHeader) OnPsmlHeader(code HandlerCode, app gowid.IApp) {
	m.called = true
	m.code = code
}

type nonHandler struct{}

//======================================================================

func TestHandlerCode_Values(t *testing.T) {
	// Verify iota values are powers of 2 for bitmask usage
	assert.Equal(t, HandlerCode(1), NoneCode)
	assert.Equal(t, HandlerCode(2), PdmlCode)
	assert.Equal(t, HandlerCode(4), PsmlCode)
	assert.Equal(t, HandlerCode(8), TailCode)
	assert.Equal(t, HandlerCode(16), IfaceCode)
	assert.Equal(t, HandlerCode(32), ConvCode)
	assert.Equal(t, HandlerCode(64), StreamCode)
	assert.Equal(t, HandlerCode(128), CapinfoCode)
}

func TestHandlerList_Unpack(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockAfterEnd{}
	list := HandlerList{h1, h2}

	unpacked := list.Unpack()

	assert.Equal(t, 2, len(unpacked))
	assert.Same(t, h1, unpacked[0])
	assert.Same(t, h2, unpacked[1])
}

func TestHandleBegin_DirectHandler(t *testing.T) {
	handler := &mockBeforeBegin{}

	result := HandleBegin(PsmlCode, nil, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, PsmlCode, handler.code)
}

func TestHandleBegin_NonHandler(t *testing.T) {
	handler := &nonHandler{}

	result := HandleBegin(PsmlCode, nil, handler)

	assert.False(t, result)
}

func TestHandleBegin_HandlerList(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockBeforeBegin{}
	list := HandlerList{h1, h2}

	result := HandleBegin(PdmlCode, nil, list)

	// HandleBegin returns false when given a list (HandleUnpack returns true,
	// so res is never set), but the handlers are still called
	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, PdmlCode, h1.code)
	assert.Equal(t, PdmlCode, h2.code)
}

func TestHandleBegin_MixedHandlerList(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &nonHandler{}
	list := HandlerList{h1, h2}

	result := HandleBegin(TailCode, nil, list)

	// Returns false for list, but handlers are still called
	assert.False(t, result)
	assert.True(t, h1.called)
	assert.Equal(t, TailCode, h1.code)
}

func TestHandleEnd_DirectHandler(t *testing.T) {
	handler := &mockAfterEnd{}

	result := HandleEnd(IfaceCode, nil, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, IfaceCode, handler.code)
}

func TestHandleEnd_NonHandler(t *testing.T) {
	handler := &nonHandler{}

	result := HandleEnd(IfaceCode, nil, handler)

	assert.False(t, result)
}

func TestHandleEnd_HandlerList(t *testing.T) {
	h1 := &mockAfterEnd{}
	h2 := &mockAfterEnd{}
	list := HandlerList{h1, h2}

	result := HandleEnd(ConvCode, nil, list)

	// Returns false for list, but handlers are still called
	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
}

func TestHandleError_DirectHandler(t *testing.T) {
	handler := &mockOnError{}
	testErr := errors.New("test error")

	result := HandleError(StreamCode, nil, testErr, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, StreamCode, handler.code)
	assert.Equal(t, testErr, handler.err)
}

func TestHandleError_NonHandler(t *testing.T) {
	handler := &nonHandler{}
	testErr := errors.New("test error")

	result := HandleError(StreamCode, nil, testErr, handler)

	assert.False(t, result)
}

func TestHandleError_HandlerList(t *testing.T) {
	h1 := &mockOnError{}
	h2 := &mockOnError{}
	testErr := errors.New("test error")
	list := HandlerList{h1, h2}

	result := HandleError(CapinfoCode, nil, testErr, list)

	// Returns false for list, but handlers are still called
	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, testErr, h1.err)
	assert.Equal(t, testErr, h2.err)
}

func TestHandleUnpack_WithUnpackable(t *testing.T) {
	h1 := &mockBeforeBegin{}
	list := HandlerList{h1}
	called := false

	result := HandleUnpack(PsmlCode, list, func(code HandlerCode, app gowid.IApp, cb interface{}) bool {
		called = true
		return true
	}, nil)

	assert.True(t, result)
	assert.True(t, called)
}

func TestHandleUnpack_WithNonUnpackable(t *testing.T) {
	handler := &mockBeforeBegin{}
	called := false

	result := HandleUnpack(PsmlCode, handler, func(code HandlerCode, app gowid.IApp, cb interface{}) bool {
		called = true
		return true
	}, nil)

	assert.False(t, result)
	assert.False(t, called)
}

func TestHandleClear_DirectHandler(t *testing.T) {
	handler := &mockClear{}

	result := handleClear(PsmlCode, nil, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, PsmlCode, handler.code)
}

func TestHandleClear_NonHandler(t *testing.T) {
	handler := &nonHandler{}

	result := handleClear(PsmlCode, nil, handler)

	assert.False(t, result)
}

func TestHandleClear_HandlerList(t *testing.T) {
	h1 := &mockClear{}
	h2 := &mockClear{}
	list := HandlerList{h1, h2}

	result := handleClear(PdmlCode, nil, list)

	// Returns false for list, but handlers are still called
	assert.False(t, result)
	assert.True(t, h1.called)
	assert.True(t, h2.called)
}

func TestHandleNewSource_DirectHandler(t *testing.T) {
	handler := &mockNewSource{}

	result := handleNewSource(TailCode, nil, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, TailCode, handler.code)
}

func TestHandleNewSource_NonHandler(t *testing.T) {
	handler := &nonHandler{}

	result := handleNewSource(TailCode, nil, handler)

	assert.False(t, result)
}

func TestHandlePsmlHeader_DirectHandler(t *testing.T) {
	handler := &mockPsmlHeader{}

	result := handlePsmlHeader(PsmlCode, nil, handler)

	assert.True(t, result)
	assert.True(t, handler.called)
	assert.Equal(t, PsmlCode, handler.code)
}

func TestHandlePsmlHeader_NonHandler(t *testing.T) {
	handler := &nonHandler{}

	result := handlePsmlHeader(PsmlCode, nil, handler)

	assert.False(t, result)
}

func TestNestedHandlerList(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockBeforeBegin{}
	innerList := HandlerList{h2}
	outerList := HandlerList{h1, innerList}

	HandleBegin(PsmlCode, nil, outerList)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
}

//======================================================================
// TypedHandlerList Tests
//======================================================================

func TestTypedHandlerList_Unpack(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockBeforeBegin{}
	list := TypedHandlerList[*mockBeforeBegin]{h1, h2}

	unpacked := list.Unpack()

	assert.Len(t, unpacked, 2)
	assert.Equal(t, h1, unpacked[0])
	assert.Equal(t, h2, unpacked[1])
}

func TestTypedHandlerList_WithHandleBegin(t *testing.T) {
	h1 := &mockBeforeBegin{}
	h2 := &mockBeforeBegin{}
	list := TypedHandlerList[*mockBeforeBegin]{h1, h2}

	HandleBegin(PsmlCode, nil, list)

	assert.True(t, h1.called)
	assert.True(t, h2.called)
	assert.Equal(t, PsmlCode, h1.code)
	assert.Equal(t, PsmlCode, h2.code)
}

func TestTypedHandlerList_Empty(t *testing.T) {
	list := TypedHandlerList[*mockBeforeBegin]{}

	unpacked := list.Unpack()

	assert.Len(t, unpacked, 0)
}

func TestTypedHandlerList_ImplementsIUnpack(t *testing.T) {
	list := TypedHandlerList[*mockBeforeBegin]{}

	// Verify it implements IUnpack
	var _ IUnpack = list
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
