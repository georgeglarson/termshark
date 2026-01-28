// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import "github.com/gcla/gowid"

//======================================================================

type HandlerCode int

const (
	NoneCode HandlerCode = 1 << iota
	PdmlCode
	PsmlCode
	TailCode
	IfaceCode
	ConvCode
	StreamCode
	CapinfoCode
)

// Handler interfaces - callbacks can implement any combination of these.
// See the Callback type alias for documentation.

type IClear interface {
	OnClear(code HandlerCode, app gowid.IApp)
}

type INewSource interface {
	OnNewSource(code HandlerCode, app gowid.IApp)
}

type IOnError interface {
	OnError(code HandlerCode, app gowid.IApp, err error)
}

type IBeforeBegin interface {
	BeforeBegin(code HandlerCode, app gowid.IApp)
}

type IAfterEnd interface {
	AfterEnd(code HandlerCode, app gowid.IApp)
}

type IPsmlHeader interface {
	OnPsmlHeader(code HandlerCode, app gowid.IApp)
}

// Callback is the type for handler callbacks throughout the pcap package.
// A callback can implement any combination of the following interfaces:
//   - IClear: called when the pcap data is cleared
//   - INewSource: called when a new packet source is loaded
//   - IOnError: called when an error occurs during loading
//   - IBeforeBegin: called before a loading operation begins
//   - IAfterEnd: called after a loading operation ends
//   - IPsmlHeader: called when PSML headers are available
//   - IUnpack: allows a callback to contain multiple handlers
//
// At runtime, the callback is checked for each interface it implements,
// and the corresponding methods are called. This allows flexible composition
// of handlers without requiring a single composite interface.
type Callback = any

// IUnpack allows a callback to contain multiple handlers.
type IUnpack interface {
	Unpack() []any
}

// HandlerList is a slice of callbacks that implements IUnpack.
// Use TypedHandlerList[T] for type-safe handler lists.
type HandlerList []any

func (h HandlerList) Unpack() []any {
	return h
}

// TypedHandlerList provides a type-safe handler list for callbacks of a specific type.
// The type parameter T should be the interface type that handlers implement.
type TypedHandlerList[T any] []T

func (h TypedHandlerList[T]) Unpack() []any {
	result := make([]any, len(h))
	for i, v := range h {
		result[i] = v
	}
	return result
}

// handlerFunc is the signature for handler dispatch functions.
type handlerFunc func(HandlerCode, gowid.IApp, any) bool

// dispatchHandler is a generic helper that handles unpacking and dispatches to a typed handler.
// It reduces boilerplate in the individual handler functions.
func dispatchHandler[T any](code HandlerCode, cb any, self handlerFunc, app gowid.IApp, action func(T)) bool {
	if !handleUnpack(code, cb, self, app) {
		if c, ok := cb.(T); ok {
			action(c)
			return true
		}
	}
	return false
}

// handleUnpack checks if cb implements IUnpack and dispatches to each handler.
func handleUnpack(code HandlerCode, cb any, handler handlerFunc, app gowid.IApp) bool {
	if c, ok := cb.(IUnpack); ok {
		handlers := c.Unpack()
		for _, h := range handlers {
			handler(code, app, h)
		}
		return true
	}
	return false
}

// HandleUnpack is the exported version for backward compatibility.
// Deprecated: Use handleUnpack internally.
type unpackedHandlerFunc func(HandlerCode, gowid.IApp, any) bool

func HandleUnpack(code HandlerCode, cb any, handler unpackedHandlerFunc, app gowid.IApp) bool {
	return handleUnpack(code, cb, handlerFunc(handler), app)
}

func HandleBegin(code HandlerCode, app gowid.IApp, cb any) bool {
	return dispatchHandler[IBeforeBegin](code, cb, HandleBegin, app, func(c IBeforeBegin) {
		c.BeforeBegin(code, app)
	})
}

func HandleEnd(code HandlerCode, app gowid.IApp, cb any) bool {
	return dispatchHandler[IAfterEnd](code, cb, HandleEnd, app, func(c IAfterEnd) {
		c.AfterEnd(code, app)
	})
}

func HandleError(code HandlerCode, app gowid.IApp, err error, cb any) bool {
	if !handleUnpack(code, cb, func(code HandlerCode, app gowid.IApp, cb2 any) bool {
		return HandleError(code, app, err, cb2)
	}, app) {
		if ec, ok := cb.(IOnError); ok {
			ec.OnError(code, app, err)
			return true
		}
	}
	return false
}

func handlePsmlHeader(code HandlerCode, app gowid.IApp, cb any) bool {
	return dispatchHandler[IPsmlHeader](code, cb, handlePsmlHeader, app, func(c IPsmlHeader) {
		c.OnPsmlHeader(code, app)
	})
}

func handleClear(code HandlerCode, app gowid.IApp, cb any) bool {
	return dispatchHandler[IClear](code, cb, handleClear, app, func(c IClear) {
		c.OnClear(code, app)
	})
}

func handleNewSource(code HandlerCode, app gowid.IApp, cb any) bool {
	return dispatchHandler[INewSource](code, cb, handleNewSource, app, func(c INewSource) {
		c.OnNewSource(code, app)
	})
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
