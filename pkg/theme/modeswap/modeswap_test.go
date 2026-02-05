// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package modeswap

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Test helpers
//======================================================================

// fakeColor is a simple IColor for testing. It returns a fixed TCellColor
// regardless of mode.
type fakeColor struct {
	id  string
	val int
}

func (f *fakeColor) ToTCellColor(mode gowid.ColorMode) (gowid.TCellColor, bool) {
	// We just return MakeTCellNoColor for simplicity; what matters for testing
	// is which fakeColor instance gets selected based on mode.
	return gowid.MakeTCellNoColor(), true
}

//======================================================================
// New() constructor tests
//======================================================================

func TestNew_ReturnsNonNil(t *testing.T) {
	hi := &fakeColor{id: "hi", val: 1}
	mid := &fakeColor{id: "mid", val: 2}
	lo := &fakeColor{id: "lo", val: 3}

	c := New(hi, mid, lo)
	assert.NotNil(t, c)
}

func TestNew_StoresColors(t *testing.T) {
	hi := &fakeColor{id: "hi", val: 1}
	mid := &fakeColor{id: "mid", val: 2}
	lo := &fakeColor{id: "lo", val: 3}

	c := New(hi, mid, lo)
	assert.Equal(t, hi, c.modeHi)
	assert.Equal(t, mid, c.mode256)
	assert.Equal(t, lo, c.mode16)
}

//======================================================================
// Interface compliance tests
//======================================================================

func TestColor_ImplementsIColor(t *testing.T) {
	// This is checked at compile time with the var _ line in the source,
	// but verify it here too
	hi := &fakeColor{id: "hi"}
	mid := &fakeColor{id: "mid"}
	lo := &fakeColor{id: "lo"}

	var c gowid.IColor = New(hi, mid, lo)
	assert.NotNil(t, c)
}

//======================================================================
// ToTCellColor mode selection tests
//======================================================================

// trackedColor records which mode it was called with
type trackedColor struct {
	calledWithMode gowid.ColorMode
	called         bool
}

func (t *trackedColor) ToTCellColor(mode gowid.ColorMode) (gowid.TCellColor, bool) {
	t.calledWithMode = mode
	t.called = true
	return gowid.MakeTCellNoColor(), true
}

func TestToTCellColor_24BitSelectsHi(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode24BitColors)
	assert.True(t, ok)
	assert.True(t, hi.called, "24-bit mode should use the hi color")
	assert.False(t, mid.called)
	assert.False(t, lo.called)
}

func TestToTCellColor_256SelectsMid(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode256Colors)
	assert.True(t, ok)
	assert.False(t, hi.called)
	assert.True(t, mid.called, "256-color mode should use the mid color")
	assert.False(t, lo.called)
}

func TestToTCellColor_16SelectsLo(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode16Colors)
	assert.True(t, ok)
	assert.False(t, hi.called)
	assert.False(t, mid.called)
	assert.True(t, lo.called, "16-color mode should use the lo color")
}

func TestToTCellColor_8SelectsLo(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode8Colors)
	assert.True(t, ok)
	assert.False(t, hi.called)
	assert.False(t, mid.called)
	assert.True(t, lo.called, "8-color mode should fall back to lo color")
}

func TestToTCellColor_88SelectsLo(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode88Colors)
	assert.True(t, ok)
	assert.False(t, hi.called)
	assert.False(t, mid.called)
	assert.True(t, lo.called, "88-color mode should fall back to lo color")
}

func TestToTCellColor_MonochromeSelectsLo(t *testing.T) {
	hi := &trackedColor{}
	mid := &trackedColor{}
	lo := &trackedColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.ModeMonochrome)
	assert.True(t, ok)
	assert.False(t, hi.called)
	assert.False(t, mid.called)
	assert.True(t, lo.called, "monochrome mode should fall back to lo color")
}

//======================================================================
// ToTCellColor passes correct mode to delegate
//======================================================================

func TestToTCellColor_PassesModeToDelegate(t *testing.T) {
	tests := []struct {
		name         string
		mode         gowid.ColorMode
		expectCalled string // "hi", "mid", or "lo"
	}{
		{"24bit", gowid.Mode24BitColors, "hi"},
		{"256", gowid.Mode256Colors, "mid"},
		{"16", gowid.Mode16Colors, "lo"},
		{"8", gowid.Mode8Colors, "lo"},
		{"88", gowid.Mode88Colors, "lo"},
		{"mono", gowid.ModeMonochrome, "lo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hi := &trackedColor{}
			mid := &trackedColor{}
			lo := &trackedColor{}
			c := New(hi, mid, lo)

			c.ToTCellColor(tt.mode)

			// Verify the mode passed to the delegate is the same as what was given
			var called *trackedColor
			switch tt.expectCalled {
			case "hi":
				called = hi
			case "mid":
				called = mid
			case "lo":
				called = lo
			}
			assert.True(t, called.called)
			assert.Equal(t, tt.mode, called.calledWithMode,
				"Delegate should receive the original color mode")
		})
	}
}

//======================================================================
// ToTCellColor with nil-like behavior
//======================================================================

// failColor always returns false for ok
type failColor struct{}

func (f *failColor) ToTCellColor(mode gowid.ColorMode) (gowid.TCellColor, bool) {
	return gowid.MakeTCellNoColor(), false
}

func TestToTCellColor_PropagatesFailure(t *testing.T) {
	// If the selected delegate returns false, Color should propagate that
	hi := &failColor{}
	mid := &failColor{}
	lo := &failColor{}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode24BitColors)
	assert.False(t, ok, "Should propagate false from hi delegate")

	_, ok = c.ToTCellColor(gowid.Mode256Colors)
	assert.False(t, ok, "Should propagate false from mid delegate")

	_, ok = c.ToTCellColor(gowid.Mode16Colors)
	assert.False(t, ok, "Should propagate false from lo delegate")
}

//======================================================================
// Mixed success/failure
//======================================================================

func TestToTCellColor_IndependentDelegateResults(t *testing.T) {
	// hi succeeds, mid fails, lo succeeds
	hi := &fakeColor{id: "hi"}
	mid := &failColor{}
	lo := &fakeColor{id: "lo"}
	c := New(hi, mid, lo)

	_, ok := c.ToTCellColor(gowid.Mode24BitColors)
	assert.True(t, ok, "Hi color should succeed")

	_, ok = c.ToTCellColor(gowid.Mode256Colors)
	assert.False(t, ok, "Mid color should fail")

	_, ok = c.ToTCellColor(gowid.Mode16Colors)
	assert.True(t, ok, "Lo color should succeed")
}

//======================================================================
// Same color for all modes
//======================================================================

func TestNew_SameColorForAllModes(t *testing.T) {
	shared := &trackedColor{}
	c := New(shared, shared, shared)

	_, ok := c.ToTCellColor(gowid.Mode24BitColors)
	assert.True(t, ok)
	assert.True(t, shared.called)
	assert.Equal(t, gowid.Mode24BitColors, shared.calledWithMode)

	// Reset and test 256
	shared.called = false
	_, ok = c.ToTCellColor(gowid.Mode256Colors)
	assert.True(t, ok)
	assert.True(t, shared.called)
	assert.Equal(t, gowid.Mode256Colors, shared.calledWithMode)

	// Reset and test 16
	shared.called = false
	_, ok = c.ToTCellColor(gowid.Mode16Colors)
	assert.True(t, ok)
	assert.True(t, shared.called)
	assert.Equal(t, gowid.Mode16Colors, shared.calledWithMode)
}
