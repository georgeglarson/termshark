// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package hexdumper

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Construction and Data tests
//======================================================================

func TestNew_EmptyData(t *testing.T) {
	w := New([]byte{})
	assert.NotNil(t, w)
	assert.Empty(t, w.Data())
	assert.Equal(t, "hexdump", w.String())
}

func TestNew_SingleByte(t *testing.T) {
	w := New([]byte{0x41})
	assert.NotNil(t, w)
	assert.Equal(t, []byte{0x41}, w.Data())

	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 1, canvas.BoxRows(), "Single byte should render as 1 row")
}

func TestNew_ExactlyOneRow(t *testing.T) {
	// Exactly 16 bytes = 1 row in hex dump
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i + 0x30) // '0', '1', ..., '?'
	}
	w := New(data)
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 1, canvas.BoxRows(), "Exactly 16 bytes should render as 1 row")
}

func TestNew_ExactlyTwoRows(t *testing.T) {
	// Exactly 32 bytes = 2 rows in hex dump
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 0x40)
	}
	w := New(data)
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 2, canvas.BoxRows(), "Exactly 32 bytes should render as 2 rows")
}

func TestNew_SeventeenBytes(t *testing.T) {
	// 17 bytes should overflow into a second row
	data := make([]byte, 17)
	for i := range data {
		data[i] = byte(i)
	}
	w := New(data)
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 2, canvas.BoxRows(), "17 bytes should render as 2 rows")
}

func TestNew_AllPrintableChars(t *testing.T) {
	// Build a byte slice containing all printable ASCII characters
	data := make([]byte, 0, 95)
	for i := byte(32); i < 127; i++ {
		data = append(data, i)
	}
	w := New(data)
	assert.Equal(t, 95, len(w.Data()))
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.True(t, canvas.BoxRows() > 0)
}

func TestNew_AllZeroBytes(t *testing.T) {
	data := make([]byte, 16)
	w := New(data)
	assert.Equal(t, 16, len(w.Data()))
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 1, canvas.BoxRows())
}

func TestNew_HighBytes(t *testing.T) {
	data := []byte{0xFF, 0xFE, 0x80, 0x7F, 0x00, 0x01}
	w := New(data)
	canvas := w.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 1, canvas.BoxRows())
}

//======================================================================
// Options and layers tests
//======================================================================

func TestNew_WithLayers(t *testing.T) {
	layers := []LayerStyler{
		{Start: 0, End: 4, ColUnselected: "l1-unsel", ColSelected: "l1-sel"},
		{Start: 4, End: 8, ColUnselected: "l2-unsel", ColSelected: "l2-sel"},
	}

	w := New([]byte("abcdefghijklmnop"), Options{
		StyledLayers:      layers,
		CursorUnselected:  "cursor-unsel",
		CursorSelected:    "cursor-sel",
		LineNumUnselected: "linenum-unsel",
		LineNumSelected:   "linenum-sel",
		PaletteIfCopying:  "copy-palette",
	})

	assert.Equal(t, 2, len(w.Layers()))
	assert.Equal(t, "l1-unsel", w.Layers()[0].ColUnselected)
	assert.Equal(t, "l2-sel", w.Layers()[1].ColSelected)
}

func TestNew_NoOptions(t *testing.T) {
	w := New([]byte("test"))
	assert.Empty(t, w.Layers())
	assert.Empty(t, w.CursorUnselected())
	assert.Empty(t, w.CursorSelected())
	assert.Empty(t, w.LineNumUnselected())
	assert.Empty(t, w.LineNumSelected())
}

//======================================================================
// toChar tests (additional edge cases)
//======================================================================

func TestToChar_BoundaryValues(t *testing.T) {
	// 31 is the last non-printable before printable range
	assert.Equal(t, byte('.'), toChar(31))
	// 32 is space, first printable
	assert.Equal(t, byte(' '), toChar(32))
	// 126 is '~', last printable
	assert.Equal(t, byte('~'), toChar(126))
	// 127 is DEL, first non-printable after printable range
	assert.Equal(t, byte('.'), toChar(127))
}

func TestToChar_AllNonPrintable(t *testing.T) {
	// All control characters (0-31)
	for i := byte(0); i < 32; i++ {
		assert.Equal(t, byte('.'), toChar(i), "toChar(%d) should be '.'", i)
	}
	// DEL and high bytes (127-255)
	for i := 127; i <= 255; i++ {
		assert.Equal(t, byte('.'), toChar(byte(i)), "toChar(%d) should be '.'", i)
	}
}

func TestToChar_AllPrintable(t *testing.T) {
	for i := byte(32); i <= 126; i++ {
		assert.Equal(t, i, toChar(i), "toChar(%d) should return itself", i)
	}
}

//======================================================================
// Hextable constant test
//======================================================================

func TestHextable_Content(t *testing.T) {
	assert.Equal(t, "0123456789abcdef", hextable)
}

//======================================================================
// Position and InHex tests (require a constructed widget with data)
//======================================================================

func TestWidget_Position_Default(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))
	// Default position should be 0
	pos := w.Position()
	assert.Equal(t, 0, pos)
}

func TestWidget_InHex_Default(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))
	// Default InHex - the build function initializes focus at hex section
	inhex := w.InHex()
	// Just verify it returns without panic; value depends on initial focus path
	_ = inhex
}

func TestWidget_SetPosition(t *testing.T) {
	w := New([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	w.SetPosition(5, gwtest.D)
	assert.Equal(t, 5, w.Position())

	w.SetPosition(0, gwtest.D)
	assert.Equal(t, 0, w.Position())

	w.SetPosition(15, gwtest.D)
	assert.Equal(t, 15, w.Position())
}

func TestWidget_SetPosition_SecondRow(t *testing.T) {
	// Need at least 32 bytes for two rows
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte('A' + i%26)
	}
	w := New(data)
	w.SetPosition(16, gwtest.D)
	assert.Equal(t, 16, w.Position())

	w.SetPosition(20, gwtest.D)
	assert.Equal(t, 20, w.Position())
}

func TestWidget_SetInHex_Toggle(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))

	initialInHex := w.InHex()
	w.SetInHex(!initialInHex, gwtest.D)
	assert.Equal(t, !initialInHex, w.InHex())

	// Toggle back
	w.SetInHex(initialInHex, gwtest.D)
	assert.Equal(t, initialInHex, w.InHex())
}

func TestWidget_SetInHex_SameValue(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))
	current := w.InHex()
	// Setting to same value should be a no-op (no panic)
	w.SetInHex(current, gwtest.D)
	assert.Equal(t, current, w.InHex())
}

//======================================================================
// RenderSize test
//======================================================================

func TestWidget_RenderSize(t *testing.T) {
	w := New([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	size := gowid.RenderFlowWith{C: 80}
	rs := w.RenderSize(size, gowid.NotSelected, gwtest.D)
	assert.True(t, rs.BoxColumns() > 0)
	assert.True(t, rs.BoxRows() > 0)
}

//======================================================================
// clipsForBytes test
//======================================================================

func TestClipsForBytes_BasicData(t *testing.T) {
	data := []byte("Hello, World!")
	clips := clipsForBytes(data, 0, len(data))
	assert.Equal(t, 4, len(clips), "Should return 4 clip formats")

	// Verify clip names
	assert.Contains(t, clips[0].ClipName(), "hex + ascii")
	assert.Contains(t, clips[1].ClipName(), "escaped string")
	assert.Contains(t, clips[2].ClipName(), "printable string")
	assert.Contains(t, clips[3].ClipName(), "hex stream")
}

func TestClipsForBytes_SubRange(t *testing.T) {
	data := []byte("abcdefghijklmnop")
	clips := clipsForBytes(data, 2, 6)
	assert.Equal(t, 4, len(clips))
	// All clips should reference bytes 2-6
	assert.Contains(t, clips[0].ClipName(), "2-6")
}

//======================================================================
// viewSwitch test
//======================================================================

func TestViewSwitch_NoPanic(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))
	vs := w.OnKey(func(ev *tcell.EventKey) bool {
		return false
	})
	_ = vs
}

//======================================================================
// LayerStyler tests
//======================================================================

func TestLayerStyler_ZeroRange(t *testing.T) {
	ls := LayerStyler{Start: 5, End: 5}
	assert.Equal(t, 5, ls.Start)
	assert.Equal(t, 5, ls.End)
}

func TestLayerStyler_LargeRange(t *testing.T) {
	ls := LayerStyler{Start: 0, End: 1000000}
	assert.Equal(t, 0, ls.Start)
	assert.Equal(t, 1000000, ls.End)
}

//======================================================================
// SetData test
//======================================================================

func TestWidget_SetData(t *testing.T) {
	w := New([]byte("original"))
	assert.Equal(t, []byte("original"), w.Data())

	w.SetData([]byte("new data here!!!"), gwtest.D)
	assert.Equal(t, []byte("new data here!!!"), w.Data())
}

func TestWidget_SetLayers(t *testing.T) {
	w := New([]byte("abcdefghijklmnop"))
	assert.Empty(t, w.Layers())

	newLayers := []LayerStyler{
		{Start: 0, End: 8, ColUnselected: "u", ColSelected: "s"},
	}
	w.SetLayers(newLayers, gwtest.D)
	assert.Equal(t, 1, len(w.Layers()))
	assert.Equal(t, "u", w.Layers()[0].ColUnselected)
}

//======================================================================
// boxedText tests
//======================================================================

func TestBoxedText_String(t *testing.T) {
	bt := twosp
	s := bt.String()
	assert.Contains(t, s, "hacktext")
}

func TestBoxedText_RenderSize(t *testing.T) {
	bt := twosp
	rs := bt.RenderSize(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 2, rs.BoxColumns())
	assert.Equal(t, 1, rs.BoxRows())

	bt2 := onesp
	rs2 := bt2.RenderSize(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 1, rs2.BoxColumns())
	assert.Equal(t, 1, rs2.BoxRows())
}

//======================================================================
// ID tests
//======================================================================

func TestHexChrsId_Equality(t *testing.T) {
	id1 := hexChrsId{idx: 0}
	id2 := hexChrsId{idx: 0}
	id3 := hexChrsId{idx: 255}

	assert.Equal(t, id1.ID(), id2.ID())
	assert.NotEqual(t, id1.ID(), id3.ID())
}

func TestHexBytesId_Equality(t *testing.T) {
	id1 := hexBytesId{idx: 0}
	id2 := hexBytesId{idx: 0}
	id3 := hexBytesId{idx: 999}

	assert.Equal(t, id1.ID(), id2.ID())
	assert.NotEqual(t, id1.ID(), id3.ID())
}

func TestHexChrsId_DifferentFromHexBytesId(t *testing.T) {
	// Same index but different types should produce different IDs
	cid := hexChrsId{idx: 42}
	bid := hexBytesId{idx: 42}
	assert.NotEqual(t, cid.ID(), bid.ID())
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
