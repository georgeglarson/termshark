// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package resizable

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Helper to make a fixed-size container widget
//======================================================================

func makeFixedContainerWidget(label string, weight int) gowid.IContainerWidget {
	return &gowid.ContainerWidget{
		IWidget: text.New(label),
		D:       gowid.RenderWithWeight{W: weight},
	}
}

func makeUnitContainerWidget(label string, units int) gowid.IContainerWidget {
	return &gowid.ContainerWidget{
		IWidget: text.New(label),
		D:       gowid.RenderWithUnits{U: units},
	}
}

//======================================================================
// ColumnsWidget.Render tests
//======================================================================

func TestColumnsWidget_Render_Basic(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("ab", 1),
		makeFixedContainerWidget("cd", 1),
	}
	cw := NewColumns(widgets)

	canvas := cw.Render(gowid.MakeRenderBox(10, 1), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 10, canvas.BoxColumns())
	assert.Equal(t, 1, canvas.BoxRows())
}

func TestColumnsWidget_Render_WithOffset(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("aaaa", 1),
		makeFixedContainerWidget("bbbb", 1),
	}
	cw := NewColumns(widgets)
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 2}}

	canvas := cw.Render(gowid.MakeRenderBox(20, 1), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 20, canvas.BoxColumns())
}

func TestColumnsWidget_Render_ThreeColumns(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("aa", 1),
		makeFixedContainerWidget("bb", 1),
		makeFixedContainerWidget("cc", 1),
	}
	cw := NewColumns(widgets)

	canvas := cw.Render(gowid.MakeRenderBox(30, 1), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 30, canvas.BoxColumns())
}

//======================================================================
// ColumnsWidget.UserInput tests
//======================================================================

func TestColumnsWidget_UserInput_KeyEvent(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("hello", 1),
		makeFixedContainerWidget("world", 1),
	}
	cw := NewColumns(widgets)

	ev := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	size := gowid.MakeRenderBox(20, 1)
	// Just verify it doesn't panic; text widgets don't handle key input
	cw.UserInput(ev, size, gowid.Focused, gwtest.D)
}

//======================================================================
// ColumnsWidget.RenderSubWidgets tests
//======================================================================

func TestColumnsWidget_RenderSubWidgets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("ab", 1),
		makeFixedContainerWidget("cd", 1),
	}
	cw := NewColumns(widgets)

	size := gowid.MakeRenderBox(10, 1)
	canvases := cw.RenderSubWidgets(size, gowid.NotSelected, 0, gwtest.D)
	assert.Equal(t, 2, len(canvases))
}

//======================================================================
// ColumnsWidget.RenderedSubWidgetsSizes tests
//======================================================================

func TestColumnsWidget_RenderedSubWidgetsSizes(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("ab", 1),
		makeFixedContainerWidget("cd", 1),
	}
	cw := NewColumns(widgets)

	size := gowid.MakeRenderBox(10, 1)
	sizes := cw.RenderedSubWidgetsSizes(size, gowid.NotSelected, 0, gwtest.D)
	assert.Equal(t, 2, len(sizes))
	// Each should get half the space
	total := 0
	for _, s := range sizes {
		total += s.BoxColumns()
	}
	assert.Equal(t, 10, total)
}

//======================================================================
// ColumnsWidget.SubWidgetSize tests
//======================================================================

func TestColumnsWidget_SubWidgetSize(t *testing.T) {
	w1 := text.New("hello")
	widgets := []gowid.IContainerWidget{
		&gowid.ContainerWidget{IWidget: w1, D: gowid.RenderWithWeight{W: 1}},
		makeFixedContainerWidget("world", 1),
	}
	cw := NewColumns(widgets)

	size := gowid.MakeRenderBox(20, 1)
	subSize := cw.SubWidgetSize(size, 10, w1, gowid.RenderWithWeight{W: 1})
	assert.NotNil(t, subSize)
}

//======================================================================
// ColumnsWidget.WidgetWidths clamping tests
//======================================================================

func TestColumnsWidget_WidgetWidths_ClampNegativeCol1(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
	}
	cw := NewColumns(widgets)

	// Offset that would make Col1 width negative
	// With 10 cols, each widget gets 5 cols. Adjust -10 would make Col1 = 5+(-10) = -5
	// The code clamps: addme = -widths[off.Col1] = -5, so widths[0] = 0, widths[1] = 10
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: -10}}

	size := gowid.MakeRenderBox(10, 1)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	assert.Equal(t, 0, widths[0], "Col1 width should be clamped to 0")
	assert.Equal(t, 10, widths[1], "Col2 width should get the full space")
}

func TestColumnsWidget_WidgetWidths_ClampNegativeCol2(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
	}
	cw := NewColumns(widgets)

	// Offset that would make Col2 width negative
	// With 10 cols, each widget gets 5 cols. Adjust +10 would make Col2 = 5-10 = -5
	// The code clamps: addme = widths[off.Col2] = 5, so widths[0] = 10, widths[1] = 0
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 10}}

	size := gowid.MakeRenderBox(10, 1)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	assert.Equal(t, 10, widths[0], "Col1 should take all space")
	assert.Equal(t, 0, widths[1], "Col2 should be clamped to 0")
}

func TestColumnsWidget_WidgetWidths_ExactBoundary(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
	}
	cw := NewColumns(widgets)

	// Exactly at the boundary: adjust = 5, each starts at 5
	// Col1 = 5 + 5 = 10, Col2 = 5 - 5 = 0
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 5}}

	size := gowid.MakeRenderBox(10, 1)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	total := 0
	for _, w := range widths {
		total += w
		assert.True(t, w >= 0, "No width should be negative")
	}
	assert.Equal(t, 10, total)
}

func TestColumnsWidget_WidgetWidths_MultipleOffsets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
		makeFixedContainerWidget("c", 1),
	}
	cw := NewColumns(widgets)

	// Two offsets adjusting different pairs
	cw.Offsets = []Offset{
		{Col1: 0, Col2: 1, Adjust: 2},
		{Col1: 1, Col2: 2, Adjust: 1},
	}

	size := gowid.MakeRenderBox(30, 1)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	assert.Equal(t, 3, len(widths))
	total := 0
	for _, w := range widths {
		total += w
		assert.True(t, w >= 0)
	}
	assert.Equal(t, 30, total)
}

//======================================================================
// ColumnsWidget.AdjustOffset (method, not standalone function)
//======================================================================

func TestColumnsWidget_AdjustOffset_Method(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
	}
	cw := NewColumns(widgets)

	cw.AdjustOffset(0, 1, Add1, nil)
	assert.Equal(t, 1, len(cw.Offsets))
	assert.Equal(t, 1, cw.Offsets[0].Adjust)

	cw.AdjustOffset(0, 1, Add1, nil)
	assert.Equal(t, 2, cw.Offsets[0].Adjust)

	cw.AdjustOffset(0, 1, Subtract1, nil)
	assert.Equal(t, 1, cw.Offsets[0].Adjust)
}

func TestColumnsWidget_AdjustOffset_NewPair(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeFixedContainerWidget("a", 1),
		makeFixedContainerWidget("b", 1),
		makeFixedContainerWidget("c", 1),
	}
	cw := NewColumns(widgets)

	cw.AdjustOffset(0, 1, Add1, nil)
	cw.AdjustOffset(1, 2, Add1, nil)

	assert.Equal(t, 2, len(cw.Offsets))
	assert.Equal(t, 1, cw.Offsets[0].Adjust)
	assert.Equal(t, 1, cw.Offsets[1].Adjust)
}

//======================================================================
// ColumnsWidget callback invocation tests
//======================================================================

// Note: Callback tests for AdjustOffset and SetOffsets are omitted because
// they require a full gowid.IApp instance which cannot be nil.

//======================================================================
// PileWidget tests
//======================================================================

func makePileContainerWidget(label string, weight int) gowid.IContainerWidget {
	return &gowid.ContainerWidget{
		IWidget: text.New(label),
		D:       gowid.RenderWithWeight{W: weight},
	}
}

func TestPileWidget_Render_Basic(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)

	canvas := pw.Render(gowid.MakeRenderBox(10, 4), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 10, canvas.BoxColumns())
	assert.Equal(t, 4, canvas.BoxRows())
}

func TestPileWidget_Render_WithOffset(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)
	pw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 1}}

	canvas := pw.Render(gowid.MakeRenderBox(10, 4), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 4, canvas.BoxRows())
}

func TestPileWidget_UserInput_Basic(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)

	ev := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	size := gowid.MakeRenderBox(10, 4)
	// Just verify it doesn't panic
	pw.UserInput(ev, size, gowid.Focused, gwtest.D)
}

func TestPileWidget_RenderedSubWidgetsSizes(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)

	size := gowid.MakeRenderBox(10, 4)
	sizes := pw.RenderedSubWidgetsSizes(size, gowid.NotSelected, 0, gwtest.D)
	assert.Equal(t, 2, len(sizes))
	totalRows := 0
	for _, s := range sizes {
		totalRows += s.BoxRows()
	}
	assert.Equal(t, 4, totalRows)
}

func TestPileWidget_RenderSubWidgets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)

	size := gowid.MakeRenderBox(10, 4)
	canvases := pw.RenderSubWidgets(size, gowid.NotSelected, 0, gwtest.D)
	assert.Equal(t, 2, len(canvases))
}

func TestPileWidget_FindNextSelectable(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)

	// text widgets are not selectable, so FindNextSelectable should
	// not find anything
	_, found := pw.FindNextSelectable(gowid.Forwards, false)
	assert.False(t, found)
}

//======================================================================
// PileWidget callback tests
//======================================================================

// Note: Pile callback tests (OnOffsetsSet, RemoveOnOffsetsSet, AdjustOffset_TriggersCallback)
// are omitted because they require a full gowid.IApp instance which cannot be nil.

//======================================================================
// PileAdjuster.MakeBox tests
//======================================================================

func TestPileWidget_RenderBoxMaker_WithOffset(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)
	pw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 1}}

	size := gowid.MakeRenderBox(10, 6)
	// Render exercises RenderBoxMaker internally
	canvas := pw.Render(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 6, canvas.BoxRows())
}

func TestPileWidget_RenderBoxMaker_NegativeAdjustClamped(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)
	// Very large negative adjust on Col1: should be clamped so rows don't go below 0
	pw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: -100}}

	size := gowid.MakeRenderBox(10, 6)
	canvas := pw.Render(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 6, canvas.BoxRows())
}

func TestPileWidget_RenderBoxMaker_LargePositiveAdjustClamped(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makePileContainerWidget("top", 1),
		makePileContainerWidget("bottom", 1),
	}
	pw := NewPile(widgets)
	// Very large positive adjust on Col2: should be clamped so Col2 rows don't go below 0
	pw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 100}}

	size := gowid.MakeRenderBox(10, 6)
	canvas := pw.Render(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 6, canvas.BoxRows())
}

//======================================================================
// AdjustFn custom functions
//======================================================================

func TestAdjustFn_Custom(t *testing.T) {
	double := AdjustFn(func(x int) int { return x * 2 })

	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 5}}}
	AdjustOffset(m, 0, 1, double, nil)
	assert.Equal(t, 10, m.offsets[0].Adjust)
}

func TestAdjustFn_Reset(t *testing.T) {
	reset := AdjustFn(func(x int) int { return 0 })

	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 99}}}
	AdjustOffset(m, 0, 1, reset, nil)
	assert.Equal(t, 0, m.offsets[0].Adjust)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
