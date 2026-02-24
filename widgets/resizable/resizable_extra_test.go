// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package resizable

import (
	"encoding/json"
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gcla/gowid/widgets/text"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Helper to create simple container widgets for testing.
//======================================================================

func makeContainerWidget(label string) gowid.IContainerWidget {
	return &gowid.ContainerWidget{
		IWidget: text.New(label),
		D:       gowid.RenderWithWeight{W: 1},
	}
}

//======================================================================
// ColumnsWidget tests
//======================================================================

func TestNewColumns_Basic(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)

	assert.NotNil(t, cw)
	assert.NotNil(t, cw.Widget)
	assert.Empty(t, cw.Offsets)
	assert.Equal(t, 0, len(cw.Offsets))
	assert.Equal(t, 2, cap(cw.Offsets), "Initial capacity should be 2")
}

func TestNewColumns_Empty(t *testing.T) {
	cw := NewColumns([]gowid.IContainerWidget{})
	assert.NotNil(t, cw)
	assert.Empty(t, cw.Offsets)
}

func TestNewColumns_ThreeWidgets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
		makeContainerWidget("c"),
	}
	cw := NewColumns(widgets)
	assert.NotNil(t, cw)
	assert.Equal(t, 3, len(cw.SubWidgets()))
}

func TestColumnsWidget_GetSetOffsets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)

	// Initially empty
	offsets := cw.GetOffsets()
	assert.Empty(t, offsets)

	// Set offsets
	newOffsets := []Offset{
		{Col1: 0, Col2: 1, Adjust: 5},
	}
	cw.SetOffsets(newOffsets, nil)

	got := cw.GetOffsets()
	assert.Equal(t, 1, len(got))
	assert.Equal(t, 0, got[0].Col1)
	assert.Equal(t, 1, got[0].Col2)
	assert.Equal(t, 5, got[0].Adjust)
}

func TestColumnsWidget_SetOffsetsOverwrite(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)

	cw.SetOffsets([]Offset{{Col1: 0, Col2: 1, Adjust: 3}}, nil)
	cw.SetOffsets([]Offset{{Col1: 0, Col2: 1, Adjust: 10}, {Col1: 1, Col2: 0, Adjust: -2}}, nil)

	got := cw.GetOffsets()
	assert.Equal(t, 2, len(got))
	assert.Equal(t, 10, got[0].Adjust)
	assert.Equal(t, -2, got[1].Adjust)
}

func TestColumnsWidget_SetOffsetsEmptySlice(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)

	cw.SetOffsets([]Offset{{Col1: 0, Col2: 1, Adjust: 3}}, nil)
	cw.SetOffsets([]Offset{}, nil)

	assert.Empty(t, cw.GetOffsets())
}

//======================================================================
// AdjustOffset tests (uses the standalone function)
//======================================================================

// mockOffsets implements IOffsets for testing AdjustOffset in isolation.
type mockOffsets struct {
	offsets []Offset
}

func (m *mockOffsets) GetOffsets() []Offset {
	return m.offsets
}

func (m *mockOffsets) SetOffsets(offs []Offset, app gowid.IApp) {
	m.offsets = offs
}

func TestAdjustOffset_CreatesNewOffset(t *testing.T) {
	m := &mockOffsets{offsets: []Offset{}}
	AdjustOffset(m, 0, 1, Add1, nil)

	assert.Equal(t, 1, len(m.GetOffsets()))
	assert.Equal(t, 0, m.offsets[0].Col1)
	assert.Equal(t, 1, m.offsets[0].Col2)
	assert.Equal(t, 1, m.offsets[0].Adjust, "After Add1 from 0, adjust should be 1")
}

func TestAdjustOffset_UpdatesExistingOffset(t *testing.T) {
	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 5}}}
	AdjustOffset(m, 0, 1, Add1, nil)

	assert.Equal(t, 1, len(m.offsets))
	assert.Equal(t, 6, m.offsets[0].Adjust, "5 + 1 = 6")
}

func TestAdjustOffset_Subtract1(t *testing.T) {
	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 3}}}
	AdjustOffset(m, 0, 1, Subtract1, nil)
	assert.Equal(t, 2, m.offsets[0].Adjust, "3 - 1 = 2")
}

func TestAdjustOffset_SubtractBelowZero(t *testing.T) {
	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 0}}}
	AdjustOffset(m, 0, 1, Subtract1, nil)
	assert.Equal(t, -1, m.offsets[0].Adjust, "0 - 1 = -1, no clamping in AdjustOffset")
}

func TestAdjustOffset_LargePositiveAdjust(t *testing.T) {
	addLarge := AdjustFn(func(x int) int { return x + 1000000 })
	m := &mockOffsets{offsets: []Offset{}}
	AdjustOffset(m, 0, 1, addLarge, nil)
	assert.Equal(t, 1000000, m.offsets[0].Adjust)
}

func TestAdjustOffset_LargeNegativeAdjust(t *testing.T) {
	subLarge := AdjustFn(func(x int) int { return x - 1000000 })
	m := &mockOffsets{offsets: []Offset{}}
	AdjustOffset(m, 2, 3, subLarge, nil)
	assert.Equal(t, -1000000, m.offsets[0].Adjust)
}

func TestAdjustOffset_MultipleOffsets(t *testing.T) {
	m := &mockOffsets{offsets: []Offset{}}
	AdjustOffset(m, 0, 1, Add1, nil)
	AdjustOffset(m, 2, 3, Add1, nil)
	AdjustOffset(m, 0, 1, Add1, nil) // should update first offset

	assert.Equal(t, 2, len(m.offsets))
	assert.Equal(t, 2, m.offsets[0].Adjust, "First offset adjusted twice: 0+1+1=2")
	assert.Equal(t, 1, m.offsets[1].Adjust, "Second offset adjusted once: 0+1=1")
}

func TestAdjustOffset_ZeroAdjust(t *testing.T) {
	identity := AdjustFn(func(x int) int { return x })
	m := &mockOffsets{offsets: []Offset{{Col1: 0, Col2: 1, Adjust: 7}}}
	AdjustOffset(m, 0, 1, identity, nil)
	assert.Equal(t, 7, m.offsets[0].Adjust, "Identity function should not change adjust")
}

//======================================================================
// WidgetWidths tests
//======================================================================

func TestColumnsWidget_WidgetWidths_NoOffsets(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)

	size := gowid.MakeRenderBox(80, 24)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	assert.Equal(t, 2, len(widths))
	total := 0
	for _, w := range widths {
		total += w
	}
	assert.Equal(t, 80, total, "Widths should sum to total columns")
}

func TestColumnsWidget_WidgetWidths_WithPositiveOffset(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: 5}}

	size := gowid.MakeRenderBox(80, 24)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	// The total should still be 80 since offset transfers width from Col2 to Col1
	total := 0
	for _, w := range widths {
		total += w
	}
	assert.Equal(t, 80, total, "Widths should still sum to total columns")
	// Col1 should be wider, Col2 should be narrower
	assert.True(t, widths[0] > widths[1], "Col1 should be wider than Col2 with +5 offset")
}

func TestColumnsWidget_WidgetWidths_WithNegativeOffset(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)
	cw.Offsets = []Offset{{Col1: 0, Col2: 1, Adjust: -5}}

	size := gowid.MakeRenderBox(80, 24)
	widths := cw.WidgetWidths(size, gowid.NotSelected, 0, gwtest.D)

	total := 0
	for _, w := range widths {
		total += w
	}
	assert.Equal(t, 80, total, "Widths should still sum to total columns")
	assert.True(t, widths[0] < widths[1], "Col1 should be narrower than Col2 with -5 offset")
}

//======================================================================
// PileWidget tests
//======================================================================

func TestNewPile_Basic(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("top"),
		makeContainerWidget("bottom"),
	}
	pw := NewPile(widgets)

	assert.NotNil(t, pw)
	assert.NotNil(t, pw.Widget)
	assert.NotNil(t, pw.Callbacks)
	assert.Empty(t, pw.Offsets)
}

func TestNewPile_Empty(t *testing.T) {
	pw := NewPile([]gowid.IContainerWidget{})
	assert.NotNil(t, pw)
	assert.Empty(t, pw.Offsets)
}

func TestPileWidget_GetSetOffsets(t *testing.T) {
	pw := NewPile([]gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	})

	assert.Empty(t, pw.GetOffsets())

	offs := []Offset{{Col1: 0, Col2: 1, Adjust: 3}}
	pw.SetOffsets(offs, nil)

	got := pw.GetOffsets()
	assert.Equal(t, 1, len(got))
	assert.Equal(t, 3, got[0].Adjust)
}

func TestPileWidget_AdjustOffset(t *testing.T) {
	pw := NewPile([]gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	})

	pw.AdjustOffset(0, 1, Add1, nil)
	assert.Equal(t, 1, len(pw.GetOffsets()))
	assert.Equal(t, 1, pw.GetOffsets()[0].Adjust)

	pw.AdjustOffset(0, 1, Add1, nil)
	assert.Equal(t, 2, pw.GetOffsets()[0].Adjust)

	pw.AdjustOffset(0, 1, Subtract1, nil)
	assert.Equal(t, 1, pw.GetOffsets()[0].Adjust)
}

//======================================================================
// Offset JSON tests (supplement existing)
//======================================================================

func TestOffset_JSONZeroValues(t *testing.T) {
	off := Offset{}
	data, err := json.Marshal(off)
	assert.NoError(t, err)
	assert.Equal(t, `{"col1":0,"col2":0,"adjust":0}`, string(data))

	var out Offset
	err = json.Unmarshal(data, &out)
	assert.NoError(t, err)
	assert.Equal(t, off, out)
}

func TestOffset_JSONNegativeAdjust(t *testing.T) {
	off := Offset{Col1: 1, Col2: 2, Adjust: -10}
	data, err := json.Marshal(off)
	assert.NoError(t, err)

	var out Offset
	err = json.Unmarshal(data, &out)
	assert.NoError(t, err)
	assert.Equal(t, off, out)
}

func TestOffset_JSONEmptySlice(t *testing.T) {
	offs := []Offset{}
	data, err := json.Marshal(offs)
	assert.NoError(t, err)
	assert.Equal(t, `[]`, string(data))
}

//======================================================================
// Add1 and Subtract1 function tests
//======================================================================

func TestAdd1_Function(t *testing.T) {
	assert.Equal(t, 1, Add1(0))
	assert.Equal(t, 0, Add1(-1))
	assert.Equal(t, 101, Add1(100))
}

func TestSubtract1_Function(t *testing.T) {
	assert.Equal(t, -1, Subtract1(0))
	assert.Equal(t, 0, Subtract1(1))
	assert.Equal(t, 99, Subtract1(100))
}

//======================================================================
// ColumnsWidget callback tests
//======================================================================

func TestColumnsWidget_OnOffsetsSet_LazyCallbackInit(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)
	// Callbacks is nil at construction
	assert.Nil(t, cw.Callbacks)

	// OnOffsetsSet should lazily initialize Callbacks
	cw.OnOffsetsSet(gowid.MakeWidgetCallback("test", func(app gowid.IApp, w gowid.IWidget) {}))
	assert.NotNil(t, cw.Callbacks)
}

func TestColumnsWidget_RemoveOnOffsetsSet_LazyCallbackInit(t *testing.T) {
	widgets := []gowid.IContainerWidget{
		makeContainerWidget("a"),
		makeContainerWidget("b"),
	}
	cw := NewColumns(widgets)
	assert.Nil(t, cw.Callbacks)

	// RemoveOnOffsetsSet should lazily initialize Callbacks
	cw.RemoveOnOffsetsSet(gowid.CallbackID{Name: "test"})
	assert.NotNil(t, cw.Callbacks)
}

//======================================================================
// IOffsets interface compliance
//======================================================================

func TestColumnsWidget_ImplementsIOffsets(t *testing.T) {
	var _ IOffsets = (*ColumnsWidget)(nil)
}

func TestPileWidget_ImplementsIOffsets(t *testing.T) {
	var _ IOffsets = (*PileWidget)(nil)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
