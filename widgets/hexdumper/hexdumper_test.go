// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package hexdumper

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestDump1(t *testing.T) {
	widget1 := New([]byte("abcdefghijklmnopqrstuvwxyz0123456789 abcdefghijklmnopqrstuvwxyz0123456789"))
	//stylers: []LayerStyler{styler},
	canvas1 := widget1.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	log.Infof("Canvas1 is %s", canvas1.String())
	assert.Equal(t, 5, canvas1.BoxRows())
}

func TestDump2(t *testing.T) {
	widget1 := New([]byte(""))
	canvas2 := widget1.Render(gowid.RenderFlowWith{C: 60}, gowid.NotSelected, gwtest.D)
	log.Infof("Canvas2 is %s", canvas2.String())
	assert.Equal(t, 1, canvas2.BoxRows())
}

func TestToChar(t *testing.T) {
	tests := []struct {
		input    byte
		expected byte
	}{
		{0, '.'},    // control character
		{31, '.'},   // control character (just before printable)
		{32, ' '},   // first printable (space)
		{'A', 'A'},  // regular letter
		{'z', 'z'},  // regular letter
		{'0', '0'},  // digit
		{'~', '~'},  // 126 - last printable
		{127, '.'},  // DEL - first non-printable after printable range
		{255, '.'},  // high byte
	}

	for _, tt := range tests {
		result := toChar(tt.input)
		assert.Equal(t, tt.expected, result, "toChar(%d) should be %c", tt.input, tt.expected)
	}
}

func TestLayerStyler(t *testing.T) {
	styler := LayerStyler{
		Start:         10,
		End:           20,
		ColUnselected: "layer-unsel",
		ColSelected:   "layer-sel",
	}

	assert.Equal(t, 10, styler.Start)
	assert.Equal(t, 20, styler.End)
	assert.Equal(t, "layer-unsel", styler.ColUnselected)
	assert.Equal(t, "layer-sel", styler.ColSelected)
}

func TestWidgetAccessors(t *testing.T) {
	layers := []LayerStyler{
		{Start: 0, End: 5, ColUnselected: "unsel1", ColSelected: "sel1"},
	}

	widget := New([]byte("test data"), Options{
		StyledLayers:      layers,
		CursorUnselected:  "cursor-unsel",
		CursorSelected:    "cursor-sel",
		LineNumUnselected: "linenum-unsel",
		LineNumSelected:   "linenum-sel",
	})

	assert.Equal(t, []byte("test data"), widget.Data())
	assert.Equal(t, layers, widget.Layers())
	assert.Equal(t, "cursor-unsel", widget.CursorUnselected())
	assert.Equal(t, "cursor-sel", widget.CursorSelected())
	assert.Equal(t, "linenum-unsel", widget.LineNumUnselected())
	assert.Equal(t, "linenum-sel", widget.LineNumSelected())
	assert.Equal(t, "hexdump", widget.String())
}

func TestWidgetWithEmptyOptions(t *testing.T) {
	widget := New([]byte("hello"))

	assert.Equal(t, []byte("hello"), widget.Data())
	assert.Empty(t, widget.Layers())
	assert.Empty(t, widget.CursorUnselected())
	assert.Empty(t, widget.CursorSelected())
}

func TestHexChrsId(t *testing.T) {
	id1 := hexChrsId{idx: 42}
	id2 := hexChrsId{idx: 42}
	id3 := hexChrsId{idx: 100}

	assert.Equal(t, id1.ID(), id2.ID())
	assert.NotEqual(t, id1.ID(), id3.ID())
}

func TestHexBytesId(t *testing.T) {
	id1 := hexBytesId{idx: 10}
	id2 := hexBytesId{idx: 10}
	id3 := hexBytesId{idx: 20}

	assert.Equal(t, id1.ID(), id2.ID())
	assert.NotEqual(t, id1.ID(), id3.ID())
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
