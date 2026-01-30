// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streamwidget

import (
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/gcla/termshark/v2/pkg/streams"
	"github.com/gcla/termshark/v2/widgets/copymodetable"
	"github.com/gcla/termshark/v2/widgets/framefocus"
	"github.com/gcla/termshark/v2/widgets/regexstyle"
)

type chunkList struct {
	clicker iChunkClicker
	chunks  []streams.IChunk
}

type asciiChunkList struct {
	*chunkList
}

type rawChunkList struct {
	*chunkList
}

var _ table.IBoundedModel = chunkList{}
var _ table.IBoundedModel = asciiChunkList{}
var _ table.IBoundedModel = rawChunkList{}
var _ copymodetable.IRowCopier = chunkList{}
var _ copymodetable.IRowCopier = asciiChunkList{}
var _ copymodetable.IRowCopier = rawChunkList{}
var _ copymodetable.ITableCopier = chunkList{}
var _ copymodetable.ITableCopier = asciiChunkList{}
var _ copymodetable.ITableCopier = rawChunkList{}

// CopyTable is here to implement copymodetable.IRowCopier
func (c chunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	hexd := format.HexDump(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy hexdump",
			Val:  hexd,
		},
	}
}

func (c asciiChunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	prt := format.MakePrintableStringWithNewlines(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy ascii",
			Val:  prt,
		},
	}
}

func (c rawChunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	raw := format.MakeHexStream(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy raw",
			Val:  raw,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c asciiChunkList) CopyTable() []gowid.ICopyResult {
	prtl := make([]string, 0, len(c.chunks))

	for i := range len(c.chunks) {
		prtl = append(prtl, format.MakePrintableStringWithNewlines(c.chunks[i].StreamData()))
	}

	prt := strings.Join(prtl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy ascii",
			Val:  prt,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c chunkList) CopyTable() []gowid.ICopyResult {
	hexdl := make([]string, 0, len(c.chunks))

	for i := range len(c.chunks) {
		hex := format.HexDump(c.chunks[i].StreamData())
		if c.chunks[i].Direction() == streams.Server {
			hex = indentRe.ReplaceAllString(hex, `    $1`)
		}

		hexdl = append(hexdl, hex)
	}

	hexd := strings.Join(hexdl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy hexdump",
			Val:  hexd,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c rawChunkList) CopyTable() []gowid.ICopyResult {
	rawl := make([]string, 0, len(c.chunks))

	for i := range len(c.chunks) {
		rawl = append(rawl, format.MakeHexStream(c.chunks[i].StreamData()))
	}

	raw := strings.Join(rawl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy raw",
			Val:  raw,
		},
	}
}

// makeButton constructs a row for the stream list that if clicked will select the
// appropriate packet in the packet list
func (c chunkList) makeButton(row table.RowId, ch gowid.IWidget) *button.Widget {
	btn := button.NewBare(ch)

	//btn.OnClickDown(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
	btn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		if c.clicker != nil && c.clicker.clickIsActive() {
			if irow, err := c.clicker.MapChunkToTableRow(int(row)); err != nil {
				c.clicker.HandleError(row, err, app)
			} else {
				c.clicker.OnPacketClicked(irow, app)
			}
		}
	}),
	)

	return btn
}

func (c chunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	var ch gowid.IWidget

	// not sorted
	hilite := c.clicker.highlightThis(table.Position(row))

	datastr := format.HexDump(c.chunks[row].StreamData())
	if c.chunks[row].Direction() == streams.Server {
		datastr = indentRe.ReplaceAllString(datastr, `    $1`)
	}

	dataw := framefocus.New(
		selectable.New(
			regexstyle.New(
				text.New(datastr),
				hilite,
			),
		),
	)

	if c.chunks[row].Direction() == streams.Client {
		ch = styled.New(
			dataw,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			dataw,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

//======================================================================

func (c asciiChunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	hl := c.clicker.highlightThis(table.Position(row))

	str := framefocus.NewSlim(
		selectable.New(
			regexstyle.New(
				text.New(strings.TrimSuffix(format.MakePrintableStringWithNewlines((*c.chunkList).chunks[row].StreamData()), "\n")),
				hl,
			),
		),
	)

	var ch gowid.IWidget

	if (*c.chunkList).chunks[row].Direction() == streams.Client {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

func (c rawChunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	hl := c.clicker.highlightThis(table.Position(row))

	str := framefocus.New(
		selectable.New(
			regexstyle.New(
				text.New(format.MakeHexStream((*c.chunkList).chunks[row].StreamData())),
				hl,
			),
		),
	)

	var ch gowid.IWidget

	if (*c.chunkList).chunks[row].Direction() == streams.Client {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

func (c asciiChunkList) Widths() []gowid.IWidgetDimension {
	return []gowid.IWidgetDimension{gowid.RenderWithWeight{W: 1}}
}

func (c chunkList) Widths() []gowid.IWidgetDimension {
	return []gowid.IWidgetDimension{gowid.RenderWithWeight{W: 1}}
}

func (c chunkList) Columns() int {
	return 1
}

func (c chunkList) Rows() int {
	return len(c.chunks)
}

func (c chunkList) HorizontalSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) HeaderSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) HeaderWidgets() []gowid.IWidget {
	return nil
}

func (c chunkList) VerticalSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) RowIdentifier(row int) (table.RowId, bool) {
	if row < 0 || row >= len(c.chunks) {
		return -1, false
	}
	return table.RowId(row), true
}

//======================================================================

// TODO - duplicated from termshark

type copyModePalette struct{}

var _ gowid.IClipboardSelected = copyModePalette{}

func (r copyModePalette) AlterWidget(w gowid.IWidget, app gowid.IApp) gowid.IWidget {
	return styled.New(w, gowid.MakePaletteRef("copy-mode"),
		styled.Options{
			OverWrite: true,
		},
	)
}
