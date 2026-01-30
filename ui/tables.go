// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/ui/tableutil"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/enableselected"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

// psmlSummary is used to generate a summary for the marks dialog
type psmlSummary []string

func (p psmlSummary) String() string {
	if len(p) <= 1 {
		return ""
	}
	// Skip packet number
	return strings.Join([]string(p)[1:], " : ")
}

//======================================================================

// An ugly interface that captures what sort of type will be suitable
// as a table widget to which a row focus can be applied.
type iRowFocusTableWidgetNeeds interface {
	gowid.IWidget
	list.IBoundedWalker
	table.IFocus
	table.IGoToMiddle
	table.ISetFocus
	list.IWalkerHome
	list.IWalkerEnd
	SetPos(pos list.IBoundedWalkerPosition, app gowid.IApp)
	FocusXY() (table.Coords, error)
	SetFocusXY(gowid.IApp, table.Coords)
	SetModel(table.IModel, gowid.IApp)
	Lower() *table.ListWithPreferedColumn
	SetFocusOnData(app gowid.IApp) bool
	OnFocusChanged(f gowid.IWidgetChangedCallback)
}

// rowFocusTableWidget provides a table that highlights the selected row or
// focused row.
type rowFocusTableWidget struct {
	iRowFocusTableWidgetNeeds
	rowSelected string
	rowFocus    string
}

func NewRowFocusTableWidget(w iRowFocusTableWidgetNeeds, rs string, rf string) *rowFocusTableWidget {
	res := &rowFocusTableWidget{
		iRowFocusTableWidgetNeeds: w,
		rowSelected:               rs,
		rowFocus:                  rf,
	}
	res.Lower().IWidget = list.NewBounded(res)
	return res
}

var _ gowid.IWidget = (*rowFocusTableWidget)(nil)

func (t *rowFocusTableWidget) SubWidget() gowid.IWidget {
	return t.iRowFocusTableWidgetNeeds
}

func (t *rowFocusTableWidget) InvertedModel() table.IInvertible {
	return t.Model().(table.IInvertible)
}

func (t *rowFocusTableWidget) Rows() int {
	return t.Model().(table.IBoundedModel).Rows()
}

// Implement withscrollbar.IScrollValues
func (t *rowFocusTableWidget) ScrollLength() int {
	return t.Rows()
}

// Implement withscrollbar.IScrollValues
func (t *rowFocusTableWidget) ScrollPosition() int {
	return t.CurrentRow()
}

func (t *rowFocusTableWidget) Up(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) Down(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyDown, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) UpPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyPgUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyPgDn, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

// list.IWalker
func (t *rowFocusTableWidget) At(lpos list.IWalkerPosition) gowid.IWidget {
	pos := int(lpos.(table.Position))
	w := t.AtRow(pos)
	if w == nil {
		return nil
	}

	// Composite so it passes through preferred column
	var res gowid.IWidget = &selectedComposite{
		Widget: isselected.New(w,
			styled.New(w, gowid.MakePaletteRef(t.rowSelected)),
			styled.New(w, gowid.MakePaletteRef(t.rowFocus)),
		),
	}

	return res
}

// Needed for WidgetAt above to work - otherwise t.Table.Focus() is called, table is the receiver,
// then it calls WidgetAt so ours is not used.
func (t *rowFocusTableWidget) Focus() list.IWalkerPosition {
	return table.Focus(t)
}

//======================================================================

// A rowFocusTableWidget that adds colors to rows
type psmlTableRowWidget struct {
	*rowFocusTableWidget
	// set to true after the first time we move focus from the table header to the data. We do this
	// once and that this happens quickly, but then assume the user might want to move back to the
	// table header manually, and it would be strange if the table keeps jumping back to the data...
	didFirstAutoFocus bool
	colors            []pcap.PacketColors
}

func NewPsmlTableRowWidget(w *rowFocusTableWidget, c []pcap.PacketColors) *psmlTableRowWidget {
	res := &psmlTableRowWidget{
		rowFocusTableWidget: w,
		colors:              c,
	}
	res.Lower().IWidget = list.NewBounded(res)
	return res
}

func (t *psmlTableRowWidget) At(lpos list.IWalkerPosition) gowid.IWidget {
	res := t.rowFocusTableWidget.At(lpos)
	if res == nil {
		return nil
	}
	pos := int(lpos.(table.Position))

	// Check the color array length because it might not yet be adequately
	// populated from the arriving psml.
	if pos >= 0 && PacketColors && pos < len(t.colors) {
		res = styled.New(res,
			gowid.MakePaletteEntry(t.colors[pos].FG, t.colors[pos].BG),
		)
	}

	return res
}

func (t *psmlTableRowWidget) Focus() list.IWalkerPosition {
	return table.Focus(t)
}

//======================================================================

// I want to have preferred position work on this, but you have to choose a subwidget
// to navigate to. We have three. I know that my use of them is very similar, so I'll
// just pick the first
type selectedComposite struct {
	*isselected.Widget
}

var _ gowid.IComposite = (*selectedComposite)(nil)

func (w *selectedComposite) SubWidget() gowid.IWidget {
	return w.Not
}

//======================================================================

type iPsmlInfo interface {
	PsmlData() [][]string
	PsmlHeaders() []string
	PsmlColors() []pcap.PacketColors
	PsmlAverageLengths() []gwutil.IntOption
	PsmlMaxLengths() []int
}

func makePacketListModel(psml iPsmlInfo, app gowid.IApp) *psmlmodel.Model {
	headers := psml.PsmlHeaders()

	avgs := psml.PsmlAverageLengths()
	maxs := psml.PsmlMaxLengths()
	widths := make([]gowid.IWidgetDimension, 0, len(avgs))
	for i := range len(avgs) {
		titleLen := 0
		if i < len(headers) {
			titleLen = len(headers[i]) + 1 // add 1 because the table clears the last cell
		}
		max := gwutil.Max(maxs[i], titleLen)

		// in case there isn't any data yet
		avg := titleLen
		if !avgs[i].IsNone() {
			avg = gwutil.Max(avgs[i].Val(), titleLen)
		}
		// This makes the UI look nicer - an extra column of space when the columns are
		// packed tightly and each column is usually full.
		if avg == max {
			widths = append(widths, weightupto(avg, max+1))
		} else {
			widths = append(widths, weightupto(avg, max))
		}
	}

	packetPsmlTableModel := table.NewSimpleModel(
		headers,
		psml.PsmlData(),
		table.SimpleOptions{
			Style: table.StyleOptions{
				VerticalSeparator:   fill.New(' '),
				HeaderStyleProvided: true,
				HeaderStyleFocus:    gowid.MakePaletteRef("packet-list-cell-focus"),
				CellStyleProvided:   true,
				CellStyleSelected:   gowid.MakePaletteRef("packet-list-cell-selected"),
				CellStyleFocus:      gowid.MakePaletteRef("packet-list-cell-focus"),
			},
			Layout: table.LayoutOptions{
				Widths: widths,
			},
		},
	)

	expandingModel := psmlmodel.New(
		packetPsmlTableModel,
		gowid.MakePaletteRef("packet-list-row-focus"),
	)

	// No need to refetch the information from the TOML file each time this is
	// called. Use a globally cached version
	cols := shark.GetPsmlColumnFormatCached()

	if len(expandingModel.Comparators) > 0 {
		for i := range expandingModel.Comparators {
			if i < len(widths) && i < len(cols) {
				if field, ok := shark.AllowedColumnFormats[cols[i].Field.Token]; ok {
					if field.Comparator != nil {
						expandingModel.Comparators[i] = field.Comparator
					}
				}
			}
		}
	}

	return expandingModel
}

func updatePacketListWithData(psml iPsmlInfo, app gowid.IApp) {
	packetListView.colors = psml.PsmlColors() // otherwise this isn't updated
	model := makePacketListModel(psml, app)
	newPacketsArrived = true
	packetListTable.SetModel(model, app)
	newPacketsArrived = false
	if AutoScroll {
		coords, err := packetListView.FocusXY()
		if err == nil {
			coords.Row = packetListTable.Length() - 1
			newPacketsArrived = true
			// Set focus on the last item in the view, then...
			packetListView.SetFocusXY(app, coords)
			newPacketsArrived = false
		}
		// ... adjust the widget so it is rendering with the last item at the bottom.
		packetListTable.GoToBottom(app)
	}
	// Only do this once, the first time.
	if !packetListView.didFirstAutoFocus && len(psml.PsmlData()) > 0 {
		packetListView.SetFocusOnData(app)
		packetListView.didFirstAutoFocus = true
	}
}

func setPacketListWidgets(psml iPsmlInfo, app gowid.IApp) {
	expandingModel := makePacketListModel(psml, app)

	packetListTable = &table.BoundedWidget{Widget: table.New(expandingModel)}
	packetListView = NewPsmlTableRowWidget(
		NewRowFocusTableWidget(
			packetListTable,
			"packet-list-row-selected",
			"packet-list-row-focus",
		),
		psml.PsmlColors(),
	)

	packetListView.OnFocusChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		fxy, err := packetListView.FocusXY()
		if err != nil {
			return
		}

		if !newPacketsArrived && !reenableAutoScroll {
			// this focus change must've been user-initiated, so stop auto-scrolling with new packets.
			// This mimics Wireshark's behavior. Note that if the user hits the end key, this may
			// update the view and run this callback, but end means to resume auto-scrolling if it's
			// enabled, so we should not promptly disable it again
			setAutoScrollWithSync(false)
		}

		row2 := fxy.Row
		row3, gotrow := packetListView.Model().RowIdentifier(row2)
		row := int(row3)

		if gotrow && row >= 0 {
			pktsPerLoad := Loader.PacketsPerLoad()

			// Use the app package's prefetch algorithm
			calculateAndSyncPrefetchRequests(row, pktsPerLoad)

			GetCacheRequestsChan() <- struct{}{}

			// Sync current packet number with Controller
			if jpos, err := packetNumberFromTableRow(row2); err == nil {
				AppController.State.SetCurrentPacket(jpos.Pos)
			}
		}

		// When the focus changes, update the hex and struct view. If they cannot
		// be populated, display a loading message

		setLowerWidgets(app)
	}))

	withScrollbar := withscrollbar.New(packetListView, withscrollbar.Options{
		HideIfContentFits: true,
	})
	selme := enableselected.New(withScrollbar)
	keys := appkeys.New(
		selme,
		tableutil.GotoHandler(&tableutil.GoToAdapter{
			BoundedWidget: packetListTable,
			KeyState:      &keyState,
		}),
	)

	packetListViewHolder.SetSubWidget(keys, app)
}
