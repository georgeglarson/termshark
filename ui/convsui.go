// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"context"
	"fmt"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/keepselected"
	"github.com/gdamore/tcell/v2"
)

var convsView *holder.Widget
var convsUi *ConvsUiWidget
var convCancel context.CancelFunc

var convsPcapSize int64 // track size of source, if changes then recalculation conversations

var vdiv string
var frameRunes framed.FrameRunes

//======================================================================

type ManageConvsCache struct{}

var _ pcap.INewSource = ManageConvsCache{}

// Make sure that existing data is discarded if the user loads a new pcap.
func (t ManageConvsCache) OnNewSource(pcap.HandlerCode, gowid.IApp) {
	convsView = nil // which then deletes all refs to loaded data
	convsPcapSize = 0
}

//======================================================================

func convsKeyPress(sections *pile.Widget, evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	switch {
	case evk.Rune() == 'q' || evk.Rune() == 'Q' || evk.Key() == tcell.KeyEscape:
		closeConvsUi(app)
		convCancel()
		handled = true
	case evk.Key() == tcell.KeyTAB:
		if next, ok := sections.FindNextSelectable(gowid.Forwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	case evk.Key() == tcell.KeyBacktab:
		if next, ok := sections.FindNextSelectable(gowid.Backwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	}
	return handled
}

//======================================================================

type pleaseWait struct{}

func (p pleaseWait) OpenPleaseWait(app gowid.IApp) {
	OpenPleaseWait(appView, app)
}

func (p pleaseWait) ClosePleaseWait(app gowid.IApp) {
	ClosePleaseWait(app)
}

// Dynamically load conv. If the convs window was last opened with a different filter, and the "limit to
// filter" checkbox is checked, then the data needs to be reloaded.
func openConvsUi(app gowid.IApp) {

	var convCtx context.Context
	convCtx, convCancel = context.WithCancel(Loader.Context())

	newSize, reset := termshark.FileSizeDifferentTo(Loader.PcapPdml, convsPcapSize)
	if reset {
		convsView = nil
	}

	// This is nil if a new pcap is loaded (or the old one cleared)
	if convsView == nil {
		convsPcapSize = newSize

		// gcla later todo - PcapPdml - hack?
		convsUi = NewConvsUi(
			Loader.String(),
			Loader.DisplayFilter(),
			Loader.PcapPdml,
			pleaseWait{},
			ConvsUiOptions{
				CopyModeWidget: CopyModeWidget,
			},
		)

		convsView = holder.New(convsUi)
	} else if convsUi.FilterValue() != Loader.DisplayFilter() && convsUi.UseFilter() {
		convsUi.ReloadNeeded()
	}

	convsUi.ctx = convCtx
	convsUi.focusOnFilter = false
	convsUi.displayFilter = Loader.DisplayFilter()

	copyModeConvsView := appkeys.New(
		appkeys.New(
			convsView,
			copyModeExitKeys20,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		copyModeEnterKeys,
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	appViewNoKeys.SetSubWidget(copyModeConvsView, app)
}

func closeConvsUi(app gowid.IApp) {
	appViewNoKeys.SetSubWidget(mainView, app)

	if convsUi.focusOnFilter {
		setFocusOnDisplayFilter(app)
	} else {
		// Do this if the user starts conversations from the menu - better UX
		setFocusOnPacketList(app)
	}
}

//======================================================================

//======================================================================

func NewConvsUi(captureDevice string, displayFilter string, pcapf string, pw IPleaseWait, opts ...ConvsUiOptions) *ConvsUiWidget {
	var opt ConvsUiOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &ConvsUiWidget{
		opt:           opt,
		displayFilter: displayFilter,
		captureDevice: captureDevice,
		pcapf:         pcapf,
		pleaseWait:    pw,
		tabIndex:      make(map[string]int),
		buttonLabels:  make(map[string]*text.Widget),
	}

	res.construct()

	return res
}

type IPleaseWait interface {
	OpenPleaseWait(app gowid.IApp)
	ClosePleaseWait(app gowid.IApp)
}

type ConvsUiOptions struct {
	CopyModeWidget gowid.IWidget // What to display when copy-mode is started.
}

type ConvsUiWidget struct {
	gowid.IWidget
	opt                 ConvsUiOptions
	captureDevice       string // "eth0"
	displayFilter       string // "tcp.stream eq 1"
	pcapf               string // "eth0-ddddd.pcap"
	ctx                 context.Context
	pleaseWait          IPleaseWait
	convHolder          *holder.Widget
	convs               []*oneConvWidget        // the widgets displayed in each tab
	prepFiltBtn         *button.Widget          // "Prepare filter" -> click to prep filter
	applyFiltBtn        *button.Widget          // "Apply filter" -> click to prep filter
	filterPrep          bool                    // if true prepare filter, don't apply; otherwise apply immediately
	filterSelectedIndex FilterCombinator        // which filter combination is active e.g. A -> B
	focusOnFilter       bool                    // Whether to set focus on display filter on closing widget
	buttonLabels        map[string]*text.Widget // map "eth" to button, so I can update with a count of conversations
	shortNames          []string                // ["eth", "ip", ...] - from config file
	tabIndex            map[string]int          // {"eth": 0, "ipv6": 2, ...} -> mapping to tabs in UI
	started             bool                    // false if stream load needs to be done, true if under way or done
}

func (w *ConvsUiWidget) AbsoluteTime() bool {
	return profiles.ConfBool("main.conv-absolute-time", false)
}

func (w *ConvsUiWidget) SetAbsoluteTime(val bool) {
	profiles.SetConf("main.conv-absolute-time", val)
}

func (w *ConvsUiWidget) ResolveNames() bool {
	return profiles.ConfBool("main.conv-resolve-names", false)
}

func (w *ConvsUiWidget) SetResolveNames(val bool) {
	profiles.SetConf("main.conv-resolve-names", val)
}

func (w *ConvsUiWidget) Context() context.Context {
	return w.ctx
}

func (w *ConvsUiWidget) FilterValue() string {
	return w.displayFilter
}

func (w *ConvsUiWidget) UseFilter() bool {
	return profiles.ConfBool("main.conv-use-filter", false)
}

func (w *ConvsUiWidget) SetUseFilter(val bool) {
	profiles.SetConf("main.conv-use-filter", val)
}

func (w *ConvsUiWidget) construct() {
	convs := make([]*oneConvWidget, 0)

	header := w.makeHeaderConvsUiWidget()

	convsHeader := columns.NewWithDim(
		gowid.RenderWithWeight{W: 1},
		header,
	)

	colws := make([]interface{}, 0)
	colws = append(colws,
		text.New(vdiv),
	)
	w.shortNames = termshark.ConvTypes()
	// Just in case there are none
	w.convHolder = holder.New(null.New())
	for i, p := range w.shortNames {
		p := p
		i := i

		w.tabIndex[p] = i
		newconv := newOneConv(p)
		convs = append(convs, newconv)

		if i == 0 {
			w.convHolder = holder.New(newconv)
		}

		w.buttonLabels[p] = text.New(fmt.Sprintf(" %s ", convTypes[p]))
		b := button.NewBare(w.buttonLabels[p])
		b.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
			w.convHolder.SetSubWidget(newconv, app)
		}))

		bs := isselected.NewExt(
			b,
			styled.New(b, gowid.MakePaletteRef("button-selected")),
			styled.New(b, gowid.MakePaletteRef("button-focus")),
		)

		colws = append(colws, bs, text.New(vdiv))
	}

	panel := framed.New(w.convHolder, framed.Options{
		Frame: frameRunes,
	})

	cols := keepselected.New(columns.NewFixed(colws...))

	nameCheck := checkbox.New(w.ResolveNames())

	nameCheck.OnClick(gowid.WidgetCallback{Name: "cb", WidgetChangedFunction: func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetResolveNames(nameCheck.IsChecked())
		w.ReloadNeeded()
	}})

	nameLabel := text.New(" Name res.")
	nameW := hpadding.New(
		columns.NewFixed(nameCheck, nameLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	filterCheck := checkbox.New(w.UseFilter())

	filterCheck.OnClick(gowid.WidgetCallback{Name: "cb", WidgetChangedFunction: func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetUseFilter(filterCheck.IsChecked())
		w.ReloadNeeded()
	}})

	filterLabel := text.New(" Limit to filter")
	filterW := hpadding.New(
		columns.NewFixed(filterCheck, filterLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	absTimeCheck := checkbox.New(w.AbsoluteTime())

	absTimeCheck.OnClick(gowid.WidgetCallback{Name: "cb", WidgetChangedFunction: func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetAbsoluteTime(absTimeCheck.IsChecked())
		w.ReloadNeeded()
	}})

	absTimeLabel := text.New(" Abs. time")
	absTimeW := hpadding.New(
		columns.NewFixed(absTimeCheck, absTimeLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	prepFiltBtnSite := menu.NewSite(menu.SiteOptions{YOffset: -8})
	w.prepFiltBtn = button.New(text.New("Prep Filter"))
	w.prepFiltBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.filterPrep = true
		filterConvsMenu1.Open(prepFiltBtnSite, app)
	}))

	styledPrepFiltBtn := styled.NewExt(
		w.prepFiltBtn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	prepFiltCols := columns.NewFixed(prepFiltBtnSite, styledPrepFiltBtn)
	prepFiltColsW := hpadding.New(
		prepFiltCols,
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	applyFiltBtnSite := menu.NewSite(menu.SiteOptions{YOffset: -8})
	w.applyFiltBtn = button.New(text.New("Apply Filter"))
	w.applyFiltBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.filterPrep = false
		filterConvsMenu1.Open(applyFiltBtnSite, app)
	}))

	styledApplyFiltBtn := styled.NewExt(
		w.applyFiltBtn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	applyFiltCols := columns.NewFixed(applyFiltBtnSite, styledApplyFiltBtn)
	applyFiltColsW := hpadding.New(
		applyFiltCols,
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	bcols := columns.NewWithDim(gowid.RenderWithWeight{W: 1},
		prepFiltColsW,
		applyFiltColsW,
		nameW,
		filterW,
		absTimeW,
	)

	main := pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: convsHeader,
			D:       gowid.RenderWithUnits{U: 2},
		},
		&gowid.ContainerWidget{
			IWidget: cols,
			D:       gowid.RenderWithUnits{U: 1},
		},
		&gowid.ContainerWidget{
			IWidget: panel,
			D:       gowid.RenderWithWeight{W: 1},
		},
		&gowid.ContainerWidget{
			IWidget: bcols,
			D:       gowid.RenderWithUnits{U: 1},
		},
	})

	w.IWidget = appkeys.New(
		main,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			return convsKeyPress(main, ev, app)
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)
	w.convs = convs
}

func (w *ConvsUiWidget) ReloadNeeded() {
	w.started = false
}

func (w *ConvsUiWidget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if !w.started {
		w.started = true

		ld := convs.NewLoader(convs.MakeCommands(), w.Context())

		handler := convsParseHandler{
			app:    app,
			ondata: w,
		}

		filter := ""
		if w.UseFilter() {
			filter = w.FilterValue()
		}

		ld.StartLoad(
			w.pcapf,
			w.shortNames,
			//w.ctype,
			filter,
			w.AbsoluteTime(),
			w.ResolveNames(),
			app,
			&handler,
		)

	}
	return w.IWidget.Render(size, focus, app)
}

// The widget displayed in the first line of the stream reassembly UI.
func (w *ConvsUiWidget) makeHeaderConvsUiWidget() gowid.IWidget {
	var headerText string
	var headerText1 string
	var headerText2 string
	var headerText3 string
	headerText1 = "Conversations"
	if w.displayFilter != "" {
		headerText2 = fmt.Sprintf("(%s)", w.displayFilter)
	}
	if w.captureDevice != "" {
		headerText3 = fmt.Sprintf("- %s", w.captureDevice)
	}
	headerText = strings.Join([]string{headerText1, headerText2, headerText3}, " ")

	headerView := overlay.New(
		hpadding.New(w.opt.CopyModeWidget, gowid.HAlignMiddle{}, fixed),
		hpadding.New(
			text.New(headerText),
			gowid.HAlignMiddle{},
			fixed,
		),
		gowid.VAlignTop{},
		gowid.RenderWithRatio{R: 1},
		gowid.HAlignMiddle{},
		gowid.RenderWithRatio{R: 1},
		overlay.Options{
			BottomGetsFocus:  true,
			TopGetsNoFocus:   true,
			BottomGetsCursor: true,
		},
	)

	return headerView
}

// convsModelWithRow is able to provide an A and a B for a conversation A <-> B. It looks
func (w *ConvsUiWidget) doFilterMenuOp(dirOp FilterMask, app gowid.IApp) {
	conv1 := w.convHolder.SubWidget()
	if conv1 != nil {
		if conv1, ok := conv1.(*oneConvWidget); ok {
			if conv1.tbl.Length() == 0 {
				OpenError("No conversation selected.", app)
				return
			}
			pos := conv1.tbl.Pos()

			cmodel := &convsModelWithRow{
				model: conv1.model,
				row:   pos,
			}

			filter := ComputeConvFilterOp(dirOp, w.filterSelectedIndex, cmodel, FilterWidget.Value())

			FilterWidget.SetValue(filter, app)

			if w.filterPrep {
				// Don't run the filter, just add to the displayfilter widget. Leave focus there
				w.focusOnFilter = true
				OpenMessage("Display filter prepared.", appView, app)
			} else {
				RequestNewFilter(filter, app)
				w.displayFilter = filter
				OpenMessage("Display filter applied.", appView, app)
				w.ReloadNeeded()
			}
		}
	}
}

//======================================================================

type oneConvWidget struct {
	gowid.IWidget
	ctype            string
	pleaseWaitWidget gowid.IWidget
	cancelledWidget  gowid.IWidget
	model            *ConvsModel
	tbl              *table.BoundedWidget
}

func newOneConv(ctype string) *oneConvWidget {
	pleaseWaitWidget := vpadding.New(
		hpadding.New(
			text.New(fmt.Sprintf("Please wait for %s", ctype)),
			gowid.HAlignMiddle{},
			gowid.RenderFixed{},
		),
		gowid.VAlignMiddle{},
		gowid.RenderFlow{},
	)

	cancelledWidget := text.New("Conversation load was cancelled.")

	res := &oneConvWidget{
		IWidget:          pleaseWaitWidget,
		ctype:            ctype,
		pleaseWaitWidget: pleaseWaitWidget,
		cancelledWidget:  cancelledWidget,
	}

	return res
}

//======================================================================

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
