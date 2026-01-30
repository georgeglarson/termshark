// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"encoding/xml"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gcla/deep"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/pkg/noroot"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetree"
	"github.com/gcla/termshark/v2/widgets/enableselected"
	"github.com/gcla/termshark/v2/widgets/expander"
	"github.com/gcla/termshark/v2/widgets/hexdumper2"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	"github.com/gdamore/tcell/v2"
	log "github.com/sirupsen/logrus"
)

//======================================================================

// run in app goroutine
func clearPacketViews(app gowid.IApp) {
	packetHexWidgets.Purge()

	packetListViewHolder.SetSubWidget(nullw, app)
	packetStructureViewHolder.SetSubWidget(nullw, app)
	packetHexViewHolder.SetSubWidget(nullw, app)
}

//======================================================================

// rememberSelected, when rendered, will save whether or not the selected flag was set.
// Another widget (deeper in the hierarchy) can then consult it to see whether it should
// render differently as the grandchild of a selected widget.
type rememberSelected struct {
	gowid.IWidget
	selectedThisTime bool
}

type iWasSelected interface {
	WasSelected() bool
}

func (w *rememberSelected) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	w.selectedThisTime = focus.Selected
	return w.IWidget.Render(size, focus, app)
}

func (w *rememberSelected) WasSelected() bool {
	return w.selectedThisTime
}

// selectIf sets the selected flag on its child if its iWasSelected type returns true
type selectIf struct {
	gowid.IWidget
	iWasSelected
}

func (w *selectIf) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if w.iWasSelected.WasSelected() {
		focus = focus.SelectIf(true)
	}
	return w.IWidget.Render(size, focus, app)
}

//======================================================================

// Construct decoration around the tree node widget - a button to collapse, etc.
func makeStructNodeDecoration(pos tree.IPos, tr tree.IModel, wmaker tree.IWidgetMaker) gowid.IWidget {
	var res gowid.IWidget
	if tr == nil {
		return nil
	}
	// Note that level should never end up < 0

	// We know our tree widget will never display the root node, so everything will be indented at
	// least one level. So we know this will never end up negative.
	level := -2
	for cur := pos; cur != nil; cur = tree.ParentPosition(cur) {
		level += 1
	}
	if level < 0 {
		panic(gowid.WithKVs(termshark.BadState, map[string]interface{}{"level": level}))
	}

	pad := strings.Repeat(" ", level*2)
	cwidgets := make([]gowid.IContainerWidget, 0)
	cwidgets = append(cwidgets,
		&gowid.ContainerWidget{
			IWidget: text.New(pad),
			D:       units(len(pad)),
		},
	)

	ct, ok := tr.(*pdmltree.Model)
	if !ok {
		panic(gowid.WithKVs(termshark.BadState, map[string]interface{}{"tree": tr}))
	}

	// Create an empty one here because the selectIf widget needs to have a pointer
	// to it, and it's constructed below as a child.
	rememberSel := &rememberSelected{}

	inner := wmaker.MakeWidget(pos, tr)
	inner = &selectIf{
		IWidget:      inner,
		iWasSelected: rememberSel,
	}

	if ct.HasChildren() {

		var bn *button.Widget
		if ct.IsCollapsed() {
			bn = button.NewAlt(text.New("+"))
		} else {
			bn = button.NewAlt(text.New("-"))
		}

		// If I use one button with conditional logic in the callback, rather than make
		// a separate button depending on whether or not the tree is collapsed, it will
		// correctly work when the DecoratorMaker is caching the widgets i.e. it will
		// collapse or expand even when the widget is rendered from the cache
		bn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
			// Run this outside current event loop because we are implicitly
			// adjusting the data structure behind the list walker, and it's
			// not prepared to handle that in the same pass of processing
			// UserInput. TODO.
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ct.SetCollapsed(app, !ct.IsCollapsed())
			}))
		}))

		expandContractKeys := appkeys.New(
			bn,
			func(ev *tcell.EventKey, app gowid.IApp) bool {
				handled := false
				switch ev.Key() {
				case tcell.KeyLeft:
					if !ct.IsCollapsed() {
						ct.SetCollapsed(app, true)
						handled = true
					}
				case tcell.KeyRight:
					if ct.IsCollapsed() {
						ct.SetCollapsed(app, false)
						handled = true
					}
				}
				return handled
			},
		)

		cwidgets = append(cwidgets,
			&gowid.ContainerWidget{
				IWidget: expandContractKeys,
				D:       fixed,
			},
			&gowid.ContainerWidget{
				IWidget: fillSpace,
				D:       units(1),
			},
		)
	} else {
		// Lines without an expander are just text - so you can't cursor down on to them unless you
		// make them selectable (because the list will jump over them)
		inner = selectable.New(inner)

		cwidgets = append(cwidgets,
			&gowid.ContainerWidget{
				IWidget: fillSpace,
				D:       units(4),
			},
		)

	}

	cwidgets = append(cwidgets, &gowid.ContainerWidget{
		IWidget: inner,
		D:       weight(1),
	})

	res = columns.New(cwidgets)

	rememberSel.IWidget = res

	res = expander.New(
		isselected.New(
			rememberSel,
			styled.New(rememberSel, gowid.MakePaletteRef("packet-struct-selected")),
			styled.New(rememberSel, gowid.MakePaletteRef("packet-struct-focus")),
		),
	)

	return res
}

//======================================================================

// The widget representing the data at this level in the tree. Simply use what we extract from
// the PDML.
func makeStructNodeWidget(pos tree.IPos, tr tree.IModel) gowid.IWidget {
	pdmlMenuButton := button.NewBare(text.New("[=]"))
	pdmlMenuButtonSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	pdmlMenuButton.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		curColumnFilter = tr.(*pdmltree.Model).Name
		curColumnFilterValue = tr.(*pdmltree.Model).Show
		curColumnFilterName = tr.(*pdmltree.Model).UiName
		pdmlFilterMenu := makePdmlFilterMenu(curColumnFilter, curColumnFilterValue)
		multiMenu1Opener.OpenMenu(pdmlFilterMenu, pdmlMenuButtonSite, app)
	}))

	styledButton1 := styled.New(pdmlMenuButton, gowid.MakePaletteRef("packet-struct-selected"))
	styledButton2 := styled.New(
		pdmlMenuButton,
		gowid.MakeStyledAs(gowid.StyleBold),
	)

	structText := text.New(tr.Leaf())

	structIfNotSel := columns.NewFixed(structText)
	structIfSel := columns.NewFixed(structText, colSpace, pdmlMenuButtonSite, styledButton1)
	structIfFocus := columns.NewFixed(structText, colSpace, pdmlMenuButtonSite, styledButton2)

	return selectable.New(isselected.New(structIfNotSel, structIfSel, structIfFocus))
}

//======================================================================

func getCurrentStructModel(row int) *pdmltree.Model {
	return getCurrentStructModelWith(row, Loader.PsmlLoader)
}

// getCurrentStructModelWith will return a termshark model of a packet section of PDML given a row number,
// or nil if there is no model for the given row.
func getCurrentStructModelWith(row int, lock sync.Locker) *pdmltree.Model {
	var res *pdmltree.Model

	pktsPerLoad := Loader.PacketsPerLoad()
	row2 := (row / pktsPerLoad) * pktsPerLoad

	lock.Lock()
	defer lock.Unlock()
	if ws, ok := Loader.PacketCache.Get(row2); ok {
		srca := ws.(pcap.CacheEntry).Pdml
		if len(srca) > row%pktsPerLoad {
			data, err := xml.Marshal(srca[row%pktsPerLoad].Packet())
			if err != nil {
				log.Fatal(err)
			}

			res = pdmltree.DecodePacket(data)
		}
	}

	return res
}

//======================================================================

// setLowerWidgets will set the packet structure and packet hex views, if there
// is suitable data to display. If not, they are left as-is.
func setLowerWidgets(app gowid.IApp) {
	var sw1 gowid.IWidget
	var sw2 gowid.IWidget
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			row2, _ := packetListView.Model().RowIdentifier(fxy.Row)
			row := int(row2)

			hex := getHexWidgetToDisplay(row)
			if hex != nil {
				sw1 = enableselected.New(
					withscrollbar.New(
						hex,
						withscrollbar.Options{
							HideIfContentFits: true,
						},
					),
				)
			}

			str := getStructWidgetToDisplay(row, app)
			if str != nil {
				sw2 = enableselected.New(str)
			}
		}
	}
	if sw1 != nil {
		packetHexViewHolder.SetSubWidget(sw1, app)
		StopEmptyHexViewTimer()
	} else {
		// If autoscroll is on, it's annoying to see the constant loading message, so
		// suppress and just remain on the last displayed hex
		timer := false
		if AutoScroll {
			// Only displaying loading if the current panel is blank. If it's data, leave the data
			if packetHexViewHolder.SubWidget() == nullw {
				timer = true
			}
		} else {
			if packetHexViewHolder.SubWidget() != MissingMsgw {
				timer = true
			}
		}

		if timer {
			if EmptyHexViewTimer == nil {
				EmptyHexViewTimer = time.AfterFunc(time.Duration(1000)*time.Millisecond, func() {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						singlePacketViewMsgHolder.SetSubWidget(Loadingw, app)
						packetHexViewHolder.SetSubWidget(MissingMsgw, app)
					}))
				})
			}
		}
	}
	if sw2 != nil {
		packetStructureViewHolder.SetSubWidget(sw2, app)
		StopEmptyStructViewTimer()
	} else {
		timer := false
		if AutoScroll {
			if packetStructureViewHolder.SubWidget() == nullw {
				timer = true
			}
		} else {
			if packetStructureViewHolder.SubWidget() != MissingMsgw {
				timer = true
			}
		}

		// If autoscroll is on, it's annoying to see the constant loading message, so
		// suppress and just remain on the last displayed hex
		if timer {
			if EmptyStructViewTimer == nil {
				EmptyStructViewTimer = time.AfterFunc(time.Duration(1000)*time.Millisecond, func() {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						singlePacketViewMsgHolder.SetSubWidget(Loadingw, app)
						packetStructureViewHolder.SetSubWidget(MissingMsgw, app)
					}))
				})
			}
		}
	}

}

//======================================================================

func expandStructWidgetAtPosition(row int, pos int, app gowid.IApp) {
	if curPacketStructWidget != nil {
		walker := curPacketStructWidget.Walker().(*noroot.Walker)
		curTree := walker.Tree().(*pdmltree.Model)

		finalPos := make([]int, 0)

		// hack accounts for the fact we always skip the first two nodes in the pdml tree but
		// only at the first level
		hack := 1
	Out:
		for {
			chosenIdx := -1
			var chosenTree *pdmltree.Model
			for i, ch := range curTree.Children_[hack:] {
				// Save the current best one - but keep going. The pdml does not necessarily present them sorted
				// by position. So we might need to skip one to find the best fit.
				if ch.Pos <= pos && pos < ch.Pos+ch.Size {
					chosenTree = ch
					chosenIdx = i
				}
			}
			if chosenTree != nil {
				chosenTree.SetCollapsed(app, false)
				finalPos = append(finalPos, chosenIdx+hack)
				curTree = chosenTree
				hack = 0
			} else {
				// didn't find any
				break Out
			}
		}
		if len(finalPos) > 0 {
			curStructPosition = tree.NewPosExt(finalPos)
			// this is to account for the fact that noRootWalker returns the next widget
			// in the tree. Whatever position we find, we need to go back one to make up for this.
			walker.SetFocus(curStructPosition, app)

			curPacketStructWidget.GoToMiddle(app)
			curStructWidgetState = curPacketStructWidget.State()

			updateCurrentPdmlPosition(walker.Tree())
		}
	}
}

func updateCurrentPdmlPosition(tr tree.IModel) {
	updateCurrentPdmlPositionFrom(tr, curStructPosition)
}

func updateCurrentPdmlPositionFrom(tr tree.IModel, pos tree.IPos) {
	treeAtCurPos := pos.GetSubStructure(tr)
	// Save [/, tcp, tcp.srcport] - so we can apply if user moves in packet list
	curPdmlPosition = treeAtCurPos.(*pdmltree.Model).PathToRoot()
}

func getLayersFromStructWidget(row int, pos int) []hexdumper2.LayerStyler {
	layers := make([]hexdumper2.LayerStyler, 0)

	model := getCurrentStructModel(row)
	if model != nil {
		layers = model.HexLayers(pos, false)
	}

	return layers
}

func getHexWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("p%d", row))
}

// Can return nil
func getHexWidgetToDisplay(row int) *hexdumper2.Widget {
	var res2 *hexdumper2.Widget

	if val, ok := packetHexWidgets.Get(row); ok {
		res2 = val.(*hexdumper2.Widget)
	} else {
		pktsPerLoad := Loader.PacketsPerLoad()

		row2 := (row / pktsPerLoad) * pktsPerLoad
		if ws, ok := Loader.PacketCache.Get(row2); ok {
			srca := ws.(pcap.CacheEntry).Pcap
			if len(srca) > row%pktsPerLoad {
				src := srca[row%pktsPerLoad]
				b := slices.Clone(src)

				layers := getLayersFromStructWidget(row, 0)
				res2 = hexdumper2.New(b, hexdumper2.Options{
					StyledLayers:      layers,
					CursorUnselected:  "hex-byte-unselected",
					CursorSelected:    "hex-byte-selected",
					LineNumUnselected: "hex-interval-unselected",
					LineNumSelected:   "hex-interval-selected",
					PaletteIfCopying:  "copy-mode",
				})

				// If the user moves the cursor in the hexdump, this callback will adjust the corresponding
				// pdml tree/struct widget's currently selected layer. That in turn will result in a callback
				// to the hex widget to set the active layers.
				res2.OnPositionChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, target gowid.IWidget) {
					// If we're not focused on hex, then don't expand the struct widget. That's because if
					// we're focused on struct, then changing the struct position causes a callback to the
					// hex to update layers - which can update the hex position - which invokes a callback
					// to change the struct again. So ultimately, moving the struct moves the hex position
					// which moves the struct and causes the struct to jump around. I need to check
					// the alt view too because the user can click with the mouse and in one view have
					// struct selected but in the other view have hex selected.

					// Propagate the adjustments to pane positions if:
					// - this was initiated from a non-struct pane e.g. the hex pane. Then we update struct
					// - this was via an override e.g. search for packet bytes. Then hex is updated on match
					//   which should then update the struct view
					if currentlyFocusedViewNotStruct() || allowHexToStructRepositioning {
						expandStructWidgetAtPosition(row, res2.Position(), app)
					}

					// Ensure the behavior is reset after this callback runs. Just do it once.
					allowHexToStructRepositioning = false
				}))

				packetHexWidgets.Add(row, res2)
			}
		}
	}
	return res2
}

//======================================================================

// pdmlFilterActor closes the menus opened via the PDML struct view, then
// either applies or preps the appropriate display filter
type pdmlFilterActor struct {
	filter  string
	prepare bool
	menu1   *menu.Widget
	menu2   *menu.Widget
}

var _ iFilterMenuActor = (*pdmlFilterActor)(nil)

func (p *pdmlFilterActor) HandleFilterMenuSelection(comb FilterCombinator, app gowid.IApp) {
	multiMenu2Opener.CloseMenu(p.menu2, app)
	multiMenu1Opener.CloseMenu(p.menu1, app)

	filter := ComputeFilterCombOp(comb, p.filter, FilterWidget.Value())

	FilterWidget.SetValue(filter, app)

	if p.prepare {
		// Don't run the filter, just add to the displayfilter widget. Leave focus there
		setFocusOnDisplayFilter(app)
	} else {
		RequestNewFilter(filter, app)
	}

}

//======================================================================

func getStructWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("s%d", row))
}

// Note - hex can be nil
// Note - returns nil if one can't be found
func getStructWidgetToDisplay(row int, app gowid.IApp) gowid.IWidget {
	var res gowid.IWidget

	model := getCurrentStructModel(row)
	if model != nil {

		// Apply expanded paths from previous packet
		model.ApplyExpandedPaths(&curExpandedStructNodes)
		model.Expanded = true

		var pos tree.IPos = tree.NewPos()
		pos = tree.NextPosition(pos, model) // Start ahead by one, then never go back

		rwalker := tree.NewWalker(model, pos,
			tree.NewCachingMaker(tree.WidgetMakerFunction(makeStructNodeWidget)),
			tree.NewCachingDecorator(tree.DecoratorFunction(makeStructNodeDecoration)))
		// Without the caching layer, clicking on a button has no effect
		walker := noroot.NewWalker(rwalker)

		// Send the layers represents the tree expansion to hex.
		// This could be the user clicking inside the tree. Or it might be the position changing
		// in the hex widget, resulting in a callback to programmatically change the tree expansion,
		// which then calls back to the hex
		updateHex := func(app gowid.IApp, doCursor bool, twalker tree.ITreeWalker) {

			newhex := getHexWidgetToDisplay(row)
			if newhex != nil {

				newtree := twalker.Tree().(*pdmltree.Model)
				newpos := twalker.Focus().(tree.IPos)

				expTree := (*pdmltree.ExpandedModel)(twalker.Tree().(*pdmltree.Model))

				leaf := newpos.GetSubStructure(expTree).(*pdmltree.ExpandedModel)

				coverWholePacket := false

				// This skips the "frame" node in the pdml that covers the entire range of bytes. If newpos
				// is [0] then the user has chosen that node by interacting with the struct view (the hex view
				// can't choose any position that maps to the first pdml child node) - so in this case, we
				// send back a layer spanning the entire packet. Otherwise we don't want to send back that
				// packet-spanning layer because it will always be the layer returned, meaning the hexdumper2
				// will always show the entire packet highlighted.
				if newpos.Equal(tree.NewPosExt([]int{0})) {
					coverWholePacket = true
				}

				newLayers := newtree.HexLayers(leaf.Pos, coverWholePacket)
				if len(newLayers) > 0 {
					newhex.SetLayers(newLayers, app)

					// If the hex view is changed by the user (or SetPosition), which then causes a callback to update
					// the struct view - which then causes a callback to update the hex layer - the cursor can move in
					// such a way it stays inside a valid layer and can't get outside. This boolean controls that
					if doCursor {
						curhexpos := newhex.Position()
						smallestlayer := newLayers[len(newLayers)-1]

						if !(smallestlayer.Start <= curhexpos && curhexpos < smallestlayer.End) {
							// The reason for this is to ensure the hex cursor moves according to the current struct
							// layer - otherwise when you tab to the hex layer, you immediately lose your struct layer
							// when you move the cursor - because it's outside of your struct context.
							newhex.SetPosition(smallestlayer.Start, app)
						}
					}
				}
			}

		}

		tb := copymodetree.New(tree.New(walker), copyModePalette{})
		res = tb
		// Save this in case the hex layer needs to change it

		curPacketStructWidget = tb

		// If not nil, it means we're re-rendering this part of the UI because of a hit in a packet
		// struct search. So set the struct position, and then the next block of code will adjust the
		// UI to focus on the part of the struct that matched the search.
		if curSearchPosition != nil {
			curStructPosition = curSearchPosition
		}

		if curStructPosition != nil {
			// if not nil, it means the user has interacted with some struct widget at least once causing
			// a focus change. We track the current focus e.g. [0, 2, 1] - the indices through the tree leading
			// to the focused item. We programmatically adjust the focus widget of the new struct (e.g. after
			// navigating down one in the packet list), but only if we can move focus to the same PDML field
			// as the old struct. For example, if we are on tcp.srcport in the old packet, and we can
			// open up tcp.srcport in the new packet, then we do so. This is not perfect, because I use the old
			// pdml tree position, which is a sequence of integer indices. This means if the next packet has
			// an extra layer before TCP, say some encapsulation, then I could still open up tcp.srcport, but
			// I don't find it because I find the candidate focus widget using the list of integer indices.

			curPos := curStructPosition // e.g. [0, 2, 1]
			expTree := (*pdmltree.ExpandedModel)(walker.Tree().(*pdmltree.Model))
			treeAtCurPos := curPos.GetSubStructure(expTree) // e.g. the TCP *pdmltree.Model
			if treeAtCurPos != nil {
				// If curSearchPosition != nil, it means out saved path will definitely be a hit in this
				// struct, so we are guaranteed to be able to apply it to the current tree walker. If
				// curSearchPosition == nil, it means we try our best to apply the previous position to
				// the current struct, knowing that the packet structure might be different.
				if curSearchPosition != nil || deep.Equal(curPdmlPosition, (*pdmltree.Model)(treeAtCurPos.(*pdmltree.ExpandedModel)).PathToRoot()) == nil {
					// if the newly selected struct has a node at [0, 2, 1] and it maps to tcp.srcport via the same path,
					// set the focus widget of the new struct i.e. which leaf has focus
					walker.SetFocus(curPos, app)

					if curStructWidgetState != nil {
						// we scrolled the previous struct a bit, apply it to the new one too
						tb.SetState(curStructWidgetState, app)
					} else {
						// First change by the user, so remember it and use it when navigating to the next
						curStructWidgetState = tb.State()
					}
				}
			}

		} else {
			curStructPosition = walker.Focus().(tree.IPos)
		}

		if curSearchPosition != nil {
			curPacketStructWidget.GoToMiddle(app)
			// Reset so as we move up and down, after a search, we do our best to preserve the
			// position, but we're not misled into thinking we have a guaranteed hit on the position.
			curSearchPosition = nil
		}

		tb.OnFocusChanged(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			curStructWidgetState = tb.State()
		})))

		walker.OnFocusChanged(tree.MakeCallback("cb", func(app gowid.IApp, twalker tree.ITreeWalker) {
			updateHex(app, currentlyFocusedViewNotHex(), twalker)

			// need to save the position, so it can be applied to the next struct widget
			// if brought into focus by packet list navigation
			curStructPosition = walker.Focus().(tree.IPos)

			updateCurrentPdmlPosition(walker.Tree())
		}))
	}
	return res
}

//======================================================================

type copyModePalette struct{}

var _ gowid.IClipboardSelected = copyModePalette{}

func (r copyModePalette) AlterWidget(w gowid.IWidget, app gowid.IApp) gowid.IWidget {
	return styled.New(w, gowid.MakePaletteRef("copy-mode"),
		styled.Options{
			OverWrite: true,
		},
	)
}
