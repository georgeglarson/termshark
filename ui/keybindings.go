// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"fmt"
	"strconv"

	"github.com/gcla/deep"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

func appKeysResize1(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		mainviewRows.AdjustOffset(2, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRows.AdjustOffset(2, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func appKeysResize2(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		mainviewRows.AdjustOffset(4, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRows.AdjustOffset(4, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview1ColsKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '>' {
		altview1Cols.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '<' {
		altview1Cols.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview1PileKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		altview1Pile.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		altview1Pile.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview2ColsKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '>' {
		altview2Cols.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '<' {
		altview2Cols.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview2PileKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		altview2Pile.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		altview2Pile.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func copyModeExitKeys(evk *tcell.EventKey, app gowid.IApp) bool {
	return copyModeExitKeysClipped(evk, 0, app)
}

// Used for limiting samples of reassembled streams
func copyModeExitKeys20(evk *tcell.EventKey, app gowid.IApp) bool {
	return copyModeExitKeysClipped(evk, 20, app)
}

func copyModeExitKeysClipped(evk *tcell.EventKey, copyLen int, app gowid.IApp) bool {
	handled := false
	if app.InCopyMode() {
		handled = true

		switch evk.Key() {
		case tcell.KeyRune:
			switch evk.Rune() {
			case 'q', 'c':
				app.InCopyMode(false)
			case '?':
				OpenTemplatedDialog(appView, "CopyModeHelp", app)
			}
		case tcell.KeyEscape:
			app.InCopyMode(false)
		case tcell.KeyCtrlC:
			processCopyChoices(copyLen, app)
		case tcell.KeyRight:
			cl := app.CopyModeClaimedAt()
			app.CopyModeClaimedAt(cl + 1)
			app.RefreshCopyMode()
		case tcell.KeyLeft:
			cl := app.CopyModeClaimedAt()
			if cl > 0 {
				app.CopyModeClaimedAt(cl - 1)
				app.RefreshCopyMode()
			}
		}
	}
	return handled
}

func copyModeEnterKeys(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	if !app.InCopyMode() {
		switch evk.Key() {
		case tcell.KeyRune:
			switch evk.Rune() {
			case 'c':
				app.InCopyMode(true)
				handled = true
			}
		}
	}
	return handled
}

func setFocusOnPacketList(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[0], app)
	gowid.SetFocusPath(altview1, altview1Paths[0], app)
	gowid.SetFocusPath(altview2, altview2Paths[0], app)
	gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
}

func setFocusOnPacketStruct(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[1], app)
	gowid.SetFocusPath(altview1, altview1Paths[1], app)
	gowid.SetFocusPath(altview2, altview2Paths[1], app)
	gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
}

func setFocusOnPacketHex(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[2], app)
	gowid.SetFocusPath(altview1, altview1Paths[2], app)
	gowid.SetFocusPath(altview2, altview2Paths[2], app)
	gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)
}

func setFocusOnDisplayFilter(app gowid.IApp) {
	gowid.SetFocusPath(mainview, filterPathMain, app)
	gowid.SetFocusPath(altview1, filterPathAlt, app)
	gowid.SetFocusPath(altview2, filterPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, filterPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, filterPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, filterPathMax, app)
}

func setFocusOnSearch(app gowid.IApp) {
	gowid.SetFocusPath(mainview, searchPathMain, app)
	gowid.SetFocusPath(altview1, searchPathAlt, app)
	gowid.SetFocusPath(altview2, searchPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, searchPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, searchPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, searchPathMax, app)
}

func clearOffsets(app gowid.IApp) {
	if mainViewNoKeys.SubWidget() == mainview {
		mainviewRows.SetOffsets([]resizable.Offset{}, app)
	} else if mainViewNoKeys.SubWidget() == altview1 {
		altview1Cols.SetOffsets([]resizable.Offset{}, app)
		altview1Pile.SetOffsets([]resizable.Offset{}, app)
	} else {
		altview2Cols.SetOffsets([]resizable.Offset{}, app)
		altview2Pile.SetOffsets([]resizable.Offset{}, app)
	}
}

func packetNumberFromCurrentTableRow() (termshark.JumpPos, error) {
	tablePos, err := packetListView.FocusXY() // e.g. table position 5
	if err != nil {
		return termshark.JumpPos{}, fmt.Errorf("No packet in focus: %w", err)
	}
	return packetNumberFromTableRow(tablePos.Row)
}

func tableRowFromPacketNumber(savedPacket int) (int, error) {
	// Map e.g. packet number #123 to the index in the PSML array - e.g. index 10 (order of psml load)
	packetRowId, ok := Loader.PacketNumberMap[savedPacket]
	if !ok {
		return -1, fmt.Errorf("Error finding packet %v", savedPacket)
	}
	// This psml order is also the table RowId order. The table might be sorted though, so
	// map this RowId to the actual table row, so we can change focus to it
	tableRow, ok := packetListView.InvertedModel().IdentifierToRow(table.RowId(packetRowId))
	if !ok {
		return -1, fmt.Errorf("Error looking up packet %v", packetRowId)
	}

	return tableRow, nil
}

func packetNumberFromTableRow(tableRow int) (termshark.JumpPos, error) {
	packetRowId, ok := packetListView.Model().RowIdentifier(tableRow)
	if !ok {
		return termshark.JumpPos{}, fmt.Errorf("Error looking up packet at row %v", tableRow)
	}

	// e.g. packet #123

	var summary string
	if len(Loader.PsmlData()) > int(packetRowId) {
		summary = psmlSummary(Loader.PsmlData()[packetRowId]).String()
	}

	if int(packetRowId) >= len(Loader.PsmlData()) {
		return termshark.JumpPos{}, fmt.Errorf("Packet %d is not loaded.", packetRowId)
	}

	packetNum, err := strconv.Atoi(Loader.PsmlData()[packetRowId][0])
	if err != nil {
		return termshark.JumpPos{}, fmt.Errorf("Unexpected error determining no. of packet %d: %w.", tableRow, err)
	}

	return termshark.JumpPos{
		Pos:     packetNum,
		Summary: summary,
	}, nil
}

func searchOpen() bool {
	return filterHolder.SubWidget() == filterWithSearch
}

func searchIsActive() bool {
	return stopCurrentSearch != nil
}

func searchPacketsMainView(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	if evk.Key() == tcell.KeyCtrlF {
		if !searchOpen() {
			filterHolder.SetSubWidget(filterWithSearch, app)
			setFocusOnSearch(app)
		} else {
			// If it's open and focus is on the text area for search, then close it
			if SearchWidget != nil && SearchWidget.FocusIsOnFilter() {
				filterHolder.SetSubWidget(filterWithoutSearch, app)
				// This seems to make the most sense
				setFocusOnPacketList(app)
			} else {
				// Otherwise, put focus on the text area. This provides for a quick
				// way to get control back on the search text area - ctrl-f will do it.
				// Closing search is then just two ctrl-f keypresses at most.
				setFocusOnSearch(app)
			}
		}
	} else {
		handled = false
	}

	return handled
}

// These only apply to the traditional wireshark-like main view
func vimKeysMainView(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	if evk.Key() == tcell.KeyCtrlW && keyState.PartialCtrlWCmd {
		cycleView(app, true, tabViewsForward)
	} else if evk.Key() == tcell.KeyRune && evk.Rune() == '=' && keyState.PartialCtrlWCmd {
		clearOffsets(app)
	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'a' && evk.Rune() <= 'z' && keyState.PartialmCmd {
		if packetListView != nil {
			tablePos, err := packetListView.FocusXY() // e.g. table position 5
			if err != nil {
				OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
			} else {
				jpos, err := packetNumberFromTableRow(tablePos.Row)
				if err != nil {
					OpenError(err.Error(), app)
				} else {
					setLocalMarkWithSync(evk.Rune(), jpos)
					OpenMessage(fmt.Sprintf("Local mark '%c' set to packet %v.", evk.Rune(), jpos.Pos), appView, app)
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'A' && evk.Rune() <= 'Z' && keyState.PartialmCmd {

		if Loader != nil {
			if Loader.Pcap() != "" {
				if packetListView != nil {
					tablePos, err := packetListView.FocusXY()
					if err != nil {
						OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
					} else {
						jpos, err := packetNumberFromTableRow(tablePos.Row)
						if err != nil {
							OpenError(err.Error(), app)
						} else {
							gpos := termshark.GlobalJumpPos{
								JumpPos:  jpos,
								Filename: Loader.Pcap(),
							}
							setGlobalMarkWithSync(evk.Rune(), gpos)
							termshark.SaveGlobalMarks(globalMarksMap)
							OpenMessage(fmt.Sprintf("Global mark '%c' set to packet %v.", evk.Rune(), jpos.Pos), appView, app)
						}
					}
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'a' && evk.Rune() <= 'z' && keyState.PartialQuoteCmd {
		if packetListView != nil {
			markedPacket, ok := marksMap[evk.Rune()]
			if ok {
				tableRow, err := tableRowFromPacketNumber(markedPacket.Pos)
				if err != nil {
					OpenError(err.Error(), app)
				} else {

					tableCol := 0
					curTablePos, err := packetListView.FocusXY()
					if err == nil {
						tableCol = curTablePos.Column
					}

					pn, _ := packetNumberFromCurrentTableRow() // save for ''
					setLastJumpPosWithSync(pn.Pos)

					packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'A' && evk.Rune() <= 'Z' && keyState.PartialQuoteCmd {
		markedPacket, ok := globalMarksMap[evk.Rune()]
		if !ok {
			OpenError("Mark not found.", app)
		} else {
			if Loader.Pcap() != markedPacket.Filename {
				MaybeKeepThenRequestLoadPcap(markedPacket.Filename, FilterWidget.Value(), markedPacket, app)
			} else {

				if packetListView != nil {
					tableRow, err := tableRowFromPacketNumber(markedPacket.Pos)
					if err != nil {
						OpenError(err.Error(), app)
					} else {

						tableCol := 0
						curTablePos, err := packetListView.FocusXY()
						if err == nil {
							tableCol = curTablePos.Column
						}

						pn, _ := packetNumberFromCurrentTableRow() // save for ''
						setLastJumpPosWithSync(pn.Pos)

						packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
					}
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() == '\'' && keyState.PartialQuoteCmd {
		if packetListView != nil {
			tablePos, err := packetListView.FocusXY()
			if err != nil {
				OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
			} else {
				// which packet number was saved as a mark
				savedPacket := lastJumpPos
				if savedPacket != -1 {
					// Map that packet number #123 to the index in the PSML array - e.g. index 10 (order of psml load)
					if packetRowId, ok := Loader.PacketNumberMap[savedPacket]; !ok {
						OpenError(fmt.Sprintf("Error finding packet %v", savedPacket), app)
					} else {
						// This psml order is also the table RowId order. The table might be sorted though, so
						// map this RowId to the actual table row, so we can change focus to it
						if tableRow, ok := packetListView.InvertedModel().IdentifierToRow(table.RowId(packetRowId)); !ok {
							OpenError(fmt.Sprintf("Error looking up packet %v", packetRowId), app)
						} else {
							pn, _ := packetNumberFromCurrentTableRow() // save for ''
							setLastJumpPosWithSync(pn.Pos)

							packetListView.SetFocusXY(app, table.Coords{Column: tablePos.Column, Row: tableRow})
						}
					}
				}
			}
		}

	} else {
		handled = false
	}

	return handled
}

func currentlyFocusedViewNotHex() bool {
	return currentlyFocusedViewNotByIndex(2)
}

func currentlyFocusedViewNotStruct() bool {
	return currentlyFocusedViewNotByIndex(1)
}

func currentlyFocusedViewNotByIndex(idx int) bool {
	if mainViewNoKeys.SubWidget() == mainview {
		v1p := gowid.FocusPath(mainview)
		if deep.Equal(v1p, mainviewPaths[idx]) != nil { // it's not hex
			return true
		}
	} else if mainViewNoKeys.SubWidget() == altview1 {
		v2p := gowid.FocusPath(altview1)
		if deep.Equal(v2p, altview1Paths[idx]) != nil { // it's not hex
			return true
		}
	} else { // altview2
		v3p := gowid.FocusPath(altview2)
		if deep.Equal(v3p, altview2Paths[idx]) != nil { // it's not hex
			return true
		}
	}
	return false
}

// Move focus among the packet list view, structure view and hex view
func cycleView(app gowid.IApp, forward bool, tabMap map[gowid.IWidget]gowid.IWidget) {
	if v, ok := tabMap[mainViewNoKeys.SubWidget()]; ok {
		mainViewNoKeys.SetSubWidget(v, app)
	}

	gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
	gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)

	if packetStructureViewHolder.SubWidget() == MissingMsgw {
		setFocusOnPacketList(app)
	} else {
		newidx := -1
		if mainViewNoKeys.SubWidget() == mainview {
			v1p := gowid.FocusPath(mainview)
			if deep.Equal(v1p, mainviewPaths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v1p, mainviewPaths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		} else if mainViewNoKeys.SubWidget() == altview1 {
			v2p := gowid.FocusPath(altview1)
			if deep.Equal(v2p, altview1Paths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v2p, altview1Paths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		} else if mainViewNoKeys.SubWidget() == altview2 {
			v3p := gowid.FocusPath(altview2)
			if deep.Equal(v3p, altview2Paths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v3p, altview2Paths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		}

		if newidx != -1 {
			// Keep the views in sync
			gowid.SetFocusPath(mainview, mainviewPaths[newidx], app)
			gowid.SetFocusPath(altview1, altview1Paths[newidx], app)
			gowid.SetFocusPath(altview2, altview2Paths[newidx], app)
		}
	}
}

// Keys for the main view - packet list, structure, etc
func mainKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	isrune := evk.Key() == tcell.KeyRune

	if scs := stopCurrentSearch; evk.Key() == tcell.KeyCtrlC && scs != nil {
		scs.RequestStop(app)
	} else if evk.Key() == tcell.KeyCtrlC && Loader.PsmlLoader.IsLoading() {
		Loader.StopLoadPsmlAndIface(NoHandlers{}) // iface and psml
	} else if evk.Key() == tcell.KeyTAB || evk.Key() == tcell.KeyBacktab {
		isTab := (evk.Key() == tcell.KeyTab)
		var tabMap map[gowid.IWidget]gowid.IWidget
		if isTab {
			tabMap = tabViewsForward
		} else {
			tabMap = tabViewsBackward
		}

		cycleView(app, isTab, tabMap)

	} else if isrune && evk.Rune() == '|' {
		if mainViewNoKeys.SubWidget() == mainview {
			mainViewNoKeys.SetSubWidget(altview1, app)
			profiles.SetConf("main.layout", "altview1")
		} else if mainViewNoKeys.SubWidget() == altview1 {
			mainViewNoKeys.SetSubWidget(altview2, app)
			profiles.SetConf("main.layout", "altview2")
		} else {
			mainViewNoKeys.SetSubWidget(mainview, app)
			profiles.SetConf("main.layout", "mainview")
		}
	} else if isrune && evk.Rune() == '\\' {
		w := mainViewNoKeys.SubWidget()
		fp := gowid.FocusPath(w)
		if w == viewOnlyPacketList || w == viewOnlyPacketStructure || w == viewOnlyPacketHex {
			switch profiles.ConfString("main.layout", "mainview") {
			case "altview1":
				mainViewNoKeys.SetSubWidget(altview1, app)
			case "altview2":
				mainViewNoKeys.SetSubWidget(altview2, app)
			default:
				mainViewNoKeys.SetSubWidget(mainview, app)
			}
			if deep.Equal(fp, maxViewPath) == nil {
				switch w {
				case viewOnlyPacketList:
					setFocusOnPacketList(app)
				case viewOnlyPacketStructure:
					setFocusOnPacketStruct(app)
				case viewOnlyPacketHex:
					setFocusOnPacketList(app)
				}
			}
		} else {
			gotov := 0
			if mainViewNoKeys.SubWidget() == mainview {
				v1p := gowid.FocusPath(mainview)
				if deep.Equal(v1p, mainviewPaths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v1p, mainviewPaths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			} else if mainViewNoKeys.SubWidget() == altview1 {
				v2p := gowid.FocusPath(altview1)
				if deep.Equal(v2p, altview1Paths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v2p, altview1Paths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			} else if mainViewNoKeys.SubWidget() == altview2 {
				v3p := gowid.FocusPath(altview2)
				if deep.Equal(v3p, altview2Paths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v3p, altview2Paths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			}

			switch gotov {
			case 0:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketList, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
				}
			case 1:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketStructure, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
				}
			case 2:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketHex, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)
				}
			}

		}
	} else if isrune && evk.Rune() == '/' {
		setFocusOnDisplayFilter(app)
	} else {
		handled = false
	}
	return handled
}

func focusOnMenuButton(app gowid.IApp) {
	gowid.SetFocusPath(mainview, menuPathMain, app)
	gowid.SetFocusPath(altview1, menuPathAlt, app)
	gowid.SetFocusPath(altview2, menuPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, menuPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, menuPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, menuPathMax, app)
}

func openGeneralMenu(app gowid.IApp) {
	focusOnMenuButton(app)
	multiMenu1Opener.OpenMenu(generalMenu, openMenuSite, app)
}

// Keys for the whole app, applicable whichever view is frontmost
func appKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	isrune := evk.Key() == tcell.KeyRune

	if evk.Key() == tcell.KeyCtrlC {
		reallyQuit(app)
	} else if evk.Key() == tcell.KeyCtrlL {
		app.Sync()
	} else if isrune && (evk.Rune() == 'q' || evk.Rune() == 'Q') {
		reallyQuit(app)
	} else if isrune && evk.Rune() == ':' {
		lastLineMode(app)
	} else if evk.Key() == tcell.KeyEscape {
		focusOnMenuButton(app)
	} else if isrune && evk.Rune() == '?' {
		OpenTemplatedDialog(appView, "UIHelp", app)
	} else if isrune && evk.Rune() == 'Z' && keyState.PartialZCmd {
		RequestQuit()
	} else if isrune && evk.Rune() == 'Z' {
		keyState.PartialZCmd = true
	} else if isrune && evk.Rune() == 'm' {
		keyState.PartialmCmd = true
	} else if isrune && evk.Rune() == '\'' {
		keyState.PartialQuoteCmd = true
	} else if isrune && evk.Rune() == 'g' {
		keyState.PartialgCmd = true
	} else if evk.Key() == tcell.KeyCtrlW {
		keyState.PartialCtrlWCmd = true
	} else if isrune && evk.Rune() >= '0' && evk.Rune() <= '9' {
		if keyState.NumberPrefix == -1 {
			keyState.NumberPrefix = int(evk.Rune() - '0')
		} else {
			keyState.NumberPrefix = (10 * keyState.NumberPrefix) + (int(evk.Rune() - '0'))
		}
	} else {
		handled = false
	}
	return handled
}

// don't claim the keypress
func ApplyAutoScroll(ev *tcell.EventKey, app gowid.IApp) bool {
	doit := false
	reenableAutoScroll = false
	switch ev.Key() {
	case tcell.KeyRune:
		if ev.Rune() == 'G' {
			doit = true
		}
	case tcell.KeyEnd:
		doit = true
	}
	if doit {
		if profiles.ConfBool("main.auto-scroll", true) {
			setAutoScrollWithSync(true)
			reenableAutoScroll = true // when packet updates come, helps
			// understand that AutoScroll should not be disabled again
		}
	}
	return false
}

//======================================================================

// prefixKeyWidget wraps a widget, and adjusts the state of the variables tracking
// "partial" key chords e.g. the first Z in ZZ, the first g in gg. It also resets
// the number prefix (which some commands use) - this is done if they key is not
// a number, and the last keypress wasn't the start of a key chord.
type prefixKeyWidget struct {
	gowid.IWidget
}

func (w *prefixKeyWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	// Save these first. If they are enabled now, any key should cancel them, so cancel
	// at the end.
	startingKeyState := keyState

	handled := w.IWidget.UserInput(ev, size, focus, app)
	switch ev := ev.(type) {
	case *tcell.EventKey:
		// If it was set this time around, whatever key was pressed resets it
		if startingKeyState.PartialgCmd {
			keyState.PartialgCmd = false
		}
		if startingKeyState.PartialZCmd {
			keyState.PartialZCmd = false
		}
		if startingKeyState.PartialCtrlWCmd {
			keyState.PartialCtrlWCmd = false
		}
		if startingKeyState.PartialmCmd {
			keyState.PartialmCmd = false
		}
		if startingKeyState.PartialQuoteCmd {
			keyState.PartialQuoteCmd = false
		}

		if ev.Key() != tcell.KeyRune || ev.Rune() < '0' || ev.Rune() > '9' {
			if !keyState.PartialZCmd && !keyState.PartialgCmd && !keyState.PartialCtrlWCmd {
				keyState.NumberPrefix = -1
			}
		}

	}
	return handled
}
