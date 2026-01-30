// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/disable"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/progress"
	"github.com/gcla/gowid/widgets/spinner"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/app"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/pkg/theme"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gcla/termshark/v2/widgets"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetree"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/ifwidget"
	"github.com/gcla/termshark/v2/widgets/mapkeys"
	"github.com/gcla/termshark/v2/widgets/minibuffer"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/gcla/termshark/v2/widgets/rossshark"
	"github.com/gcla/termshark/v2/widgets/search"
	"github.com/gdamore/tcell/v2"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//======================================================================

type WidgetOwner int

const (
	NoOwner WidgetOwner = iota
	LoaderOwns
	SearchOwns
)

// Global so that we can change the displayed packet in the struct view, etc
// test
var appViewNoKeys *holder.Widget
var appView *holder.Widget
var mbView *holder.Widget
var mainViewNoKeys *holder.Widget
var mainView *appkeys.KeyWidget
var pleaseWaitSpinner *spinner.Widget
var mainviewRows *resizable.PileWidget
var mainview gowid.IWidget
var altview1 gowid.IWidget
var altview1OuterRows *resizable.PileWidget
var altview1Pile *resizable.PileWidget
var altview1Cols *resizable.ColumnsWidget
var altview2 gowid.IWidget
var altview2OuterRows *resizable.PileWidget
var altview2Pile *resizable.PileWidget
var altview2Cols *resizable.ColumnsWidget
var viewOnlyPacketList *pile.Widget
var viewOnlyPacketStructure *pile.Widget
var viewOnlyPacketHex *pile.Widget
var filterCols *columns.Widget
var loadProg *columns.Widget
var loadStop *button.Widget
var searchProg *columns.Widget
var searchStop *button.Widget
var progWidgetIdx int
var mainviewPaths [][]interface{}
var altview1Paths [][]interface{}
var altview2Paths [][]interface{}
var maxViewPath []interface{}
var filterPathMain []interface{}
var filterPathAlt []interface{}
var filterPathMax []interface{}
var searchPathMain []interface{}
var searchPathAlt []interface{}
var searchPathMax []interface{}
var menuPathMain []interface{}
var menuPathAlt []interface{}
var menuPathMax []interface{}
var view1idx int
var view2idx int
var generalMenu *menu.Widget
var analysisMenu *menu.Widget
var savedMenu *menu.Widget
var profileMenu *menu.Widget
var FilterWidget *filter.Widget
var Fin *rossshark.Widget
var CopyModeWidget gowid.IWidget
var CopyModePredicate ifwidget.Predicate
var openMenuSite *menu.SiteWidget
var openAnalysisSite *menu.SiteWidget
var packetListViewHolder *holder.Widget
var packetListTable *table.BoundedWidget
var packetStructureViewHolder *holder.Widget
var packetHexViewHolder *holder.Widget
var progressHolder *holder.Widget
var progressOwner WidgetOwner
var stopCurrentSearch search.IRequestStop
var loadProgress *progress.Widget
var loadSpinner *spinner.Widget
var savedListBoxWidgetHolder *holder.Widget
var singlePacketViewMsgHolder *holder.Widget // either empty or "loading..."
var keyMapper *mapkeys.Widget

// For deconstructing the @showname PDML attribute into a short form for the UI
var shownameRe = regexp.MustCompile(`(.*?= )?([^:]+)`)

type MenuHolder struct {
	gowid.IMenuCompatible
}

var multiMenu *MenuHolder = &MenuHolder{}
var multiMenuWidget *holder.Widget
var multiMenu2 *MenuHolder = &MenuHolder{}
var multiMenu2Widget *holder.Widget
var multiMenu1Opener MultiMenuOpener
var multiMenu2Opener MultiMenuOpener

var tabViewsForward map[gowid.IWidget]gowid.IWidget
var tabViewsBackward map[gowid.IWidget]gowid.IWidget

var currentProfile *text.Widget
var currentProfileWidget *columns.Widget
var currentProfileWidgetHolder *holder.Widget
var openProfileSite *menu.SiteWidget

var currentCapture *text.Widget
var currentCaptureWidget *columns.Widget
var currentCaptureWidgetHolder *holder.Widget

var nullw *null.Widget // empty
var fillSpace *fill.Widget
var fillVBar *fill.Widget
var colSpace *gowid.ContainerWidget

var curPacketStructWidget *copymodetree.Widget
var packetHexWidgets *lru.Cache
var packetListView *psmlTableRowWidget

// Usually false. When the user moves the cursor in the hex widget, a callback will update the
// struct widget's current expansion. That results in a callback to the current hex widget to
// update its position - ad inf. The hex widget callback checks to see whether or not the hex
// widget has "focus". If it doesn't, the callback is suppressed - to short circuit the callback
// loop. BUT - after a packet search, we reposition the hex widget and want the callback from
// hex to struct to happen once. So this is a workaround to allow it in that case.
//
// This variable has two effects:
// - when the hex widget is positioned programmatically, and focus is not on the hex widget,
//   the struct widget is nevertheless updated accordingly
// - but when the struct widget is updated, if the innermost layer does not capture the
//   current hex location (the search destination), DON'T update the hex position to be
//   inside the PDML's innermost layer, which maybe somewhere else in the packet.
//
var allowHexToStructRepositioning bool

var filterWithSearch gowid.IWidget
var filterWithoutSearch gowid.IWidget
var filterHolder *holder.Widget
var SearchWidget *search.Widget

var Loadingw gowid.IWidget    // "loading..."
var MissingMsgw gowid.IWidget // centered, holding singlePacketViewMsgHolder
var EmptyStructViewTimer *time.Timer
var EmptyHexViewTimer *time.Timer

var curSearchPosition tree.IPos                   // e.g. [0, 4] -> the indices of the struct layer
var curExpandedStructNodes pdmltree.ExpandedPaths // a path to each expanded node in the packet, preserved while navigating
var curStructPosition tree.IPos                   // e.g. [0, 2, 1] -> the indices of the expanded nodes
var curPdmlPosition []string                      // e.g. [ , tcp, tcp.srcport ] -> the path from focus to root in the current struct
var curStructWidgetState interface{}              // e.g. {linesFromTop: 1, ...} -> the positioning of the current struct widget
var curColumnFilter string                        // e.g. tcp.port - updated as the user moves through the struct widget
var curColumnFilterName string                    // e.g. "TCP port" - from the showname attribute in the PDML
var curColumnFilterValue string                   // e.g. "80" - from the show attribute

var CacheRequests []pcap.LoadPcapSlice

var CacheRequestsChan chan struct{} // false means started, true means finished
var QuitRequestedChan chan struct{}
var StartUIChan chan struct{}
var StartUIOnce sync.Once

// Store this for vim-like keypresses that are a sequence e.g. "ZZ"
var keyState termshark.KeyState
var marksMap map[rune]termshark.JumpPos
var globalMarksMap map[rune]termshark.GlobalJumpPos
var lastJumpPos int

var NoGlobalJump termshark.GlobalJumpPos // leave as default, like a placeholder

var Loader *pcap.PacketLoader
var FieldCompleter *fields.TSharkFields // share this - safe once constructed
var AppController *app.Controller       // Application controller for business logic

var WriteToSelected bool       // true if the user provided the -w flag
var WriteToDeleted bool        // true if the user deleted the temporary pcap before quitting
var DarkMode bool              // global state in app
var PacketColors bool          // global state in app
var PacketColorsSupported bool // global state in app - true if it's even possible
var AutoScroll bool            // true if the packet list should auto-scroll when listening on an interface.
var newPacketsArrived bool     // true if current updates are due to new packets when listening on an interface.
var reenableAutoScroll bool    // set to true by keypress processing widgets - used with newPacketsArrived
var Running bool               // true if gowid/tcell is controlling the terminal
var QuitRequested bool         // true if a quit has been issued, but not yet processed. Stops some handlers displaying errors.

//======================================================================

func init() {
	curExpandedStructNodes = make(pdmltree.ExpandedPaths, 0, 20)
	QuitRequestedChan = make(chan struct{}, 1) // buffered because send happens from ui goroutine, which runs global select
	CacheRequestsChan = make(chan struct{}, 1000)
	CacheRequests = make([]pcap.LoadPcapSlice, 0)
	// Buffered because I might send something in this goroutine
	StartUIChan = make(chan struct{}, 1)
	keyState.NumberPrefix = -1 // 0 might be meaningful
	marksMap = make(map[rune]termshark.JumpPos)
	globalMarksMap = make(map[rune]termshark.GlobalJumpPos)
	lastJumpPos = -1

	// Initialize the application controller
	AppController = app.NewController()

	EnsureTemplateData()
	TemplateData["Marks"] = marksMap
	TemplateData["GlobalMarks"] = globalMarksMap
	TemplateData["Maps"] = getMappings{}
}

type globalJump struct {
	file string
	pos  int
}

type getMappings struct{}

func (g getMappings) Get() []termshark.KeyMapping {
	return termshark.LoadKeyMappings()
}

func (g getMappings) None() bool {
	return len(termshark.LoadKeyMappings()) == 0
}

//======================================================================
// Mark synchronization helpers - bridge between old global maps and Controller
//======================================================================

// setLocalMarkWithSync sets a local mark in both the old marksMap and the Controller.
func setLocalMarkWithSync(mark rune, jpos termshark.JumpPos) {
	marksMap[mark] = jpos
	AppController.State.SetLocalMark(mark, app.MarkPosition{
		Summary: jpos.Summary,
		Pos:     jpos.Pos,
	})
}

// setGlobalMarkWithSync sets a global mark in both the old globalMarksMap and the Controller.
func setGlobalMarkWithSync(mark rune, gpos termshark.GlobalJumpPos) {
	globalMarksMap[mark] = gpos
	AppController.State.SetGlobalMark(mark, app.GlobalMarkPosition{
		MarkPosition: app.MarkPosition{
			Summary: gpos.Summary,
			Pos:     gpos.Pos,
		},
		Filename: gpos.Filename,
	})
}

// setLastJumpPosWithSync sets the last jump position in both lastJumpPos and the Controller.
func setLastJumpPosWithSync(pos int) {
	lastJumpPos = pos
	AppController.State.SetLastJumpPos(pos)
}

// syncControllerPcap updates the Controller with the current pcap path.
func syncControllerPcap() {
	if Loader != nil {
		AppController.State.SetCurrentPcap(Loader.Pcap())
	}
}

// setAutoScrollWithSync sets the AutoScroll state in both the global var and the Controller.
func setAutoScrollWithSync(enabled bool) {
	AutoScroll = enabled
	if UI != nil && UI.App != nil {
		UI.App.AutoScroll = enabled
	}
	AppController.State.SetAutoScroll(enabled)
}

// setDarkModeWithSync sets the DarkMode state in both the global var and the Controller.
func setDarkModeWithSync(enabled bool) {
	DarkMode = enabled
	if UI != nil && UI.App != nil {
		UI.App.DarkMode = enabled
	}
	AppController.State.SetDarkMode(enabled)
}

// setPacketColorsWithSync sets the PacketColors state in both the global var and the Controller.
func setPacketColorsWithSync(enabled bool) {
	PacketColors = enabled
	if UI != nil && UI.App != nil {
		UI.App.PacketColors = enabled
	}
	AppController.State.SetPacketColors(enabled)
}

//======================================================================
// calculateAndSyncPrefetchRequests uses the Controller's prefetch algorithm and syncs
// with the CacheRequests global for backward compatibility.
func calculateAndSyncPrefetchRequests(currentRow, pktsPerLoad int) {
	// Use the app package's pure prefetch algorithm
	requests := app.CalculatePrefetchRequests(currentRow, pktsPerLoad)

	// Build the cache requests slice
	cacheReqs := make([]pcap.LoadPcapSlice, 0, len(requests))
	for _, req := range requests {
		cacheReqs = append(cacheReqs, req.ToLoadPcapSlice())
	}
	// Use SetCacheRequests to update both global and UI.Channels.CacheRequests
	SetCacheRequests(cacheReqs)

	// Also update the Controller's pending requests
	AppController.State.ClearPendingRequests()
	for _, req := range requests {
		AppController.State.AddPendingRequest(req)
	}
}

//======================================================================
// Controller callback setup
//======================================================================

// SetupControllerCallbacks registers callbacks on the Controller for UI notifications.
// This should be called after the gowid App is created but before user interaction.
func SetupControllerCallbacks(gowApp gowid.IApp) {
	// OnError callback - display errors to the user
	AppController.SetOnError(func(event app.ErrorEvent) {
		gowApp.Run(gowid.RunFunction(func(app gowid.IApp) {
			msg := event.Message
			if event.Err != nil {
				msg = fmt.Sprintf("%s: %v", msg, event.Err)
			}
			OpenError(msg, app)
		}))
	})

	// OnLoadRequest callback - trigger packet cache loading
	// Currently a no-op since calculateAndSyncPrefetchRequests handles this,
	// but prepared for future use when we fully migrate to Controller-driven loading.
	AppController.SetOnLoadRequest(func(event app.LoadRequestEvent) {
		// Future: trigger actual loading via Loader
		// For now, calculateAndSyncPrefetchRequests already updates CacheRequests
	})

	// OnStateChange callback - for future UI widget updates driven by state
	// Currently most updates happen via the old paths, but this prepares for
	// full migration to state-driven UI.
	AppController.SetOnStateChange(func(event app.StateChangeEvent) {
		// Future: update UI widgets based on state changes
		// For now, the sync helpers and existing code paths handle this
	})
}

//======================================================================

type MultiMenuOpener struct {
	under gowid.IWidget
	mm    *MenuHolder
}

var _ menu.IOpener = (*MultiMenuOpener)(nil)

func (o *MultiMenuOpener) OpenMenu(mnu *menu.Widget, site menu.ISite, app gowid.IApp) bool {
	if o.mm.IMenuCompatible != mnu {
		// Adds the menu to the render tree - when not open, under is here instead
		o.mm.IMenuCompatible = mnu
		// Now make under the lower layer of the menu
		mnu.SetSubWidget(o.under, app)
		mnu.OpenImpl(site, app)
		app.Redraw()
		return true
	} else {
		return false
	}
}

func (o *MultiMenuOpener) CloseMenu(mnu *menu.Widget, app gowid.IApp) {
	if o.mm.IMenuCompatible == mnu {
		mnu.CloseImpl(app)
		o.mm.IMenuCompatible = holder.New(o.under)
	}
}

//======================================================================

//
// Handle examples like
// .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
// Extract just
// LG bit
//
// I'm trying to copy what Wireshark does, more or less
//
func columnNameFromShowname(showname string) string {
	matches := shownameRe.FindStringSubmatch(showname)
	if len(matches) >= 3 {
		return matches[2]
	}
	return showname
}

func useAsColumn(filter string, name string, app gowid.IApp) {
	newCols := profiles.ConfStringSlice("main.column-format", []string{})
	colsBak := make([]string, len(newCols))
	for i, col := range newCols {
		colsBak[i] = col
	}

	newCols = append(newCols,
		fmt.Sprintf("%%Cus:%s:0:R", filter),
		columnNameFromShowname(name),
		"true",
	)

	profiles.SetConf("main.column-format-bak", colsBak)
	profiles.SetConf("main.column-format", newCols)

	RequestReload(app)
}

// Build the menu dynamically when needed so I can include the filter in the widgets
func makePdmlFilterMenu(filter string, val string) *menu.Widget {
	sites := make(menuutil.SiteMap)

	needQuotes := false

	ok, field := FieldCompleter.LookupField(filter)
	// should be ok, because this filter comes from the PDML, so the filter should
	// be valid. But if it isn't e.g. newer tshark perhaps, then assume no quotes
	// are needed.
	if ok {
		switch field.Type {
		case fields.FT_STRING:
			needQuotes = true
		case fields.FT_STRINGZ:
			needQuotes = true
		case fields.FT_STRINGZPAD:
			needQuotes = true
		}
	}

	filterStr := filter
	if val != "" {
		if needQuotes {
			filterStr = fmt.Sprintf("%s == \"%s\"", filter, strings.ReplaceAll(val, "\\", "\\\\"))
		} else {
			filterStr = fmt.Sprintf("%s == %s", filter, val)
		}
	}

	var pdmlFilterMenu *menu.Widget

	openPdmlFilterMenu2 := func(prep bool, w gowid.IWidget, app gowid.IApp) {
		st, ok := sites[w]
		if !ok {
			log.Warnf("Unexpected application state: missing menu site for %v", w)
			return
		}

		// This contains logic to close the two PDML menus opened from the struct
		// view and then to either apply or prepare a new display filter based on
		// the one that is currently selected by the user (i.e. the one associated
		// with the open menu)
		actor := &pdmlFilterActor{
			filter:  filterStr,
			prepare: prep,
			menu1:   pdmlFilterMenu,
		}

		menuBox := makeFilterCombineMenuWidget(actor)

		m2 := menu.New("pdmlfilter2", menuBox, fixed, menu.Options{
			Modal:             true,
			CloseKeysProvided: true,
			CloseKeys: []gowid.IKey{
				gowid.MakeKey('q'),
				gowid.MakeKeyExt(tcell.KeyLeft),
				gowid.MakeKeyExt(tcell.KeyEscape),
				gowid.MakeKeyExt(tcell.KeyCtrlC),
			},
		})

		// I need to set this up after constructing m2; m2 itself needs
		// the menu box widget to display; that needs the actor to process
		// the clicks of buttons within that widget, and that actor needs
		// the menu m2 so that it can close it.
		actor.menu2 = m2

		multiMenu2Opener.OpenMenu(m2, st, app)
	}

	pdmlFilterItems := []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Apply as Column: %s", filter),
			Key: gowid.MakeKey('c'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(pdmlFilterMenu, app)
				useAsColumn(curColumnFilter, curColumnFilterName, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Apply Filter: %s", filterStr),
			Key: gowid.MakeKey('a'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				openPdmlFilterMenu2(false, w, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Prep Filter: %s", filterStr),
			Key: gowid.MakeKey('p'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				openPdmlFilterMenu2(true, w, app)
			},
		},
	}

	pdmlFilterListBox, pdmlFilterWidth := menuutil.MakeMenuWithHotKeys(pdmlFilterItems, sites)

	// this menu is opened from the PDML struct view and has, as context, the current PDML node. I
	// need a name for it because I use that var in the closure above.
	pdmlFilterMenu = menu.New("pdmlfiltermenu", pdmlFilterListBox, units(pdmlFilterWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	return pdmlFilterMenu
}

//======================================================================

func RequestQuit() {
	select {
	case GetQuitRequestedChan() <- struct{}{}:
	default:
		// Ok for the send not to succeed - there is a buffer of one, and it only
		// needs one message to start the shutdown sequence. So this means a
		// message has already been sent (before the main loop gets round to processing
		// this channel)
	}
}

// Runs in app goroutine
func UpdateProgressBarForInterface(c *pcap.InterfaceLoader, app gowid.IApp) {
	SetProgressIndeterminateFor(app, LoaderOwns)
	loadSpinner.Update()
}

// Runs in app goroutine
func UpdateProgressBarForFile(c *pcap.PacketLoader, prevRatio float64, app gowid.IApp) float64 {
	SetProgressDeterminateFor(app, LoaderOwns)

	psmlProg := Prog{0, 100}
	pdmlPacketProg := Prog{0, 100}
	pdmlIdxProg := Prog{0, 100}
	pcapPacketProg := Prog{0, 100}
	pcapIdxProg := Prog{0, 100}
	curRowProg := Prog{100, 100}

	var err error
	var c2 int64
	var m int64
	var x int

	// This shows where we are in the packet list. We want progress to be active only
	// as long as our view has missing widgets. So this can help predict when our little
	// view into the list of packets will be populated. Note that if a new pcap is loading,
	// the packet list view should always be further away than the last packet, so we won't
	// need the progress bar to tell the user how long until packets appear in the packet
	// list view; but the packet struct and hex views are populated using a different
	// mechanism (separate tshark processes) and may leave their views blank while the
	// packet list view shows data - so the progress bar is useful to indicate when info
	// will show up in the struct and hex views.
	currentDisplayedRow := -1
	var currentDisplayedRowMod int64 = -1
	var currentDisplayedRowDiv int = -1
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			currentRowId, ok := packetListView.Model().RowIdentifier(fxy.Row)
			if ok {
				pktsPerLoad := c.PacketsPerLoad()
				currentDisplayedRow = int(currentRowId)
				currentDisplayedRowMod = int64(currentDisplayedRow % pktsPerLoad)
				// Rounded to 1000 by default
				currentDisplayedRowDiv = (currentDisplayedRow / pktsPerLoad) * pktsPerLoad
				c.PsmlLoader.Lock()
				curRowProg.cur, curRowProg.max = int64(currentDisplayedRow), int64(len(c.PsmlDataLocked()))
				c.PsmlLoader.Unlock()
			}
		}
	}

	// Progress determined by how many of the (up to) pktsPerLoad pdml packets are read
	// If it's not the same chunk of rows, assume it won't affect our view, so no progress needed
	if c.PdmlLoader.IsLoading() {
		if c.LoadingRow() == currentDisplayedRowDiv {
			// Data being loaded from pdml + pcap may overlap the current view
			if x, err = c.LengthOfPdmlCacheEntry(c.LoadingRow()); err == nil {
				pdmlPacketProg.cur = int64(x)
				pdmlPacketProg.max = int64(c.KillAfterReadingThisMany())
				if currentDisplayedRow != -1 && currentDisplayedRowMod < pdmlPacketProg.max {
					pdmlPacketProg.max = currentDisplayedRowMod + 1 // zero-based
					if pdmlPacketProg.cur > pdmlPacketProg.max {
						pdmlPacketProg.cur = pdmlPacketProg.max
					}
				}
			}

			// Progress determined by how far through the pcap the pdml reader is.
			c2, m, err = system.ProcessProgress(c.PdmlPid(), c.PcapPdml)
			if err == nil {
				pdmlIdxProg.cur, pdmlIdxProg.max = c2, m
				if currentDisplayedRow != -1 && curRowProg.max != 0 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}

			// Progress determined by how many of the (up to) pktsPerLoad pcap packets are read
			if x, err = c.LengthOfPcapCacheEntry(c.LoadingRow()); err == nil {
				pcapPacketProg.cur = int64(x)
				pcapPacketProg.max = int64(c.KillAfterReadingThisMany())
				if currentDisplayedRow != -1 && currentDisplayedRowMod < pcapPacketProg.max {
					pcapPacketProg.max = currentDisplayedRowMod + 1 // zero-based
					if pcapPacketProg.cur > pcapPacketProg.max {
						pcapPacketProg.cur = pcapPacketProg.max
					}
				}
			}

			// Progress determined by how far through the pcap the pcap reader is.
			c2, m, err = system.ProcessProgress(c.PcapPid(), c.PcapPcap)
			if err == nil {
				pcapIdxProg.cur, pcapIdxProg.max = c2, m
				if currentDisplayedRow != -1 && curRowProg.max != 0 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}
		}
	}

	if psml, ok := c.PcapPsml.(string); ok && c.PsmlLoader.IsLoading() {
		c.PsmlLoader.Lock()
		c2, m, err = system.ProcessProgress(termshark.SafePid(c.PsmlCmd), psml)
		c.PsmlLoader.Unlock()
		if err == nil {
			psmlProg.cur, psmlProg.max = c2, m
		}
	}

	var prog Prog

	// state is guaranteed not to include pcap.Loadingiface if we showing a determinate progress bar
	switch {
	case c.PsmlLoader.IsLoading() && c.PdmlLoader.IsLoading() && c.PdmlLoader.LoadIsVisible():
		select {
		case <-c.StartStage2ChanFn():
			prog = psmlProg.Add(
				progMax(pcapPacketProg, pcapIdxProg).Add(
					progMax(pdmlPacketProg, pdmlIdxProg),
				),
			)
		default:
			prog = psmlProg.Div(2) // temporarily divide in 2. Leave original for case above - so that the 50%
		}
	case c.PsmlLoader.IsLoading():
		prog = psmlProg
	case c.PdmlLoader.IsLoading() && c.PdmlLoader.LoadIsVisible():
		prog = progMax(pcapPacketProg, pcapIdxProg).Add(
			progMax(pdmlPacketProg, pdmlIdxProg),
		)
	}

	var curRatio float64
	if prog.max != 0 {
		curRatio = float64(prog.cur) / float64(prog.max)
	}

	if prevRatio < curRatio {
		loadProgress.SetTarget(app, int(prog.max))
		loadProgress.SetProgress(app, int(prog.cur))
	}

	return max(prevRatio, curRatio)
}

//======================================================================
//======================================================================

type RenderWeightUpTo struct {
	gowid.RenderWithWeight
	max int
}

func (s RenderWeightUpTo) MaxUnits() int {
	return s.max
}

func weightupto(w int, max int) RenderWeightUpTo {
	return RenderWeightUpTo{gowid.RenderWithWeight{W: w}, max}
}

func units(n int) gowid.RenderWithUnits {
	return gowid.RenderWithUnits{U: n}
}

func weight(n int) gowid.RenderWithWeight {
	return gowid.RenderWithWeight{W: n}
}

func ratio(r float64) gowid.RenderWithRatio {
	return gowid.RenderWithRatio{R: r}
}

type RenderRatioUpTo struct {
	gowid.RenderWithRatio
	max int
}

func (r RenderRatioUpTo) String() string {
	return fmt.Sprintf("upto(%v,%d)", r.RenderWithRatio, r.max)
}

func (r RenderRatioUpTo) MaxUnits() int {
	return r.max
}

func ratioupto(f float64, max int) RenderRatioUpTo {
	return RenderRatioUpTo{gowid.RenderWithRatio{R: f}, max}
}

//======================================================================

type pleaseWaitCallbacks struct {
	w    *spinner.Widget
	app  gowid.IApp
	open bool
}

func (s *pleaseWaitCallbacks) ProcessWaitTick() error {
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		s.w.Update()
		if !s.open {
			OpenPleaseWait(appView, s.app)
			s.open = true
		}
	}))
	return nil
}

// Call in app context
func (s *pleaseWaitCallbacks) closeWaitDialog(app gowid.IApp) {
	if s.open {
		ClosePleaseWait(app)
		s.open = false
	}
}

func (s *pleaseWaitCallbacks) ProcessCommandDone() {
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		s.closeWaitDialog(app)
	}))
}

//======================================================================

// Wait until the copy command has finished, then open up a dialog with the results.
type urlCopiedCallbacks struct {
	app      gowid.IApp
	tmplName string
	*pleaseWaitCallbacks
}

var (
	_ termshark.ICommandOutput     = urlCopiedCallbacks{}
	_ termshark.ICommandError      = urlCopiedCallbacks{}
	_ termshark.ICommandDone       = urlCopiedCallbacks{}
	_ termshark.ICommandKillError  = urlCopiedCallbacks{}
	_ termshark.ICommandTimeout    = urlCopiedCallbacks{}
	_ termshark.ICommandWaitTicker = urlCopiedCallbacks{}
)

func (h urlCopiedCallbacks) displayDialog(output string) {
	TemplateData["CopyCommandMessage"] = output

	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenTemplatedDialog(appView, h.tmplName, app)
		delete(TemplateData, "CopyCommandMessage")
	}))
}

func (h urlCopiedCallbacks) ProcessOutput(output string) error {
	var msg string
	if len(output) == 0 {
		msg = "URL copied to clipboard."
	} else {
		msg = output
	}
	h.displayDialog(msg)
	return nil
}

func (h urlCopiedCallbacks) ProcessCommandTimeout() error {
	h.displayDialog("")
	return nil
}

func (h urlCopiedCallbacks) ProcessCommandError(err error) error {
	h.displayDialog("")
	return nil
}

func (h urlCopiedCallbacks) ProcessKillError(err error) error {
	h.displayDialog("")
	return nil
}

//======================================================================

type userCopiedCallbacks struct {
	app     gowid.IApp
	copyCmd []string
	*pleaseWaitCallbacks
}

var (
	_ termshark.ICommandOutput     = userCopiedCallbacks{}
	_ termshark.ICommandError      = userCopiedCallbacks{}
	_ termshark.ICommandDone       = userCopiedCallbacks{}
	_ termshark.ICommandKillError  = userCopiedCallbacks{}
	_ termshark.ICommandTimeout    = userCopiedCallbacks{}
	_ termshark.ICommandWaitTicker = userCopiedCallbacks{}
)

func (h userCopiedCallbacks) ProcessCommandTimeout() error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Copy command \"%v\" timed out", strings.Join(h.copyCmd, " ")), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessCommandError(err error) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Copy command \"%v\" failed: %v", strings.Join(h.copyCmd, " "), err), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessKillError(err error) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Timed out, but could not kill copy command: %v", err), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessOutput(output string) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		if len(output) == 0 {
			OpenMessage("   Copied!   ", appView, app)
		} else {
			OpenMessage(fmt.Sprintf("Copied! Output was:\n%s\n", output), appView, app)
		}
	}))
	return nil
}

//======================================================================

type OpenErrorDialog struct{}

func (f OpenErrorDialog) OnError(err error, app gowid.IApp) {
	OpenError(err.Error(), app)
}

func OpenError(msgt string, app gowid.IApp) *dialog.Widget {
	// the same, for now
	return OpenMessage(msgt, appView, app)
}

func OpenLongError(msgt string, app gowid.IApp) *dialog.Widget {
	// the same, for now
	return OpenLongMessage(msgt, appView, app)
}

func openResultsAfterCopy(tmplName string, tocopy string, app gowid.IApp) {
	v := urlCopiedCallbacks{
		app:      app,
		tmplName: tmplName,
		pleaseWaitCallbacks: &pleaseWaitCallbacks{
			w:   pleaseWaitSpinner,
			app: app,
		},
	}
	termshark.CopyCommand(strings.NewReader(tocopy), v)
}

func processCopyChoices(copyLen int, app gowid.IApp) {
	var cc *dialog.Widget

	copyCmd := profiles.ConfStringSlice(
		"main.copy-command",
		system.CopyToClipboard,
	)

	if len(copyCmd) == 0 {
		OpenError("Config file has an invalid copy-command entry! Please remove it.", app)
		return
	}

	clips := app.Clips()

	// No need to display a choice dialog with one choice - just copy right away
	if len(clips) == 1 {
		app.InCopyMode(false)
		termshark.CopyCommand(strings.NewReader(clips[0].ClipValue()), userCopiedCallbacks{
			app:     app,
			copyCmd: copyCmd,
			pleaseWaitCallbacks: &pleaseWaitCallbacks{
				w:   pleaseWaitSpinner,
				app: app,
			},
		})
		return
	}

	cws := make([]gowid.IWidget, 0, len(clips))

	for _, clip := range clips {
		c2 := clip
		lbl := text.New(clip.ClipName() + ":")
		btxt1 := clip.ClipValue()
		if copyLen > 0 {
			blines := strings.Split(btxt1, "\n")
			if len(blines) > copyLen {
				blines[copyLen-1] = "..."
				blines = blines[0:copyLen]
			}
			btxt1 = strings.Join(blines, "\n")
		}

		btn := button.NewBare(text.New(btxt1, text.Options{
			Wrap:          text.WrapClip,
			ClipIndicator: "...",
		}))

		btn.OnClick(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			cc.Close(app)
			app.InCopyMode(false)

			termshark.CopyCommand(strings.NewReader(c2.ClipValue()), userCopiedCallbacks{
				app:     app,
				copyCmd: copyCmd,
				pleaseWaitCallbacks: &pleaseWaitCallbacks{
					w:   pleaseWaitSpinner,
					app: app,
				},
			})
		})))

		btn2 := styled.NewFocus(btn, gowid.MakeStyledAs(gowid.StyleReverse))
		tog := pile.NewFlow(lbl, btn2, divider.NewUnicode())
		cws = append(cws, tog)
	}

	walker := list.NewSimpleListWalker(cws)
	clipList := list.New(walker)

	// Do this so the list box scrolls inside the dialog
	view2 := &gowid.ContainerWidget{
		IWidget: clipList,
		D:       weight(1),
	}

	var view1 gowid.IWidget = pile.NewFlow(text.New("Select option to copy:"), divider.NewUnicode(), view2)

	cc = dialog.New(view1,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			FocusOnWidget:   true,
		},
	)

	cc.OnOpenClose(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
		if !cc.IsOpen() {
			app.InCopyMode(false)
		}
	})))

	dialog.OpenExt(cc, appView, ratio(0.5), ratio(0.8), app)
}

type callWithAppFn func(gowid.IApp)

func askToSave(app gowid.IApp, next callWithAppFn) {
	msgt := fmt.Sprintf("Current capture saved to %s", Loader.InterfaceFile())
	msg := text.New(msgt)
	var keepPackets *dialog.Widget
	keepPackets = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Keep",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							keepPackets.Close(app)
							next(app)
						},
					),
				},
				dialog.Button{
					Msg: "Delete",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							WriteToDeleted = true
							err := os.Remove(Loader.InterfaceFile())
							if err != nil {
								log.Errorf("Could not delete file %s: %v", Loader.InterfaceFile(), err)
							}
							keepPackets.Close(app)
							next(app)
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)
	keepPackets.Open(appView, units(len(msgt)+20), app)
}

func reallyQuit(app gowid.IApp) {
	msgt := "Do you want to quit?"
	msg := text.New(msgt)
	YesNo = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							YesNo.Close(app)
							// (a) Loader is in interface mode (b) User did not set -w flag
							// (c) always-keep-pcap setting is unset (def false) or false
							if Loader.InterfaceFile() != "" && !WriteToSelected &&
								!profiles.ConfBool("main.always-keep-pcap", false) {
								askToSave(app, func(app gowid.IApp) {
									RequestQuit()
								})
							} else {
								RequestQuit()
							}
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
		},
	)
	YesNo.Open(appView, units(len(msgt)+20), app)
}

func lastLineMode(app gowid.IApp) {
	MiniBuffer = minibuffer.New()

	MiniBuffer.Register("quit", minibufferFn(func(gowid.IApp, ...string) error {
		reallyQuit(app)
		return nil
	}))

	// force quit
	MiniBuffer.Register("q!", quietMinibufferFn(func(gowid.IApp, ...string) error {
		RequestQuit()
		return nil
	}))

	MiniBuffer.Register("no-theme", minibufferFn(func(app gowid.IApp, s ...string) error {
		mode := theme.Mode(app.GetColorMode()).String() // more concise
		profiles.DeleteConf(fmt.Sprintf("main.theme-%s", mode))
		ApplyCurrentTheme(app)
		SetupColors()
		var prof string
		if profiles.Current() != profiles.Default() {
			prof = fmt.Sprintf("in profile %s ", profiles.CurrentName())
		}
		OpenMessage(fmt.Sprintf("Cleared theme %sfor terminal mode %v.", prof, app.GetColorMode()), appView, app)
		return nil
	}))

	MiniBuffer.Register("convs", minibufferFn(func(gowid.IApp, ...string) error {
		openConvsUi(app)
		return nil
	}))

	MiniBuffer.Register("streams", minibufferFn(func(gowid.IApp, ...string) error {
		startStreamReassembly(app)
		return nil
	}))

	MiniBuffer.Register("capinfo", minibufferFn(func(gowid.IApp, ...string) error {
		startCapinfo(app)
		return nil
	}))

	MiniBuffer.Register("columns", minibufferFn(func(gowid.IApp, ...string) error {
		openEditColumns(app)
		return nil
	}))

	MiniBuffer.Register("wormhole", minibufferFn(func(gowid.IApp, ...string) error {
		openWormhole(app)
		return nil
	}))

	MiniBuffer.Register("menu", minibufferFn(func(gowid.IApp, ...string) error {
		openGeneralMenu(app)
		return nil
	}))

	MiniBuffer.Register("clear-packets", minibufferFn(func(gowid.IApp, ...string) error {
		reallyClear(app)
		return nil
	}))

	MiniBuffer.Register("clear-filter", minibufferFn(func(gowid.IApp, ...string) error {
		FilterWidget.SetValue("", app)
		RequestNewFilter(FilterWidget.Value(), app)
		return nil
	}))

	MiniBuffer.Register("marks", minibufferFn(func(gowid.IApp, ...string) error {
		OpenTemplatedDialogExt(appView, "Marks", fixed, ratio(0.6), app)
		return nil
	}))

	if runtime.GOOS != "windows" {
		MiniBuffer.Register("logs", minibufferFn(func(gowid.IApp, ...string) error {
			openLogsUi(app)
			return nil
		}))
		MiniBuffer.Register("config", minibufferFn(func(gowid.IApp, ...string) error {
			openConfigUi(app)
			return nil
		}))
	}

	MiniBuffer.Register("set", setCommand{})

	// read new pcap
	MiniBuffer.Register("r", readCommand{complete: false})
	MiniBuffer.Register("e", readCommand{complete: false})
	MiniBuffer.Register("load", readCommand{complete: true})
	MiniBuffer.Register("recents", recentsCommand{})
	MiniBuffer.Register("filter", filterCommand{})
	MiniBuffer.Register("theme", themeCommand{})
	MiniBuffer.Register("profile", newProfileCommand())
	MiniBuffer.Register("map", mapCommand{w: keyMapper})
	MiniBuffer.Register("unmap", unmapCommand{w: keyMapper})
	MiniBuffer.Register("help", helpCommand{})

	minibuffer.Open(MiniBuffer, mbView, ratio(1.0), app)
}


func reallyClear(app gowid.IApp) {
	confirmAction(
		"Do you want to clear current capture?",
		func(app gowid.IApp) {
			Loader.ClearPcap(
				pcap.HandlerList{
					SimpleErrors{},
					MakePacketViewUpdater(),
					MakeUpdateCurrentCaptureInTitle(),
					ManageStreamCache{},
					ManageCapinfoCache{},
					SetStructWidgets{Loader}, // for OnClear
					ClearMarksHandler{},
					ManageSearchData{},
					CancelledMessage{},
				},
			)
		},
		app,
	)
}

func confirmAction(msgt string, ok func(gowid.IApp), app gowid.IApp) {
	msg := text.New(msgt)
	YesNo = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, w gowid.IWidget) {
							YesNo.Close(app)
							ok(app)
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)
	YesNo.Open(mainViewNoKeys, units(len(msgt)+28), app)
}

// don't claim the keypress
//======================================================================


func RequestLoadInterfaces(psrcs []pcap.IPacketSource, captureFilter string, displayFilter string, tmpfile string, app gowid.IApp) {
	// Sync filter with Controller (interface captures don't have a fixed pcap path)
	AppController.State.SetCurrentFilter(displayFilter)

	Loader.Renew()
	Loader.LoadInterfaces(psrcs, captureFilter, displayFilter, tmpfile,
		pcap.HandlerList{
			StartUIWhenThereArePackets{},
			SimpleErrors{},
			MakeSaveRecents("", displayFilter),
			MakePacketViewUpdater(),
			MakeUpdateCurrentCaptureInTitle(),
			ManageStreamCache{},
			ManageCapinfoCache{},
			SetStructWidgets{Loader}, // for OnClear
			ClearWormholeState{},
			ClearMarksHandler{},
			ManageSearchData{},
			CancelledMessage{},
		},
		app,
	)
}

//======================================================================

// MaybeKeepThenRequestLoadPcap loads a pcap after first checking to see whether
// the current load is a live load and the packets need to be kept.
func MaybeKeepThenRequestLoadPcap(pcapf string, displayFilter string, jump termshark.GlobalJumpPos, app gowid.IApp) {
	if Loader.InterfaceFile() != "" && !WriteToSelected && !profiles.ConfBool("main.always-keep-pcap", false) {
		askToSave(app, func(app gowid.IApp) {
			RequestLoadPcap(pcapf, displayFilter, jump, app)
		})
	} else {
		RequestLoadPcap(pcapf, displayFilter, jump, app)
	}
}

// Call from app goroutine context
func RequestLoadPcap(pcapf string, displayFilter string, jump termshark.GlobalJumpPos, app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakeSaveRecents(pcapf, displayFilter),
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		ManageStreamCache{},
		ManageCapinfoCache{},
		SetStructWidgets{Loader}, // for OnClear
		MakeCheckGlobalJumpAfterPsml(jump),
		ClearWormholeState{},
		ClearMarksHandler{},
		ManageSearchData{},
		CancelledMessage{},
	}

	if _, err := os.Stat(pcapf); os.IsNotExist(err) {
		pcap.HandleError(pcap.NoneCode, app, err, handlers)
	} else {
		// no auto-scroll when reading a file
		setAutoScrollWithSync(false)
		// Sync pcap and filter with Controller
		AppController.State.SetCurrentPcap(pcapf)
		AppController.State.SetCurrentFilter(displayFilter)
		Loader.LoadPcap(pcapf, displayFilter, handlers, app)
	}
}

//======================================================================

func RequestNewFilter(displayFilter string, app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakeSaveRecents("", displayFilter),
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		SetStructWidgets{Loader}, // for OnClear
		ClearMarksHandler{},
		ManageSearchData{},
		// Don't use this one - we keep the cancelled flag set so that we
		// don't restart live captures on clear if ctrl-c has been issued
		// so we don't want this handler on a new filter because we don't
		// want to be told again after applying the filter that the load
		// was cancelled
		//MakeCancelledMessage(),
	}

	if Loader.DisplayFilter() == displayFilter {
		log.Infof("No operation - same filter applied ('%s').", displayFilter)
	} else {
		// Sync filter with Controller
		AppController.State.SetCurrentFilter(displayFilter)
		Loader.Reload(displayFilter, handlers, app)
	}
}

func RequestReload(app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		SetStructWidgets{Loader}, // for OnClear
		ClearMarksHandler{},
		ManageSearchData{},
		// Don't use this one - we keep the cancelled flag set so that we
		// don't restart live captures on clear if ctrl-c has been issued
		// so we don't want this handler on a new filter because we don't
		// want to be told again after applying the filter that the load
		// was cancelled
		//MakeCancelledMessage(),
	}

	Loader.Reload(Loader.DisplayFilter(), handlers, app)
}

//======================================================================

//======================================================================

func makeRecentMenuWidget() (gowid.IWidget, int) {
	savedItems := make([]menuutil.SimpleMenuItem, 0)
	cfiles := profiles.ConfStringSlice("main.recent-files", []string{})
	if cfiles != nil {
		for i, s := range cfiles {
			scopy := s
			savedItems = append(savedItems,
				menuutil.SimpleMenuItem{
					Txt: s,
					Key: gowid.MakeKey('a' + rune(i)),
					CB: func(app gowid.IApp, w gowid.IWidget) {
						multiMenu1Opener.CloseMenu(savedMenu, app)
						// capFilter global, set up in cmain()
						MaybeKeepThenRequestLoadPcap(scopy, FilterWidget.Value(), NoGlobalJump, app)
					},
				},
			)
		}
	}
	return menuutil.MakeMenuWithHotKeys(savedItems, nil)
}

func UpdateRecentMenu(app gowid.IApp) {
	savedListBox, _ := makeRecentMenuWidget()
	savedListBoxWidgetHolder.SetSubWidget(savedListBox, app)
}

//======================================================================

type savedCompleterCallback struct {
	prefix string
	comp   fields.IPrefixCompleterCallback
}

var _ fields.IPrefixCompleterCallback = (*savedCompleterCallback)(nil)

func (s *savedCompleterCallback) Call(orig []string) {
	if s.prefix == "" {
		comps := profiles.ConfStrings("main.recent-filters")
		if len(comps) == 0 {
			comps = orig
		}
		s.comp.Call(comps)
	} else {
		s.comp.Call(orig)
	}
}

type savedCompleter struct {
	def fields.IPrefixCompleter
}

var _ fields.IPrefixCompleter = (*savedCompleter)(nil)

func (s savedCompleter) Completions(prefix string, cb fields.IPrefixCompleterCallback) {
	ncomp := &savedCompleterCallback{
		prefix: prefix,
		comp:   cb,
	}
	s.def.Completions(prefix, ncomp)
}

//======================================================================

func StopEmptyStructViewTimer() {
	if EmptyStructViewTimer != nil {
		EmptyStructViewTimer.Stop()
		EmptyStructViewTimer = nil
	}
}

func StopEmptyHexViewTimer() {
	if EmptyHexViewTimer != nil {
		EmptyHexViewTimer.Stop()
		EmptyHexViewTimer = nil
	}
}

//======================================================================

func assignTo(wp interface{}, w gowid.IWidget) gowid.IWidget {
	reflect.ValueOf(wp).Elem().Set(reflect.ValueOf(w))
	return w
}

//======================================================================

//======================================================================

func SetDarkMode(mode bool) {
	setDarkModeWithSync(mode)
	profiles.SetConf("main.dark-mode", DarkMode)
}

// SetPacketColors sets the PacketColors state and persists to config.
func SetPacketColors(enabled bool) {
	setPacketColorsWithSync(enabled)
	profiles.SetConf("main.packet-colors", PacketColors)
}

// SetAutoScroll sets the AutoScroll state and persists to config.
func SetAutoScroll(enabled bool) {
	setAutoScrollWithSync(enabled)
	profiles.SetConf("main.auto-scroll", AutoScroll)
}

// InitDarkMode sets the DarkMode state without persisting (for initialization from config).
func InitDarkMode(mode bool) {
	setDarkModeWithSync(mode)
}

// InitPacketColors sets the PacketColors state without persisting (for initialization from config).
func InitPacketColors(enabled bool) {
	setPacketColorsWithSync(enabled)
}

// InitAutoScroll sets the AutoScroll state without persisting (for initialization from config).
func InitAutoScroll(enabled bool) {
	setAutoScrollWithSync(enabled)
}

func UpdateProfileWidget(name string, app gowid.IApp) {
	currentProfile.SetText(name, app)
	if name != "" && name != "default" {
		currentProfileWidgetHolder.SetSubWidget(currentProfileWidget, app)
	} else {
		currentProfileWidgetHolder.SetSubWidget(nullw, app)
	}
}

// vp and vc guaranteed to be non-nil
func ApplyCurrentProfile(app gowid.IApp, vp *viper.Viper, vc *viper.Viper) error {
	UpdateProfileWidget(profiles.CurrentName(), app)

	reload := false

	SetDarkMode(profiles.ConfBool("main.dark-mode", true))

	curWireshark := profiles.ConfStringFrom(vp, profiles.Default(), "main.wireshark-profile", "")
	newWireshark := profiles.ConfStringFrom(vc, profiles.Default(), "main.wireshark-profile", "")
	if curWireshark != newWireshark {
		reload = true
	}

	curcols := profiles.ConfStringSliceFrom(vp, profiles.Default(), "main.column-format", []string{})
	newcols := profiles.ConfStringSliceFrom(vc, profiles.Default(), "main.column-format", []string{})
	if !slices.Equal(newcols, curcols) {
		reload = true
	}

	if reload {
		RequestReload(app)
	}

	ApplyCurrentTheme(app)
	SetupColors()

	return nil
}

func ApplyCurrentTheme(app gowid.IApp) {
	var err error
	mode := app.GetColorMode()
	modeStr := theme.Mode(mode) // more concise
	themeName := profiles.ConfString(fmt.Sprintf("main.theme-%s", modeStr), "default")
	loaded := false
	if themeName != "" {
		err = theme.Load(themeName, app)
		if err != nil {
			log.Warnf("Theme %s could not be loaded: %v", themeName, err)
		} else {
			loaded = true
		}
	}
	if !loaded && themeName != "default" {
		err = theme.Load("default", app)
		if err != nil {
			log.Warnf("Theme %s could not be loaded: %v", themeName, err)
		}
	}
}

//======================================================================

func Build(tty string) (*gowid.App, error) {
	// Initialize the UIState container for the new state management system
	UI = NewUIState()

	var err error
	var app *gowid.App

	widgetCacheSize := profiles.ConfInt("main.ui-cache-size", 1000)
	if widgetCacheSize < 64 {
		widgetCacheSize = 64
	}
	packetHexWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		return nil, gowid.WithKVs(termshark.InternalErr, map[string]interface{}{
			"err": err,
		})
	}
	UI.Packets.PacketHexWidgets = packetHexWidgets

	nullw = null.New()
	UI.Widgets.Nullw = nullw

	Loadingw = text.New("Loading, please wait...")
	UI.Widgets.Loadingw = Loadingw
	singlePacketViewMsgHolder = holder.New(nullw)
	UI.Widgets.SinglePacketViewMsgHolder = singlePacketViewMsgHolder
	fillSpace = fill.New(' ')
	UI.Widgets.FillSpace = fillSpace
	if runtime.GOOS == "windows" {
		fillVBar = fill.New('|')
	} else {
		fillVBar = fill.New('┃')
	}
	UI.Widgets.FillVBar = fillVBar

	colSpace = &gowid.ContainerWidget{
		IWidget: fillSpace,
		D:       units(1),
	}
	UI.Widgets.ColSpace = colSpace

	MissingMsgw = vpadding.New( // centred
		hpadding.New(singlePacketViewMsgHolder, hmiddle, fixed),
		vmiddle,
		flow,
	)
	UI.Widgets.MissingMsgw = MissingMsgw

	pleaseWaitSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})
	UI.Widgets.PleaseWaitSpinner = pleaseWaitSpinner

	PleaseWait = dialog.New(framed.NewSpace(
		pile.NewFlow(
			&gowid.ContainerWidget{
				IWidget: text.New(" Please wait... "),
				D:       gowid.RenderFixed{},
			},
			fillSpace,
			pleaseWaitSpinner,
		)),
		dialog.Options{
			Buttons:         dialog.NoButtons,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	title := styled.New(text.New(termshark.TemplateToString(Templates, "NameVer", TemplateData)), gowid.MakePaletteRef("title"))

	currentCapture = text.New("")
	UI.Nav.CurrentCapture = currentCapture
	currentCaptureStyled := styled.New(
		currentCapture,
		gowid.MakePaletteRef("current-capture"),
	)

	sp := text.New("  ")

	currentCaptureWidget = columns.NewFixed(
		sp,
		&gowid.ContainerWidget{
			IWidget: fill.New('|'),
			D:       gowid.MakeRenderBox(1, 1),
		},
		sp,
		currentCaptureStyled,
	)
	UI.Nav.CurrentCaptureWidget = currentCaptureWidget
	currentCaptureWidgetHolder = holder.New(nullw)
	UI.Nav.CurrentCaptureWidgetHolder = currentCaptureWidgetHolder

	CopyModePredicate = func() bool {
		return app != nil && app.InCopyMode()
	}
	UI.Widgets.CopyModePredicate = CopyModePredicate

	CopyModeWidget = styled.New(
		ifwidget.New(
			text.New(" COPY-MODE "),
			null.New(),
			CopyModePredicate,
		),
		gowid.MakePaletteRef("copy-mode-label"),
	)
	UI.Widgets.CopyModeWidget = CopyModeWidget

	//======================================================================

	openMenu := button.NewBare(text.New("  Misc  "))
	openMenu2 := clicktracker.New(
		styled.NewExt(
			openMenu,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)

	openMenuSite = menu.NewSite(menu.SiteOptions{YOffset: 1})
	UI.Menus.OpenMenuSite = openMenuSite
	openMenu.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		multiMenu1Opener.OpenMenu(generalMenu, openMenuSite, app)
	}))

	//======================================================================

	generalMenuItems := make([]menuutil.SimpleMenuItem, 0)

	generalMenuItems = append(generalMenuItems, []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: "Refresh Screen",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlL, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				app.Sync()
			},
		},
		// Put 2nd so a simple menu click, down, enter without thinking doesn't toggle dark mode (annoying...)
		menuutil.SimpleMenuItem{
			Txt: "Toggle Dark Mode",
			Key: gowid.MakeKey('d'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				SetDarkMode(!DarkMode)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Search Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlF, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !searchOpen() {
					filterHolder.SetSubWidget(filterWithSearch, app)
				}
				setFocusOnSearch(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Clear Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlW, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				reallyClear(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Send Pcap",
			Key: gowid.MakeKey('s'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openWormhole(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Edit Columns",
			Key: gowid.MakeKey('e'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openEditColumns(app)
			},
		}}...)

	if runtime.GOOS != "windows" {
		generalMenuItems = append(generalMenuItems, menuutil.SimpleMenuItem{
			Txt: "Show Log",
			Key: gowid.MakeKey('l'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openLogsUi(app)
			},
		})
		generalMenuItems = append(generalMenuItems, menuutil.SimpleMenuItem{
			Txt: "Show Config",
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openConfigUi(app)
			},
		})
	}

	generalMenuItems = append(generalMenuItems, []menuutil.SimpleMenuItem{
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Help",
			Key: gowid.MakeKey('?'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				OpenTemplatedDialog(appView, "UIHelp", app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "User Guide",
			Key: gowid.MakeKey('u'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.UserGuideURL)
				}
				openResultsAfterCopy("UIUserGuide", termshark.UserGuideURL, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "FAQ",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.FAQURL)
				}
				openResultsAfterCopy("UIFAQ", termshark.FAQURL, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Found a Bug?",
			Key: gowid.MakeKey('b'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.BugURL)
				}
				openResultsAfterCopy("UIBug", termshark.BugURL, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Feature Request?",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.FeatureURL)
				}
				openResultsAfterCopy("UIFeature", termshark.FeatureURL, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Quit",
			Key: gowid.MakeKey('q'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				reallyQuit(app)
			},
		},
	}...)

	if PacketColorsSupported {
		generalMenuItems = append(
			generalMenuItems[0:2],
			append(
				[]menuutil.SimpleMenuItem{
					menuutil.SimpleMenuItem{
						Txt: "Toggle Packet Colors",
						Key: gowid.MakeKey('c'),
						CB: func(app gowid.IApp, w gowid.IWidget) {
							multiMenu1Opener.CloseMenu(generalMenu, app)
							setPacketColorsWithSync(!PacketColors)
							profiles.SetConf("main.packet-colors", PacketColors)
						},
					},
				},
				generalMenuItems[2:]...,
			)...,
		)
	}

	generalMenuListBox, generalMenuWidth := menuutil.MakeMenuWithHotKeys(generalMenuItems, nil)

	var generalNext menuutil.NextMenu

	generalMenuListBoxWithKeys := appkeys.New(
		generalMenuListBox,
		menuutil.MakeMenuNavigatingKeyPress(
			&generalNext,
			nil,
		),
	)

	// Hack. What's a more general way of doing this? The length of the <Menu> button I suppose
	openMenuSite.Options.XOffset = -generalMenuWidth + 8

	generalMenu = menu.New("main", generalMenuListBoxWithKeys, units(generalMenuWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})
	UI.Menus.GeneralMenu = generalMenu

	//======================================================================

	openAnalysis := button.NewBare(text.New("  Analysis  "))
	openAnalysis2 := clicktracker.New(
		styled.NewExt(
			openAnalysis,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)

	openAnalysisSite = menu.NewSite(menu.SiteOptions{XOffset: -12, YOffset: 1})
	UI.Menus.OpenAnalysisSite = openAnalysisSite
	openAnalysis.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		multiMenu1Opener.OpenMenu(analysisMenu, openAnalysisSite, app)
	}))

	analysisMenuItems := []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: "Capture file properties",
			Key: gowid.MakeKey('p'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				startCapinfo(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Reassemble stream",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				startStreamReassembly(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Conversations",
			Key: gowid.MakeKey('c'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				openConvsUi(app)
			},
		},
	}

	analysisMenuListBox, analysisMenuWidth := menuutil.MakeMenuWithHotKeys(analysisMenuItems, nil)

	var analysisNext menuutil.NextMenu

	analysisMenuListBoxWithKeys := appkeys.New(
		analysisMenuListBox,
		menuutil.MakeMenuNavigatingKeyPress(
			nil,
			&analysisNext,
		),
	)

	analysisMenu = menu.New("analysis", analysisMenuListBoxWithKeys, units(analysisMenuWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})
	UI.Menus.AnalysisMenu = analysisMenu

	//======================================================================

	loadProgress = progress.New(progress.Options{
		Normal:   gowid.MakePaletteRef("progress-default"),
		Complete: gowid.MakePaletteRef("progress-complete"),
	})
	UI.Progress.LoadProgress = loadProgress

	loadSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})
	UI.Progress.LoadSpinner = loadSpinner

	savedListBox, _ := makeRecentMenuWidget()
	savedListBoxWidgetHolder = holder.New(savedListBox)
	UI.Menus.SavedListBoxWidgetHolder = savedListBoxWidgetHolder

	savedMenu = menu.New("saved", savedListBoxWidgetHolder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})
	UI.Menus.SavedMenu = savedMenu

	//======================================================================

	currentProfile = text.New("default")
	UI.Nav.CurrentProfile = currentProfile
	currentProfileWidget = columns.NewFixed(
		text.New("Profile: "),
		currentProfile,
		sp,
		&gowid.ContainerWidget{
			IWidget: fill.New('|'),
			D:       gowid.MakeRenderBox(1, 1),
		},
		sp,
	)
	currentProfileWidgetHolder = holder.New(currentProfileWidget)
	UI.Nav.CurrentProfileWidget = currentProfileWidget
	UI.Nav.CurrentProfileWidgetHolder = currentProfileWidgetHolder

	// Update display to show the profile if it isn't the default
	UpdateProfileWidget(profiles.CurrentName(), app)

	var titleCols *columns.Widget

	// If anything gets added or removed here, see [[generalmenu1]]
	// and [[generalmenu2]] and [[generalmenu3]]
	titleView := overlay.New(
		hpadding.New(CopyModeWidget, gowid.HAlignMiddle{}, fixed),
		assignTo(&titleCols, columns.NewFixed(
			title,
			&gowid.ContainerWidget{
				IWidget: currentCaptureWidgetHolder,
				D:       weight(10), // give it priority when the window isn't wide enough
			},
			&gowid.ContainerWidget{
				IWidget: fill.New(' '),
				D:       weight(1),
			},
			&gowid.ContainerWidget{
				IWidget: currentProfileWidgetHolder,
				D:       fixed, // give it priority when the window isn't wide enough
			},
			openAnalysisSite,
			openAnalysis2,
			openMenuSite,
			openMenu2,
		)),
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

	// Fill this in once generalMenu is defined and titleView is defined
	// <<generalmenu1>>
	generalNext.Cur = generalMenu
	generalNext.Next = analysisMenu
	generalNext.Site = openAnalysisSite
	generalNext.Container = titleCols
	generalNext.MenuOpener = &multiMenu1Opener
	generalNext.Focus = 5 // should really find by ID

	// <<generalmenu2>>
	analysisNext.Cur = analysisMenu
	analysisNext.Next = generalMenu
	analysisNext.Site = openMenuSite
	analysisNext.Container = titleCols
	analysisNext.MenuOpener = &multiMenu1Opener
	analysisNext.Focus = 7 // should really find by ID

	packetListViewHolder = holder.New(nullw)
	UI.Packets.PacketListViewHolder = packetListViewHolder
	packetStructureViewHolder = holder.New(nullw)
	UI.Packets.PacketStructureViewHolder = packetStructureViewHolder
	packetHexViewHolder = holder.New(nullw)
	UI.Packets.PacketHexViewHolder = packetHexViewHolder

	progressHolder = holder.New(nullw)
	UI.Progress.ProgressHolder = progressHolder

	applyw := button.New(text.New("Apply"))
	applyWidget := disable.NewEnabled(
		clicktracker.New(
			styled.NewExt(
				applyw,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
		),
	)

	// For completing filter expressions
	FieldCompleter = fields.New()
	FieldCompleter.Init()
	UI.App.FieldCompleter = FieldCompleter

	FilterWidget = filter.New("filter", filter.Options{
		Completer:  savedCompleter{def: FieldCompleter},
		MenuOpener: &multiMenu1Opener,
	})
	UI.Filter.FilterWidget = FilterWidget

	validFilterCb := gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		if Loader.DisplayFilter() == FilterWidget.Value() {
			OpenError("Same filter - nothing to do", app)
		} else {
			RequestNewFilter(FilterWidget.Value(), app)
		}
	})

	// Will only be enabled to click if filter is valid
	applyw.OnClick(validFilterCb)
	// Will only fire OnSubmit if filter is valid
	FilterWidget.OnSubmit(validFilterCb)

	FilterWidget.OnValid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Enable()
	}))
	FilterWidget.OnInvalid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Disable()
	}))
	filterLabel := text.New("Filter: ")

	savedw := button.New(text.New("Recent"))
	savedWidget := clicktracker.New(
		styled.NewExt(
			savedw,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)
	savedBtnSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	savedw.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		multiMenu1Opener.OpenMenu(savedMenu, savedBtnSite, app)
		// if !multiMenu1Opener.OpenMenu(savedMenu, savedBtnSite, app) {
		// 	multiMenu1Opener.CloseMenu(savedMenu, app)
		// }
	}))

	progWidgetIdx = 7 // adjust this if nullw moves position in filterCols
	UI.Progress.ProgWidgetIdx = progWidgetIdx
	filterCols = columns.NewFixed(filterLabel,
		&gowid.ContainerWidget{
			IWidget: FilterWidget,
			D:       weight(100),
		},
		applyWidget, colSpace, savedBtnSite, savedWidget, colSpace, nullw)
	UI.Filter.FilterCols = filterCols

	//======================================================================

	loadStop, loadProg = createLoaderProgressWidget()
	UI.Progress.LoadStop = loadStop
	UI.Progress.LoadProg = loadProg
	searchStop, searchProg = createProgressWidget()
	UI.Progress.SearchStop = searchStop
	UI.Progress.SearchProg = searchProg

	//======================================================================

	searchCh := make(chan search.IntermediateResult)

	cbs := &commonSearchCallbacks{}

	listSearchCallbacks := func() search.ICallbacks {
		return &ListSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	structSearchCallbacks := func() search.ICallbacks {
		return &StructSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	bytesSearchCallbacks := func() search.ICallbacks {
		return &BytesSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	filterSearchCallbacks := func() search.ICallbacks {
		return NewFilterSearchCallbacks(cbs, searchCh)
	}

	SearchWidget = search.New(
		&PacketSearcher{
			resultChan: searchCh,
		},
		listSearchCallbacks,
		structSearchCallbacks,
		bytesSearchCallbacks,
		filterSearchCallbacks,
		&multiMenu1Opener,
		savedCompleter{def: FieldCompleter},
		OpenErrorDialog{},
	)
	UI.Filter.SearchWidget = SearchWidget

	//======================================================================

	filterWithoutSearch = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: filterCols,
			D:       units(1),
		},
	})
	UI.Filter.FilterWithoutSearch = filterWithoutSearch

	filterWithSearch = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: filterCols,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: fill.New('━'),
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: SearchWidget,
			D:       units(1),
		},
	})
	UI.Filter.FilterWithSearch = filterWithSearch

	filterHolder = holder.New(filterWithoutSearch)
	UI.Filter.FilterHolder = filterHolder

	filterView := framed.NewUnicode(filterHolder)

	// swallowMovementKeys will prevent cursor movement that is not accepted
	// by the main views (column or pile) to change focus e.g. moving from the
	// packet structure view to the packet list view. Often you'd want this
	// movement to be possible, but in termshark it's more often annoying -
	// you navigate to the top of the packet structure, hit up one more time
	// and you're in the packet list view accidentally, hit down instinctively
	// to go back and you change the selected packet.
	packetListViewWithKeys := appkeys.NewMouse(
		appkeys.New(
			appkeys.New(
				appkeys.New(
					packetListViewHolder,
					ApplyAutoScroll,
					appkeys.Options{
						ApplyBefore: true,
					},
				),
				appKeysResize1,
			),
			widgets.SwallowMovementKeys,
		),
		widgets.SwallowMouseScroll,
	)

	packetStructureViewWithKeys :=
		appkeys.New(
			appkeys.New(
				appkeys.NewMouse(
					appkeys.New(
						appkeys.New(
							packetStructureViewHolder,
							appKeysResize2,
						),
						widgets.SwallowMovementKeys,
					),
					widgets.SwallowMouseScroll,
				),
				copyModeEnterKeys,
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			copyModeExitKeys,
			appkeys.Options{
				ApplyBefore: true,
			},
		)

	packetHexViewHolderWithKeys :=
		appkeys.New(
			appkeys.New(
				appkeys.NewMouse(
					appkeys.New(
						packetHexViewHolder,
						widgets.SwallowMovementKeys,
					),
					widgets.SwallowMouseScroll,
				),
				copyModeEnterKeys,
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			copyModeExitKeys,
			appkeys.Options{
				ApplyBefore: true,
			},
		)

	mainviewRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetListViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolderWithKeys,
			D:       weight(1),
		},
	})
	UI.Layout.MainviewRows = mainviewRows

	mainviewRows.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("mainview", mainviewRows.GetOffsets())
	}))

	viewOnlyPacketList = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetListViewHolder,
			D:       weight(1),
		},
	})
	UI.Layout.ViewOnlyPacketList = viewOnlyPacketList

	viewOnlyPacketStructure = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewHolder,
			D:       weight(1),
		},
	})
	UI.Layout.ViewOnlyPacketStructure = viewOnlyPacketStructure

	viewOnlyPacketHex = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolder,
			D:       weight(1),
		},
	})
	UI.Layout.ViewOnlyPacketHex = viewOnlyPacketHex

	tabViewsForward = make(map[gowid.IWidget]gowid.IWidget)
	tabViewsBackward = make(map[gowid.IWidget]gowid.IWidget)
	UI.Layout.TabViewsForward = tabViewsForward
	UI.Layout.TabViewsBackward = tabViewsBackward

	tabViewsForward[viewOnlyPacketList] = viewOnlyPacketStructure
	tabViewsForward[viewOnlyPacketStructure] = viewOnlyPacketHex
	tabViewsForward[viewOnlyPacketHex] = viewOnlyPacketList

	tabViewsBackward[viewOnlyPacketList] = viewOnlyPacketHex
	tabViewsBackward[viewOnlyPacketStructure] = viewOnlyPacketList
	tabViewsBackward[viewOnlyPacketHex] = viewOnlyPacketStructure

	//======================================================================

	altview1Pile = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: packetListViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewWithKeys,
			D:       weight(1),
		},
	})

	UI.Layout.Altview1Pile = altview1Pile
	altview1Pile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altviewleft", altview1Pile.GetOffsets())
	}))

	altview1PileAndKeys := appkeys.New(altview1Pile, altview1PileKeyPress)

	altview1Cols = resizable.NewColumns([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: altview1PileAndKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: fillVBar,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolderWithKeys,
			D:       weight(1),
		},
	})
	UI.Layout.Altview1Cols = altview1Cols

	altview1Cols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altviewright", altview1Cols.GetOffsets())
	}))

	altview1ColsAndKeys := appkeys.New(altview1Cols, altview1ColsKeyPress)

	altview1OuterRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: altview1ColsAndKeys,
			D:       weight(1),
		},
	})
	UI.Layout.Altview1OuterRows = altview1OuterRows

	//======================================================================

	altview2ColsAndKeys := appkeys.New(
		assignTo(&altview2Cols,
			resizable.NewColumns([]gowid.IContainerWidget{
				&gowid.ContainerWidget{
					IWidget: packetStructureViewWithKeys,
					D:       weight(1),
				},
				&gowid.ContainerWidget{
					IWidget: fillVBar,
					D:       units(1),
				},
				&gowid.ContainerWidget{
					IWidget: packetHexViewHolderWithKeys,
					D:       weight(1),
				},
			}),
		),
		altview2ColsKeyPress,
	)

	UI.Layout.Altview2Cols = altview2Cols
	altview2Cols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2vertical", altview2Cols.GetOffsets())
	}))

	altview2PileAndKeys := appkeys.New(
		assignTo(&altview2Pile,
			resizable.NewPile([]gowid.IContainerWidget{
				&gowid.ContainerWidget{
					IWidget: packetListViewWithKeys,
					D:       weight(1),
				},
				&gowid.ContainerWidget{
					IWidget: divider.NewUnicode(),
					D:       flow,
				},
				&gowid.ContainerWidget{
					IWidget: altview2ColsAndKeys,
					D:       weight(1),
				},
			}),
		),
		altview2PileKeyPress,
	)
	UI.Layout.Altview2Pile = altview2Pile

	altview2Pile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2horizontal", altview2Pile.GetOffsets())
	}))

	altview2OuterRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: altview2PileAndKeys,
			D:       weight(1),
		},
	})
	UI.Layout.Altview2OuterRows = altview2OuterRows

	//======================================================================

	maxViewPath = []interface{}{2, 0} // list, structure or hex - whichever one is selected
	UI.Layout.MaxViewPath = maxViewPath

	mainviewPaths = [][]interface{}{
		{2}, // packet list
		{4}, // packet structure
		{6}, // packet hex
	}
	UI.Layout.MainviewPaths = mainviewPaths

	altview1Paths = [][]interface{}{
		{2, 0, 0}, // packet list
		{2, 0, 2}, // packet structure
		{2, 2},    // packet hex
	}
	UI.Layout.Altview1Paths = altview1Paths

	altview2Paths = [][]interface{}{
		{2, 0},    // packet list
		{2, 2, 0}, // packet structure
		{2, 2, 2}, // packet hex
	}
	UI.Layout.Altview2Paths = altview2Paths

	filterPathMain = []interface{}{1, 0, 1}
	filterPathAlt = []interface{}{1, 0, 1}
	filterPathMax = []interface{}{1, 0, 1}
	UI.Layout.FilterPathMain = filterPathMain
	UI.Layout.FilterPathAlt = filterPathAlt
	UI.Layout.FilterPathMax = filterPathMax

	searchPathMain = []interface{}{1, 2, 6} // 6 is the index of the filter in the search widget
	searchPathAlt = []interface{}{1, 2, 6}
	searchPathMax = []interface{}{1, 2, 6}
	UI.Layout.SearchPathMain = searchPathMain
	UI.Layout.SearchPathAlt = searchPathAlt
	UI.Layout.SearchPathMax = searchPathMax

	mainview = mainviewRows
	altview1 = altview1OuterRows
	altview2 = altview2OuterRows
	UI.Layout.Mainview = mainview
	UI.Layout.Altview1 = altview1
	UI.Layout.Altview2 = altview2

	mainViewNoKeys = holder.New(mainview)
	UI.Widgets.MainViewNoKeys = mainViewNoKeys
	defaultLayout := profiles.ConfString("main.layout", "")
	switch defaultLayout {
	case "altview1":
		mainViewNoKeys = holder.New(altview1)
	case "altview2":
		mainViewNoKeys = holder.New(altview2)
	}

	// <<generalmenu3>>
	menuPathMain = []interface{}{0, 7}
	menuPathAlt = []interface{}{0, 7}
	menuPathMax = []interface{}{0, 7}
	UI.Layout.MenuPathMain = menuPathMain
	UI.Layout.MenuPathAlt = menuPathAlt
	UI.Layout.MenuPathMax = menuPathMax

	buildStreamUi()
	buildFilterConvsMenu()
	buildNamesMenu(app)
	buildFieldsMenu(app)

	mainView = appkeys.New(
		appkeys.New(
			appkeys.New(
				mainViewNoKeys,
				mainKeyPress, // applied after mainViewNoKeys processes the input
			),
			vimKeysMainView,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		searchPacketsMainView,
		appkeys.Options{
			ApplyBefore: true,
		},
	)
	UI.Widgets.MainView = mainView

	//======================================================================

	palette := PaletteSwitcher{
		P1:        &DarkModePalette,
		P2:        &RegularPalette,
		ChooseOne: &DarkMode,
	}

	appViewWithKeys := &prefixKeyWidget{
		IWidget: appkeys.New(
			assignTo(&appViewNoKeys, holder.New(mainView)),
			appKeyPress,
		),
	}

	// For minibuffer
	mbView = holder.New(appViewWithKeys)
	UI.Widgets.MbView = mbView

	if !profiles.ConfBool("main.disable-shark-fin", false) {
		Fin = rossshark.New(mbView)
		UI.Widgets.Fin = Fin

		steerableFin := appkeys.NewMouse(
			appkeys.New(
				Fin,
				func(evk *tcell.EventKey, app gowid.IApp) bool {
					if Fin.Active() {
						switch evk.Key() {
						case tcell.KeyLeft:
							Fin.Dir = rossshark.Backward
						case tcell.KeyRight:
							Fin.Dir = rossshark.Forward
						default:
							Fin.Deactivate()
						}
						return true
					}
					return false
				},
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			func(evm *tcell.EventMouse, app gowid.IApp) bool {
				if Fin.Active() {
					Fin.Deactivate()
					return true
				}
				return false
			},
			appkeys.Options{
				ApplyBefore: true,
			},
		)

		appView = holder.New(steerableFin)
	} else {
		appView = holder.New(mbView)
	}
	UI.Widgets.AppView = appView
	UI.Widgets.AppViewNoKeys = appViewNoKeys

	// A restriction on the multiMenu is that it only holds one open menu, so using
	// this trick, only one menu can be open at a time per multiMenu variable. So
	// I am making two because all I need at the moment is two levels of menu.
	multiMenu.IMenuCompatible = holder.New(appView)
	multiMenu2.IMenuCompatible = holder.New(multiMenu)
	UI.Menus.MultiMenu = multiMenu
	UI.Menus.MultiMenuWidget = multiMenu.IMenuCompatible.(*holder.Widget)
	UI.Menus.MultiMenu2 = multiMenu2
	UI.Menus.MultiMenu2Widget = multiMenu2.IMenuCompatible.(*holder.Widget)

	multiMenu1Opener.under = appView
	multiMenu1Opener.mm = multiMenu
	multiMenu2Opener.under = multiMenu
	multiMenu2Opener.mm = multiMenu2
	UI.Menus.MultiMenu1Opener = multiMenu1Opener
	UI.Menus.MultiMenu2Opener = multiMenu2Opener

	var lastMenu gowid.IWidget = multiMenu2
	menus := []gowid.IMenuCompatible{
		// These menus can both be open at the same time, so I have special
		// handling here. I should use a more general method for all menus. The
		// current method only allows one menu to be open at a time.
		filterConvsMenu1,
		filterConvsMenu2,
	}

	for _, w := range menus {
		w.SetSubWidget(lastMenu, app)
		lastMenu = w
	}

	keyMapper = mapkeys.New(lastMenu)
	UI.Widgets.KeyMapper = keyMapper
	keyMappings := termshark.LoadKeyMappings()
	for _, km := range keyMappings {
		log.Infof("Applying keymapping %v --> %v", km.From, km.To)
		keyMapper.AddMapping(km.From, km.To, app)
	}

	if err = termshark.LoadGlobalMarks(globalMarksMap); err != nil {
		// Not fatal
		log.Error(err)
	}

	// Create app, etc, but don't init screen which sets ICANON, etc
	app, err = gowid.NewApp(gowid.AppArgs{
		View:                 keyMapper,
		Palette:              palette,
		Log:                  log.StandardLogger(),
		EnableBracketedPaste: true,
		DontActivate:         true,
		Tty:                  tty,
	})

	if err != nil {
		return nil, err
	}

	gowid.SetFocusPath(mainview, mainviewPaths[0], app)
	gowid.SetFocusPath(altview1, altview1Paths[0], app)
	gowid.SetFocusPath(altview2, altview2Paths[0], app)

	if offs, err := termshark.LoadOffsetFromConfig("mainview"); err == nil {
		mainviewRows.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altviewleft"); err == nil {
		altview1Pile.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altviewright"); err == nil {
		altview1Cols.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altview2horizontal"); err == nil {
		altview2Pile.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altview2vertical"); err == nil {
		altview2Cols.SetOffsets(offs, app)
	}

	// Wire up Controller callbacks now that the gowid app exists
	SetupControllerCallbacks(app)

	return app, err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
