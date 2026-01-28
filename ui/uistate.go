// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"context"
	"sync"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/progress"
	"github.com/gcla/gowid/widgets/spinner"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/app"
	"github.com/gcla/termshark/v2/pkg/capinfo"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/pkg/streams"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetree"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/ifwidget"
	"github.com/gcla/termshark/v2/widgets/mapkeys"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/gcla/termshark/v2/widgets/rossshark"
	"github.com/gcla/termshark/v2/widgets/search"
	"github.com/gcla/termshark/v2/widgets/wormhole"
	lru "github.com/hashicorp/golang-lru"
)

//======================================================================
// UIState is the central container for all UI state.
// This replaces the scattered global variables throughout the ui package.
//======================================================================

// UI is the package-level UIState instance.
// It is initialized in Build() before any widgets are created.
var UI *UIState

// UIState holds all UI-related state organized into logical groups.
type UIState struct {
	App      *ApplicationState
	Widgets  *WidgetState
	Layout   *LayoutState
	Menus    *MenuState
	Packets  *PacketState
	Filter   *FilterState
	Progress *ProgressState
	Nav      *NavigationState
	Channels *ChannelState
	Keyboard *KeyboardState
	Features *FeatureState
}

// NewUIState creates a new UIState with all sub-states initialized.
func NewUIState() *UIState {
	return &UIState{
		App:      NewApplicationState(),
		Widgets:  &WidgetState{},
		Layout:   NewLayoutState(),
		Menus:    &MenuState{},
		Packets:  NewPacketState(),
		Filter:   &FilterState{},
		Progress: &ProgressState{},
		Nav:      &NavigationState{},
		Channels: NewChannelState(),
		Keyboard: NewKeyboardState(),
		Features: NewFeatureState(),
	}
}

//======================================================================
// ApplicationState holds core application flags and loaders.
//======================================================================

// ApplicationState contains application-wide state and flags.
type ApplicationState struct {
	Loader                *pcap.PacketLoader
	FieldCompleter        *fields.TSharkFields
	AppController         *app.Controller
	WriteToSelected       bool
	WriteToDeleted        bool
	DarkMode              bool
	PacketColors          bool
	PacketColorsSupported bool
	AutoScroll            bool
	NewPacketsArrived     bool
	ReenableAutoScroll    bool
	Running               bool
	QuitRequested         bool
	EmptyStructViewTimer  *time.Timer
	EmptyHexViewTimer     *time.Timer
}

// NewApplicationState creates a new ApplicationState with defaults.
func NewApplicationState() *ApplicationState {
	return &ApplicationState{}
}

//======================================================================
// WidgetState holds core widget references.
//======================================================================

// WidgetState contains core widget references used throughout the UI.
type WidgetState struct {
	AppViewNoKeys             *holder.Widget
	AppView                   *holder.Widget
	MbView                    *holder.Widget
	MainViewNoKeys            *holder.Widget
	MainView                  *appkeys.KeyWidget
	PleaseWaitSpinner         *spinner.Widget
	KeyMapper                 *mapkeys.Widget
	Nullw                     *null.Widget
	FillSpace                 *fill.Widget
	FillVBar                  *fill.Widget
	ColSpace                  *gowid.ContainerWidget
	Loadingw                  gowid.IWidget
	MissingMsgw               gowid.IWidget
	SinglePacketViewMsgHolder *holder.Widget
	CopyModeWidget            gowid.IWidget
	CopyModePredicate         ifwidget.Predicate
	Fin                       *rossshark.Widget
}

//======================================================================
// LayoutState holds view layout and navigation paths.
//======================================================================

// LayoutState contains view hierarchy and navigation paths.
type LayoutState struct {
	// Main views
	MainviewRows      *resizable.PileWidget
	Mainview          gowid.IWidget
	Altview1          gowid.IWidget
	Altview1OuterRows *resizable.PileWidget
	Altview1Pile      *resizable.PileWidget
	Altview1Cols      *resizable.ColumnsWidget
	Altview2          gowid.IWidget
	Altview2OuterRows *resizable.PileWidget
	Altview2Pile      *resizable.PileWidget
	Altview2Cols      *resizable.ColumnsWidget

	// View-only modes
	ViewOnlyPacketList      *pile.Widget
	ViewOnlyPacketStructure *pile.Widget
	ViewOnlyPacketHex       *pile.Widget

	// Navigation paths
	MainviewPaths  [][]interface{}
	Altview1Paths  [][]interface{}
	Altview2Paths  [][]interface{}
	MaxViewPath    []interface{}
	FilterPathMain []interface{}
	FilterPathAlt  []interface{}
	FilterPathMax  []interface{}
	SearchPathMain []interface{}
	SearchPathAlt  []interface{}
	SearchPathMax  []interface{}
	MenuPathMain   []interface{}
	MenuPathAlt    []interface{}
	MenuPathMax    []interface{}

	// View indices
	View1idx int
	View2idx int

	// Tab navigation maps
	TabViewsForward  map[gowid.IWidget]gowid.IWidget
	TabViewsBackward map[gowid.IWidget]gowid.IWidget
}

// NewLayoutState creates a new LayoutState with initialized maps.
func NewLayoutState() *LayoutState {
	return &LayoutState{
		TabViewsForward:  make(map[gowid.IWidget]gowid.IWidget),
		TabViewsBackward: make(map[gowid.IWidget]gowid.IWidget),
	}
}

//======================================================================
// MenuState holds menu widgets and sites.
//======================================================================

// MenuState contains menu widgets and their sites.
type MenuState struct {
	GeneralMenu      *menu.Widget
	AnalysisMenu     *menu.Widget
	SavedMenu        *menu.Widget
	ProfileMenu      *menu.Widget
	OpenMenuSite     *menu.SiteWidget
	OpenAnalysisSite *menu.SiteWidget
	OpenProfileSite  *menu.SiteWidget

	// Multi-menu system
	MultiMenu        *MenuHolder
	MultiMenuWidget  *holder.Widget
	MultiMenu2       *MenuHolder
	MultiMenu2Widget *holder.Widget
	MultiMenu1Opener MultiMenuOpener
	MultiMenu2Opener MultiMenuOpener

	// Saved menu
	SavedListBoxWidgetHolder *holder.Widget
}

//======================================================================
// PacketState holds packet display widgets and caches.
//======================================================================

// PacketState contains packet view widgets and current packet state.
type PacketState struct {
	// View holders
	PacketListViewHolder      *holder.Widget
	PacketStructureViewHolder *holder.Widget
	PacketHexViewHolder       *holder.Widget

	// Packet list
	PacketListTable *table.BoundedWidget
	PacketListView  *psmlTableRowWidget

	// Packet structure
	CurPacketStructWidget *copymodetree.Widget

	// Caches
	PacketHexWidgets *lru.Cache

	// Current packet position state
	CurSearchPosition      tree.IPos
	CurExpandedStructNodes pdmltree.ExpandedPaths
	CurStructPosition      tree.IPos
	CurPdmlPosition        []string
	CurStructWidgetState   interface{}
	CurColumnFilter        string
	CurColumnFilterName    string
	CurColumnFilterValue   string

	// Hex-to-struct repositioning flag
	AllowHexToStructRepositioning bool
}

// NewPacketState creates a new PacketState with initialized slices.
func NewPacketState() *PacketState {
	return &PacketState{
		CurExpandedStructNodes: make(pdmltree.ExpandedPaths, 0, 20),
	}
}

//======================================================================
// FilterState holds filter and search widgets.
//======================================================================

// FilterState contains filter and search widgets.
type FilterState struct {
	FilterWidget        *filter.Widget
	SearchWidget        *search.Widget
	FilterCols          *columns.Widget
	FilterWithSearch    gowid.IWidget
	FilterWithoutSearch gowid.IWidget
	FilterHolder        *holder.Widget
}

//======================================================================
// ProgressState holds progress indicators.
//======================================================================

// ProgressState contains progress display widgets.
type ProgressState struct {
	ProgressHolder    *holder.Widget
	ProgressOwner     WidgetOwner
	LoadProgress      *progress.Widget
	LoadSpinner       *spinner.Widget
	LoadProg          *columns.Widget
	LoadStop          *button.Widget
	SearchProg        *columns.Widget
	SearchStop        *button.Widget
	ProgWidgetIdx     int
	StopCurrentSearch search.IRequestStop
}

//======================================================================
// NavigationState holds profile and capture display.
//======================================================================

// NavigationState contains profile and capture display widgets.
type NavigationState struct {
	CurrentProfile             *text.Widget
	CurrentProfileWidget       *columns.Widget
	CurrentProfileWidgetHolder *holder.Widget
	CurrentCapture             *text.Widget
	CurrentCaptureWidget       *columns.Widget
	CurrentCaptureWidgetHolder *holder.Widget
}

//======================================================================
// ChannelState holds communication channels.
//======================================================================

// ChannelState contains channels for inter-component communication.
type ChannelState struct {
	CacheRequests     []pcap.LoadPcapSlice
	CacheRequestsChan chan struct{}
	QuitRequestedChan chan struct{}
	StartUIChan       chan struct{}
	StartUIOnce       sync.Once
}

// NewChannelState creates a new ChannelState with initialized channels.
func NewChannelState() *ChannelState {
	return &ChannelState{
		CacheRequests:     make([]pcap.LoadPcapSlice, 0),
		CacheRequestsChan: make(chan struct{}, 1000),
		QuitRequestedChan: make(chan struct{}, 1),
		StartUIChan:       make(chan struct{}, 1),
	}
}

//======================================================================
// KeyboardState holds keyboard and mark state.
//======================================================================

// KeyboardState contains keyboard state for vim-like operations.
type KeyboardState struct {
	KeyState       termshark.KeyState
	MarksMap       map[rune]termshark.JumpPos
	GlobalMarksMap map[rune]termshark.GlobalJumpPos
	LastJumpPos    int
	NoGlobalJump   termshark.GlobalJumpPos
}

// NewKeyboardState creates a new KeyboardState with initialized maps.
func NewKeyboardState() *KeyboardState {
	ks := &KeyboardState{
		MarksMap:       make(map[rune]termshark.JumpPos),
		GlobalMarksMap: make(map[rune]termshark.GlobalJumpPos),
		LastJumpPos:    -1,
	}
	ks.KeyState.NumberPrefix = -1
	return ks
}

//======================================================================
// FeatureState holds feature-specific state (streams, convs, etc).
//======================================================================

// FeatureState contains state for specialized features.
type FeatureState struct {
	// Stream UI
	StreamViewNoKeysHolder *holder.Widget
	StreamView             *appkeys.KeyWidget
	ConversationMenu       *menu.Widget
	ConversationMenuHolder *holder.Widget
	StreamsPcapSize        int64
	CurrentStreamKey       *streamKey
	StreamWidgets          *lru.Cache
	StreamLoader           *streams.Loader

	// Conversations UI
	ConvsView     *holder.Widget
	ConvsUi       *ConvsUiWidget
	ConvCancel    context.CancelFunc
	ConvsPcapSize int64

	// Capinfo
	CapinfoLoader *capinfo.Loader
	CapinfoData   string
	CapinfoTime   time.Time

	// PSML Columns
	ColNamesMenu               *menu.Widget
	ColFieldsMenu              *menu.Widget
	CurrentColsWidget          *psmlColumnsModel
	ColsCurrentModelRow        int
	ColNamesMenuListBoxHolder  *holder.Widget
	ColFieldsMenuListBoxHolder *holder.Widget

	// Filter conversations menus
	FilterConvsMenu1     *menu.Widget
	FilterConvsMenu1Site *menu.SiteWidget
	FilterConvsMenu2     *menu.Widget

	// Wormhole
	CurrentWormholeWidget *wormhole.Widget
}

// NewFeatureState creates a new FeatureState.
func NewFeatureState() *FeatureState {
	return &FeatureState{}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
