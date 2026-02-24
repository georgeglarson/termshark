// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"bytes"
	"sync"
	"testing"

	"github.com/blang/semver"
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Accessor nil-safety tests
//======================================================================

func TestGetLoader_NilUI(t *testing.T) {
	savedUI := UI
	savedLoader := Loader
	defer func() {
		UI = savedUI
		Loader = savedLoader
	}()

	UI = nil
	Loader = nil
	assert.Nil(t, GetLoader(), "GetLoader should return nil when both UI and Loader are nil")
}

func TestSetLoader_NilUI(t *testing.T) {
	savedUI := UI
	savedLoader := Loader
	defer func() {
		UI = savedUI
		Loader = savedLoader
	}()

	UI = nil
	SetLoader(nil)
	assert.Nil(t, Loader)
}

func TestIsRunning_NilUI(t *testing.T) {
	savedUI := UI
	savedRunning := Running
	defer func() {
		UI = savedUI
		Running = savedRunning
	}()

	UI = nil
	Running = false
	assert.False(t, IsRunning())

	Running = true
	assert.True(t, IsRunning())
}

func TestSetRunning_NilUI(t *testing.T) {
	savedUI := UI
	savedRunning := Running
	defer func() {
		UI = savedUI
		Running = savedRunning
	}()

	UI = nil
	SetRunning(true)
	assert.True(t, Running)

	SetRunning(false)
	assert.False(t, Running)
}

func TestIsQuitRequested_NilUI(t *testing.T) {
	savedUI := UI
	savedQR := QuitRequested
	defer func() {
		UI = savedUI
		QuitRequested = savedQR
	}()

	UI = nil
	QuitRequested = false
	assert.False(t, IsQuitRequested())

	QuitRequested = true
	assert.True(t, IsQuitRequested())
}

func TestSetQuitRequested_NilUI(t *testing.T) {
	savedUI := UI
	savedQR := QuitRequested
	defer func() {
		UI = savedUI
		QuitRequested = savedQR
	}()

	UI = nil
	SetQuitRequested(true)
	assert.True(t, QuitRequested)
	SetQuitRequested(false)
	assert.False(t, QuitRequested)
}

func TestSetQuitRequested_WithUI(t *testing.T) {
	savedUI := UI
	savedQR := QuitRequested
	defer func() {
		UI = savedUI
		QuitRequested = savedQR
	}()

	UI = &UIState{App: NewApplicationState()}
	SetQuitRequested(true)
	assert.True(t, UI.App.QuitRequested)
	assert.True(t, QuitRequested)
}

func TestIsDarkMode_NilUI(t *testing.T) {
	savedUI := UI
	savedDM := DarkMode
	defer func() {
		UI = savedUI
		DarkMode = savedDM
	}()

	UI = nil
	DarkMode = true
	assert.True(t, IsDarkMode())

	DarkMode = false
	assert.False(t, IsDarkMode())
}

func TestIsDarkMode_WithUI(t *testing.T) {
	savedUI := UI
	savedDM := DarkMode
	defer func() {
		UI = savedUI
		DarkMode = savedDM
	}()

	UI = &UIState{App: NewApplicationState()}
	UI.App.DarkMode = true
	assert.True(t, IsDarkMode())

	UI.App.DarkMode = false
	assert.False(t, IsDarkMode())
}

func TestIsPacketColorsEnabled_NilUI(t *testing.T) {
	savedUI := UI
	savedPC := PacketColors
	defer func() {
		UI = savedUI
		PacketColors = savedPC
	}()

	UI = nil
	PacketColors = true
	assert.True(t, IsPacketColorsEnabled())

	PacketColors = false
	assert.False(t, IsPacketColorsEnabled())
}

func TestIsPacketColorsSupported_NilUI(t *testing.T) {
	savedUI := UI
	savedPCS := PacketColorsSupported
	defer func() {
		UI = savedUI
		PacketColorsSupported = savedPCS
	}()

	UI = nil
	PacketColorsSupported = true
	assert.True(t, IsPacketColorsSupported())
}

func TestSetPacketColorsSupportedState(t *testing.T) {
	savedUI := UI
	savedPCS := PacketColorsSupported
	defer func() {
		UI = savedUI
		PacketColorsSupported = savedPCS
	}()

	UI = &UIState{App: NewApplicationState()}
	SetPacketColorsSupportedState(true)
	assert.True(t, UI.App.PacketColorsSupported)
	assert.True(t, PacketColorsSupported)
}

func TestIsAutoScrollEnabled_NilUI(t *testing.T) {
	savedUI := UI
	savedAS := AutoScroll
	defer func() {
		UI = savedUI
		AutoScroll = savedAS
	}()

	UI = nil
	AutoScroll = true
	assert.True(t, IsAutoScrollEnabled())
}

func TestGetWriteToSelected_NilUI(t *testing.T) {
	savedUI := UI
	savedWTS := WriteToSelected
	defer func() {
		UI = savedUI
		WriteToSelected = savedWTS
	}()

	UI = nil
	WriteToSelected = true
	assert.True(t, GetWriteToSelected())
}

func TestSetWriteToSelected_WithUI(t *testing.T) {
	savedUI := UI
	savedWTS := WriteToSelected
	defer func() {
		UI = savedUI
		WriteToSelected = savedWTS
	}()

	UI = &UIState{App: NewApplicationState()}
	SetWriteToSelected(true)
	assert.True(t, UI.App.WriteToSelected)
	assert.True(t, WriteToSelected)
}

func TestGetWriteToDeleted_NilUI(t *testing.T) {
	savedUI := UI
	savedWTD := WriteToDeleted
	defer func() {
		UI = savedUI
		WriteToDeleted = savedWTD
	}()

	UI = nil
	WriteToDeleted = false
	assert.False(t, GetWriteToDeleted())
}

func TestSetWriteToDeleted_WithUI(t *testing.T) {
	savedUI := UI
	savedWTD := WriteToDeleted
	defer func() {
		UI = savedUI
		WriteToDeleted = savedWTD
	}()

	UI = &UIState{App: NewApplicationState()}
	SetWriteToDeleted(true)
	assert.True(t, UI.App.WriteToDeleted)
	assert.True(t, WriteToDeleted)
}

func TestGetStreamLoader_NilUI(t *testing.T) {
	savedUI := UI
	savedSL := StreamLoader
	defer func() {
		UI = savedUI
		StreamLoader = savedSL
	}()

	UI = nil
	StreamLoader = nil
	assert.Nil(t, GetStreamLoader())
}

func TestGetFin_NilUI(t *testing.T) {
	savedUI := UI
	savedFin := Fin
	defer func() {
		UI = savedUI
		Fin = savedFin
	}()

	UI = nil
	Fin = nil
	assert.Nil(t, GetFin())
}

func TestGetFilterWidget_NilUI(t *testing.T) {
	savedUI := UI
	savedFW := FilterWidget
	defer func() {
		UI = savedUI
		FilterWidget = savedFW
	}()

	UI = nil
	FilterWidget = nil
	assert.Nil(t, GetFilterWidget())
}

func TestGetSearchWidget_NilUI(t *testing.T) {
	savedUI := UI
	savedSW := SearchWidget
	defer func() {
		UI = savedUI
		SearchWidget = savedSW
	}()

	UI = nil
	SearchWidget = nil
	assert.Nil(t, GetSearchWidget())
}

func TestGetCacheRequests_NilUI(t *testing.T) {
	savedUI := UI
	savedCR := CacheRequests
	defer func() {
		UI = savedUI
		CacheRequests = savedCR
	}()

	UI = nil
	CacheRequests = nil
	assert.Nil(t, GetCacheRequests())
}

//======================================================================
// Accessor with partial UI state tests
//======================================================================

func TestGetLoader_UIWithNilApp(t *testing.T) {
	savedUI := UI
	savedLoader := Loader
	defer func() {
		UI = savedUI
		Loader = savedLoader
	}()

	UI = &UIState{App: nil}
	Loader = nil
	assert.Nil(t, GetLoader(), "Should fall through to global when App is nil")
}

func TestIsRunning_UIWithNilApp(t *testing.T) {
	savedUI := UI
	savedRunning := Running
	defer func() {
		UI = savedUI
		Running = savedRunning
	}()

	UI = &UIState{App: nil}
	Running = true
	assert.True(t, IsRunning(), "Should fall through to global when App is nil")
}

func TestGetFilterWidget_UIWithNilFilter(t *testing.T) {
	savedUI := UI
	savedFW := FilterWidget
	defer func() {
		UI = savedUI
		FilterWidget = savedFW
	}()

	UI = &UIState{Filter: nil}
	FilterWidget = nil
	assert.Nil(t, GetFilterWidget(), "Should fall through to global when Filter is nil")
}

func TestGetStreamLoader_UIWithNilFeatures(t *testing.T) {
	savedUI := UI
	savedSL := StreamLoader
	defer func() {
		UI = savedUI
		StreamLoader = savedSL
	}()

	UI = &UIState{Features: nil}
	StreamLoader = nil
	assert.Nil(t, GetStreamLoader(), "Should fall through to global when Features is nil")
}

func TestGetQuitRequestedChan_UIWithNilChannels(t *testing.T) {
	savedUI := UI
	savedQRC := QuitRequestedChan
	defer func() {
		UI = savedUI
		QuitRequestedChan = savedQRC
	}()

	UI = &UIState{Channels: nil}
	ch := make(chan struct{}, 1)
	QuitRequestedChan = ch
	assert.Equal(t, ch, GetQuitRequestedChan(), "Should fall through to global when Channels is nil")
}

//======================================================================
// SetRunning with full UI path tests
//======================================================================

func TestSetRunning_UpdatesBothUIAndGlobal(t *testing.T) {
	savedUI := UI
	savedRunning := Running
	defer func() {
		UI = savedUI
		Running = savedRunning
	}()

	UI = &UIState{App: NewApplicationState()}
	SetRunning(true)
	assert.True(t, UI.App.Running)
	assert.True(t, Running)

	SetRunning(false)
	assert.False(t, UI.App.Running)
	assert.False(t, Running)
}

//======================================================================
// SearchStopper extra tests
//======================================================================

func TestSearchStopper_MultipleRequestStops(t *testing.T) {
	s := &SearchStopper{}
	s.RequestStop(nil)
	s.RequestStop(nil)
	s.RequestStop(nil)

	callCount := 0
	s.DoIfStopped(func() { callCount++ })
	assert.Equal(t, 1, callCount, "Multiple RequestStops should still only fire callback once")
	assert.False(t, s.Requested, "Should be reset after DoIfStopped")
}

func TestSearchStopper_RequestStopAfterDoIfStopped(t *testing.T) {
	s := &SearchStopper{}

	// First cycle
	s.RequestStop(nil)
	called1 := false
	s.DoIfStopped(func() { called1 = true })
	assert.True(t, called1)

	// Second cycle
	s.RequestStop(nil)
	called2 := false
	s.DoIfStopped(func() { called2 = true })
	assert.True(t, called2, "Should be able to request and handle stop again")
}

func TestSearchStopper_ConcurrentRequestAndDoIfStopped(t *testing.T) {
	s := &SearchStopper{}
	var wg sync.WaitGroup
	iterations := 1000

	wg.Add(3)

	// Writer 1
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			s.RequestStop(nil)
		}
	}()

	// Writer 2
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			s.RequestStop(nil)
		}
	}()

	// Reader
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			s.DoIfStopped(func() {})
		}
	}()

	wg.Wait()
	// Success if no data races detected
}

//======================================================================
// PaletteSwitcher extra tests
//======================================================================

func TestPaletteSwitcher_ToggleSwitch(t *testing.T) {
	p1 := newMockPalette("dark", "unique-dark-key")
	p2 := newMockPalette("light", "unique-light-key")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	// With P1 selected
	_, ok := ps.CellStyler("unique-dark-key")
	assert.True(t, ok)
	_, ok = ps.CellStyler("unique-light-key")
	assert.False(t, ok)

	// Toggle to P2
	chooseOne = false
	_, ok = ps.CellStyler("unique-light-key")
	assert.True(t, ok)
	_, ok = ps.CellStyler("unique-dark-key")
	assert.False(t, ok)
}

func TestPaletteSwitcher_EmptyPalettes(t *testing.T) {
	p1 := newMockPalette("empty1")
	p2 := newMockPalette("empty2")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	_, ok := ps.CellStyler("anything")
	assert.False(t, ok, "Empty palette should not have any styles")

	count := 0
	ps.RangeOverPalette(func(key string, value gowid.ICellStyler) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count, "Empty palette should have 0 entries")
}

//======================================================================
// ConvTypes filter builder tests
//======================================================================

func TestConvTypes_EthernetFilter(t *testing.T) {
	fb := convTypes["eth"]
	assert.NotNil(t, fb)
	assert.Equal(t, "Ethernet", fb.String())
	assert.Contains(t, fb.FilterFrom("aa:bb:cc:dd:ee:ff"), "eth.src")
	assert.Contains(t, fb.FilterTo("aa:bb:cc:dd:ee:ff"), "eth.dst")
	assert.Contains(t, fb.FilterAny("aa:bb:cc:dd:ee:ff"), "eth.addr")
}

func TestConvTypes_IPv4Filter(t *testing.T) {
	fb := convTypes["ip"]
	assert.NotNil(t, fb)
	assert.Equal(t, "IPv4", fb.String())
	assert.Contains(t, fb.FilterFrom("10.0.0.1"), "ip.src")
	assert.Contains(t, fb.FilterTo("10.0.0.1"), "ip.dst")
	assert.Contains(t, fb.FilterAny("10.0.0.1"), "ip.addr")
}

func TestConvTypes_IPv6Filter(t *testing.T) {
	fb := convTypes["ipv6"]
	assert.NotNil(t, fb)
	assert.Equal(t, "IPv6", fb.String())
	assert.Contains(t, fb.FilterFrom("::1"), "ipv6.src")
	assert.Contains(t, fb.FilterTo("::1"), "ipv6.dst")
}

func TestConvTypes_UDPFilter(t *testing.T) {
	fb := convTypes["udp"]
	assert.NotNil(t, fb)
	assert.Equal(t, "UDP", fb.String())

	fromFilter := fb.FilterFrom("10.0.0.1", "53")
	assert.Contains(t, fromFilter, "udp.srcport")
	assert.Contains(t, fromFilter, "ip.src")

	toFilter := fb.FilterTo("10.0.0.1", "53")
	assert.Contains(t, toFilter, "udp.dstport")
}

func TestConvTypes_TCPFilter(t *testing.T) {
	fb := convTypes["tcp"]
	assert.NotNil(t, fb)
	assert.Equal(t, "TCP", fb.String())

	fromFilter := fb.FilterFrom("192.168.1.1", "80")
	assert.Contains(t, fromFilter, "tcp.srcport")
	assert.Contains(t, fromFilter, "ip.src")

	anyFilter := fb.FilterAny("192.168.1.1", "443")
	assert.Contains(t, anyFilter, "tcp.port")
}

func TestConvTypes_Indices(t *testing.T) {
	// Ethernet, IPv4, IPv6 have single-element A and B indices
	for _, name := range []string{"eth", "ip", "ipv6"} {
		fb := convTypes[name]
		assert.Equal(t, 1, len(fb.AIndex()), "%s should have 1 A index", name)
		assert.Equal(t, 1, len(fb.BIndex()), "%s should have 1 B index", name)
	}

	// TCP and UDP have two-element indices (addr + port)
	for _, name := range []string{"tcp", "udp"} {
		fb := convTypes[name]
		assert.Equal(t, 2, len(fb.AIndex()), "%s should have 2 A indices", name)
		assert.Equal(t, 2, len(fb.BIndex()), "%s should have 2 B indices", name)
	}
}

func TestConvTypes_TCPABIndices(t *testing.T) {
	fb := convs.TCP{}
	assert.Equal(t, []int{0, 1}, fb.AIndex())
	assert.Equal(t, []int{2, 3}, fb.BIndex())
}

func TestConvTypes_IPv4AIndex(t *testing.T) {
	fb := convs.IPv4{}
	assert.Equal(t, []int{0}, fb.AIndex())
	assert.Equal(t, []int{1}, fb.BIndex())
}

//======================================================================
// Template rendering tests
//======================================================================

func TestWriteVersion_Output(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	WriteVersion(nil, &buf)
	output := buf.String()
	assert.Contains(t, output, "termshark")
}

func TestWriteTsharkVersion_Output(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	ver := semver.Version{Major: 4, Minor: 0, Patch: 1}
	WriteTsharkVersion(nil, "/usr/bin/tshark", ver, &buf)
	output := buf.String()
	assert.Contains(t, output, "4.0.1")
	assert.Contains(t, output, "/usr/bin/tshark")
}

func TestTemplates_Header(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "Header", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "termshark")
	assert.Contains(t, output, "georgeglarson")
}

func TestTemplates_Footer(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "Footer", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "pass-thru")
	assert.Contains(t, output, "tshark")
}

func TestTemplates_UIUserGuide(t *testing.T) {
	EnsureTemplateData()
	TemplateData["CopyCommandMessage"] = "test copy message"
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "UIUserGuide", TemplateData)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "test copy message")
}

func TestTemplates_UIBug(t *testing.T) {
	EnsureTemplateData()
	TemplateData["CopyCommandMessage"] = "report bugs"
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "UIBug", TemplateData)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "report bugs")
}

func TestTemplates_UIFeature(t *testing.T) {
	EnsureTemplateData()
	TemplateData["CopyCommandMessage"] = "request feature"
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "UIFeature", TemplateData)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "request feature")
}

//======================================================================
// Direction, ConvAddr, FilterMask, FilterCombinator enum completeness
//======================================================================

func TestDirection_AllValues(t *testing.T) {
	assert.Equal(t, Direction(0), Any)
	assert.Equal(t, Direction(1), To)
	assert.Equal(t, Direction(2), From)
	// Verify they are distinct
	assert.NotEqual(t, Any, To)
	assert.NotEqual(t, To, From)
	assert.NotEqual(t, Any, From)
}

func TestFilterCombinator_AllValues(t *testing.T) {
	vals := []FilterCombinator{Selected, NotSelected, AndSelected, OrSelected, AndNotSelected, OrNotSelected}
	seen := make(map[FilterCombinator]bool)
	for _, v := range vals {
		assert.False(t, seen[v], "FilterCombinator values should be unique")
		seen[v] = true
	}
	assert.Equal(t, 6, len(seen))
}

//======================================================================
// NewUIState tests
//======================================================================

func TestNewUIState_AllFieldsInitialized(t *testing.T) {
	us := NewUIState()
	assert.NotNil(t, us.App)
	assert.NotNil(t, us.Widgets)
	assert.NotNil(t, us.Layout)
	assert.NotNil(t, us.Menus)
	assert.NotNil(t, us.Packets)
	assert.NotNil(t, us.Filter)
	assert.NotNil(t, us.Progress)
	assert.NotNil(t, us.Nav)
	assert.NotNil(t, us.Channels)
	assert.NotNil(t, us.Keyboard)
	assert.NotNil(t, us.Features)
}

func TestNewChannelState_ChannelsInitialized(t *testing.T) {
	cs := NewChannelState()
	assert.NotNil(t, cs.CacheRequests)
	assert.NotNil(t, cs.CacheRequestsChan)
	assert.NotNil(t, cs.QuitRequestedChan)
	assert.NotNil(t, cs.StartUIChan)
}

func TestNewKeyboardState_Defaults(t *testing.T) {
	ks := NewKeyboardState()
	assert.NotNil(t, ks.MarksMap)
	assert.NotNil(t, ks.GlobalMarksMap)
	assert.Equal(t, -1, ks.LastJumpPos)
	assert.Equal(t, -1, ks.KeyState.NumberPrefix)
}

func TestNewLayoutState_MapsInitialized(t *testing.T) {
	ls := NewLayoutState()
	assert.NotNil(t, ls.TabViewsForward)
	assert.NotNil(t, ls.TabViewsBackward)
}

func TestNewPacketState_ExpandedPaths(t *testing.T) {
	ps := NewPacketState()
	assert.NotNil(t, ps.CurExpandedStructNodes)
	assert.Equal(t, 0, len(ps.CurExpandedStructNodes))
}

//======================================================================
// CloseWidgets nil-safety test
//======================================================================

func TestCloseWidgets_NilWidgets(t *testing.T) {
	savedFW := FilterWidget
	savedSW := SearchWidget
	savedCCW := CurrentColsWidget
	defer func() {
		FilterWidget = savedFW
		SearchWidget = savedSW
		CurrentColsWidget = savedCCW
	}()

	FilterWidget = nil
	SearchWidget = nil
	CurrentColsWidget = nil

	// Should not panic with all nil widgets
	assert.NotPanics(t, func() {
		CloseWidgets(nil)
	})
}

//======================================================================
// OfficialNameToType mapping test
//======================================================================

func TestOfficialNameToType(t *testing.T) {
	expected := map[string]string{
		"Ethernet": "eth",
		"IPv4":     "ip",
		"IPv6":     "ipv6",
		"UDP":      "udp",
		"TCP":      "tcp",
	}
	for name, short := range expected {
		got, ok := convs.OfficialNameToType[name]
		assert.True(t, ok, "OfficialNameToType should contain %q", name)
		assert.Equal(t, short, got, "OfficialNameToType[%q] should be %q", name, short)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
