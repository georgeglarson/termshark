// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/search"
)

//======================================================================
// Accessor functions for externally-accessed globals.
// These provide a stable API while we migrate from globals to UIState.
//======================================================================

// GetLoader returns the packet loader.
// Deprecated: Access UI.App.Loader directly when migration is complete.
func GetLoader() *pcap.PacketLoader {
	if UI != nil && UI.App != nil {
		return UI.App.Loader
	}
	return Loader // fallback to old global during transition
}

// SetLoader sets the packet loader.
// Deprecated: Access UI.App.Loader directly when migration is complete.
func SetLoader(l *pcap.PacketLoader) {
	if UI != nil && UI.App != nil {
		UI.App.Loader = l
	}
	Loader = l // keep old global in sync during transition
}

// IsRunning returns whether the UI is currently running.
// Deprecated: Access UI.App.Running directly when migration is complete.
func IsRunning() bool {
	if UI != nil && UI.App != nil {
		return UI.App.Running
	}
	return Running // fallback to old global during transition
}

// SetRunning sets the running state.
// Deprecated: Access UI.App.Running directly when migration is complete.
func SetRunning(r bool) {
	if UI != nil && UI.App != nil {
		UI.App.Running = r
	}
	Running = r // keep old global in sync during transition
}

// IsQuitRequested returns whether a quit has been requested.
// Deprecated: Access UI.App.QuitRequested directly when migration is complete.
func IsQuitRequested() bool {
	if UI != nil && UI.App != nil {
		return UI.App.QuitRequested
	}
	return QuitRequested // fallback to old global during transition
}

// SetQuitRequested sets the quit requested state.
// Deprecated: Access UI.App.QuitRequested directly when migration is complete.
func SetQuitRequested(q bool) {
	if UI != nil && UI.App != nil {
		UI.App.QuitRequested = q
	}
	QuitRequested = q // keep old global in sync during transition
}

// GetQuitRequestedChan returns the quit request channel.
// Deprecated: Access UI.Channels.QuitRequestedChan directly when migration is complete.
func GetQuitRequestedChan() chan struct{} {
	if UI != nil && UI.Channels != nil {
		return UI.Channels.QuitRequestedChan
	}
	return QuitRequestedChan // fallback to old global during transition
}

// GetCacheRequestsChan returns the cache requests channel.
// Deprecated: Access UI.Channels.CacheRequestsChan directly when migration is complete.
func GetCacheRequestsChan() chan struct{} {
	if UI != nil && UI.Channels != nil {
		return UI.Channels.CacheRequestsChan
	}
	return CacheRequestsChan // fallback to old global during transition
}

// GetStartUIChan returns the start UI channel.
// Deprecated: Access UI.Channels.StartUIChan directly when migration is complete.
func GetStartUIChan() chan struct{} {
	if UI != nil && UI.Channels != nil {
		return UI.Channels.StartUIChan
	}
	return StartUIChan // fallback to old global during transition
}

// GetFilterWidget returns the filter widget.
// Deprecated: Access UI.Filter.FilterWidget directly when migration is complete.
func GetFilterWidget() *filter.Widget {
	if UI != nil && UI.Filter != nil {
		return UI.Filter.FilterWidget
	}
	return FilterWidget // fallback to old global during transition
}

// GetSearchWidget returns the search widget.
// Deprecated: Access UI.Filter.SearchWidget directly when migration is complete.
func GetSearchWidget() *search.Widget {
	if UI != nil && UI.Filter != nil {
		return UI.Filter.SearchWidget
	}
	return SearchWidget // fallback to old global during transition
}

// Note: DarkMode, PacketColors, and AutoScroll have existing setter functions
// in ui.go that also persist to config. Use those functions instead:
// - SetDarkMode(bool)
// - SetPacketColors(bool)
// - SetAutoScroll(bool)
// The getters below are read-only accessors.

// IsDarkMode returns whether dark mode is enabled.
func IsDarkMode() bool {
	if UI != nil && UI.App != nil {
		return UI.App.DarkMode
	}
	return DarkMode // fallback to old global during transition
}

// IsPacketColorsEnabled returns whether packet colors are enabled.
func IsPacketColorsEnabled() bool {
	if UI != nil && UI.App != nil {
		return UI.App.PacketColors
	}
	return PacketColors // fallback to old global during transition
}

// IsPacketColorsSupported returns whether packet colors are supported.
func IsPacketColorsSupported() bool {
	if UI != nil && UI.App != nil {
		return UI.App.PacketColorsSupported
	}
	return PacketColorsSupported // fallback to old global during transition
}

// SetPacketColorsSupported sets whether packet colors are supported.
// Note: This doesn't persist to config as it's determined at runtime.
func SetPacketColorsSupportedState(supported bool) {
	if UI != nil && UI.App != nil {
		UI.App.PacketColorsSupported = supported
	}
	PacketColorsSupported = supported // keep old global in sync during transition
}

// IsAutoScrollEnabled returns whether auto-scroll is enabled.
func IsAutoScrollEnabled() bool {
	if UI != nil && UI.App != nil {
		return UI.App.AutoScroll
	}
	return AutoScroll // fallback to old global during transition
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
