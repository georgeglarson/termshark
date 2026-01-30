// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"github.com/gcla/termshark/v2/pkg/state"
)

// PacketLoaderAdapter wraps a PacketLoader to implement state.LoaderAdapter.
type PacketLoaderAdapter struct {
	loader *PacketLoader
}

// NewPacketLoaderAdapter creates a new adapter wrapping the given loader.
func NewPacketLoaderAdapter(loader *PacketLoader) *PacketLoaderAdapter {
	return &PacketLoaderAdapter{loader: loader}
}

// PsmlData returns the packet summary data.
func (a *PacketLoaderAdapter) PsmlData() [][]string {
	if a.loader == nil || a.loader.PsmlLoader == nil {
		return nil
	}
	return a.loader.PsmlLoader.PsmlData()
}

// PsmlHeaders returns the column headers.
func (a *PacketLoaderAdapter) PsmlHeaders() []string {
	if a.loader == nil || a.loader.PsmlLoader == nil {
		return nil
	}
	return a.loader.PsmlLoader.PsmlHeaders()
}

// PsmlColors returns the colors for each packet.
func (a *PacketLoaderAdapter) PsmlColors() []state.PacketColor {
	if a.loader == nil || a.loader.PsmlLoader == nil {
		return nil
	}
	colors := a.loader.PsmlLoader.PsmlColors()
	result := make([]state.PacketColor, len(colors))
	for i, c := range colors {
		result[i] = state.PacketColor{
			FG: c.FG,
			BG: c.BG,
		}
	}
	return result
}

// PacketNumberMap returns a copy of the mapping from packet number to row index.
func (a *PacketLoaderAdapter) PacketNumberMap() map[int]int {
	if a.loader == nil || a.loader.PsmlLoader == nil {
		return nil
	}
	a.loader.PsmlLoader.Lock()
	defer a.loader.PsmlLoader.Unlock()
	result := make(map[int]int, len(a.loader.PsmlLoader.PacketNumberMap))
	for k, v := range a.loader.PsmlLoader.PacketNumberMap {
		result[k] = v
	}
	return result
}

// DisplayFilter returns the current display filter.
func (a *PacketLoaderAdapter) DisplayFilter() string {
	if a.loader == nil || a.loader.ParentLoader == nil {
		return ""
	}
	return a.loader.ParentLoader.displayFilter
}

// Pcap returns the current pcap file path.
func (a *PacketLoaderAdapter) Pcap() string {
	if a.loader == nil || a.loader.ParentLoader == nil {
		return ""
	}
	return a.loader.Pcap()
}

// IsLoading returns whether loading is in progress.
func (a *PacketLoaderAdapter) IsLoading() bool {
	if a.loader == nil || a.loader.PsmlLoader == nil {
		return false
	}
	return a.loader.PsmlLoader.IsLoading()
}

var _ state.LoaderAdapter = (*PacketLoaderAdapter)(nil)
