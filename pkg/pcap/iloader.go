// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"

	"github.com/gcla/gowid"
	lru "github.com/hashicorp/golang-lru"
)

// ILoader defines the interface for packet loading that the UI depends on.
// This allows different implementations (PacketLoader, StateBackedLoader).
type ILoader interface {
	// Data access
	PsmlData() [][]string
	PsmlHeaders() []string
	PsmlColors() []PacketColors
	PacketNumberMap() map[int]int
	PacketNumberOrder() map[int]int
	PacketCache() *lru.Cache
	PacketsPerLoad() int

	// State queries
	Pcap() string
	InterfaceFile() string
	DisplayFilter() string
	CaptureFilter() string
	IsLoading() bool
	LoadIsVisible() bool
	LoadWasCancelled() bool
	Context() context.Context
	String() string

	// Loading operations
	LoadPcap(pcap string, displayFilter string, cb Callback, app gowid.IApp)
	LoadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb Callback, app gowid.IApp)
	Reload(filter string, cb Callback, app gowid.IApp)
	Renew()
	ClearPcap(cb Callback, app gowid.IApp)

	// Control operations
	StopLoad()
	StopLoadPsmlAndIface(cb Callback)
	StartLoad(row int)

	// Thread safety
	Lock()
	Unlock()

	// PsmlLoader access (for progress tracking)
	PsmlLoader() IPsmlLoader
	PdmlLoader() IPdmlLoader
}

// IPsmlLoader defines the interface for PSML loading state.
type IPsmlLoader interface {
	IsLoading() bool
	Lock()
	Unlock()
}

// IPdmlLoader defines the interface for PDML loading state.
type IPdmlLoader interface {
	IsLoading() bool
	LoadIsVisible() bool
	Lock()
	Unlock()
}
