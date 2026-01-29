// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"
	"sync"
	"time"

	"github.com/gcla/termshark/v2/pkg/state"
)

// LoaderBridge synchronizes a PacketLoader's state to a state.Manager.
// This allows gradual migration of the UI from direct Loader access to Manager access.
type LoaderBridge struct {
	loader  *PacketLoader
	manager *state.Manager
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
}

// NewLoaderBridge creates a bridge between a PacketLoader and a Manager.
func NewLoaderBridge(loader *PacketLoader, manager *state.Manager) *LoaderBridge {
	ctx, cancel := context.WithCancel(context.Background())
	return &LoaderBridge{
		loader:  loader,
		manager: manager,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start begins syncing loader state to manager.
func (b *LoaderBridge) Start() {
	go b.syncLoop()
}

// Stop stops the sync loop.
func (b *LoaderBridge) Stop() {
	b.cancel()
}

// syncLoop periodically syncs loader state to manager.
func (b *LoaderBridge) syncLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.sync()
		}
	}
}

// sync updates the manager with current loader state.
func (b *LoaderBridge) sync() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.loader == nil || b.loader.ParentLoader == nil {
		return
	}

	session := b.manager.Session()
	if session == nil {
		return
	}

	// Sync source
	if pcap := b.loader.Pcap(); pcap != "" {
		session.SetSource(pcap, state.SourceFile)
	} else if iface := b.loader.InterfaceFile(); iface != "" {
		session.SetSource(iface, state.SourceInterface)
	}

	// Sync packet count
	b.loader.PsmlLoader.Lock()
	count := len(b.loader.PsmlLoader.packetPsmlData)
	b.loader.PsmlLoader.Unlock()
	session.SetPacketCount(count)

	// Sync filter
	if filter := b.loader.DisplayFilter(); filter != session.GetStatus().DisplayFilter {
		session.SetDisplayFilter(filter)
	}

	// Sync columns
	b.loader.PsmlLoader.Lock()
	if len(b.loader.PsmlLoader.packetPsmlHeaders) > 0 {
		session.SetColumns(b.loader.PsmlLoader.packetPsmlHeaders)
	}
	b.loader.PsmlLoader.Unlock()

	// Sync loading state
	if b.loader.InterfaceLoader != nil {
		session.SetCaptureRunning(b.loader.PsmlLoader.IsLoading())
	}
}

// Manager returns the underlying manager.
func (b *LoaderBridge) Manager() *state.Manager {
	return b.manager
}

// Loader returns the underlying loader.
func (b *LoaderBridge) Loader() *PacketLoader {
	return b.loader
}
