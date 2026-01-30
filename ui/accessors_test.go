// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"sync"
	"testing"

	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/stretchr/testify/assert"
)

// TestAccessorsBeforeBuild verifies that accessors return global variables
// before ui.Build() is called (when UI is nil).
func TestAccessorsBeforeBuild(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	defer func() { UI = savedUI }()

	// Simulate state before ui.Build()
	UI = nil

	// Initialize globals like init() does
	QuitRequestedChan = make(chan struct{}, 1)
	CacheRequestsChan = make(chan struct{}, 1000)
	StartUIChan = make(chan struct{}, 1)
	CacheRequests = make([]pcap.LoadPcapSlice, 0)

	// Accessors should return the globals
	assert.Equal(t, QuitRequestedChan, GetQuitRequestedChan(),
		"GetQuitRequestedChan should return global before Build")
	assert.Equal(t, CacheRequestsChan, GetCacheRequestsChan(),
		"GetCacheRequestsChan should return global before Build")
	assert.Equal(t, StartUIChan, GetStartUIChan(),
		"GetStartUIChan should return global before Build")
}

// TestAccessorsAfterBuild verifies that accessors return UI.Channels values
// after ui.Build() is called (when UI is initialized).
func TestAccessorsAfterBuild(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	defer func() { UI = savedUI }()

	// Simulate state after ui.Build() - create a minimal UIState
	UI = &UIState{
		Channels: NewChannelState(),
	}

	// Accessors should return UI.Channels values, not globals
	assert.Equal(t, UI.Channels.QuitRequestedChan, GetQuitRequestedChan(),
		"GetQuitRequestedChan should return UI.Channels value after Build")
	assert.Equal(t, UI.Channels.CacheRequestsChan, GetCacheRequestsChan(),
		"GetCacheRequestsChan should return UI.Channels value after Build")
	assert.Equal(t, UI.Channels.StartUIChan, GetStartUIChan(),
		"GetStartUIChan should return UI.Channels value after Build")

	// Verify these are different from globals (the key insight of the bug)
	assert.NotEqual(t, QuitRequestedChan, GetQuitRequestedChan(),
		"After Build, accessor should NOT return global QuitRequestedChan")
	assert.NotEqual(t, CacheRequestsChan, GetCacheRequestsChan(),
		"After Build, accessor should NOT return global CacheRequestsChan")
	assert.NotEqual(t, StartUIChan, GetStartUIChan(),
		"After Build, accessor should NOT return global StartUIChan")
}

// TestSetCacheRequestsUpdatesBoth verifies that SetCacheRequests updates
// both the global and UI.Channels.CacheRequests.
func TestSetCacheRequestsUpdatesBoth(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	savedCacheRequests := CacheRequests
	defer func() {
		UI = savedUI
		CacheRequests = savedCacheRequests
	}()

	// Simulate state after ui.Build()
	UI = &UIState{
		Channels: NewChannelState(),
	}

	// Create test data
	testReqs := []pcap.LoadPcapSlice{
		{Row: 0, CancelCurrent: false},
		{Row: 100, CancelCurrent: true},
	}

	// Use SetCacheRequests
	SetCacheRequests(testReqs)

	// Both should be updated
	assert.Equal(t, testReqs, CacheRequests,
		"SetCacheRequests should update global")
	assert.Equal(t, testReqs, UI.Channels.CacheRequests,
		"SetCacheRequests should update UI.Channels")
	assert.Equal(t, testReqs, GetCacheRequests(),
		"GetCacheRequests should return the updated value")
}

// TestChannelCommunicationAfterBuild verifies that sending on the accessor
// channel is received by the accessor channel (not the global).
func TestChannelCommunicationAfterBuild(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	defer func() { UI = savedUI }()

	// Simulate state after ui.Build()
	UI = &UIState{
		Channels: NewChannelState(),
	}

	// Send on the accessor channel
	select {
	case GetQuitRequestedChan() <- struct{}{}:
		// Good, sent successfully
	default:
		t.Fatal("Failed to send on GetQuitRequestedChan()")
	}

	// Should be able to receive from the same accessor
	select {
	case <-GetQuitRequestedChan():
		// Good, received successfully
	default:
		t.Fatal("Failed to receive from GetQuitRequestedChan()")
	}

	// The global channel should be empty (nothing was sent there)
	select {
	case <-QuitRequestedChan:
		t.Fatal("Global QuitRequestedChan should be empty")
	default:
		// Good, global is empty as expected
	}
}

// TestCloseStartUIChanAfterBuild verifies that closing GetStartUIChan()
// (via the accessor) closes the channel the main loop listens on.
// This is critical for the live capture flow where packets arriving
// trigger the UI to start.
func TestCloseStartUIChanAfterBuild(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	savedStartUIChan := StartUIChan
	defer func() {
		UI = savedUI
		StartUIChan = savedStartUIChan
		StartUIOnce = sync.Once{}
	}()

	// Reset the sync.Once for testing
	StartUIOnce = sync.Once{}

	// Initialize fresh channels
	StartUIChan = make(chan struct{}, 1)

	// Simulate state after ui.Build() - this is what happens in real code
	UI = &UIState{
		Channels: NewChannelState(),
	}

	// The accessor now returns UI.Channels.StartUIChan (different from global)
	accessorChan := GetStartUIChan()
	assert.NotEqual(t, StartUIChan, accessorChan,
		"After Build, accessor returns different channel than global")

	// Close via accessor (this is what prochandlers.go should do)
	close(GetStartUIChan())

	// Verify we can receive from the accessor channel (it's closed)
	select {
	case <-GetStartUIChan():
		// Good - channel is closed, receive returns immediately
	default:
		t.Fatal("GetStartUIChan() should be closed and receive should succeed")
	}

	// The global channel should NOT be closed
	select {
	case <-StartUIChan:
		t.Fatal("Global StartUIChan should NOT be closed")
	default:
		// Good - global is still open
	}
}

// TestSetStartUIChanToNil verifies that SetStartUIChan(nil) works correctly
// to disable the channel after it's been triggered.
func TestSetStartUIChanToNil(t *testing.T) {
	// Save and restore UI state
	savedUI := UI
	savedStartUIChan := StartUIChan
	defer func() {
		UI = savedUI
		StartUIChan = savedStartUIChan
	}()

	// Simulate state after ui.Build()
	UI = &UIState{
		Channels: NewChannelState(),
	}

	// Set to nil (like activateUI does)
	SetStartUIChan(nil)

	// Both should be nil
	assert.Nil(t, StartUIChan, "Global StartUIChan should be nil")
	assert.Nil(t, UI.Channels.StartUIChan, "UI.Channels.StartUIChan should be nil")
	assert.Nil(t, GetStartUIChan(), "GetStartUIChan() should return nil")
}
