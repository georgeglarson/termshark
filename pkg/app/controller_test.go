// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewController(t *testing.T) {
	c := NewController()

	assert.NotNil(t, c.State)
	assert.Equal(t, 1000, c.packetsPerLoad)
}

func TestNewControllerWithState(t *testing.T) {
	state := NewState()
	state.SetCurrentPacket(42)

	c := NewControllerWithState(state)

	assert.Equal(t, 42, c.State.GetCurrentPacket())
}

func TestController_SetCurrentPacket(t *testing.T) {
	c := NewController()

	// Track callbacks
	var stateChangeEvents []StateChangeEvent
	var loadRequestEvents []LoadRequestEvent

	c.SetOnStateChange(func(e StateChangeEvent) {
		stateChangeEvents = append(stateChangeEvents, e)
	})
	c.SetOnLoadRequest(func(e LoadRequestEvent) {
		loadRequestEvents = append(loadRequestEvents, e)
	})

	c.SetCurrentPacket(500)

	// Should have emitted state change
	assert.Len(t, stateChangeEvents, 1)
	assert.Equal(t, StateChangePacket, stateChangeEvents[0].Type)
	assert.Equal(t, 500, stateChangeEvents[0].Data)

	// Should have emitted load request
	assert.Len(t, loadRequestEvents, 1)
	assert.Len(t, loadRequestEvents[0].Requests, 2)

	// Verify current packet is set
	assert.Equal(t, 500, c.GetCurrentPacket())
}

func TestController_SetFilter(t *testing.T) {
	c := NewController()

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	// Set filter
	changed := c.SetFilter("tcp")
	assert.True(t, changed)
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangeFilter, events[0].Type)
	assert.Equal(t, "tcp", c.GetFilter())

	// Set same filter - should not change
	changed = c.SetFilter("tcp")
	assert.False(t, changed)
	assert.Len(t, events, 1) // No new event

	// Set different filter
	changed = c.SetFilter("udp")
	assert.True(t, changed)
	assert.Len(t, events, 2)
	assert.Equal(t, "udp", c.GetFilter())
}

func TestController_SetCurrentPcap(t *testing.T) {
	c := NewController()

	// Set up some local marks
	SetMark(c.State, 'a', 10, "test", "old.pcap")
	SetMark(c.State, 'b', 20, "test", "old.pcap")

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	c.SetCurrentPcap("/path/to/new.pcap")

	// Should emit pcap change event
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangePcap, events[0].Type)
	assert.Equal(t, "/path/to/new.pcap", c.GetCurrentPcap())

	// Local marks should be cleared
	assert.Equal(t, 0, LocalMarkCount(c.State))
}

func TestController_SetMarkAtCurrentPacket(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPacket(42)
	c.State.SetCurrentPcap("/path/to/file.pcap")

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	// Set local mark
	err := c.SetMarkAtCurrentPacket('a', "test summary")
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangeMark, events[0].Type)

	mark, ok := c.State.GetLocalMark('a')
	assert.True(t, ok)
	assert.Equal(t, 42, mark.Pos)

	// Set global mark
	err = c.SetMarkAtCurrentPacket('A', "test summary")
	assert.NoError(t, err)

	gmark, ok := c.State.GetGlobalMark('A')
	assert.True(t, ok)
	assert.Equal(t, 42, gmark.Pos)
	assert.Equal(t, "/path/to/file.pcap", gmark.Filename)

	// Invalid mark should emit error
	var errors []ErrorEvent
	c.SetOnError(func(e ErrorEvent) {
		errors = append(errors, e)
	})

	err = c.SetMarkAtCurrentPacket('0', "test")
	assert.Error(t, err)
	assert.Len(t, errors, 1)
}

func TestController_JumpToMark_Local(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPacket(100)
	c.State.SetCurrentPcap("/path/to/file.pcap")
	c.State.SetLocalMark('a', MarkPosition{Pos: 42, Summary: "test"})

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	packet, err := c.JumpToMark('a')

	assert.NoError(t, err)
	assert.Equal(t, 42, packet)
	assert.Equal(t, 42, c.GetCurrentPacket())

	// Should have saved previous position
	assert.Equal(t, 100, c.State.GetLastJumpPos())
}

func TestController_JumpToMark_GlobalSamePcap(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPacket(100)
	c.State.SetCurrentPcap("/path/to/file.pcap")
	c.State.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 200, Summary: "test"},
		Filename:     "/path/to/file.pcap",
	})

	packet, err := c.JumpToMark('A')

	assert.NoError(t, err)
	assert.Equal(t, 200, packet)
	assert.Equal(t, 200, c.GetCurrentPacket())
}

func TestController_JumpToMark_GlobalDifferentPcap(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPacket(100)
	c.State.SetCurrentPcap("/path/to/file.pcap")
	c.State.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 200, Summary: "test"},
		Filename:     "/path/to/other.pcap",
	})

	packet, err := c.JumpToMark('A')

	// Should return the target packet but with a NeedsPcapLoadError
	assert.Equal(t, 200, packet)
	assert.Error(t, err)
	assert.True(t, IsNeedsPcapLoadError(err))

	needsLoad, ok := GetNeedsPcapLoadError(err)
	assert.True(t, ok)
	assert.Equal(t, "/path/to/other.pcap", needsLoad.PcapPath)
	assert.Equal(t, 200, needsLoad.TargetPacket)

	// Current packet should NOT be changed (caller handles loading)
	assert.Equal(t, 100, c.GetCurrentPacket())
}

func TestController_JumpToMark_NotFound(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPcap("/path/to/file.pcap")

	var errors []ErrorEvent
	c.SetOnError(func(e ErrorEvent) {
		errors = append(errors, e)
	})

	packet, err := c.JumpToMark('a')

	assert.Error(t, err)
	assert.Equal(t, -1, packet)
	assert.Len(t, errors, 1)
}

func TestController_JumpToLastPosition(t *testing.T) {
	c := NewController()
	c.State.SetCurrentPacket(100)

	// No previous position
	packet := c.JumpToLastPosition()
	assert.Equal(t, -1, packet)

	// Set up a previous position
	c.State.SetLastJumpPos(50)
	packet = c.JumpToLastPosition()
	assert.Equal(t, 50, packet)
	assert.Equal(t, 50, c.GetCurrentPacket())

	// Last position should now be 100
	assert.Equal(t, 100, c.State.GetLastJumpPos())
}

func TestController_DeleteMark(t *testing.T) {
	c := NewController()
	c.State.SetLocalMark('a', MarkPosition{Pos: 42})

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	err := c.DeleteMark('a')
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangeMark, events[0].Type)

	_, ok := c.State.GetLocalMark('a')
	assert.False(t, ok)
}

func TestController_DeleteMark_InvalidChar(t *testing.T) {
	c := NewController()

	var errors []ErrorEvent
	c.SetOnError(func(e ErrorEvent) {
		errors = append(errors, e)
	})

	err := c.DeleteMark('!')
	assert.Error(t, err)
	assert.Len(t, errors, 1)
}

func TestController_AutoScroll(t *testing.T) {
	c := NewController()

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	assert.False(t, c.GetAutoScroll())

	c.SetAutoScroll(true)
	assert.True(t, c.GetAutoScroll())
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangeAutoScroll, events[0].Type)
	assert.Equal(t, true, events[0].Data)
}

func TestController_DarkMode(t *testing.T) {
	c := NewController()

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	assert.False(t, c.GetDarkMode())

	c.SetDarkMode(true)
	assert.True(t, c.GetDarkMode())
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangeDarkMode, events[0].Type)
}

func TestController_PacketColors(t *testing.T) {
	c := NewController()

	var events []StateChangeEvent
	c.SetOnStateChange(func(e StateChangeEvent) {
		events = append(events, e)
	})

	assert.False(t, c.GetPacketColors())

	c.SetPacketColors(true)
	assert.True(t, c.GetPacketColors())
	assert.Len(t, events, 1)
	assert.Equal(t, StateChangePacketColors, events[0].Type)
}

func TestController_SetPacketsPerLoad(t *testing.T) {
	c := NewController()

	c.SetPacketsPerLoad(500)
	assert.Equal(t, 500, c.packetsPerLoad)

	// Verify prefetch uses new value
	var loadEvents []LoadRequestEvent
	c.SetOnLoadRequest(func(e LoadRequestEvent) {
		loadEvents = append(loadEvents, e)
	})

	c.SetCurrentPacket(300)

	// With 500 packets per load, row 300 is in batch 0 (0-499)
	assert.Len(t, loadEvents, 1)
	assert.Equal(t, 0, loadEvents[0].Requests[0].Row)
}

func TestNeedsPcapLoadError(t *testing.T) {
	err := &NeedsPcapLoadError{
		PcapPath:     "/path/to/file.pcap",
		TargetPacket: 42,
	}

	assert.Contains(t, err.Error(), "/path/to/file.pcap")
	assert.True(t, IsNeedsPcapLoadError(err))

	// Regular error should return false
	assert.False(t, IsNeedsPcapLoadError(ErrMarkNotFound))

	// GetNeedsPcapLoadError
	got, ok := GetNeedsPcapLoadError(err)
	assert.True(t, ok)
	assert.Equal(t, err, got)

	got, ok = GetNeedsPcapLoadError(ErrMarkNotFound)
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestController_NoCallbacksSet(t *testing.T) {
	c := NewController()

	// These should not panic even without callbacks
	c.SetCurrentPacket(100)
	c.SetFilter("tcp")
	c.SetAutoScroll(true)
	_ = c.SetMarkAtCurrentPacket('0', "invalid") // Will emit error
}

func TestController_Integration(t *testing.T) {
	// Integration test simulating a typical workflow
	c := NewController()
	c.SetPacketsPerLoad(1000)

	// Load a pcap
	c.SetCurrentPcap("/capture.pcap")
	c.SetFilter("tcp")

	// Navigate to packet 500
	c.SetCurrentPacket(500)
	assert.Equal(t, 500, c.GetCurrentPacket())

	// Set a local mark
	err := c.SetMarkAtCurrentPacket('a', "interesting packet")
	assert.NoError(t, err)

	// Navigate to packet 2000
	c.SetCurrentPacket(2000)

	// Jump back to mark
	packet, err := c.JumpToMark('a')
	assert.NoError(t, err)
	assert.Equal(t, 500, packet)

	// Jump to last position (2000)
	packet = c.JumpToLastPosition()
	assert.Equal(t, 2000, packet)

	// Set a global mark
	c.SetCurrentPacket(2500)
	err = c.SetMarkAtCurrentPacket('A', "global mark")
	assert.NoError(t, err)

	gmark, ok := c.State.GetGlobalMark('A')
	assert.True(t, ok)
	assert.Equal(t, 2500, gmark.Pos)
	assert.Equal(t, "/capture.pcap", gmark.Filename)
}
