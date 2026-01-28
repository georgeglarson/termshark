// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewState(t *testing.T) {
	s := NewState()

	assert.NotNil(t, s.LocalMarks)
	assert.NotNil(t, s.GlobalMarks)
	assert.NotNil(t, s.ExpandedNodes)
	assert.NotNil(t, s.PendingRequests)
	assert.Equal(t, -1, s.LastJumpPos)
	assert.Equal(t, -1, s.KeyState.NumberPrefix)
	assert.Empty(t, s.LocalMarks)
	assert.Empty(t, s.GlobalMarks)
}

func TestState_LocalMarks(t *testing.T) {
	s := NewState()

	// Test setting a mark
	mark := MarkPosition{Summary: "test packet", Pos: 42}
	s.SetLocalMark('a', mark)

	// Test getting the mark
	got, ok := s.GetLocalMark('a')
	assert.True(t, ok)
	assert.Equal(t, mark, got)

	// Test getting non-existent mark
	_, ok = s.GetLocalMark('b')
	assert.False(t, ok)

	// Test deleting a mark
	s.DeleteLocalMark('a')
	_, ok = s.GetLocalMark('a')
	assert.False(t, ok)
}

func TestState_GlobalMarks(t *testing.T) {
	s := NewState()

	// Test setting a global mark
	mark := GlobalMarkPosition{
		MarkPosition: MarkPosition{Summary: "test packet", Pos: 42},
		Filename:     "/path/to/file.pcap",
	}
	s.SetGlobalMark('A', mark)

	// Test getting the mark
	got, ok := s.GetGlobalMark('A')
	assert.True(t, ok)
	assert.Equal(t, mark, got)
	assert.True(t, got.IsSet())

	// Test getting non-existent mark
	got, ok = s.GetGlobalMark('B')
	assert.False(t, ok)
	assert.False(t, got.IsSet())

	// Test deleting a global mark
	s.DeleteGlobalMark('A')
	_, ok = s.GetGlobalMark('A')
	assert.False(t, ok)
}

func TestState_GetAllMarks(t *testing.T) {
	s := NewState()

	// Set some marks
	s.SetLocalMark('a', MarkPosition{Pos: 1})
	s.SetLocalMark('b', MarkPosition{Pos: 2})
	s.SetGlobalMark('A', GlobalMarkPosition{MarkPosition: MarkPosition{Pos: 10}, Filename: "file1.pcap"})

	// Get all local marks
	localMarks := s.GetAllLocalMarks()
	assert.Len(t, localMarks, 2)
	assert.Equal(t, 1, localMarks['a'].Pos)
	assert.Equal(t, 2, localMarks['b'].Pos)

	// Get all global marks
	globalMarks := s.GetAllGlobalMarks()
	assert.Len(t, globalMarks, 1)
	assert.Equal(t, 10, globalMarks['A'].Pos)

	// Verify the returned maps are copies (modifying them shouldn't affect state)
	localMarks['c'] = MarkPosition{Pos: 3}
	_, ok := s.GetLocalMark('c')
	assert.False(t, ok)
}

func TestState_PendingRequests(t *testing.T) {
	s := NewState()

	// Add some requests
	s.AddPendingRequest(LoadRequest{Row: 0, CancelCurrent: true})
	s.AddPendingRequest(LoadRequest{Row: 1000, CancelCurrent: false})

	// Get pending requests
	reqs := s.GetPendingRequests()
	assert.Len(t, reqs, 2)
	assert.Equal(t, 0, reqs[0].Row)
	assert.True(t, reqs[0].CancelCurrent)
	assert.Equal(t, 1000, reqs[1].Row)
	assert.False(t, reqs[1].CancelCurrent)

	// Clear requests
	s.ClearPendingRequests()
	reqs = s.GetPendingRequests()
	assert.Empty(t, reqs)
}

func TestState_AutoScroll(t *testing.T) {
	s := NewState()

	assert.False(t, s.GetAutoScroll())

	s.SetAutoScroll(true)
	assert.True(t, s.GetAutoScroll())

	s.SetAutoScroll(false)
	assert.False(t, s.GetAutoScroll())
}

func TestState_CurrentFilter(t *testing.T) {
	s := NewState()

	assert.Empty(t, s.GetCurrentFilter())

	s.SetCurrentFilter("tcp.port == 80")
	assert.Equal(t, "tcp.port == 80", s.GetCurrentFilter())

	s.SetCurrentFilter("")
	assert.Empty(t, s.GetCurrentFilter())
}

func TestState_CurrentPcap(t *testing.T) {
	s := NewState()

	assert.Empty(t, s.GetCurrentPcap())

	s.SetCurrentPcap("/path/to/file.pcap")
	assert.Equal(t, "/path/to/file.pcap", s.GetCurrentPcap())
}

func TestState_LastJumpPos(t *testing.T) {
	s := NewState()

	assert.Equal(t, -1, s.GetLastJumpPos())

	s.SetLastJumpPos(100)
	assert.Equal(t, 100, s.GetLastJumpPos())

	s.SetLastJumpPos(-1)
	assert.Equal(t, -1, s.GetLastJumpPos())
}

func TestState_ColumnFilter(t *testing.T) {
	s := NewState()

	filter, name, value := s.GetColumnFilter()
	assert.Empty(t, filter)
	assert.Empty(t, name)
	assert.Empty(t, value)

	s.SetColumnFilter("tcp.port", "TCP port", "80")
	filter, name, value = s.GetColumnFilter()
	assert.Equal(t, "tcp.port", filter)
	assert.Equal(t, "TCP port", name)
	assert.Equal(t, "80", value)
}

func TestState_DarkMode(t *testing.T) {
	s := NewState()

	assert.False(t, s.GetDarkMode())

	s.SetDarkMode(true)
	assert.True(t, s.GetDarkMode())
}

func TestState_PacketColors(t *testing.T) {
	s := NewState()

	assert.False(t, s.GetPacketColors())

	s.SetPacketColors(true)
	assert.True(t, s.GetPacketColors())
}

func TestState_CurrentPacket(t *testing.T) {
	s := NewState()

	assert.Equal(t, 0, s.GetCurrentPacket())

	s.SetCurrentPacket(42)
	assert.Equal(t, 42, s.GetCurrentPacket())
}

func TestKeyState_Reset(t *testing.T) {
	k := &KeyState{
		NumberPrefix:    5,
		PartialgCmd:     true,
		PartialZCmd:     true,
		PartialCtrlWCmd: true,
		PartialmCmd:     true,
		PartialQuoteCmd: true,
	}

	k.Reset()

	assert.Equal(t, -1, k.NumberPrefix)
	assert.False(t, k.PartialgCmd)
	assert.False(t, k.PartialZCmd)
	assert.False(t, k.PartialCtrlWCmd)
	assert.False(t, k.PartialmCmd)
	assert.False(t, k.PartialQuoteCmd)
}

func TestLoadRequest_ToLoadPcapSlice(t *testing.T) {
	req := LoadRequest{
		Row:           100,
		CancelCurrent: true,
	}

	slice := req.ToLoadPcapSlice()
	assert.Equal(t, 100, slice.Row)
	assert.True(t, slice.CancelCurrent)
}

func TestGlobalMarkPosition_IsSet(t *testing.T) {
	// Empty global mark
	empty := GlobalMarkPosition{}
	assert.False(t, empty.IsSet())

	// Set global mark
	set := GlobalMarkPosition{
		Filename: "/path/to/file.pcap",
	}
	assert.True(t, set.IsSet())
}

func TestState_Concurrency(t *testing.T) {
	s := NewState()
	var wg sync.WaitGroup

	// Run multiple goroutines accessing state concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Mix of reads and writes
			s.SetCurrentPacket(i)
			_ = s.GetCurrentPacket()
			s.SetLocalMark(rune('a'+i%26), MarkPosition{Pos: i})
			_, _ = s.GetLocalMark(rune('a' + i%26))
			s.AddPendingRequest(LoadRequest{Row: i * 1000})
			_ = s.GetPendingRequests()
			s.SetAutoScroll(i%2 == 0)
			_ = s.GetAutoScroll()
		}(i)
	}

	wg.Wait()
	// If we get here without a race condition panic, the test passes
}

func TestState_PdmlPosition(t *testing.T) {
	s := NewState()

	// Initially empty
	pos := s.GetPdmlPosition()
	assert.Empty(t, pos)

	// Set position
	s.SetPdmlPosition([]string{"", "tcp", "tcp.srcport"})
	pos = s.GetPdmlPosition()
	assert.Equal(t, []string{"", "tcp", "tcp.srcport"}, pos)

	// Verify it's a copy
	pos[0] = "modified"
	pos2 := s.GetPdmlPosition()
	assert.Equal(t, "", pos2[0])
}

func TestState_ExpandedNodes(t *testing.T) {
	s := NewState()

	// Initially empty but not nil
	nodes := s.GetExpandedNodes()
	assert.NotNil(t, nodes)
	assert.Empty(t, nodes)

	// Set expanded nodes
	paths := [][]string{
		{"frame", "tcp"},
		{"frame", "ip"},
	}
	s.SetExpandedNodes(paths)

	nodes = s.GetExpandedNodes()
	assert.Len(t, nodes, 2)
	assert.Equal(t, []string{"frame", "tcp"}, nodes[0])
	assert.Equal(t, []string{"frame", "ip"}, nodes[1])
}
