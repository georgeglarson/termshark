// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLocalMark(t *testing.T) {
	// Valid local marks
	for r := 'a'; r <= 'z'; r++ {
		assert.True(t, IsLocalMark(r), "IsLocalMark(%c)", r)
	}

	// Invalid local marks
	assert.False(t, IsLocalMark('A'))
	assert.False(t, IsLocalMark('Z'))
	assert.False(t, IsLocalMark('0'))
	assert.False(t, IsLocalMark(' '))
}

func TestIsGlobalMark(t *testing.T) {
	// Valid global marks
	for r := 'A'; r <= 'Z'; r++ {
		assert.True(t, IsGlobalMark(r), "IsGlobalMark(%c)", r)
	}

	// Invalid global marks
	assert.False(t, IsGlobalMark('a'))
	assert.False(t, IsGlobalMark('z'))
	assert.False(t, IsGlobalMark('0'))
	assert.False(t, IsGlobalMark(' '))
}

func TestIsValidMark(t *testing.T) {
	// Valid marks (a-z, A-Z)
	assert.True(t, IsValidMark('a'))
	assert.True(t, IsValidMark('z'))
	assert.True(t, IsValidMark('A'))
	assert.True(t, IsValidMark('Z'))

	// Invalid marks
	assert.False(t, IsValidMark('0'))
	assert.False(t, IsValidMark(' '))
	assert.False(t, IsValidMark('!'))
}

func TestValidateMarkChar(t *testing.T) {
	assert.NoError(t, ValidateMarkChar('a'))
	assert.NoError(t, ValidateMarkChar('Z'))
	assert.ErrorIs(t, ValidateMarkChar('0'), ErrInvalidMark)
	assert.ErrorIs(t, ValidateMarkChar(' '), ErrInvalidMark)
}

func TestSetMark_Local(t *testing.T) {
	state := NewState()

	err := SetMark(state, 'a', 42, "packet summary", "/path/to/file.pcap")
	assert.NoError(t, err)

	mark, ok := state.GetLocalMark('a')
	assert.True(t, ok)
	assert.Equal(t, 42, mark.Pos)
	assert.Equal(t, "packet summary", mark.Summary)
}

func TestSetMark_Global(t *testing.T) {
	state := NewState()

	err := SetMark(state, 'A', 100, "packet summary", "/path/to/file.pcap")
	assert.NoError(t, err)

	mark, ok := state.GetGlobalMark('A')
	assert.True(t, ok)
	assert.Equal(t, 100, mark.Pos)
	assert.Equal(t, "packet summary", mark.Summary)
	assert.Equal(t, "/path/to/file.pcap", mark.Filename)
}

func TestSetMark_GlobalNoPcap(t *testing.T) {
	state := NewState()

	err := SetMark(state, 'A', 100, "packet summary", "")
	assert.ErrorIs(t, err, ErrNoPcapLoaded)
}

func TestSetMark_InvalidMark(t *testing.T) {
	state := NewState()

	err := SetMark(state, '0', 42, "packet summary", "/path/to/file.pcap")
	assert.ErrorIs(t, err, ErrInvalidMark)
}

func TestJumpToMark_LocalFound(t *testing.T) {
	state := NewState()
	state.SetLocalMark('a', MarkPosition{Pos: 42, Summary: "test"})

	result := JumpToMark(state, 'a', 100, "/path/to/file.pcap")

	assert.True(t, result.IsSuccess())
	assert.Equal(t, 42, result.TargetPacket)
	assert.Equal(t, 100, result.PreviousPosition)
	assert.False(t, result.NeedsPcapLoad)
}

func TestJumpToMark_LocalNotFound(t *testing.T) {
	state := NewState()

	result := JumpToMark(state, 'a', 100, "/path/to/file.pcap")

	assert.False(t, result.IsSuccess())
	assert.ErrorIs(t, result.Error, ErrMarkNotFound)
}

func TestJumpToMark_GlobalSamePcap(t *testing.T) {
	state := NewState()
	state.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 200, Summary: "test"},
		Filename:     "/path/to/file.pcap",
	})

	result := JumpToMark(state, 'A', 100, "/path/to/file.pcap")

	assert.True(t, result.IsSuccess())
	assert.Equal(t, 200, result.TargetPacket)
	assert.False(t, result.NeedsPcapLoad)
}

func TestJumpToMark_GlobalDifferentPcap(t *testing.T) {
	state := NewState()
	state.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 200, Summary: "test"},
		Filename:     "/path/to/other.pcap",
	})

	result := JumpToMark(state, 'A', 100, "/path/to/file.pcap")

	assert.True(t, result.IsSuccess())
	assert.Equal(t, 200, result.TargetPacket)
	assert.True(t, result.NeedsPcapLoad)
	assert.Equal(t, "/path/to/other.pcap", result.PcapToLoad)
}

func TestJumpToMark_GlobalNotFound(t *testing.T) {
	state := NewState()

	result := JumpToMark(state, 'A', 100, "/path/to/file.pcap")

	assert.False(t, result.IsSuccess())
	assert.ErrorIs(t, result.Error, ErrMarkNotFound)
}

func TestJumpToMark_InvalidMark(t *testing.T) {
	state := NewState()

	result := JumpToMark(state, '0', 100, "/path/to/file.pcap")

	assert.False(t, result.IsSuccess())
	assert.ErrorIs(t, result.Error, ErrInvalidMark)
}

func TestJumpToLastPosition(t *testing.T) {
	state := NewState()

	// Initially, no last position
	pos := JumpToLastPosition(state, 100)
	assert.Equal(t, -1, pos)

	// Set a last position
	state.SetLastJumpPos(50)
	pos = JumpToLastPosition(state, 100)
	assert.Equal(t, 50, pos)

	// Now the last position should be 100
	assert.Equal(t, 100, state.GetLastJumpPos())

	// Jump again
	pos = JumpToLastPosition(state, 200)
	assert.Equal(t, 100, pos)
	assert.Equal(t, 200, state.GetLastJumpPos())
}

func TestClearLocalMarks(t *testing.T) {
	state := NewState()
	state.SetLocalMark('a', MarkPosition{Pos: 1})
	state.SetLocalMark('b', MarkPosition{Pos: 2})
	state.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 100},
		Filename:     "file.pcap",
	})

	ClearLocalMarks(state)

	// Local marks should be cleared
	_, ok := state.GetLocalMark('a')
	assert.False(t, ok)
	_, ok = state.GetLocalMark('b')
	assert.False(t, ok)

	// Global marks should remain
	_, ok = state.GetGlobalMark('A')
	assert.True(t, ok)
}

func TestDeleteMark(t *testing.T) {
	state := NewState()
	state.SetLocalMark('a', MarkPosition{Pos: 1})
	state.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 100},
		Filename:     "file.pcap",
	})

	// Delete local mark
	err := DeleteMark(state, 'a')
	assert.NoError(t, err)
	_, ok := state.GetLocalMark('a')
	assert.False(t, ok)

	// Delete global mark
	err = DeleteMark(state, 'A')
	assert.NoError(t, err)
	_, ok = state.GetGlobalMark('A')
	assert.False(t, ok)

	// Invalid mark
	err = DeleteMark(state, '0')
	assert.ErrorIs(t, err, ErrInvalidMark)
}

func TestGlobalMarkBase(t *testing.T) {
	gm := GlobalMarkPosition{
		Filename: "/path/to/some/file.pcap",
	}

	assert.Equal(t, "file.pcap", GlobalMarkBase(gm))
}

func TestFormatMarkInfo(t *testing.T) {
	// Local mark
	info := FormatMarkInfo('a', 42)
	assert.Contains(t, info, "a")
	assert.Contains(t, info, "42")

	// Global mark
	info = FormatMarkInfo('A', 100)
	assert.Contains(t, info, "A")
	assert.Contains(t, info, "100")
}

func TestItoa(t *testing.T) {
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "1", itoa(1))
	assert.Equal(t, "42", itoa(42))
	assert.Equal(t, "12345", itoa(12345))
	assert.Equal(t, "-1", itoa(-1))
	assert.Equal(t, "-42", itoa(-42))
}

func TestMarkCounts(t *testing.T) {
	state := NewState()

	assert.Equal(t, 0, LocalMarkCount(state))
	assert.Equal(t, 0, GlobalMarkCount(state))
	assert.Equal(t, 0, TotalMarkCount(state))

	state.SetLocalMark('a', MarkPosition{Pos: 1})
	state.SetLocalMark('b', MarkPosition{Pos: 2})

	assert.Equal(t, 2, LocalMarkCount(state))
	assert.Equal(t, 0, GlobalMarkCount(state))
	assert.Equal(t, 2, TotalMarkCount(state))

	state.SetGlobalMark('A', GlobalMarkPosition{
		MarkPosition: MarkPosition{Pos: 100},
		Filename:     "file.pcap",
	})

	assert.Equal(t, 2, LocalMarkCount(state))
	assert.Equal(t, 1, GlobalMarkCount(state))
	assert.Equal(t, 3, TotalMarkCount(state))
}

func TestJumpResult_IsSuccess(t *testing.T) {
	success := JumpResult{TargetPacket: 42}
	assert.True(t, success.IsSuccess())

	failure := JumpResult{Error: ErrMarkNotFound}
	assert.False(t, failure.IsSuccess())
}
