// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"errors"
	"path/filepath"
	"unicode"
)

//======================================================================
// Mark errors
//======================================================================

var (
	// ErrMarkNotFound indicates the requested mark does not exist.
	ErrMarkNotFound = errors.New("mark not found")

	// ErrInvalidMark indicates the mark character is not valid.
	ErrInvalidMark = errors.New("invalid mark character")

	// ErrNoPacketInFocus indicates no packet is currently selected.
	ErrNoPacketInFocus = errors.New("no packet in focus")

	// ErrNoPcapLoaded indicates no pcap file is loaded.
	ErrNoPcapLoaded = errors.New("no pcap file loaded")
)

//======================================================================
// Mark validation
//======================================================================

// IsLocalMark returns true if the rune is a valid local mark (a-z).
func IsLocalMark(r rune) bool {
	return r >= 'a' && r <= 'z'
}

// IsGlobalMark returns true if the rune is a valid global mark (A-Z).
func IsGlobalMark(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

// IsValidMark returns true if the rune is a valid mark character.
func IsValidMark(r rune) bool {
	return IsLocalMark(r) || IsGlobalMark(r)
}

// ValidateMarkChar validates a mark character and returns an error if invalid.
func ValidateMarkChar(r rune) error {
	if !IsValidMark(r) {
		return ErrInvalidMark
	}
	return nil
}

//======================================================================
// Jump result types
//======================================================================

// JumpResult represents the result of a jump to mark operation.
type JumpResult struct {
	// TargetPacket is the packet number to jump to.
	TargetPacket int

	// NeedsPcapLoad is true if a different pcap file needs to be loaded.
	NeedsPcapLoad bool

	// PcapToLoad is the path to the pcap file to load (only if NeedsPcapLoad is true).
	PcapToLoad string

	// PreviousPosition is the position before the jump (for implementing '').
	PreviousPosition int

	// Error is set if the jump cannot be performed.
	Error error
}

// IsSuccess returns true if the jump result indicates success.
func (j JumpResult) IsSuccess() bool {
	return j.Error == nil
}

//======================================================================
// Mark operations on State
//======================================================================

// SetMark sets a mark (local or global) at the current packet position.
// For global marks, the current pcap filename must be provided.
//
// Parameters:
//   - state: the application state
//   - mark: the mark character (a-z for local, A-Z for global)
//   - currentPacket: the current packet position
//   - summary: a summary of the packet for display
//   - currentPcap: the current pcap filename (required for global marks)
//
// Returns an error if the mark character is invalid or if a global mark
// is set without a pcap file.
func SetMark(state *State, mark rune, currentPacket int, summary string, currentPcap string) error {
	if err := ValidateMarkChar(mark); err != nil {
		return err
	}

	pos := MarkPosition{
		Pos:     currentPacket,
		Summary: summary,
	}

	if IsLocalMark(mark) {
		state.SetLocalMark(mark, pos)
		return nil
	}

	// Global mark requires a pcap file
	if currentPcap == "" {
		return ErrNoPcapLoaded
	}

	state.SetGlobalMark(mark, GlobalMarkPosition{
		MarkPosition: pos,
		Filename:     currentPcap,
	})

	return nil
}

// JumpToMark computes the result of jumping to a mark.
//
// Parameters:
//   - state: the application state
//   - mark: the mark character to jump to
//   - currentPacket: the current packet position (saved for jump-to-previous-position)
//   - currentPcap: the current pcap filename
//
// Returns a JumpResult indicating whether the jump can be performed
// and any special actions needed (like loading a different pcap).
func JumpToMark(state *State, mark rune, currentPacket int, currentPcap string) JumpResult {
	if err := ValidateMarkChar(mark); err != nil {
		return JumpResult{Error: err}
	}

	result := JumpResult{
		PreviousPosition: currentPacket,
	}

	if IsLocalMark(mark) {
		pos, ok := state.GetLocalMark(mark)
		if !ok {
			result.Error = ErrMarkNotFound
			return result
		}
		result.TargetPacket = pos.Pos
		return result
	}

	// Global mark
	pos, ok := state.GetGlobalMark(mark)
	if !ok {
		result.Error = ErrMarkNotFound
		return result
	}

	result.TargetPacket = pos.Pos

	// Check if we need to load a different pcap
	if pos.Filename != currentPcap {
		result.NeedsPcapLoad = true
		result.PcapToLoad = pos.Filename
	}

	return result
}

// JumpToLastPosition jumps back to the last position before a mark jump.
// This implements the vi jump-to-previous-position command (two single quotes).
//
// Parameters:
//   - state: the application state
//   - currentPacket: the current packet position
//
// Returns the packet number to jump to, or -1 if no previous position exists.
func JumpToLastPosition(state *State, currentPacket int) int {
	lastPos := state.GetLastJumpPos()
	if lastPos < 0 {
		return -1
	}

	// Save current position as the new last jump position
	state.SetLastJumpPos(currentPacket)

	return lastPos
}

// ClearLocalMarks removes all local marks from state.
func ClearLocalMarks(state *State) {
	// Get all local marks and delete them
	marks := state.GetAllLocalMarks()
	for mark := range marks {
		state.DeleteLocalMark(mark)
	}
}

// DeleteMark removes a specific mark (local or global).
func DeleteMark(state *State, mark rune) error {
	if err := ValidateMarkChar(mark); err != nil {
		return err
	}

	if IsLocalMark(mark) {
		state.DeleteLocalMark(mark)
	} else {
		state.DeleteGlobalMark(mark)
	}

	return nil
}

//======================================================================
// Utility functions for global marks
//======================================================================

// GlobalMarkBase returns just the filename (without directory) for a global mark.
func GlobalMarkBase(gm GlobalMarkPosition) string {
	return filepath.Base(gm.Filename)
}

// FormatMarkInfo formats mark information for display.
func FormatMarkInfo(mark rune, packet int) string {
	if unicode.IsUpper(mark) {
		return formatGlobalMarkInfo(mark, packet)
	}
	return formatLocalMarkInfo(mark, packet)
}

func formatLocalMarkInfo(mark rune, packet int) string {
	return string(mark) + ": packet " + itoa(packet)
}

func formatGlobalMarkInfo(mark rune, packet int) string {
	return string(mark) + ": packet " + itoa(packet)
}

// itoa is a simple int to string conversion without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := false
	if i < 0 {
		negative = true
		i = -i
	}

	digits := make([]byte, 0, 10)
	for i > 0 {
		digits = append(digits, byte('0'+i%10))
		i /= 10
	}

	// Reverse
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}

	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

//======================================================================
// Mark counts
//======================================================================

// LocalMarkCount returns the number of local marks set.
func LocalMarkCount(state *State) int {
	return len(state.GetAllLocalMarks())
}

// GlobalMarkCount returns the number of global marks set.
func GlobalMarkCount(state *State) int {
	return len(state.GetAllGlobalMarks())
}

// TotalMarkCount returns the total number of marks set.
func TotalMarkCount(state *State) int {
	return LocalMarkCount(state) + GlobalMarkCount(state)
}
