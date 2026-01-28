// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package app contains business logic extracted from the UI layer, providing
// testable state management, algorithms, and commands for termshark.
package app

import (
	"sync"

	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
)

//======================================================================

// MarkPosition represents a local mark position within a pcap file.
type MarkPosition struct {
	Summary string `json:"summary"`
	Pos     int    `json:"position"`
}

// GlobalMarkPosition represents a mark that includes the filename,
// allowing jumps across different pcap files.
type GlobalMarkPosition struct {
	MarkPosition
	Filename string `json:"filename"`
}

// IsSet returns true if this global mark has been set.
func (g GlobalMarkPosition) IsSet() bool {
	return g.Filename != ""
}

//======================================================================

// LoadRequest represents a request to load a batch of packets.
type LoadRequest struct {
	Row           int
	CancelCurrent bool
}

// ToLoadPcapSlice converts a LoadRequest to the pcap package type.
func (r LoadRequest) ToLoadPcapSlice() pcap.LoadPcapSlice {
	return pcap.LoadPcapSlice{
		Row:           r.Row,
		CancelCurrent: r.CancelCurrent,
	}
}

//======================================================================

// KeyState stores state for vim-like multi-key sequences.
type KeyState struct {
	NumberPrefix    int
	PartialgCmd     bool
	PartialZCmd     bool
	PartialCtrlWCmd bool
	PartialmCmd     bool
	PartialQuoteCmd bool
}

// Reset clears all partial key state.
func (k *KeyState) Reset() {
	k.NumberPrefix = -1
	k.PartialgCmd = false
	k.PartialZCmd = false
	k.PartialCtrlWCmd = false
	k.PartialmCmd = false
	k.PartialQuoteCmd = false
}

//======================================================================

// State holds the application state that was previously scattered across
// global variables in the UI layer. This makes the state testable and
// allows for cleaner separation between business logic and presentation.
type State struct {
	mu sync.RWMutex

	// Packet navigation
	CurrentPacket int
	StructPosition tree.IPos
	ExpandedNodes  pdmltree.ExpandedPaths

	// Marks for vim-like navigation
	LocalMarks  map[rune]MarkPosition
	GlobalMarks map[rune]GlobalMarkPosition
	LastJumpPos int

	// Display state
	AutoScroll   bool
	DarkMode     bool
	PacketColors bool

	// Loading state
	CurrentFilter string
	CurrentPcap   string

	// Pending cache requests
	PendingRequests []LoadRequest

	// Key state for multi-key vim sequences
	KeyState KeyState

	// PDML position tracking
	PdmlPosition []string // e.g. [ , tcp, tcp.srcport ] -> path from focus to root

	// Column filter state (for the struct view context menu)
	ColumnFilter      string // e.g. tcp.port
	ColumnFilterName  string // e.g. "TCP port"
	ColumnFilterValue string // e.g. "80"
}

// NewState creates a new State with initialized maps and default values.
func NewState() *State {
	s := &State{
		LocalMarks:      make(map[rune]MarkPosition),
		GlobalMarks:     make(map[rune]GlobalMarkPosition),
		ExpandedNodes:   make(pdmltree.ExpandedPaths, 0, 20),
		PendingRequests: make([]LoadRequest, 0),
		LastJumpPos:     -1,
	}
	s.KeyState.NumberPrefix = -1
	return s
}

//======================================================================
// Thread-safe accessors
//======================================================================

// GetCurrentPacket returns the current packet index.
func (s *State) GetCurrentPacket() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentPacket
}

// SetCurrentPacket sets the current packet index.
func (s *State) SetCurrentPacket(packet int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentPacket = packet
}

// GetAutoScroll returns whether auto-scroll is enabled.
func (s *State) GetAutoScroll() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AutoScroll
}

// SetAutoScroll enables or disables auto-scroll.
func (s *State) SetAutoScroll(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AutoScroll = enabled
}

// GetCurrentFilter returns the current display filter.
func (s *State) GetCurrentFilter() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentFilter
}

// SetCurrentFilter sets the current display filter.
func (s *State) SetCurrentFilter(filter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentFilter = filter
}

// GetCurrentPcap returns the current pcap file path.
func (s *State) GetCurrentPcap() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentPcap
}

// SetCurrentPcap sets the current pcap file path.
func (s *State) SetCurrentPcap(pcap string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentPcap = pcap
}

// GetDarkMode returns whether dark mode is enabled.
func (s *State) GetDarkMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.DarkMode
}

// SetDarkMode enables or disables dark mode.
func (s *State) SetDarkMode(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DarkMode = enabled
}

// GetPacketColors returns whether packet colors are enabled.
func (s *State) GetPacketColors() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PacketColors
}

// SetPacketColors enables or disables packet colors.
func (s *State) SetPacketColors(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PacketColors = enabled
}

//======================================================================
// Mark operations
//======================================================================

// GetLocalMark returns the local mark for the given rune, if it exists.
func (s *State) GetLocalMark(mark rune) (MarkPosition, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pos, ok := s.LocalMarks[mark]
	return pos, ok
}

// SetLocalMark sets a local mark.
func (s *State) SetLocalMark(mark rune, pos MarkPosition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LocalMarks[mark] = pos
}

// DeleteLocalMark removes a local mark.
func (s *State) DeleteLocalMark(mark rune) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.LocalMarks, mark)
}

// GetGlobalMark returns the global mark for the given rune, if it exists.
func (s *State) GetGlobalMark(mark rune) (GlobalMarkPosition, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pos, ok := s.GlobalMarks[mark]
	return pos, ok
}

// SetGlobalMark sets a global mark.
func (s *State) SetGlobalMark(mark rune, pos GlobalMarkPosition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GlobalMarks[mark] = pos
}

// DeleteGlobalMark removes a global mark.
func (s *State) DeleteGlobalMark(mark rune) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.GlobalMarks, mark)
}

// GetLastJumpPos returns the last jump position.
func (s *State) GetLastJumpPos() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastJumpPos
}

// SetLastJumpPos sets the last jump position.
func (s *State) SetLastJumpPos(pos int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastJumpPos = pos
}

// GetAllLocalMarks returns a copy of all local marks.
func (s *State) GetAllLocalMarks() map[rune]MarkPosition {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[rune]MarkPosition, len(s.LocalMarks))
	for k, v := range s.LocalMarks {
		result[k] = v
	}
	return result
}

// GetAllGlobalMarks returns a copy of all global marks.
func (s *State) GetAllGlobalMarks() map[rune]GlobalMarkPosition {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[rune]GlobalMarkPosition, len(s.GlobalMarks))
	for k, v := range s.GlobalMarks {
		result[k] = v
	}
	return result
}

//======================================================================
// Pending request operations
//======================================================================

// ClearPendingRequests removes all pending load requests.
func (s *State) ClearPendingRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingRequests = s.PendingRequests[:0]
}

// AddPendingRequest adds a load request to the pending queue.
func (s *State) AddPendingRequest(req LoadRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingRequests = append(s.PendingRequests, req)
}

// GetPendingRequests returns a copy of all pending load requests.
func (s *State) GetPendingRequests() []LoadRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]LoadRequest, len(s.PendingRequests))
	copy(result, s.PendingRequests)
	return result
}

//======================================================================
// Expanded nodes operations
//======================================================================

// GetExpandedNodes returns a copy of the expanded node paths.
func (s *State) GetExpandedNodes() pdmltree.ExpandedPaths {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(pdmltree.ExpandedPaths, len(s.ExpandedNodes))
	copy(result, s.ExpandedNodes)
	return result
}

// SetExpandedNodes sets the expanded node paths.
func (s *State) SetExpandedNodes(paths pdmltree.ExpandedPaths) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpandedNodes = paths
}

//======================================================================
// PDML position operations
//======================================================================

// GetPdmlPosition returns a copy of the current PDML position path.
func (s *State) GetPdmlPosition() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, len(s.PdmlPosition))
	copy(result, s.PdmlPosition)
	return result
}

// SetPdmlPosition sets the current PDML position path.
func (s *State) SetPdmlPosition(path []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PdmlPosition = path
}

//======================================================================
// Column filter operations
//======================================================================

// GetColumnFilter returns the current column filter state.
func (s *State) GetColumnFilter() (filter, name, value string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ColumnFilter, s.ColumnFilterName, s.ColumnFilterValue
}

// SetColumnFilter sets the column filter state.
func (s *State) SetColumnFilter(filter, name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ColumnFilter = filter
	s.ColumnFilterName = name
	s.ColumnFilterValue = value
}
