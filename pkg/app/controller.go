// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"sync"
)

//======================================================================
// Event types for UI callbacks
//======================================================================

// StateChangeType indicates what part of the state changed.
type StateChangeType int

const (
	// StateChangePacket indicates the current packet changed.
	StateChangePacket StateChangeType = iota
	// StateChangeFilter indicates the filter changed.
	StateChangeFilter
	// StateChangePcap indicates a new pcap was loaded.
	StateChangePcap
	// StateChangeMark indicates a mark was set or deleted.
	StateChangeMark
	// StateChangeAutoScroll indicates auto-scroll setting changed.
	StateChangeAutoScroll
	// StateChangeDarkMode indicates dark mode setting changed.
	StateChangeDarkMode
	// StateChangePacketColors indicates packet colors setting changed.
	StateChangePacketColors
)

// StateChangeEvent is emitted when application state changes.
type StateChangeEvent struct {
	Type StateChangeType
	// Optional data related to the change
	Data interface{}
}

// ErrorEvent is emitted when an error occurs.
type ErrorEvent struct {
	Message string
	Err     error
}

// LoadRequestEvent is emitted when packet data should be loaded.
type LoadRequestEvent struct {
	Requests []LoadRequest
}

//======================================================================
// Controller callbacks
//======================================================================

// OnStateChange is called when application state changes.
type OnStateChange func(event StateChangeEvent)

// OnError is called when an error occurs.
type OnError func(event ErrorEvent)

// OnLoadRequest is called when packet data should be loaded.
type OnLoadRequest func(event LoadRequestEvent)

//======================================================================
// Controller
//======================================================================

// Controller coordinates between the application state and the UI layer.
// It provides a clean interface for state mutations and notifies the UI
// of changes via callbacks.
type Controller struct {
	mu sync.RWMutex

	// State is the application state.
	State *State

	// Callbacks for UI notification
	onStateChange OnStateChange
	onError       OnError
	onLoadRequest OnLoadRequest

	// Current pcap loader state (passed from UI)
	packetsPerLoad int
}

// NewController creates a new Controller with initialized state.
func NewController() *Controller {
	return &Controller{
		State:          NewState(),
		packetsPerLoad: 1000, // default
	}
}

// NewControllerWithState creates a new Controller with the provided state.
func NewControllerWithState(state *State) *Controller {
	return &Controller{
		State:          state,
		packetsPerLoad: 1000,
	}
}

//======================================================================
// Callback registration
//======================================================================

// SetOnStateChange registers a callback for state changes.
func (c *Controller) SetOnStateChange(fn OnStateChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = fn
}

// SetOnError registers a callback for errors.
func (c *Controller) SetOnError(fn OnError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onError = fn
}

// SetOnLoadRequest registers a callback for load requests.
func (c *Controller) SetOnLoadRequest(fn OnLoadRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onLoadRequest = fn
}

// SetPacketsPerLoad sets the number of packets loaded per batch.
func (c *Controller) SetPacketsPerLoad(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packetsPerLoad = n
}

//======================================================================
// Internal helpers for emitting events
//======================================================================

func (c *Controller) emitStateChange(changeType StateChangeType, data interface{}) {
	c.mu.RLock()
	fn := c.onStateChange
	c.mu.RUnlock()

	if fn != nil {
		fn(StateChangeEvent{Type: changeType, Data: data})
	}
}

func (c *Controller) emitError(message string, err error) {
	c.mu.RLock()
	fn := c.onError
	c.mu.RUnlock()

	if fn != nil {
		fn(ErrorEvent{Message: message, Err: err})
	}
}

func (c *Controller) emitLoadRequest(requests []LoadRequest) {
	c.mu.RLock()
	fn := c.onLoadRequest
	c.mu.RUnlock()

	if fn != nil {
		fn(LoadRequestEvent{Requests: requests})
	}
}

//======================================================================
// Packet navigation
//======================================================================

// SetCurrentPacket sets the current packet and triggers prefetch.
func (c *Controller) SetCurrentPacket(packet int) {
	c.State.SetCurrentPacket(packet)
	c.emitStateChange(StateChangePacket, packet)

	// Calculate and emit prefetch requests
	c.mu.RLock()
	pktsPerLoad := c.packetsPerLoad
	c.mu.RUnlock()

	requests := CalculatePrefetchRequests(packet, pktsPerLoad)
	if len(requests) > 0 {
		c.State.ClearPendingRequests()
		for _, req := range requests {
			c.State.AddPendingRequest(req)
		}
		c.emitLoadRequest(requests)
	}
}

// GetCurrentPacket returns the current packet number.
func (c *Controller) GetCurrentPacket() int {
	return c.State.GetCurrentPacket()
}

//======================================================================
// Filter operations
//======================================================================

// SetFilter sets the display filter. Returns true if the filter changed.
func (c *Controller) SetFilter(filter string) bool {
	oldFilter := c.State.GetCurrentFilter()
	if !ShouldReloadForFilter(oldFilter, filter) {
		return false
	}

	c.State.SetCurrentFilter(filter)
	c.emitStateChange(StateChangeFilter, filter)
	return true
}

// GetFilter returns the current display filter.
func (c *Controller) GetFilter() string {
	return c.State.GetCurrentFilter()
}

//======================================================================
// Pcap operations
//======================================================================

// SetCurrentPcap sets the current pcap file path.
func (c *Controller) SetCurrentPcap(pcap string) {
	c.State.SetCurrentPcap(pcap)
	// Clear local marks when loading a new pcap
	ClearLocalMarks(c.State)
	c.emitStateChange(StateChangePcap, pcap)
}

// GetCurrentPcap returns the current pcap file path.
func (c *Controller) GetCurrentPcap() string {
	return c.State.GetCurrentPcap()
}

//======================================================================
// Mark operations
//======================================================================

// SetMark sets a mark at the current packet position.
func (c *Controller) SetMarkAtCurrentPacket(mark rune, summary string) error {
	currentPacket := c.State.GetCurrentPacket()
	currentPcap := c.State.GetCurrentPcap()

	err := SetMark(c.State, mark, currentPacket, summary, currentPcap)
	if err != nil {
		c.emitError("Failed to set mark", err)
		return err
	}

	c.emitStateChange(StateChangeMark, mark)
	return nil
}

// JumpToMark jumps to a mark and returns the target packet number.
// Returns -1 and an error if the jump cannot be performed.
func (c *Controller) JumpToMark(mark rune) (int, error) {
	currentPacket := c.State.GetCurrentPacket()
	currentPcap := c.State.GetCurrentPcap()

	result := JumpToMark(c.State, mark, currentPacket, currentPcap)
	if !result.IsSuccess() {
		c.emitError("Jump to mark failed", result.Error)
		return -1, result.Error
	}

	// Save position for '' functionality
	c.State.SetLastJumpPos(result.PreviousPosition)

	if result.NeedsPcapLoad {
		// Caller needs to handle loading a different pcap
		return result.TargetPacket, &NeedsPcapLoadError{
			PcapPath:     result.PcapToLoad,
			TargetPacket: result.TargetPacket,
		}
	}

	c.SetCurrentPacket(result.TargetPacket)
	return result.TargetPacket, nil
}

// JumpToLastPosition jumps back to the position before the last mark jump.
// Returns -1 if there is no previous position.
func (c *Controller) JumpToLastPosition() int {
	currentPacket := c.State.GetCurrentPacket()
	targetPacket := JumpToLastPosition(c.State, currentPacket)

	if targetPacket >= 0 {
		c.SetCurrentPacket(targetPacket)
	}

	return targetPacket
}

// DeleteMark removes a mark.
func (c *Controller) DeleteMark(mark rune) error {
	err := DeleteMark(c.State, mark)
	if err != nil {
		c.emitError("Failed to delete mark", err)
		return err
	}

	c.emitStateChange(StateChangeMark, mark)
	return nil
}

//======================================================================
// Display settings
//======================================================================

// SetAutoScroll enables or disables auto-scroll.
func (c *Controller) SetAutoScroll(enabled bool) {
	c.State.SetAutoScroll(enabled)
	c.emitStateChange(StateChangeAutoScroll, enabled)
}

// GetAutoScroll returns whether auto-scroll is enabled.
func (c *Controller) GetAutoScroll() bool {
	return c.State.GetAutoScroll()
}

// SetDarkMode enables or disables dark mode.
func (c *Controller) SetDarkMode(enabled bool) {
	c.State.SetDarkMode(enabled)
	c.emitStateChange(StateChangeDarkMode, enabled)
}

// GetDarkMode returns whether dark mode is enabled.
func (c *Controller) GetDarkMode() bool {
	return c.State.GetDarkMode()
}

// SetPacketColors enables or disables packet colors.
func (c *Controller) SetPacketColors(enabled bool) {
	c.State.SetPacketColors(enabled)
	c.emitStateChange(StateChangePacketColors, enabled)
}

// GetPacketColors returns whether packet colors are enabled.
func (c *Controller) GetPacketColors() bool {
	return c.State.GetPacketColors()
}

//======================================================================
// Error types
//======================================================================

// NeedsPcapLoadError indicates a jump requires loading a different pcap file.
type NeedsPcapLoadError struct {
	PcapPath     string
	TargetPacket int
}

func (e *NeedsPcapLoadError) Error() string {
	return "need to load pcap: " + e.PcapPath
}

// IsNeedsPcapLoadError returns true if the error is a NeedsPcapLoadError.
func IsNeedsPcapLoadError(err error) bool {
	_, ok := err.(*NeedsPcapLoadError)
	return ok
}

// GetNeedsPcapLoadError extracts the NeedsPcapLoadError from an error if present.
func GetNeedsPcapLoadError(err error) (*NeedsPcapLoadError, bool) {
	e, ok := err.(*NeedsPcapLoadError)
	return e, ok
}
