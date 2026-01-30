// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"sync"
	"time"
)

// Session represents the current termshark session state.
// All state is accessed through this struct to ensure consistency
// across different UI frontends.
type Session struct {
	mu sync.RWMutex

	// Source information
	source     string
	sourceType SourceType

	// Capture state (for live capture)
	captureRunning bool
	captureFile    string // temp file path for live capture

	// Packet data state
	packetCount   int
	filteredCount int
	columns       []string

	// View state
	displayFilter  string
	selectedPacket int // 1-based packet number, 0 = none selected

	// Duration of loaded capture
	duration float64

	// Subscribers for state changes
	subscribers   map[int]chan StateChange
	subscriberSeq int
}

// NewSession creates a new session with default state.
func NewSession() *Session {
	return &Session{
		subscribers: make(map[int]chan StateChange),
	}
}

// GetStatus returns the current session status.
func (s *Session) GetStatus() *Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Deep copy columns to prevent aliasing
	cols := make([]string, len(s.columns))
	copy(cols, s.columns)

	return &Status{
		Source:         s.source,
		SourceType:     s.sourceType,
		PacketCount:    s.packetCount,
		DisplayFilter:  s.displayFilter,
		FilteredCount:  s.filteredCount,
		CaptureRunning: s.captureRunning,
		Duration:       s.duration,
		Columns:        cols,
	}
}

// SetSource updates the source information.
func (s *Session) SetSource(source string, sourceType SourceType) {
	s.mu.Lock()
	s.source = source
	s.sourceType = sourceType
	s.mu.Unlock()

	s.notify(StateChange{
		Type:      ChangeSourceChanged,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"source": source, "type": sourceType.String()},
	})
}

// SetPacketCount updates the packet count.
func (s *Session) SetPacketCount(count int) {
	s.mu.Lock()
	oldCount := s.packetCount
	s.packetCount = count
	s.mu.Unlock()

	if count > oldCount {
		s.notify(StateChange{
			Type:      ChangePacketsAdded,
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"count": count, "added": count - oldCount},
		})
	}
}

// SetFilteredCount updates the filtered packet count.
func (s *Session) SetFilteredCount(count int) {
	s.mu.Lock()
	s.filteredCount = count
	s.mu.Unlock()
}

// SetColumns updates the column headers.
func (s *Session) SetColumns(columns []string) {
	// Deep copy to prevent aliasing with caller's slice
	copied := make([]string, len(columns))
	copy(copied, columns)

	s.mu.Lock()
	s.columns = copied
	s.mu.Unlock()
}

// SetDuration updates the capture duration.
func (s *Session) SetDuration(duration float64) {
	s.mu.Lock()
	s.duration = duration
	s.mu.Unlock()
}

// SetDisplayFilter updates the display filter.
func (s *Session) SetDisplayFilter(filter string) {
	s.mu.Lock()
	s.displayFilter = filter
	s.mu.Unlock()

	s.notify(StateChange{
		Type:      ChangeFilterChanged,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"filter": filter},
	})
}

// SetSelectedPacket updates the selected packet number.
func (s *Session) SetSelectedPacket(num int) {
	s.mu.Lock()
	s.selectedPacket = num
	s.mu.Unlock()

	s.notify(StateChange{
		Type:      ChangeSelectionChanged,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"packet": num},
	})
}

// GetSelectedPacket returns the currently selected packet number (1-based, 0 = none).
func (s *Session) GetSelectedPacket() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selectedPacket
}

// SetCaptureRunning updates the capture running state.
func (s *Session) SetCaptureRunning(running bool) {
	s.mu.Lock()
	s.captureRunning = running
	s.mu.Unlock()

	changeType := ChangeCaptureStopped
	if running {
		changeType = ChangeCaptureStarted
	}
	s.notify(StateChange{
		Type:      changeType,
		Timestamp: time.Now(),
	})
}

// SetCaptureFile sets the temporary capture file path.
func (s *Session) SetCaptureFile(path string) {
	s.mu.Lock()
	s.captureFile = path
	s.mu.Unlock()
}

// GetCaptureFile returns the temporary capture file path.
func (s *Session) GetCaptureFile() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.captureFile
}

// Clear resets the session state.
func (s *Session) Clear() {
	s.mu.Lock()
	s.source = ""
	s.sourceType = SourceNone
	s.captureRunning = false
	s.captureFile = ""
	s.packetCount = 0
	s.filteredCount = 0
	s.displayFilter = ""
	s.selectedPacket = 0
	s.duration = 0
	s.mu.Unlock()

	s.notify(StateChange{
		Type:      ChangePacketsCleared,
		Timestamp: time.Now(),
	})
}

// Subscribe returns a channel that receives state changes.
// The returned function should be called to unsubscribe.
func (s *Session) Subscribe(bufferSize int) (<-chan StateChange, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan StateChange, bufferSize)
	id := s.subscriberSeq
	s.subscriberSeq++
	s.subscribers[id] = ch

	unsubscribe := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if ch, ok := s.subscribers[id]; ok {
			close(ch)
			delete(s.subscribers, id)
		}
	}

	return ch, unsubscribe
}

// notify sends a state change to all subscribers.
func (s *Session) notify(change StateChange) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- change:
		default:
			// Channel full, skip (subscriber too slow)
		}
	}
}

// NotifyError sends an error notification to all subscribers.
func (s *Session) NotifyError(err error) {
	s.notify(StateChange{
		Type:      ChangeError,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"error": err.Error()},
	})
}
