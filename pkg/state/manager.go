// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// Manager coordinates the session state and backend.
// It provides the API that UI clients call via JSON-RPC.
type Manager struct {
	mu       sync.RWMutex
	session  *Session
	backend  Backend
	capture  *CaptureCoordinator
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewManager creates a new state manager with the given backend.
func NewManager(backend Backend) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		session: NewSession(),
		backend: backend,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Session returns the underlying session state.
func (m *Manager) Session() *Session {
	return m.session
}

// LoadFile loads a pcap file for analysis.
func (m *Manager) LoadFile(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Clear previous state
	m.session.Clear()

	// Load file in backend
	if err := m.backend.LoadFile(m.ctx, absPath); err != nil {
		return fmt.Errorf("failed to load file: %w", err)
	}

	// Update session state
	m.session.SetSource(absPath, SourceFile)

	// Get initial status from backend
	status, err := m.backend.GetStatus(m.ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	m.session.SetPacketCount(status.PacketCount)
	m.session.SetColumns(status.Columns)
	m.session.SetDuration(status.Duration)

	return nil
}

// GetStatus returns the current session status.
func (m *Manager) GetStatus() (*Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get base status from session
	status := m.session.GetStatus()

	// If we have a backend, get fresh packet count
	if m.backend != nil {
		backendStatus, err := m.backend.GetStatus(m.ctx)
		if err == nil {
			status.PacketCount = backendStatus.PacketCount
			status.Duration = backendStatus.Duration
			if len(backendStatus.Columns) > 0 {
				status.Columns = backendStatus.Columns
			}
		}
	}

	return status, nil
}

// SetFilter sets the display filter.
func (m *Manager) SetFilter(filter string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.backend == nil {
		return fmt.Errorf("no backend available")
	}

	// Validate filter first
	if filter != "" {
		validation, err := m.backend.ValidateFilter(m.ctx, filter)
		if err != nil {
			return fmt.Errorf("filter validation failed: %w", err)
		}
		if !validation.Valid {
			return fmt.Errorf("invalid filter: %s", validation.Message)
		}
	}

	m.session.SetDisplayFilter(filter)
	return nil
}

// GetPackets returns packet summaries for the given range.
func (m *Manager) GetPackets(start, count int) ([]PacketSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.backend == nil {
		return nil, fmt.Errorf("no backend available")
	}

	filter := m.session.GetStatus().DisplayFilter
	return m.backend.GetPackets(m.ctx, filter, start, count)
}

// GetPacketDetail returns the full detail for a single packet.
func (m *Manager) GetPacketDetail(num int) (*PacketDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.backend == nil {
		return nil, fmt.Errorf("no backend available")
	}

	return m.backend.GetPacketDetail(m.ctx, num)
}

// SelectPacket updates the selected packet.
func (m *Manager) SelectPacket(num int) (*PacketDetail, error) {
	m.session.SetSelectedPacket(num)

	if num <= 0 {
		return nil, nil
	}

	// GetPacketDetail already acquires its own lock
	return m.GetPacketDetail(num)
}

// Note: SelectPacket does not acquire m.mu because SetSelectedPacket has its
// own lock (session.mu) and GetPacketDetail acquires m.mu.RLock internally.

// ValidateFilter checks if a display filter is valid.
func (m *Manager) ValidateFilter(filter string) (*FilterValidation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.backend.ValidateFilter(m.ctx, filter)
}

// Subscribe returns a channel for state change notifications.
func (m *Manager) Subscribe(bufferSize int) (<-chan StateChange, func()) {
	return m.session.Subscribe(bufferSize)
}

// StartCapture begins live packet capture on the specified interface.
func (m *Manager) StartCapture(iface string, captureFilter string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop any existing capture
	if m.capture != nil && m.capture.IsRunning() {
		m.capture.Stop()
	}

	// Clear previous state
	m.session.Clear()

	// Create new capture coordinator
	m.capture = NewCaptureCoordinator()

	// Capture local references for use in callbacks -- avoids reading m.capture
	// and m.backend without holding m.mu from the monitor goroutine.
	captureRef := m.capture
	backendRef := m.backend

	// Set up callbacks to update session state
	m.capture.SetCallbacks(
		func(count int) {
			// Packets added - reload from backend
			tmpFile := captureRef.TempFile()
			if tmpFile != "" && backendRef != nil {
				backendRef.LoadFile(m.ctx, tmpFile)
				status, err := backendRef.GetStatus(m.ctx)
				if err == nil {
					m.session.SetPacketCount(status.PacketCount)
				}
			}
		},
		func(err error) {
			// Error occurred
			m.session.NotifyError(err)
		},
		func() {
			// Capture stopped
			m.session.SetCaptureRunning(false)
		},
	)

	// Start capture
	config := CaptureConfig{
		Interface:     iface,
		CaptureFilter: captureFilter,
	}
	if err := m.capture.Start(config); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// Update session state
	m.session.SetSource(iface, SourceInterface)
	m.session.SetCaptureRunning(true)
	m.session.SetCaptureFile(m.capture.TempFile())

	// Wait briefly for initial packets, then load the file.
	// Use captured references to avoid reading m.capture/m.backend without lock.
	go func() {
		select {
		case <-time.After(1 * time.Second):
		case <-m.ctx.Done():
			return
		}

		if captureRef.IsRunning() && backendRef != nil {
			tmpFile := captureRef.TempFile()
			if tmpFile != "" {
				backendRef.LoadFile(m.ctx, tmpFile)
				status, err := backendRef.GetStatus(m.ctx)
				if err == nil {
					m.session.SetPacketCount(status.PacketCount)
					m.session.SetColumns(status.Columns)
				}
			}
		}
	}()

	return nil
}

// StopCapture stops the current live capture.
func (m *Manager) StopCapture() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture == nil {
		return nil
	}

	if err := m.capture.Stop(); err != nil {
		return err
	}

	m.session.SetCaptureRunning(false)
	return nil
}

// IsCapturing returns whether live capture is active.
func (m *Manager) IsCapturing() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.capture != nil && m.capture.IsRunning()
}

// GetCaptureFile returns the path to the current capture file.
func (m *Manager) GetCaptureFile() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.capture != nil {
		return m.capture.TempFile()
	}
	return ""
}

// FollowStream returns the reassembled data for a stream.
func (m *Manager) FollowStream(protocol string, streamIndex int) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.backend == nil {
		return nil, fmt.Errorf("no backend available")
	}

	return m.backend.FollowStream(m.ctx, protocol, streamIndex)
}

// Close shuts down the manager and releases resources.
func (m *Manager) Close() error {
	m.cancel()

	// Stop capture before acquiring m.mu to avoid blocking all Manager
	// methods while the capture process is being torn down.
	m.mu.RLock()
	capture := m.capture
	m.mu.RUnlock()

	if capture != nil {
		capture.Stop()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture != nil {
		m.capture.Cleanup()
	}

	if m.backend != nil {
		return m.backend.Close()
	}
	return nil
}
