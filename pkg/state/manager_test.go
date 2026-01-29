// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockBackend implements Backend for testing.
type mockBackend struct {
	loadedFile      string
	loadError       error
	status          *Status
	statusError     error
	packets         []PacketSummary
	packetsError    error
	packetDetail    *PacketDetail
	detailError     error
	filterValid     bool
	filterMessage   string
	validateError   error
}

func (m *mockBackend) LoadFile(ctx context.Context, path string) error {
	if m.loadError != nil {
		return m.loadError
	}
	m.loadedFile = path
	return nil
}

func (m *mockBackend) GetStatus(ctx context.Context) (*Status, error) {
	if m.statusError != nil {
		return nil, m.statusError
	}
	if m.status == nil {
		return &Status{PacketCount: 100, Columns: []string{"No.", "Time"}}, nil
	}
	return m.status, nil
}

func (m *mockBackend) GetPackets(ctx context.Context, filter string, start, count int) ([]PacketSummary, error) {
	if m.packetsError != nil {
		return nil, m.packetsError
	}
	return m.packets, nil
}

func (m *mockBackend) GetPacketDetail(ctx context.Context, num int) (*PacketDetail, error) {
	if m.detailError != nil {
		return nil, m.detailError
	}
	if m.packetDetail != nil {
		return m.packetDetail, nil
	}
	return &PacketDetail{Number: num, Tree: []ProtocolNode{{Label: "Ethernet"}}}, nil
}

func (m *mockBackend) ValidateFilter(ctx context.Context, filter string) (*FilterValidation, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return &FilterValidation{Valid: m.filterValid, Message: m.filterMessage}, nil
}

func (m *mockBackend) GetStreamInfo(ctx context.Context, protocol string) ([]StreamInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockBackend) FollowStream(ctx context.Context, protocol string, streamIndex int) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockBackend) Close() error {
	return nil
}

func TestNewManager(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	assert.NotNil(t, m)
	assert.NotNil(t, m.Session())
}

func TestManager_LoadFile(t *testing.T) {
	backend := &mockBackend{
		status: &Status{PacketCount: 50, Duration: 10.5, Columns: []string{"No.", "Time", "Source"}},
	}
	m := NewManager(backend)

	err := m.LoadFile("test.pcap")
	assert.NoError(t, err)

	status, err := m.GetStatus()
	assert.NoError(t, err)
	assert.Equal(t, 50, status.PacketCount)
	assert.Equal(t, 10.5, status.Duration)
	assert.Equal(t, []string{"No.", "Time", "Source"}, status.Columns)
}

func TestManager_LoadFile_Error(t *testing.T) {
	backend := &mockBackend{
		loadError: errors.New("file not found"),
	}
	m := NewManager(backend)

	err := m.LoadFile("nonexistent.pcap")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load file")
}

func TestManager_LoadFile_StatusError(t *testing.T) {
	backend := &mockBackend{
		statusError: errors.New("status error"),
	}
	m := NewManager(backend)

	err := m.LoadFile("test.pcap")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get status")
}

func TestManager_GetStatus(t *testing.T) {
	backend := &mockBackend{
		status: &Status{PacketCount: 200, Duration: 5.0},
	}
	m := NewManager(backend)

	status, err := m.GetStatus()
	assert.NoError(t, err)
	assert.Equal(t, 200, status.PacketCount)
	assert.Equal(t, 5.0, status.Duration)
}

func TestManager_GetStatus_BackendError(t *testing.T) {
	backend := &mockBackend{
		statusError: errors.New("backend unavailable"),
	}
	m := NewManager(backend)

	// Should still return session status even if backend fails
	status, err := m.GetStatus()
	assert.NoError(t, err)
	assert.NotNil(t, status)
}

func TestManager_SetFilter_Valid(t *testing.T) {
	backend := &mockBackend{filterValid: true}
	m := NewManager(backend)

	err := m.SetFilter("tcp.port == 80")
	assert.NoError(t, err)

	status, _ := m.GetStatus()
	assert.Equal(t, "tcp.port == 80", status.DisplayFilter)
}

func TestManager_SetFilter_Invalid(t *testing.T) {
	backend := &mockBackend{filterValid: false, filterMessage: "syntax error"}
	m := NewManager(backend)

	err := m.SetFilter("invalid filter ===")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid filter")
}

func TestManager_SetFilter_Empty(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	// Empty filter should be allowed without validation
	err := m.SetFilter("")
	assert.NoError(t, err)

	status, _ := m.GetStatus()
	assert.Equal(t, "", status.DisplayFilter)
}

func TestManager_SetFilter_ValidationError(t *testing.T) {
	backend := &mockBackend{validateError: errors.New("connection lost")}
	m := NewManager(backend)

	err := m.SetFilter("tcp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "filter validation failed")
}

func TestManager_GetPackets(t *testing.T) {
	packets := []PacketSummary{
		{Number: 1, Columns: []string{"1", "0.000", "10.0.0.1"}},
		{Number: 2, Columns: []string{"2", "0.001", "10.0.0.2"}},
	}
	backend := &mockBackend{packets: packets}
	m := NewManager(backend)

	result, err := m.GetPackets(0, 100)
	assert.NoError(t, err)
	assert.Equal(t, packets, result)
}

func TestManager_GetPackets_Error(t *testing.T) {
	backend := &mockBackend{packetsError: errors.New("no packets")}
	m := NewManager(backend)

	_, err := m.GetPackets(0, 100)
	assert.Error(t, err)
}

func TestManager_GetPacketDetail(t *testing.T) {
	detail := &PacketDetail{
		Number: 5,
		Tree:   []ProtocolNode{{Label: "Ethernet II"}},
		Bytes:  []byte{0x00, 0x01, 0x02},
	}
	backend := &mockBackend{packetDetail: detail}
	m := NewManager(backend)

	result, err := m.GetPacketDetail(5)
	assert.NoError(t, err)
	assert.Equal(t, detail, result)
}

func TestManager_GetPacketDetail_Error(t *testing.T) {
	backend := &mockBackend{detailError: errors.New("packet not found")}
	m := NewManager(backend)

	_, err := m.GetPacketDetail(999)
	assert.Error(t, err)
}

func TestManager_SelectPacket(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	detail, err := m.SelectPacket(10)
	assert.NoError(t, err)
	assert.NotNil(t, detail)
	assert.Equal(t, 10, detail.Number)
}

func TestManager_SelectPacket_Zero(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	detail, err := m.SelectPacket(0)
	assert.NoError(t, err)
	assert.Nil(t, detail)
}

func TestManager_ValidateFilter(t *testing.T) {
	backend := &mockBackend{filterValid: true}
	m := NewManager(backend)

	result, err := m.ValidateFilter("tcp")
	assert.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestManager_Subscribe(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	ch, unsub := m.Subscribe(10)
	defer unsub()

	assert.NotNil(t, ch)
}

func TestManager_Close(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	err := m.Close()
	assert.NoError(t, err)
}

func TestManager_Close_NilBackend(t *testing.T) {
	// Create manager with nil backend passed to NewManager
	m := NewManager(nil)

	err := m.Close()
	assert.NoError(t, err)
}

func TestManager_FollowStream(t *testing.T) {
	streamData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	backend := &mockFollowBackend{
		mockBackend: mockBackend{},
		streamData:  streamData,
	}
	m := NewManager(backend)

	data, err := m.FollowStream("tcp", 0)
	assert.NoError(t, err)
	assert.Equal(t, streamData, data)
}

func TestManager_FollowStream_Error(t *testing.T) {
	backend := &mockFollowBackend{
		mockBackend: mockBackend{},
		streamError: errors.New("stream not found"),
	}
	m := NewManager(backend)

	_, err := m.FollowStream("tcp", 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stream not found")
}

func TestManager_FollowStream_NilBackend(t *testing.T) {
	m := NewManager(nil)

	_, err := m.FollowStream("tcp", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backend available")
}

// mockFollowBackend extends mockBackend with configurable FollowStream
type mockFollowBackend struct {
	mockBackend
	streamData  []byte
	streamError error
}

func (m *mockFollowBackend) FollowStream(ctx context.Context, protocol string, streamIndex int) ([]byte, error) {
	if m.streamError != nil {
		return nil, m.streamError
	}
	return m.streamData, nil
}

func TestManager_StopCapture_WhenNotCapturing(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	err := m.StopCapture()
	assert.NoError(t, err)
}

func TestManager_IsCapturing_Initial(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	assert.False(t, m.IsCapturing())
}

func TestManager_GetCaptureFile_NoCapture(t *testing.T) {
	backend := &mockBackend{}
	m := NewManager(backend)

	assert.Equal(t, "", m.GetCaptureFile())
}
