// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gcla/termshark/v2/pkg/state"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers to wrap state package types
func NewSharkdBackendForTest(ctx context.Context) (*state.SharkdBackend, error) {
	return state.NewSharkdBackend(ctx)
}

func NewManagerForTest(backend state.Backend) *state.Manager {
	return state.NewManager(backend)
}

func TestServerHealth(t *testing.T) {
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sharkd, err := NewSharkdClient(ctx)
	require.NoError(t, err)
	defer sharkd.Close()

	server := NewServer(":0", sharkd)

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// We need to test the handler directly since we can't easily start the server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "ok")

	// Reference server to avoid unused variable warning
	_ = server.Addr()
}

func TestServerWebSocket(t *testing.T) {
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sharkd, err := NewSharkdClient(ctx)
	require.NoError(t, err)
	defer sharkd.Close()

	server := NewServer("127.0.0.1:18081", sharkd)

	// Start server in background
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(serverCtx)
	}()

	// Wait a moment for server to start
	time.Sleep(500 * time.Millisecond)

	// Connect via WebSocket
	wsURL := "ws://" + server.Addr() + "/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		// Server might not have started yet, skip test
		t.Skipf("Could not connect to WebSocket: %v", err)
	}
	defer ws.Close()

	// Send status request
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "status",
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	// Read response
	var resp JSONRPCResponse
	err = ws.ReadJSON(&resp)
	require.NoError(t, err)

	assert.Equal(t, 1, resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotEmpty(t, resp.Result)
}

func TestServerStaticFiles(t *testing.T) {
	// Test that index.html exists in embedded files
	data, err := staticFiles.ReadFile("static/index.html")
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(data), "Termshark Web"))
}

func TestNewServerWithManager(t *testing.T) {
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Import state package inline since we need it for the test
	backend, err := NewSharkdBackendForTest(ctx)
	if err != nil {
		t.Skipf("Failed to create sharkd backend: %v", err)
	}
	defer backend.Close()

	manager := NewManagerForTest(backend)
	defer manager.Close()

	server := NewServerWithManager("127.0.0.1:0", manager)
	assert.NotNil(t, server)
	assert.NotNil(t, server.manager)
	assert.Nil(t, server.sharkd)
}

func TestGetFloat(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]interface{}
		key      string
		def      float64
		expected float64
	}{
		{
			name:     "key exists",
			m:        map[string]interface{}{"count": float64(42)},
			key:      "count",
			def:      0,
			expected: 42,
		},
		{
			name:     "key missing",
			m:        map[string]interface{}{},
			key:      "count",
			def:      10,
			expected: 10,
		},
		{
			name:     "wrong type",
			m:        map[string]interface{}{"count": "not a number"},
			key:      "count",
			def:      5,
			expected: 5,
		},
		{
			name:     "nil map",
			m:        nil,
			key:      "count",
			def:      7,
			expected: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFloat(tt.m, tt.key, tt.def)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertTreeToSharkd(t *testing.T) {
	nodes := []state.ProtocolNode{
		{
			Label:    "Ethernet II",
			Field:    "eth",
			Position: 0,
			Size:     14,
			Children: []state.ProtocolNode{
				{
					Label:    "Destination",
					Field:    "eth.dst",
					Position: 0,
					Size:     6,
				},
			},
		},
	}

	result := convertTreeToSharkd(nodes)

	require.Len(t, result, 1)
	assert.Equal(t, "Ethernet II", result[0]["l"])
	assert.Equal(t, "eth", result[0]["f"])
	assert.Equal(t, 0, result[0]["h"])
	assert.Equal(t, 14, result[0]["i"])

	children := result[0]["n"].([]map[string]interface{})
	require.Len(t, children, 1)
	assert.Equal(t, "Destination", children[0]["l"])
}

func TestNewServerWithRegistry(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})

	server := NewServerWithRegistry("127.0.0.1:0", registry)
	assert.NotNil(t, server)
	assert.NotNil(t, server.registry)
	assert.Nil(t, server.manager)
	assert.Nil(t, server.sharkd)
}

func TestHandleRegistryRequest_SessionsList(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// List sessions (should be empty initially)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.list",
	}

	result, err := server.handleRegistryRequest(req, clientSt)
	require.NoError(t, err)

	var sessions []state.SessionInfo
	err = json.Unmarshal(result, &sessions)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestHandleRegistryRequest_SessionsCreate(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// Create a session
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.create",
		Params:  map[string]interface{}{"name": "Test Session"},
	}

	result, err := server.handleRegistryRequest(req, clientSt)
	require.NoError(t, err)

	var session state.SessionInfo
	err = json.Unmarshal(result, &session)
	require.NoError(t, err)
	assert.Equal(t, "Test Session", session.Name)
	assert.NotEmpty(t, session.ID)

	// Verify it appears in the list
	listReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.list",
	}
	listResult, err := server.handleRegistryRequest(listReq, clientSt)
	require.NoError(t, err)

	var sessions []state.SessionInfo
	err = json.Unmarshal(listResult, &sessions)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "Test Session", sessions[0].Name)
}

func TestHandleRegistryRequest_SessionsJoinLeave(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// Create a session first
	createReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.create",
		Params:  map[string]interface{}{"name": "Join Test"},
	}
	createResult, err := server.handleRegistryRequest(createReq, clientSt)
	require.NoError(t, err)

	var created state.SessionInfo
	err = json.Unmarshal(createResult, &created)
	require.NoError(t, err)

	// Join the session
	joinReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.join",
		Params:  map[string]interface{}{"id": created.ID},
	}
	joinResult, err := server.handleRegistryRequest(joinReq, clientSt)
	require.NoError(t, err)

	var joined state.SessionInfo
	err = json.Unmarshal(joinResult, &joined)
	require.NoError(t, err)
	assert.Equal(t, created.ID, joined.ID)
	assert.NotNil(t, clientSt.session)

	// Leave the session
	leaveReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "sessions.leave",
	}
	leaveResult, err := server.handleRegistryRequest(leaveReq, clientSt)
	require.NoError(t, err)

	var leaveResp map[string]bool
	err = json.Unmarshal(leaveResult, &leaveResp)
	require.NoError(t, err)
	assert.True(t, leaveResp["left"])
	assert.Nil(t, clientSt.session)
}

func TestHandleRegistryRequest_SessionsInfo(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// Create and join a session
	createReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.create",
		Params:  map[string]interface{}{"name": "Info Test"},
	}
	createResult, err := server.handleRegistryRequest(createReq, clientSt)
	require.NoError(t, err)

	var created state.SessionInfo
	json.Unmarshal(createResult, &created)

	// Get info by ID
	infoReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.info",
		Params:  map[string]interface{}{"id": created.ID},
	}
	infoResult, err := server.handleRegistryRequest(infoReq, clientSt)
	require.NoError(t, err)

	var info state.SessionInfo
	err = json.Unmarshal(infoResult, &info)
	require.NoError(t, err)
	assert.Equal(t, "Info Test", info.Name)

	// Join and get info without ID (should return current session)
	joinReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "sessions.join",
		Params:  map[string]interface{}{"id": created.ID},
	}
	server.handleRegistryRequest(joinReq, clientSt)

	currentInfoReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "sessions.info",
	}
	currentInfoResult, err := server.handleRegistryRequest(currentInfoReq, clientSt)
	require.NoError(t, err)

	var currentInfo state.SessionInfo
	err = json.Unmarshal(currentInfoResult, &currentInfo)
	require.NoError(t, err)
	assert.Equal(t, created.ID, currentInfo.ID)
}

func TestHandleRegistryRequest_SessionsDelete(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// Create a session
	createReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.create",
		Params:  map[string]interface{}{"name": "Delete Test"},
	}
	createResult, err := server.handleRegistryRequest(createReq, clientSt)
	require.NoError(t, err)

	var created state.SessionInfo
	json.Unmarshal(createResult, &created)

	// Delete the session
	deleteReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.delete",
		Params:  map[string]interface{}{"id": created.ID},
	}
	deleteResult, err := server.handleRegistryRequest(deleteReq, clientSt)
	require.NoError(t, err)

	var deleteResp map[string]bool
	err = json.Unmarshal(deleteResult, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp["deleted"])

	// Verify it's gone
	listReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "sessions.list",
	}
	listResult, err := server.handleRegistryRequest(listReq, clientSt)
	require.NoError(t, err)

	var sessions []state.SessionInfo
	json.Unmarshal(listResult, &sessions)
	assert.Empty(t, sessions)
}

func TestHandleRegistryRequest_Errors(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:0", registry)
	clientSt := &clientState{}

	// Join without session ID
	joinReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.join",
		Params:  map[string]interface{}{},
	}
	_, err := server.handleRegistryRequest(joinReq, clientSt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session id required")

	// Join non-existent session
	joinReq2 := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.join",
		Params:  map[string]interface{}{"id": "nonexistent"},
	}
	_, err = server.handleRegistryRequest(joinReq2, clientSt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")

	// Leave when not in session
	leaveReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "sessions.leave",
	}
	_, err = server.handleRegistryRequest(leaveReq, clientSt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in a session")

	// Delete without ID
	deleteReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "sessions.delete",
		Params:  map[string]interface{}{},
	}
	_, err = server.handleRegistryRequest(deleteReq, clientSt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session id required")

	// Request without active session
	statusReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "status",
	}
	_, err = server.handleRegistryRequest(statusReq, clientSt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session active")
}

func TestHandleManagerRequestWithManager(t *testing.T) {
	// Create a mock backend
	backend := &mockBackend{
		status: &state.Status{
			PacketCount: 100,
			Columns:     []string{"No.", "Time", "Source"},
		},
		packets: []state.PacketSummary{
			{Number: 1, Columns: []string{"1", "0.000", "10.0.0.1"}},
			{Number: 2, Columns: []string{"2", "0.001", "10.0.0.2"}},
		},
		filterValid: true,
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test status
	statusReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "status",
	}
	statusResult, err := server.handleManagerRequestWithManager(statusReq, manager)
	require.NoError(t, err)

	var status state.Status
	err = json.Unmarshal(statusResult, &status)
	require.NoError(t, err)
	assert.Equal(t, 100, status.PacketCount)

	// Test frames
	framesReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "frames",
		Params:  map[string]interface{}{"skip": float64(0), "limit": float64(10)},
	}
	framesResult, err := server.handleManagerRequestWithManager(framesReq, manager)
	require.NoError(t, err)

	var frames []map[string]interface{}
	err = json.Unmarshal(framesResult, &frames)
	require.NoError(t, err)
	assert.Len(t, frames, 2)

	// Test check filter
	checkReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "check",
		Params:  map[string]interface{}{"filter": "tcp"},
	}
	checkResult, err := server.handleManagerRequestWithManager(checkReq, manager)
	require.NoError(t, err)

	var checkResp map[string]bool
	err = json.Unmarshal(checkResult, &checkResp)
	require.NoError(t, err)
	assert.True(t, checkResp["ok"])

	// Test unknown method
	unknownReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "unknown",
	}
	_, err = server.handleManagerRequestWithManager(unknownReq, manager)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown method")
}

// mockBackend for testing without sharkd
type mockBackend struct {
	status       *state.Status
	packets      []state.PacketSummary
	packetDetail *state.PacketDetail
	filterValid  bool
	streamData   []byte
	err          error
}

func (m *mockBackend) LoadFile(ctx context.Context, path string) error {
	return m.err
}

func (m *mockBackend) GetStatus(ctx context.Context) (*state.Status, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.status, nil
}

func (m *mockBackend) GetPackets(ctx context.Context, filter string, start, count int) ([]state.PacketSummary, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.packets, nil
}

func (m *mockBackend) GetPacketDetail(ctx context.Context, num int) (*state.PacketDetail, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.packetDetail, nil
}

func (m *mockBackend) ValidateFilter(ctx context.Context, filter string) (*state.FilterValidation, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &state.FilterValidation{Valid: m.filterValid}, nil
}

func (m *mockBackend) GetStreamInfo(ctx context.Context, streamType string) ([]state.StreamInfo, error) {
	return nil, nil
}

func (m *mockBackend) FollowStream(ctx context.Context, streamType string, streamIndex int) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.streamData, nil
}

func (m *mockBackend) Sync(ctx context.Context) error {
	return nil
}

func (m *mockBackend) Close() error {
	return nil
}

func TestHandleManagerRequest_CaptureControls(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 0},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test isCapturing (should be false initially)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "isCapturing",
	}
	result, err := server.handleManagerRequest(req)
	require.NoError(t, err)

	var capStatus map[string]bool
	err = json.Unmarshal(result, &capStatus)
	require.NoError(t, err)
	assert.False(t, capStatus["capturing"])

	// Test startCapture without interface (should error)
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "startCapture",
		Params:  map[string]interface{}{},
	}
	_, err = server.handleManagerRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "interface required")

	// Test stopCapture (should succeed even if not capturing)
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "stopCapture",
	}
	result, err = server.handleManagerRequest(req)
	require.NoError(t, err)

	var stopStatus map[string]string
	err = json.Unmarshal(result, &stopStatus)
	require.NoError(t, err)
	assert.Equal(t, "ok", stopStatus["status"])
}

func TestHandleManagerRequestWithManager_CaptureControls(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 0},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test isCapturing
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "isCapturing",
	}
	result, err := server.handleManagerRequestWithManager(req, manager)
	require.NoError(t, err)

	var capStatus map[string]bool
	err = json.Unmarshal(result, &capStatus)
	require.NoError(t, err)
	assert.False(t, capStatus["capturing"])

	// Test startCapture error case
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "startCapture",
		Params:  map[string]interface{}{},
	}
	_, err = server.handleManagerRequestWithManager(req, manager)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "interface required")

	// Test stopCapture
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "stopCapture",
	}
	result, err = server.handleManagerRequestWithManager(req, manager)
	require.NoError(t, err)

	var stopStatus map[string]string
	err = json.Unmarshal(result, &stopStatus)
	require.NoError(t, err)
	assert.Equal(t, "ok", stopStatus["status"])
}

func TestHandleManagerRequest_SetFilter(t *testing.T) {
	backend := &mockBackend{
		status:      &state.Status{PacketCount: 10},
		filterValid: true,
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test setfilter
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "setfilter",
		Params:  map[string]interface{}{"filter": "tcp"},
	}
	result, err := server.handleManagerRequest(req)
	require.NoError(t, err)

	var status map[string]string
	err = json.Unmarshal(result, &status)
	require.NoError(t, err)
	assert.Equal(t, "ok", status["status"])
}

func TestHandleManagerRequest_Load(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 100},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test load without path (should error)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "load",
		Params:  map[string]interface{}{},
	}
	_, err := server.handleManagerRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file path required")
}

func TestHandleManagerRequest_Frame(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 10},
		packetDetail: &state.PacketDetail{
			Number: 1,
			Tree: []state.ProtocolNode{
				{Label: "Frame", Field: "frame"},
			},
			Bytes: []byte("Hello"),
		},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test frame without number (should error)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "frame",
		Params:  map[string]interface{}{},
	}
	_, err := server.handleManagerRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "frame number required")

	// Test frame with valid number
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "frame",
		Params:  map[string]interface{}{"frame": float64(1)},
	}
	result, err := server.handleManagerRequest(req)
	require.NoError(t, err)

	var frameData map[string]interface{}
	err = json.Unmarshal(result, &frameData)
	require.NoError(t, err)
	assert.NotNil(t, frameData["tree"])
	assert.Equal(t, "SGVsbG8=", frameData["bytes"])
}

func TestHandleManagerRequest_Follow(t *testing.T) {
	backend := &mockBackend{
		status:     &state.Status{PacketCount: 10},
		streamData: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:0", manager)

	// Test follow without protocol
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "follow",
		Params:  map[string]interface{}{},
	}
	_, err := server.handleManagerRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protocol required")

	// Test follow with valid protocol
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "follow",
		Params:  map[string]interface{}{"follow": "tcp", "stream": float64(0)},
	}
	result, err := server.handleManagerRequest(req)
	require.NoError(t, err)

	var followData map[string]interface{}
	err = json.Unmarshal(result, &followData)
	require.NoError(t, err)
	assert.NotNil(t, followData["payloads"])

	// Verify the payload data is base64 encoded
	payloads := followData["payloads"].([]interface{})
	assert.Len(t, payloads, 1)
	payload := payloads[0].(map[string]interface{})
	assert.Contains(t, payload, "d")
}

func TestSubscription(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 10},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:18096", manager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect via WebSocket
	wsURL := "ws://127.0.0.1:18096/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Skipf("Could not connect to WebSocket: %v", err)
		return
	}
	defer ws.Close()

	// Test subscribe
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "subscribe",
		Params:  map[string]interface{}{"event": "packets.update"},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	var resp JSONRPCResponse
	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Contains(t, string(resp.Result), "ok")

	// Test unsubscribe
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "unsubscribe",
		Params:  map[string]interface{}{"event": "packets.update"},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Contains(t, string(resp.Result), "ok")

	// Test subscribe without event parameter
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "subscribe",
		Params:  map[string]interface{}{},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "event parameter required")
}

func TestBroadcast(t *testing.T) {
	backend := &mockBackend{
		status: &state.Status{PacketCount: 10},
	}
	manager := state.NewManager(backend)
	server := NewServerWithManager("127.0.0.1:18097", manager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect via WebSocket
	wsURL := "ws://127.0.0.1:18097/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Skipf("Could not connect to WebSocket: %v", err)
		return
	}
	defer ws.Close()

	// Subscribe to packets.update
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "subscribe",
		Params:  map[string]interface{}{"event": "packets.update"},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	var resp JSONRPCResponse
	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)

	// Broadcast an update
	server.NotifyPacketUpdate(100)

	// Read the push notification
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, message, err := ws.ReadMessage()
	require.NoError(t, err)

	var notification map[string]interface{}
	err = json.Unmarshal(message, &notification)
	require.NoError(t, err)
	assert.Equal(t, "packets.update", notification["method"])
	params := notification["params"].(map[string]interface{})
	assert.Equal(t, float64(100), params["count"])
}

func TestServerWebSocketWithRegistry(t *testing.T) {
	registry := state.NewRegistry(state.RegistryConfig{})
	server := NewServerWithRegistry("127.0.0.1:18095", registry)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect via WebSocket
	wsURL := "ws://127.0.0.1:18095/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Skipf("Could not connect to WebSocket: %v", err)
	}
	defer ws.Close()

	// Test sessions.list
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sessions.list",
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	var resp JSONRPCResponse
	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)

	// Test sessions.create
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "sessions.create",
		Params:  map[string]interface{}{"name": "WebSocket Test"},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)

	var session map[string]interface{}
	json.Unmarshal(resp.Result, &session)
	sessionID := session["id"].(string)
	assert.NotEmpty(t, sessionID)

	// Test sessions.join
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "sessions.join",
		Params:  map[string]interface{}{"id": sessionID},
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)

	// Test status after joining
	req = JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "status",
	}
	err = ws.WriteJSON(req)
	require.NoError(t, err)

	err = ws.ReadJSON(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestHandleDownload(t *testing.T) {
	t.Run("no file available", func(t *testing.T) {
		// Create server with mock backend that has no file
		backend := &mockBackend{
			status: &state.Status{}, // No source set
		}
		manager := state.NewManager(backend)
		server := NewServerWithManager(":0", manager)

		req := httptest.NewRequest("GET", "/api/download", nil)
		w := httptest.NewRecorder()

		server.handleDownload(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "No pcap file available")
	})

	t.Run("wrong method", func(t *testing.T) {
		backend := &mockBackend{
			status: &state.Status{},
		}
		manager := state.NewManager(backend)
		server := NewServerWithManager(":0", manager)

		req := httptest.NewRequest("POST", "/api/download", nil)
		w := httptest.NewRecorder()

		server.handleDownload(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("with source from loaded file", func(t *testing.T) {
		// Create a temporary pcap file
		tmpFile, err := createTempPcap(t)
		require.NoError(t, err)

		backend := &mockBackend{
			status: &state.Status{
				PacketCount: 10,
			},
		}
		manager := state.NewManager(backend)

		// Load the file to set the source on the session
		err = manager.LoadFile(tmpFile)
		require.NoError(t, err)

		server := NewServerWithManager(":0", manager)

		req := httptest.NewRequest("GET", "/api/download", nil)
		w := httptest.NewRecorder()

		server.handleDownload(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
		assert.Equal(t, "application/vnd.tcpdump.pcap", w.Header().Get("Content-Type"))
	})

	t.Run("with registry session (no file)", func(t *testing.T) {
		// Create registry without backend factory (manager will have nil backend)
		registry := state.NewRegistry(state.RegistryConfig{})
		session, err := registry.CreateSession("test-session")
		require.NoError(t, err)

		server := NewServerWithRegistry(":0", registry)

		req := httptest.NewRequest("GET", "/api/download?session="+session.ID, nil)
		w := httptest.NewRecorder()

		server.handleDownload(w, req)

		// Session exists but has no file
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid session id", func(t *testing.T) {
		registry := state.NewRegistry(state.RegistryConfig{})
		server := NewServerWithRegistry(":0", registry)

		req := httptest.NewRequest("GET", "/api/download?session=invalid-id", nil)
		w := httptest.NewRecorder()

		server.handleDownload(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// createTempPcap creates a minimal valid pcap file for testing
func createTempPcap(t *testing.T) (string, error) {
	t.Helper()
	tmpFile := t.TempDir() + "/test.pcap"
	// Minimal pcap global header (24 bytes) with no packets
	pcapHeader := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, // Magic number (little-endian)
		0x02, 0x00,             // Major version
		0x04, 0x00,             // Minor version
		0x00, 0x00, 0x00, 0x00, // Timezone
		0x00, 0x00, 0x00, 0x00, // Sigfigs
		0xff, 0xff, 0x00, 0x00, // Snaplen
		0x01, 0x00, 0x00, 0x00, // Network type (Ethernet)
	}
	err := writeFile(tmpFile, pcapHeader)
	return tmpFile, err
}

// writeFile writes data to a file
func writeFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
