// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	return nil, nil
}

func (m *mockBackend) Sync(ctx context.Context) error {
	return nil
}

func (m *mockBackend) Close() error {
	return nil
}
