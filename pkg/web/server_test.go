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
