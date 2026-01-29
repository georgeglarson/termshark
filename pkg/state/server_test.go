// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestMustMarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "simple map",
			input:    map[string]string{"key": "value"},
			expected: `{"key":"value"}`,
		},
		{
			name:     "number",
			input:    42,
			expected: "42",
		},
		{
			name:     "nil",
			input:    nil,
			expected: "null",
		},
		{
			name:     "string",
			input:    "hello",
			expected: `"hello"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustMarshal(tt.input)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestMustMarshal_UnmarshalableType(t *testing.T) {
	// Channel types can't be marshaled
	ch := make(chan int)
	result := mustMarshal(ch)
	assert.Equal(t, "null", string(result))
}

func TestNewServer(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{
		UnixSocket: "/tmp/test.sock",
		HTTPAddr:   "127.0.0.1:8080",
	})

	assert.NotNil(t, server)
	assert.Equal(t, "/tmp/test.sock", server.UnixSocketPath())
	assert.Equal(t, "127.0.0.1:8080", server.HTTPAddr())
}

func TestNewServer_EmptyConfig(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})

	assert.NotNil(t, server)
	assert.Equal(t, "", server.UnixSocketPath())
	assert.Equal(t, "", server.HTTPAddr())
}

func TestServer_StartStop_UnixSocket(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	socketPath := filepath.Join(os.TempDir(), "termshark-test-server.sock")
	defer os.Remove(socketPath)

	server := NewServer(manager, ServerConfig{
		UnixSocket: socketPath,
	})

	err := server.Start()
	require.NoError(t, err)

	// Verify socket exists
	_, err = os.Stat(socketPath)
	assert.NoError(t, err)

	// Stop server
	err = server.Stop()
	assert.NoError(t, err)

	// Socket should be cleaned up
	_, err = os.Stat(socketPath)
	assert.True(t, os.IsNotExist(err))
}

func TestServer_UnixSocket_Communication(t *testing.T) {
	backend := &mockBackend{
		status: &Status{PacketCount: 42, Duration: 1.5},
	}
	manager := NewManager(backend)

	socketPath := filepath.Join(os.TempDir(), "termshark-test-comm.sock")
	defer os.Remove(socketPath)

	server := NewServer(manager, ServerConfig{
		UnixSocket: socketPath,
	})

	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect as a client
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send a JSON-RPC request
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "session.status",
	}
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(req)
	require.NoError(t, err)

	// Read response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	decoder := json.NewDecoder(conn)
	var resp jsonRPCResponse
	err = decoder.Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 1, resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestServer_Dispatch_SessionStatus(t *testing.T) {
	backend := &mockBackend{
		status: &Status{PacketCount: 100},
	}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("session.status", nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	status := result.(*Status)
	assert.Equal(t, 100, status.PacketCount)
}

func TestServer_Dispatch_SessionLoadFile(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.loadFile", map[string]interface{}{
		"path": "/tmp/test.pcap",
	})
	assert.NoError(t, err)
}

func TestServer_Dispatch_SessionLoadFile_MissingPath(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.loadFile", map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path required")
}

func TestServer_Dispatch_SessionSetFilter(t *testing.T) {
	backend := &mockBackend{filterValid: true}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.setFilter", map[string]interface{}{
		"filter": "tcp",
	})
	assert.NoError(t, err)
}

func TestServer_Dispatch_SessionGetPackets(t *testing.T) {
	packets := []PacketSummary{
		{Number: 1, Columns: []string{"1", "0.0"}},
	}
	backend := &mockBackend{packets: packets}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("session.getPackets", map[string]interface{}{
		"start": float64(0),
		"count": float64(100),
	})
	assert.NoError(t, err)

	resultPackets := result.([]PacketSummary)
	assert.Len(t, resultPackets, 1)
}

func TestServer_Dispatch_SessionGetPacket(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("session.getPacket", map[string]interface{}{
		"num": float64(5),
	})
	assert.NoError(t, err)

	detail := result.(*PacketDetail)
	assert.Equal(t, 5, detail.Number)
}

func TestServer_Dispatch_SessionGetPacket_MissingNum(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.getPacket", map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "num required")
}

func TestServer_Dispatch_SessionSelectPacket(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.selectPacket", map[string]interface{}{
		"num": float64(10),
	})
	assert.NoError(t, err)
}

func TestServer_Dispatch_SessionValidateFilter(t *testing.T) {
	backend := &mockBackend{filterValid: true}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("session.validateFilter", map[string]interface{}{
		"filter": "tcp",
	})
	assert.NoError(t, err)

	validation := result.(*FilterValidation)
	assert.True(t, validation.Valid)
}

func TestServer_Dispatch_UnknownMethod(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("unknown.method", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown method")
}

func TestServer_Dispatch_ParamsConversion(t *testing.T) {
	backend := &mockBackend{filterValid: true}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	// Test with struct params that need JSON conversion
	type customParams struct {
		Filter string `json:"filter"`
	}
	params := customParams{Filter: "udp"}

	_, err := client.dispatch("session.setFilter", params)
	assert.NoError(t, err)
}

func TestClientConn_HandleRequest(t *testing.T) {
	backend := &mockBackend{
		status: &Status{PacketCount: 50},
	}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      42,
		Method:  "session.status",
	}

	resp := client.handleRequest(req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 42, resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestClientConn_HandleRequest_Error(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown.method",
	}

	resp := client.handleRequest(req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 1, resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestClientConn_Close(t *testing.T) {
	client := &clientConn{}

	// Should not panic with nil connections
	client.close()
}

func TestServer_AddRemoveClient(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})

	client := &clientConn{server: server}

	// Add client
	server.addClient(client)
	assert.True(t, server.clients[client])
	assert.NotNil(t, client.subCh)
	assert.NotNil(t, client.unsubFn)

	// Remove client
	server.removeClient(client)
	assert.False(t, server.clients[client])
}

func TestSharkdBackendFactory(t *testing.T) {
	factory := &SharkdBackendFactory{}

	assert.Equal(t, "sharkd", factory.Name())
	// Available depends on whether sharkd is installed
	_ = factory.Available()
}

func TestSharkdBackendFactory_Create(t *testing.T) {
	factory := &SharkdBackendFactory{}

	if !factory.Available() {
		t.Skip("sharkd not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend, err := factory.Create(ctx)
	if err != nil {
		t.Skipf("failed to create sharkd backend: %v", err)
	}
	defer backend.Close()

	assert.NotNil(t, backend)
}

func TestServer_HandleHealth(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})

	// Create a test response writer
	rr := &httpResponseRecorder{
		headers: make(http.Header),
	}

	server.handleHealth(rr, nil)

	assert.Equal(t, "application/json", rr.headers.Get("Content-Type"))
	assert.Contains(t, rr.body, `"status":"ok"`)
}

// httpResponseRecorder implements http.ResponseWriter for testing
type httpResponseRecorder struct {
	headers    http.Header
	body       string
	statusCode int
}

func (w *httpResponseRecorder) Header() http.Header {
	return w.headers
}

func (w *httpResponseRecorder) Write(b []byte) (int, error) {
	w.body += string(b)
	return len(b), nil
}

func (w *httpResponseRecorder) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func TestServer_Dispatch_StartCapture_MissingInterface(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("session.startCapture", map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "interface required")
}

func TestServer_Dispatch_StopCapture(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	// Stop capture when not running should be fine
	_, err := client.dispatch("session.stopCapture", nil)
	assert.NoError(t, err)
}

func TestServer_Dispatch_IsCapturing(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	server := NewServer(manager, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("session.isCapturing", nil)
	assert.NoError(t, err)

	captureResult := result.(map[string]bool)
	assert.False(t, captureResult["capturing"])
}

func TestServer_Stop_NoListeners(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})

	// Stop without starting should be fine
	err := server.Stop()
	assert.NoError(t, err)
}

func TestNewServerWithRegistry(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{
		HTTPAddr: "127.0.0.1:0",
	})

	assert.NotNil(t, server)
	assert.Equal(t, registry, server.Registry())
	assert.Nil(t, server.manager) // No default manager when using registry
}

func TestServer_Dispatch_SessionsList(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Empty list initially
	result, err := client.dispatch("sessions.list", nil)
	assert.NoError(t, err)
	sessions := result.([]SessionInfo)
	assert.Empty(t, sessions)
}

func TestServer_Dispatch_SessionsCreate(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	result, err := client.dispatch("sessions.create", map[string]interface{}{
		"name": "test-session",
	})
	assert.NoError(t, err)

	info := result.(SessionInfo)
	assert.Equal(t, "test-session", info.Name)
	assert.NotEmpty(t, info.ID)
}

func TestServer_Dispatch_SessionsJoin(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Create a session first
	session, _ := registry.CreateSession("join-test")

	// Join the session
	result, err := client.dispatch("sessions.join", map[string]interface{}{
		"id": session.ID,
	})
	assert.NoError(t, err)

	info := result.(SessionInfo)
	assert.Equal(t, session.ID, info.ID)
	assert.NotNil(t, client.session)
}

func TestServer_Dispatch_SessionsJoin_NotFound(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("sessions.join", map[string]interface{}{
		"id": "nonexistent",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestServer_Dispatch_SessionsLeave(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Create and join a session
	session, _ := registry.CreateSession("leave-test")
	client.dispatch("sessions.join", map[string]interface{}{"id": session.ID})

	// Leave the session
	result, err := client.dispatch("sessions.leave", nil)
	assert.NoError(t, err)

	leftResult := result.(map[string]bool)
	assert.True(t, leftResult["left"])
	assert.Nil(t, client.session)
}

func TestServer_Dispatch_SessionsLeave_NotInSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	_, err := client.dispatch("sessions.leave", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in a session")
}

func TestServer_Dispatch_SessionsInfo(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Create a session
	session, _ := registry.CreateSession("info-test")

	// Get info by ID
	result, err := client.dispatch("sessions.info", map[string]interface{}{
		"id": session.ID,
	})
	assert.NoError(t, err)

	info := result.(SessionInfo)
	assert.Equal(t, "info-test", info.Name)
}

func TestServer_Dispatch_SessionsInfo_CurrentSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Create and join a session
	session, _ := registry.CreateSession("current-info")
	client.dispatch("sessions.join", map[string]interface{}{"id": session.ID})

	// Get info without ID (returns current session)
	result, err := client.dispatch("sessions.info", map[string]interface{}{})
	assert.NoError(t, err)

	info := result.(SessionInfo)
	assert.Equal(t, "current-info", info.Name)
}

func TestServer_Dispatch_SessionsDelete(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Create a session
	session, _ := registry.CreateSession("to-delete")

	// Delete it
	result, err := client.dispatch("sessions.delete", map[string]interface{}{
		"id": session.ID,
	})
	assert.NoError(t, err)

	deleteResult := result.(map[string]bool)
	assert.True(t, deleteResult["deleted"])
	assert.Equal(t, 0, registry.SessionCount())
}

func TestServer_Dispatch_NoSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	server := NewServerWithRegistry(registry, ServerConfig{})
	client := &clientConn{server: server}

	// Try to get status without joining a session
	_, err := client.dispatch("session.status", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session active")
}

func TestServer_ClientCount(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)

	server := NewServer(manager, ServerConfig{})

	assert.Equal(t, 0, server.ClientCount())

	// Add a client manually
	client := &clientConn{server: server}
	server.addClient(client)

	assert.Equal(t, 1, server.ClientCount())
}
