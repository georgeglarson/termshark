// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharedSession_MultipleClients tests that multiple clients can share a session
// and see each other's state changes in real-time.
func TestSharedSession_MultipleClients(t *testing.T) {
	// Create a registry with a mock backend
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	// Create server with registry
	socketPath := filepath.Join(os.TempDir(), "termshark-shared-test.sock")
	defer os.Remove(socketPath)

	server := NewServerWithRegistry(registry, ServerConfig{
		UnixSocket: socketPath,
	})

	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect two clients
	conn1, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn2.Close()

	// Helper to send JSON-RPC request and get response
	sendRequest := func(conn net.Conn, method string, params map[string]interface{}) (json.RawMessage, error) {
		req := jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  method,
			Params:  params,
		}
		encoder := json.NewEncoder(conn)
		if err := encoder.Encode(req); err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		decoder := json.NewDecoder(conn)
		var resp jsonRPCResponse
		if err := decoder.Decode(&resp); err != nil {
			return nil, err
		}

		if resp.Error != nil {
			return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}

	// Client 1 creates a session
	result, err := sendRequest(conn1, "sessions.create", map[string]interface{}{
		"name": "shared-test",
	})
	require.NoError(t, err)

	var sessionInfo SessionInfo
	err = json.Unmarshal(result, &sessionInfo)
	require.NoError(t, err)
	assert.Equal(t, "shared-test", sessionInfo.Name)
	sessionID := sessionInfo.ID

	t.Logf("Created session: %s (ID: %s)", sessionInfo.Name, sessionID)

	// Client 1 joins the session
	result, err = sendRequest(conn1, "sessions.join", map[string]interface{}{
		"id": sessionID,
	})
	require.NoError(t, err)
	t.Log("Client 1 joined session")

	// Client 2 lists sessions and sees the shared session
	result, err = sendRequest(conn2, "sessions.list", nil)
	require.NoError(t, err)

	var sessions []SessionInfo
	err = json.Unmarshal(result, &sessions)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "shared-test", sessions[0].Name)
	t.Logf("Client 2 sees %d session(s)", len(sessions))

	// Client 2 joins the same session
	result, err = sendRequest(conn2, "sessions.join", map[string]interface{}{
		"id": sessionID,
	})
	require.NoError(t, err)
	t.Log("Client 2 joined session")

	// Check session now has 2 clients
	result, err = sendRequest(conn1, "sessions.info", map[string]interface{}{
		"id": sessionID,
	})
	require.NoError(t, err)

	err = json.Unmarshal(result, &sessionInfo)
	require.NoError(t, err)
	assert.Equal(t, 2, sessionInfo.ClientCount)
	t.Logf("Session has %d clients", sessionInfo.ClientCount)

	// Client 1 gets status (both clients can access the same session state)
	result, err = sendRequest(conn1, "session.status", nil)
	require.NoError(t, err)
	t.Log("Client 1 got session status")

	// Client 2 also gets status
	result, err = sendRequest(conn2, "session.status", nil)
	require.NoError(t, err)
	t.Log("Client 2 got session status")

	// Client 1 leaves
	result, err = sendRequest(conn1, "sessions.leave", nil)
	require.NoError(t, err)
	t.Log("Client 1 left session")

	// Check session now has 1 client
	result, err = sendRequest(conn2, "sessions.info", map[string]interface{}{})
	require.NoError(t, err)

	err = json.Unmarshal(result, &sessionInfo)
	require.NoError(t, err)
	assert.Equal(t, 1, sessionInfo.ClientCount)
	t.Logf("Session now has %d client(s)", sessionInfo.ClientCount)
}

// TestSharedSession_StateChangeBroadcast tests that state changes are broadcast
// to all clients in a session.
func TestSharedSession_StateChangeBroadcast(t *testing.T) {
	// Create registry and session directly (simpler for this test)
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, err := registry.CreateSession("broadcast-test")
	require.NoError(t, err)

	// Create two mock clients that subscribe to state changes
	ch1, unsub1 := session.Manager.Subscribe(10)
	defer unsub1()

	ch2, unsub2 := session.Manager.Subscribe(10)
	defer unsub2()

	// Make a state change
	session.Manager.Session().SetPacketCount(100)

	// Both clients should receive the change
	select {
	case change := <-ch1:
		assert.Equal(t, ChangePacketsAdded, change.Type)
		t.Log("Client 1 received state change")
	case <-time.After(time.Second):
		t.Error("Client 1 did not receive state change")
	}

	select {
	case change := <-ch2:
		assert.Equal(t, ChangePacketsAdded, change.Type)
		t.Log("Client 2 received state change")
	case <-time.After(time.Second):
		t.Error("Client 2 did not receive state change")
	}
}

// TestSharedSession_IsolatedSessions tests that different sessions are isolated.
func TestSharedSession_IsolatedSessions(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	// Create two separate sessions
	session1, err := registry.CreateSession("session-1")
	require.NoError(t, err)

	session2, err := registry.CreateSession("session-2")
	require.NoError(t, err)

	// Subscribe to changes in session 1
	ch1, unsub1 := session1.Manager.Subscribe(10)
	defer unsub1()

	// Make a change in session 2
	session2.Manager.Session().SetPacketCount(50)

	// Session 1's subscriber should NOT receive the change
	select {
	case <-ch1:
		t.Error("Session 1 incorrectly received change from session 2")
	case <-time.After(100 * time.Millisecond):
		t.Log("Sessions are properly isolated")
	}

	// Verify each session has its own state
	status1, _ := session1.Manager.GetStatus()
	status2, _ := session2.Manager.GetStatus()

	assert.Equal(t, 0, status1.PacketCount)
	assert.Equal(t, 50, status2.PacketCount)
}

// TestSharedSession_JoinSwitchSession tests switching from one session to another.
func TestSharedSession_JoinSwitchSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	socketPath := filepath.Join(os.TempDir(), "termshark-switch-test.sock")
	defer os.Remove(socketPath)

	server := NewServerWithRegistry(registry, ServerConfig{
		UnixSocket: socketPath,
	})

	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	sendRequest := func(method string, params map[string]interface{}) (json.RawMessage, error) {
		req := jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  method,
			Params:  params,
		}
		encoder := json.NewEncoder(conn)
		if err := encoder.Encode(req); err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		decoder := json.NewDecoder(conn)
		var resp jsonRPCResponse
		if err := decoder.Decode(&resp); err != nil {
			return nil, err
		}

		if resp.Error != nil {
			return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}

	// Create two sessions
	result, err := sendRequest("sessions.create", map[string]interface{}{"name": "first"})
	require.NoError(t, err)
	var info1 SessionInfo
	json.Unmarshal(result, &info1)

	result, err = sendRequest("sessions.create", map[string]interface{}{"name": "second"})
	require.NoError(t, err)
	var info2 SessionInfo
	json.Unmarshal(result, &info2)

	// Join first session
	_, err = sendRequest("sessions.join", map[string]interface{}{"id": info1.ID})
	require.NoError(t, err)

	// Verify in first session
	result, err = sendRequest("sessions.info", nil)
	require.NoError(t, err)
	var currentInfo SessionInfo
	json.Unmarshal(result, &currentInfo)
	assert.Equal(t, "first", currentInfo.Name)

	// Switch to second session (join automatically leaves previous)
	_, err = sendRequest("sessions.join", map[string]interface{}{"id": info2.ID})
	require.NoError(t, err)

	// Verify in second session
	result, err = sendRequest("sessions.info", nil)
	require.NoError(t, err)
	json.Unmarshal(result, &currentInfo)
	assert.Equal(t, "second", currentInfo.Name)

	// First session should have 0 clients now
	session1, _ := registry.GetSession(info1.ID)
	assert.Equal(t, 0, session1.ClientCount())

	t.Log("Successfully switched sessions")
}
