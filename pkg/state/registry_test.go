// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})

	assert.NotNil(t, registry)
	assert.Equal(t, 0, registry.SessionCount())
}

func TestRegistry_CreateSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, err := registry.CreateSession("test-session")
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "test-session", session.Name)
	assert.NotEmpty(t, session.ID)
	assert.NotNil(t, session.Manager)
	assert.Equal(t, 1, registry.SessionCount())
}

func TestRegistry_CreateSession_DefaultName(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, err := registry.CreateSession("")
	require.NoError(t, err)
	assert.Contains(t, session.Name, "Session")
}

func TestRegistry_GetSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, _ := registry.CreateSession("test")

	// Get existing session
	found, ok := registry.GetSession(session.ID)
	assert.True(t, ok)
	assert.Equal(t, session, found)

	// Get non-existent session
	_, ok = registry.GetSession("nonexistent")
	assert.False(t, ok)
}

func TestRegistry_ListSessions(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	// Empty list
	sessions := registry.ListSessions()
	assert.Empty(t, sessions)

	// Create some sessions
	registry.CreateSession("session-1")
	registry.CreateSession("session-2")

	sessions = registry.ListSessions()
	assert.Len(t, sessions, 2)
}

func TestRegistry_DeleteSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, _ := registry.CreateSession("to-delete")
	id := session.ID

	assert.Equal(t, 1, registry.SessionCount())

	err := registry.DeleteSession(id)
	assert.NoError(t, err)
	assert.Equal(t, 0, registry.SessionCount())

	// Delete non-existent
	err = registry.DeleteSession("nonexistent")
	assert.Error(t, err)
}

func TestRegistry_Close(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})

	registry.CreateSession("session-1")
	registry.CreateSession("session-2")
	assert.Equal(t, 2, registry.SessionCount())

	err := registry.Close()
	assert.NoError(t, err)
	assert.Equal(t, 0, registry.SessionCount())
}

func TestManagedSession_Info(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, _ := registry.CreateSession("info-test")
	info := session.Info()

	assert.Equal(t, session.ID, info.ID)
	assert.Equal(t, "info-test", info.Name)
	assert.Equal(t, 0, info.ClientCount)
	assert.False(t, info.IsCapturing)
}

func TestManagedSession_ClientManagement(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, _ := registry.CreateSession("client-test")

	// Initially no clients
	assert.Equal(t, 0, session.ClientCount())

	// Add client
	client := &clientConn{}
	session.AddClient(client)
	assert.Equal(t, 1, session.ClientCount())

	// Add another client
	client2 := &clientConn{}
	session.AddClient(client2)
	assert.Equal(t, 2, session.ClientCount())

	// Remove client
	session.RemoveClient(client)
	assert.Equal(t, 1, session.ClientCount())
}

func TestManagedSession_Close(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	session, _ := registry.CreateSession("close-test")

	// Add a client
	client := &clientConn{}
	session.AddClient(client)
	assert.Equal(t, 1, session.ClientCount())

	// Close session
	err := session.Close()
	assert.NoError(t, err)
	assert.Equal(t, 0, session.ClientCount())
}

func TestRegistry_GetOrCreateDefaultSession(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	defer registry.Close()

	// First call creates the session
	session1, err := registry.GetOrCreateDefaultSession()
	require.NoError(t, err)
	assert.Equal(t, "default", session1.Name)

	// Second call returns the same session
	session2, err := registry.GetOrCreateDefaultSession()
	require.NoError(t, err)
	assert.Equal(t, session1.ID, session2.ID)
}

func TestRegistry_WithBackendFactory(t *testing.T) {
	factory := &mockBackendFactory{available: true}
	registry := NewRegistry(RegistryConfig{
		BackendFactory: factory,
	})
	defer registry.Close()

	session, err := registry.CreateSession("with-backend")
	require.NoError(t, err)
	assert.NotNil(t, session)
}

// mockBackendFactory implements BackendFactory for testing.
type mockBackendFactory struct {
	available bool
}

func (f *mockBackendFactory) Name() string {
	return "mock"
}

func (f *mockBackendFactory) Available() bool {
	return f.available
}

func (f *mockBackendFactory) Create(ctx context.Context) (Backend, error) {
	return &mockBackend{}, nil
}
