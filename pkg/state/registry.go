// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SessionInfo contains metadata about a session.
type SessionInfo struct {
	// ID is the unique session identifier.
	ID string `json:"id"`
	// Name is an optional human-readable name for the session.
	Name string `json:"name,omitempty"`
	// CreatedAt is when the session was created.
	CreatedAt time.Time `json:"createdAt"`
	// Source is the current packet source (file path or interface).
	Source string `json:"source,omitempty"`
	// SourceType indicates whether source is a file or interface.
	SourceType SourceType `json:"sourceType"`
	// ClientCount is the number of connected clients.
	ClientCount int `json:"clientCount"`
	// PacketCount is the current number of packets loaded.
	PacketCount int `json:"packetCount"`
	// IsCapturing indicates if live capture is active.
	IsCapturing bool `json:"isCapturing"`
}

// ManagedSession wraps a Manager with session metadata.
type ManagedSession struct {
	ID        string
	Name      string
	CreatedAt time.Time
	Manager   *Manager
	Server    *Server
	clients   map[*clientConn]bool
	mu        sync.RWMutex
}

// Registry manages multiple shared sessions.
type Registry struct {
	mu             sync.RWMutex
	sessions       map[string]*ManagedSession
	backendFactory BackendFactory
	ctx            context.Context
	cancel         context.CancelFunc

	// Default server config for new sessions
	defaultHTTPAddr   string
	defaultUnixSocket string
}

// RegistryConfig configures the session registry.
type RegistryConfig struct {
	// BackendFactory creates backends for new sessions.
	BackendFactory BackendFactory
	// DefaultHTTPAddr is the base HTTP address (sessions append port offset).
	DefaultHTTPAddr string
	// DefaultUnixSocket is the base Unix socket path pattern.
	DefaultUnixSocket string
}

// NewRegistry creates a new session registry.
func NewRegistry(config RegistryConfig) *Registry {
	ctx, cancel := context.WithCancel(context.Background())
	return &Registry{
		sessions:          make(map[string]*ManagedSession),
		backendFactory:    config.BackendFactory,
		defaultHTTPAddr:   config.DefaultHTTPAddr,
		defaultUnixSocket: config.DefaultUnixSocket,
		ctx:               ctx,
		cancel:            cancel,
	}
}

// CreateSession creates a new session with the given name.
// If name is empty, a default name is generated.
func (r *Registry) CreateSession(name string) (*ManagedSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := generateSessionID()

	if name == "" {
		name = fmt.Sprintf("Session %s", id)
	}

	// Create backend
	var backend Backend
	var err error
	if r.backendFactory != nil && r.backendFactory.Available() {
		backend, err = r.backendFactory.Create(r.ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create backend: %w", err)
		}
	}

	// Create manager
	manager := NewManager(backend)

	session := &ManagedSession{
		ID:        id,
		Name:      name,
		CreatedAt: time.Now(),
		Manager:   manager,
		clients:   make(map[*clientConn]bool),
	}

	r.sessions[id] = session
	return session, nil
}

// GetSession returns a session by ID.
func (r *Registry) GetSession(id string) (*ManagedSession, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[id]
	return session, ok
}

// ListSessions returns info about all active sessions.
func (r *Registry) ListSessions() []SessionInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]SessionInfo, 0, len(r.sessions))
	for _, session := range r.sessions {
		result = append(result, session.Info())
	}
	return result
}

// DeleteSession removes and cleans up a session.
func (r *Registry) DeleteSession(id string) error {
	r.mu.Lock()
	session, ok := r.sessions[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("session not found: %s", id)
	}
	delete(r.sessions, id)
	r.mu.Unlock()

	// Close the session
	session.Close()
	return nil
}

// Close shuts down the registry and all sessions.
func (r *Registry) Close() error {
	r.cancel()

	r.mu.Lock()
	defer r.mu.Unlock()

	for id, session := range r.sessions {
		session.Close()
		delete(r.sessions, id)
	}
	return nil
}

// SessionCount returns the number of active sessions.
func (r *Registry) SessionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Info returns metadata about the session.
func (s *ManagedSession) Info() SessionInfo {
	s.mu.RLock()
	clientCount := len(s.clients)
	s.mu.RUnlock()

	status, _ := s.Manager.GetStatus()

	info := SessionInfo{
		ID:          s.ID,
		Name:        s.Name,
		CreatedAt:   s.CreatedAt,
		ClientCount: clientCount,
		IsCapturing: s.Manager.IsCapturing(),
	}

	if status != nil {
		info.Source = status.Source
		info.SourceType = status.SourceType
		info.PacketCount = status.PacketCount
	}

	return info
}

// AddClient adds a client to the session.
func (s *ManagedSession) AddClient(client *clientConn) {
	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()
}

// RemoveClient removes a client from the session.
func (s *ManagedSession) RemoveClient(client *clientConn) {
	s.mu.Lock()
	delete(s.clients, client)
	s.mu.Unlock()
}

// ClientCount returns the number of connected clients.
func (s *ManagedSession) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// Close shuts down the session and disconnects all clients.
func (s *ManagedSession) Close() error {
	s.mu.Lock()
	clients := make([]*clientConn, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	s.clients = make(map[*clientConn]bool)
	s.mu.Unlock()

	// Close all clients
	for _, client := range clients {
		client.close()
	}

	// Close server if running
	if s.Server != nil {
		s.Server.Stop()
	}

	// Close manager
	return s.Manager.Close()
}

// GetOrCreateDefaultSession gets the default session or creates one.
// This is useful for simple single-session scenarios.
func (r *Registry) GetOrCreateDefaultSession() (*ManagedSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Look for a session named "default"
	for _, session := range r.sessions {
		if session.Name == "default" {
			return session, nil
		}
	}

	// Create default session
	r.mu.Unlock()
	session, err := r.CreateSession("default")
	r.mu.Lock()
	return session, err
}

// generateSessionID creates a short random session ID.
func generateSessionID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFFFFFF)
	}
	return hex.EncodeToString(b)
}
