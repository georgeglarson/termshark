// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"sync"

	"github.com/gcla/termshark/v2/pkg/state"
	"github.com/gorilla/websocket"
)

// clientState tracks per-connection state
type clientState struct {
	session       *state.ManagedSession
	conn          *websocket.Conn
	subscriptions map[string]bool // Event types this client is subscribed to
	mu            sync.RWMutex
	writeMu       sync.Mutex // Protects concurrent WebSocket writes
}

// PushNotification is a server-initiated notification sent to clients.
type PushNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// Subscribe adds an event subscription for a client.
func (cs *clientState) Subscribe(event string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.subscriptions == nil {
		cs.subscriptions = make(map[string]bool)
	}
	cs.subscriptions[event] = true
}

// Unsubscribe removes an event subscription for a client.
func (cs *clientState) Unsubscribe(event string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.subscriptions, event)
}

// WriteJSON safely writes a JSON message to the WebSocket connection.
// This serializes all writes to prevent concurrent write panics.
func (cs *clientState) WriteJSON(v interface{}) error {
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	return cs.conn.WriteJSON(v)
}

// Broadcast sends a push notification to all connected clients subscribed to the event.
func (s *Server) Broadcast(event string, params interface{}) {
	notification := PushNotification{
		JSONRPC: "2.0",
		Method:  event,
		Params:  params,
	}

	s.mu.RLock()
	clients := make([]*clientState, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.RUnlock()

	for _, client := range clients {
		client.mu.RLock()
		subscribed := client.subscriptions[event]
		client.mu.RUnlock()

		if subscribed {
			go func(cs *clientState) {
				cs.WriteJSON(notification)
			}(client)
		}
	}
}

// BroadcastToSession sends a push notification to all clients in a specific session.
func (s *Server) BroadcastToSession(session *state.ManagedSession, event string, params interface{}) {
	notification := PushNotification{
		JSONRPC: "2.0",
		Method:  event,
		Params:  params,
	}

	s.mu.RLock()
	clients := make([]*clientState, 0)
	for _, client := range s.clients {
		client.mu.RLock()
		clientSession := client.session
		client.mu.RUnlock()
		if clientSession == session {
			clients = append(clients, client)
		}
	}
	s.mu.RUnlock()

	for _, client := range clients {
		client.mu.RLock()
		subscribed := client.subscriptions[event]
		client.mu.RUnlock()

		if subscribed {
			go func(cs *clientState) {
				cs.WriteJSON(notification)
			}(client)
		}
	}
}

// NotifyPacketUpdate sends a packet count update to subscribed clients.
func (s *Server) NotifyPacketUpdate(packetCount int) {
	s.Broadcast("packets.update", map[string]interface{}{
		"count": packetCount,
	})
}

// NotifyCaptureState sends a capture state change to subscribed clients.
func (s *Server) NotifyCaptureState(capturing bool, iface string) {
	s.Broadcast("capture.state", map[string]interface{}{
		"capturing": capturing,
		"interface": iface,
	})
}
