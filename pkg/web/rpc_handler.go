// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/state"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// handleWebSocket handles WebSocket connections and proxies to sharkd or manager.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	clientSt := &clientState{
		conn:          conn,
		subscriptions: make(map[string]bool),
	}
	s.mu.Lock()
	s.clients[conn] = clientSt
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		// Leave session if in one
		clientSt.mu.RLock()
		sess := clientSt.session
		clientSt.mu.RUnlock()
		if sess != nil {
			sess.RemoveClient(nil)
		}
	}()

	log.Info("WebSocket client connected")

	for {
		// Read message from client
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Errorf("WebSocket error: %v", err)
			}
			break
		}

		// Parse the JSON-RPC request
		var req JSONRPCRequest
		if err := json.Unmarshal(message, &req); err != nil {
			s.sendErrorVia(clientSt, 0, -32700, "Parse error")
			continue
		}

		// Handle subscription methods first (available for all clients)
		if req.Method == "subscribe" || req.Method == "unsubscribe" {
			var p map[string]interface{}
			if req.Params != nil {
				switch v := req.Params.(type) {
				case map[string]interface{}:
					p = v
				default:
					b, err := json.Marshal(req.Params)
					if err == nil {
						json.Unmarshal(b, &p)
					}
				}
			}
			event, _ := p["event"].(string)
			if event == "" {
				s.sendErrorVia(clientSt, req.ID, -32602, "event parameter required")
				continue
			}
			if req.Method == "subscribe" {
				clientSt.Subscribe(event)
			} else {
				clientSt.Unsubscribe(event)
			}
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  json.RawMessage(`{"status":"ok"}`),
			}
			clientSt.WriteJSON(resp)
			continue
		}

		// Handle via registry, manager, or sharkd
		var result json.RawMessage
		if s.registry != nil {
			result, err = s.handleRegistryRequest(req, clientSt)
		} else if s.manager != nil {
			result, err = s.handleManagerRequest(req)
		} else {
			// Fallback to direct sharkd
			result, err = s.sharkd.Call(req.Method, req.Params)
		}

		if err != nil {
			s.sendErrorVia(clientSt, req.ID, -32603, err.Error())
			continue
		}

		// Send response back to client
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}
		if err := clientSt.WriteJSON(resp); err != nil {
			log.Errorf("Failed to write response: %v", err)
			break
		}
	}
}

// handleRegistryRequest routes a request through the session registry.
func (s *Server) handleRegistryRequest(req JSONRPCRequest, clientSt *clientState) (json.RawMessage, error) {
	// Convert params to map if needed
	var p map[string]interface{}
	if req.Params != nil {
		switch v := req.Params.(type) {
		case map[string]interface{}:
			p = v
		default:
			b, err := json.Marshal(req.Params)
			if err == nil {
				json.Unmarshal(b, &p)
			}
		}
	}

	var result interface{}

	// Handle session management methods
	switch req.Method {
	case "sessions.list":
		result = s.registry.ListSessions()
		return json.Marshal(result)

	case "sessions.create":
		name, _ := p["name"].(string)
		session, err := s.registry.CreateSession(name)
		if err != nil {
			return nil, err
		}
		result = session.Info()
		return json.Marshal(result)

	case "sessions.join":
		sessionID, _ := p["id"].(string)
		if sessionID == "" {
			return nil, fmt.Errorf("session id required")
		}
		session, ok := s.registry.GetSession(sessionID)
		if !ok {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		// Leave current session if any
		clientSt.mu.Lock()
		oldSession := clientSt.session
		clientSt.mu.Unlock()
		if oldSession != nil {
			oldSession.RemoveClient(nil)
		}
		clientSt.mu.Lock()
		clientSt.session = session
		clientSt.mu.Unlock()
		session.AddClient(nil)
		result = session.Info()
		return json.Marshal(result)

	case "sessions.leave":
		clientSt.mu.RLock()
		sess := clientSt.session
		clientSt.mu.RUnlock()
		if sess == nil {
			return nil, fmt.Errorf("not in a session")
		}
		sess.RemoveClient(nil)
		clientSt.mu.Lock()
		clientSt.session = nil
		clientSt.mu.Unlock()
		result = map[string]bool{"left": true}
		return json.Marshal(result)

	case "sessions.info":
		sessionID, _ := p["id"].(string)
		if sessionID == "" {
			clientSt.mu.RLock()
			infoSess := clientSt.session
			clientSt.mu.RUnlock()
			if infoSess != nil {
				result = infoSess.Info()
				return json.Marshal(result)
			}
			return nil, fmt.Errorf("not in a session and no id provided")
		}
		session, ok := s.registry.GetSession(sessionID)
		if !ok {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		result = session.Info()
		return json.Marshal(result)

	case "sessions.delete":
		sessionID, _ := p["id"].(string)
		if sessionID == "" {
			return nil, fmt.Errorf("session id required")
		}
		if err := s.registry.DeleteSession(sessionID); err != nil {
			return nil, err
		}
		result = map[string]bool{"deleted": true}
		return json.Marshal(result)
	}

	// For other methods, require an active session
	clientSt.mu.RLock()
	sess := clientSt.session
	clientSt.mu.RUnlock()
	if sess == nil {
		return nil, fmt.Errorf("no session active - use sessions.join first")
	}

	// Route through the session's manager
	manager := sess.Manager
	return s.handleManagerRequestWithManager(req, manager)
}

// handleManagerRequestWithManager routes a request through a specific manager.
func (s *Server) handleManagerRequestWithManager(req JSONRPCRequest, manager *state.Manager) (json.RawMessage, error) {
	// Convert params to map if needed
	var p map[string]interface{}
	if req.Params != nil {
		switch v := req.Params.(type) {
		case map[string]interface{}:
			p = v
		default:
			b, err := json.Marshal(req.Params)
			if err == nil {
				json.Unmarshal(b, &p)
			}
		}
	}

	var result interface{}
	var err error

	switch req.Method {
	case "status":
		status, statusErr := manager.GetStatus()
		if statusErr != nil {
			err = statusErr
		} else {
			// Return sharkd-compatible format for frontend
			result = map[string]interface{}{
				"frames":   status.PacketCount,
				"duration": status.Duration,
				"columns":  status.Columns,
				"filename": status.Source,
			}
		}

	case "load":
		path, _ := p["file"].(string)
		if path == "" {
			return nil, fmt.Errorf("file path required")
		}
		err = manager.LoadFile(path)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "frames":
		start := int(getFloat(p, "skip", 0))
		count := int(getFloat(p, "limit", 100))
		packets, err := manager.GetPackets(start, count)
		if err != nil {
			return nil, err
		}
		frames := make([]map[string]interface{}, len(packets))
		for i, pkt := range packets {
			frames[i] = map[string]interface{}{
				"num": pkt.Number,
				"c":   pkt.Columns,
			}
			if pkt.BGColor != "" {
				frames[i]["bg"] = pkt.BGColor
			}
			if pkt.FGColor != "" {
				frames[i]["fg"] = pkt.FGColor
			}
		}
		result = frames

	case "frame":
		num := int(getFloat(p, "frame", 0))
		if num <= 0 {
			return nil, fmt.Errorf("frame number required")
		}
		detail, err := manager.GetPacketDetail(num)
		if err != nil {
			return nil, err
		}
		result = map[string]interface{}{
			"tree":  convertTreeToSharkd(detail.Tree),
			"bytes": detail.Bytes,
		}

	case "check":
		filter, _ := p["filter"].(string)
		validation, err := manager.ValidateFilter(filter)
		if err != nil {
			return nil, err
		}
		result = map[string]bool{"ok": validation.Valid}

	case "follow":
		protocol, _ := p["follow"].(string)
		if protocol == "" {
			return nil, fmt.Errorf("follow protocol required (e.g., 'tcp', 'udp', 'http')")
		}
		streamIndex := 0
		if idx, ok := p["stream"].(float64); ok {
			streamIndex = int(idx)
		}
		data, err := manager.FollowStream(protocol, streamIndex)
		if err != nil {
			return nil, err
		}
		// Return base64-encoded data in payload format
		result = map[string]interface{}{
			"payloads": []map[string]string{
				{"d": base64.StdEncoding.EncodeToString(data)},
			},
		}

	case "setfilter":
		filter, _ := p["filter"].(string)
		err = manager.SetFilter(filter)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "startCapture":
		iface, _ := p["interface"].(string)
		if iface == "" {
			return nil, fmt.Errorf("interface required")
		}
		captureFilter, _ := p["captureFilter"].(string)
		err = manager.StartCapture(iface, captureFilter)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "stopCapture":
		err = manager.StopCapture()
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "isCapturing":
		result = map[string]bool{"capturing": manager.IsCapturing()}

	case "listInterfaces":
		ifaces, err := termshark.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %w", err)
		}
		// Convert to list of interface info
		ifaceList := make([]map[string]interface{}, 0)
		for idx, names := range ifaces {
			if len(names) > 0 {
				ifaceList = append(ifaceList, map[string]interface{}{
					"index": idx,
					"name":  names[0],
					"aliases": names[1:],
				})
			}
		}
		result = ifaceList

	default:
		return nil, fmt.Errorf("unknown method: %s", req.Method)
	}

	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

// handleManagerRequest routes a request through the state manager.
func (s *Server) handleManagerRequest(req JSONRPCRequest) (json.RawMessage, error) {
	// Convert params to map if needed
	var p map[string]interface{}
	if req.Params != nil {
		switch v := req.Params.(type) {
		case map[string]interface{}:
			p = v
		default:
			// Try to convert via JSON
			b, err := json.Marshal(req.Params)
			if err == nil {
				json.Unmarshal(b, &p)
			}
		}
	}

	var result interface{}
	var err error

	switch req.Method {
	case "status":
		status, statusErr := s.manager.GetStatus()
		if statusErr != nil {
			err = statusErr
		} else {
			result = map[string]interface{}{
				"frames":   status.PacketCount,
				"duration": status.Duration,
				"columns":  status.Columns,
				"filename": status.Source,
			}
		}

	case "load":
		path, _ := p["file"].(string)
		if path == "" {
			return nil, fmt.Errorf("file path required")
		}
		err = s.manager.LoadFile(path)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "frames":
		start := int(getFloat(p, "skip", 0))
		count := int(getFloat(p, "limit", 100))
		packets, err := s.manager.GetPackets(start, count)
		if err != nil {
			return nil, err
		}
		// Convert to sharkd-compatible format
		frames := make([]map[string]interface{}, len(packets))
		for i, pkt := range packets {
			frames[i] = map[string]interface{}{
				"num": pkt.Number,
				"c":   pkt.Columns,
			}
			if pkt.BGColor != "" {
				frames[i]["bg"] = pkt.BGColor
			}
			if pkt.FGColor != "" {
				frames[i]["fg"] = pkt.FGColor
			}
		}
		result = frames

	case "frame":
		num := int(getFloat(p, "frame", 0))
		if num <= 0 {
			return nil, fmt.Errorf("frame number required")
		}
		detail, err := s.manager.GetPacketDetail(num)
		if err != nil {
			return nil, err
		}
		// Convert to sharkd-compatible format
		result = map[string]interface{}{
			"tree":  convertTreeToSharkd(detail.Tree),
			"bytes": detail.Bytes,
		}

	case "check":
		filter, _ := p["filter"].(string)
		validation, err := s.manager.ValidateFilter(filter)
		if err != nil {
			return nil, err
		}
		result = map[string]bool{"ok": validation.Valid}

	case "follow":
		protocol, _ := p["follow"].(string)
		if protocol == "" {
			return nil, fmt.Errorf("follow protocol required (e.g., 'tcp', 'udp', 'http')")
		}
		streamIndex := 0
		if idx, ok := p["stream"].(float64); ok {
			streamIndex = int(idx)
		}
		data, err := s.manager.FollowStream(protocol, streamIndex)
		if err != nil {
			return nil, err
		}
		result = map[string]interface{}{
			"payloads": []map[string]string{
				{"d": base64.StdEncoding.EncodeToString(data)},
			},
		}

	case "setfilter":
		filter, _ := p["filter"].(string)
		err = s.manager.SetFilter(filter)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "startCapture":
		iface, _ := p["interface"].(string)
		if iface == "" {
			return nil, fmt.Errorf("interface required")
		}
		captureFilter, _ := p["captureFilter"].(string)
		err = s.manager.StartCapture(iface, captureFilter)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "stopCapture":
		err = s.manager.StopCapture()
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

	case "isCapturing":
		result = map[string]bool{"capturing": s.manager.IsCapturing()}

	case "listInterfaces":
		ifaces, err := termshark.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %w", err)
		}
		ifaceList := make([]map[string]interface{}, 0)
		for idx, names := range ifaces {
			if len(names) > 0 {
				ifaceList = append(ifaceList, map[string]interface{}{
					"index":   idx,
					"name":    names[0],
					"aliases": names[1:],
				})
			}
		}
		result = ifaceList

	default:
		return nil, fmt.Errorf("unknown method: %s", req.Method)
	}

	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

// convertTreeToSharkd converts protocol nodes to sharkd format.
func convertTreeToSharkd(nodes []state.ProtocolNode) []map[string]interface{} {
	result := make([]map[string]interface{}, len(nodes))
	for i, n := range nodes {
		m := map[string]interface{}{
			"l": n.Label,
		}
		if n.Field != "" {
			m["f"] = n.Field
		}
		// Include position if size is set (indicates a byte range)
		if n.Size > 0 {
			m["h"] = n.Position
			m["i"] = n.Size
		}
		if len(n.Children) > 0 {
			m["n"] = convertTreeToSharkd(n.Children)
		}
		result[i] = m
	}
	return result
}

// getFloat gets a float64 from a map with a default value.
func getFloat(m map[string]interface{}, key string, def float64) float64 {
	if m == nil {
		return def
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	return def
}

// sendErrorVia sends a JSON-RPC error response through the clientState write mutex.
func (s *Server) sendErrorVia(cs *clientState, id int, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	cs.WriteJSON(resp)
}
