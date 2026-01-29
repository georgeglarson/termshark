// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/state"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

//go:embed static
var staticFiles embed.FS

// Server represents the web server for termshark.
type Server struct {
	addr     string
	sharkd   *SharkdClient         // Deprecated: use manager instead
	manager  *state.Manager        // New unified state manager
	registry *state.Registry       // Session registry for multi-session support
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]*clientState
}

// clientState tracks per-connection state
type clientState struct {
	session       *state.ManagedSession
	conn          *websocket.Conn
	subscriptions map[string]bool // Event types this client is subscribed to
	mu            sync.RWMutex
}

// PushNotification is a server-initiated notification sent to clients.
type PushNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// NewServer creates a new web server with a SharkdClient.
// Deprecated: Use NewServerWithManager instead.
func NewServer(addr string, sharkd *SharkdClient) *Server {
	return &Server{
		addr:   addr,
		sharkd: sharkd,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local development
			},
		},
		clients: make(map[*websocket.Conn]*clientState),
	}
}

// NewServerWithManager creates a new web server using the unified state manager.
func NewServerWithManager(addr string, manager *state.Manager) *Server {
	return &Server{
		addr:    addr,
		manager: manager,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local development
			},
		},
		clients: make(map[*websocket.Conn]*clientState),
	}
}

// NewServerWithRegistry creates a new web server with session registry support.
func NewServerWithRegistry(addr string, registry *state.Registry) *Server {
	return &Server{
		addr:     addr,
		registry: registry,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local development
			},
		},
		clients: make(map[*websocket.Conn]*clientState),
	}
}

// Start begins serving HTTP requests.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Serve static files from embedded filesystem
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to create static filesystem: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.handleWebSocket)

	// File load endpoint
	mux.HandleFunc("/api/load", s.handleLoadFile)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Download pcap endpoint
	mux.HandleFunc("/api/download", s.handleDownload)

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Infof("Web server starting on http://%s", s.addr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

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
		if clientSt.session != nil {
			clientSt.session.RemoveClient(nil)
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
			s.sendError(conn, 0, -32700, "Parse error")
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
					b, _ := json.Marshal(req.Params)
					json.Unmarshal(b, &p)
				}
			}
			event, _ := p["event"].(string)
			if event == "" {
				s.sendError(conn, req.ID, -32602, "event parameter required")
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
			conn.WriteJSON(resp)
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
			s.sendError(conn, req.ID, -32603, err.Error())
			continue
		}

		// Send response back to client
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}
		if err := conn.WriteJSON(resp); err != nil {
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
			b, _ := json.Marshal(req.Params)
			json.Unmarshal(b, &p)
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
		if clientSt.session != nil {
			clientSt.session.RemoveClient(nil)
		}
		clientSt.session = session
		session.AddClient(nil)
		result = session.Info()
		return json.Marshal(result)

	case "sessions.leave":
		if clientSt.session == nil {
			return nil, fmt.Errorf("not in a session")
		}
		clientSt.session.RemoveClient(nil)
		clientSt.session = nil
		result = map[string]bool{"left": true}
		return json.Marshal(result)

	case "sessions.info":
		sessionID, _ := p["id"].(string)
		if sessionID == "" {
			if clientSt.session != nil {
				result = clientSt.session.Info()
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
	if clientSt.session == nil {
		return nil, fmt.Errorf("no session active - use sessions.join first")
	}

	// Route through the session's manager
	manager := clientSt.session.Manager
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
			b, _ := json.Marshal(req.Params)
			json.Unmarshal(b, &p)
		}
	}

	var result interface{}
	var err error

	switch req.Method {
	case "status":
		result, err = manager.GetStatus()

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
			b, _ := json.Marshal(req.Params)
			json.Unmarshal(b, &p)
		}
	}

	var result interface{}
	var err error

	switch req.Method {
	case "status":
		result, err = s.manager.GetStatus()

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

// sendError sends a JSON-RPC error response.
func (s *Server) sendError(conn *websocket.Conn, id int, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	conn.WriteJSON(resp)
}

// handleLoadFile handles loading a pcap file by path (for server-side files).
func (s *Server) handleLoadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		File string `json:"file"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.File == "" {
		http.Error(w, "File path required", http.StatusBadRequest)
		return
	}

	// Load file via manager or sharkd
	if s.manager != nil {
		if err := s.manager.LoadFile(req.File); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
		})
	} else {
		// Fallback to direct sharkd
		result, err := s.sharkd.Call("load", map[string]string{"file": req.File})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"result": json.RawMessage(result),
		})
	}
}

// handleDownload handles downloading the current pcap file.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var filePath string

	// Check for session parameter (registry mode)
	sessionID := r.URL.Query().Get("session")
	if sessionID != "" && s.registry != nil {
		session, found := s.registry.GetSession(sessionID)
		if found && session != nil && session.Manager != nil {
			filePath = session.Manager.GetCaptureFile()
			if filePath == "" {
				status, err := session.Manager.GetStatus()
				if err == nil && status.Source != "" {
					filePath = status.Source
				}
			}
		}
	}

	// Fall back to direct manager
	if filePath == "" && s.manager != nil {
		filePath = s.manager.GetCaptureFile()
		if filePath == "" {
			// Try to get the source path
			status, err := s.manager.GetStatus()
			if err == nil && status.Source != "" {
				filePath = status.Source
			}
		}
	}

	if filePath == "" {
		http.Error(w, "No pcap file available", http.StatusNotFound)
		return
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Failed to open file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get file info for size
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Failed to stat file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set headers for download
	filename := filepath.Base(filePath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))

	// Stream the file
	http.ServeContent(w, r, filename, stat.ModTime(), file)
}

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.addr
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
		conn := client.conn
		client.mu.RUnlock()

		if subscribed && conn != nil {
			go func(c *websocket.Conn) {
				c.WriteJSON(notification)
			}(conn)
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
		if client.session == session {
			clients = append(clients, client)
		}
	}
	s.mu.RUnlock()

	for _, client := range clients {
		client.mu.RLock()
		subscribed := client.subscriptions[event]
		conn := client.conn
		client.mu.RUnlock()

		if subscribed && conn != nil {
			go func(c *websocket.Conn) {
				c.WriteJSON(notification)
			}(conn)
		}
	}
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
