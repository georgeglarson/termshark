// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// Server provides JSON-RPC access to the state manager.
// It supports both Unix socket (for terminal UI) and WebSocket (for web UI).
type Server struct {
	manager    *Manager
	unixPath   string
	httpAddr   string
	unixLn     net.Listener
	httpServer *http.Server
	upgrader   websocket.Upgrader
	mu         sync.RWMutex
	clients    map[*clientConn]bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// clientConn represents a connected client.
type clientConn struct {
	ws       *websocket.Conn
	unix     net.Conn
	server   *Server
	subCh    <-chan StateChange
	unsubFn  func()
	sendMu   sync.Mutex
}

// ServerConfig configures the server.
type ServerConfig struct {
	// UnixSocket path for terminal UI connection (optional).
	UnixSocket string
	// HTTPAddr for WebSocket connections (optional, e.g., "127.0.0.1:8080").
	HTTPAddr string
}

// NewServer creates a new JSON-RPC server.
func NewServer(manager *Manager, config ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		manager:  manager,
		unixPath: config.UnixSocket,
		httpAddr: config.HTTPAddr,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		clients: make(map[*clientConn]bool),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start starts the server.
func (s *Server) Start() error {
	// Start Unix socket listener if configured
	if s.unixPath != "" {
		// Ensure directory exists
		dir := filepath.Dir(s.unixPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}

		// Remove existing socket
		os.Remove(s.unixPath)

		ln, err := net.Listen("unix", s.unixPath)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket: %w", err)
		}
		s.unixLn = ln
		log.Infof("State server listening on unix:%s", s.unixPath)

		go s.acceptUnixConnections()
	}

	// Start HTTP server if configured
	if s.httpAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", s.handleWebSocket)
		mux.HandleFunc("/health", s.handleHealth)

		s.httpServer = &http.Server{
			Addr:    s.httpAddr,
			Handler: mux,
		}
		log.Infof("State server listening on http://%s/ws", s.httpAddr)

		go func() {
			if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
				log.Errorf("HTTP server error: %v", err)
			}
		}()
	}

	return nil
}

// Stop stops the server.
func (s *Server) Stop() error {
	s.cancel()

	// Close all clients
	s.mu.Lock()
	for client := range s.clients {
		client.close()
	}
	s.mu.Unlock()

	// Close listeners
	if s.unixLn != nil {
		s.unixLn.Close()
		os.Remove(s.unixPath)
	}
	if s.httpServer != nil {
		s.httpServer.Close()
	}

	return nil
}

// acceptUnixConnections accepts connections on the Unix socket.
func (s *Server) acceptUnixConnections() {
	for {
		conn, err := s.unixLn.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Errorf("Unix accept error: %v", err)
				continue
			}
		}

		client := &clientConn{
			unix:   conn,
			server: s,
		}
		s.addClient(client)
		go client.handleUnix()
	}
}

// handleWebSocket handles WebSocket connections.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("WebSocket upgrade error: %v", err)
		return
	}

	client := &clientConn{
		ws:     ws,
		server: s,
	}
	s.addClient(client)
	go client.handleWebSocket()
}

// handleHealth handles health check requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// addClient adds a client to the server.
func (s *Server) addClient(client *clientConn) {
	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()

	// Subscribe to state changes
	client.subCh, client.unsubFn = s.manager.Subscribe(100)
	go client.forwardStateChanges()

	log.Info("Client connected")
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *clientConn) {
	s.mu.Lock()
	delete(s.clients, client)
	s.mu.Unlock()

	if client.unsubFn != nil {
		client.unsubFn()
	}

	log.Info("Client disconnected")
}

// close closes the client connection.
func (c *clientConn) close() {
	if c.ws != nil {
		c.ws.Close()
	}
	if c.unix != nil {
		c.unix.Close()
	}
}

// handleUnix handles messages from a Unix socket client.
func (c *clientConn) handleUnix() {
	defer func() {
		c.server.removeClient(c)
		c.close()
	}()

	decoder := json.NewDecoder(c.unix)
	for {
		var req jsonRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		resp := c.handleRequest(req)
		c.sendUnix(resp)
	}
}

// handleWebSocket handles messages from a WebSocket client.
func (c *clientConn) handleWebSocket() {
	defer func() {
		c.server.removeClient(c)
		c.close()
	}()

	for {
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			return
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			c.sendWS(jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &jsonRPCError{Code: -32700, Message: "Parse error"},
			})
			continue
		}

		resp := c.handleRequest(req)
		c.sendWS(resp)
	}
}

// handleRequest processes a JSON-RPC request.
func (c *clientConn) handleRequest(req jsonRPCRequest) jsonRPCResponse {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	result, err := c.dispatch(req.Method, req.Params)
	if err != nil {
		resp.Error = &jsonRPCError{Code: -32603, Message: err.Error()}
	} else {
		resultJSON, _ := json.Marshal(result)
		resp.Result = resultJSON
	}

	return resp
}

// dispatch routes the request to the appropriate handler.
func (c *clientConn) dispatch(method string, params interface{}) (interface{}, error) {
	m := c.server.manager

	// Convert params to map if needed
	var p map[string]interface{}
	if params != nil {
		switch v := params.(type) {
		case map[string]interface{}:
			p = v
		default:
			// Try to convert via JSON
			b, _ := json.Marshal(params)
			json.Unmarshal(b, &p)
		}
	}

	switch method {
	case "session.status":
		return m.GetStatus()

	case "session.loadFile":
		path, _ := p["path"].(string)
		if path == "" {
			return nil, fmt.Errorf("path required")
		}
		return nil, m.LoadFile(path)

	case "session.setFilter":
		filter, _ := p["filter"].(string)
		return nil, m.SetFilter(filter)

	case "session.getPackets":
		start := int(getFloat(p, "start", 0))
		count := int(getFloat(p, "count", 100))
		return m.GetPackets(start, count)

	case "session.getPacket":
		num := int(getFloat(p, "num", 0))
		if num <= 0 {
			return nil, fmt.Errorf("num required")
		}
		return m.GetPacketDetail(num)

	case "session.selectPacket":
		num := int(getFloat(p, "num", 0))
		return m.SelectPacket(num)

	case "session.validateFilter":
		filter, _ := p["filter"].(string)
		return m.ValidateFilter(filter)

	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

// getFloat gets a float64 from a map with a default value.
func getFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return def
}

// forwardStateChanges forwards state changes to the client.
func (c *clientConn) forwardStateChanges() {
	for change := range c.subCh {
		notification := jsonRPCRequest{
			JSONRPC: "2.0",
			Method:  "state.change",
			Params:  change,
		}

		if c.ws != nil {
			c.sendWS(jsonRPCResponse{
				JSONRPC: "2.0",
				Result:  mustMarshal(notification.Params),
			})
		} else if c.unix != nil {
			c.sendUnix(jsonRPCResponse{
				JSONRPC: "2.0",
				Result:  mustMarshal(notification.Params),
			})
		}
	}
}

// sendWS sends a response over WebSocket.
func (c *clientConn) sendWS(resp jsonRPCResponse) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.ws.WriteJSON(resp)
}

// sendUnix sends a response over Unix socket.
func (c *clientConn) sendUnix(resp jsonRPCResponse) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	encoder := json.NewEncoder(c.unix)
	encoder.Encode(resp)
}

// mustMarshal marshals to JSON or returns null.
func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// UnixSocketPath returns the Unix socket path.
func (s *Server) UnixSocketPath() string {
	return s.unixPath
}

// HTTPAddr returns the HTTP address.
func (s *Server) HTTPAddr() string {
	return s.httpAddr
}
