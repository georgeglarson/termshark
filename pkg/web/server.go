// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

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
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]bool
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
		clients: make(map[*websocket.Conn]bool),
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
		clients: make(map[*websocket.Conn]bool),
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

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
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

		// Handle via manager or sharkd
		var result json.RawMessage
		if s.manager != nil {
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

	case "setfilter":
		filter, _ := p["filter"].(string)
		err = s.manager.SetFilter(filter)
		if err == nil {
			result = map[string]string{"status": "ok"}
		}

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

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.addr
}
