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

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

//go:embed static
var staticFiles embed.FS

// Server represents the web server for termshark.
type Server struct {
	addr     string
	sharkd   *SharkdClient
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]bool
}

// NewServer creates a new web server.
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

// handleWebSocket handles WebSocket connections and proxies to sharkd.
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

		// Forward to sharkd
		result, err := s.sharkd.Call(req.Method, req.Params)
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

	// Load file via sharkd
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

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.addr
}
