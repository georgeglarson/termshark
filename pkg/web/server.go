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
	sharkd   *SharkdClient   // Deprecated: use manager instead
	manager  *state.Manager  // New unified state manager
	registry *state.Registry // Session registry for multi-session support
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]*clientState
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
		Addr:        s.addr,
		Handler:     mux,
		ReadTimeout: 15 * time.Second,
		// WriteTimeout is intentionally not set because WebSocket connections
		// are long-lived and would be killed by a write timeout.
		IdleTimeout: 60 * time.Second,
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

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.addr
}
