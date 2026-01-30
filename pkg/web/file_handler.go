// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

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

	// Validate file path - must be absolute and exist
	absPath, err := filepath.Abs(req.File)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	req.File = absPath

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
	} else if s.sharkd != nil {
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
	} else {
		http.Error(w, "File loading not available - use WebSocket sessions.join first", http.StatusBadRequest)
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
