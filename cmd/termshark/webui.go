// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/gcla/termshark/v2/pkg/pcap"
	statemgr "github.com/gcla/termshark/v2/pkg/state"
	"github.com/gcla/termshark/v2/pkg/web"
	"github.com/gcla/termshark/v2/ui"
)

func runWebServer(addr string, psrcs []pcap.IPacketSource) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		cancel()
	}()

	// Create sharkd backend using the unified state package
	backend, err := statemgr.NewSharkdBackend(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start sharkd: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure sharkd is installed (usually part of wireshark-common).")
		return 1
	}
	defer backend.Close()

	// Create state manager
	manager := statemgr.NewManager(backend)
	defer manager.Close()

	// Handle packet sources using the unified capture API
	for _, src := range psrcs {
		switch s := src.(type) {
		case pcap.FileSource:
			if err := manager.LoadFile(s.Filename); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load pcap file: %v\n", err)
				return 1
			}
			fmt.Printf("Loaded: %s\n", s.Filename)

		case pcap.InterfaceSource:
			// Use the unified capture API
			if err := manager.StartCapture(s.Iface, ""); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to start capture on %s: %v\n", s.Iface, err)
				return 1
			}
			fmt.Printf("Capturing on interface: %s\n", s.Iface)
			fmt.Printf("Temp file: %s\n", manager.GetCaptureFile())
		}
	}

	// Start web server with state manager
	server := web.NewServerWithManager(addr, manager)
	fmt.Printf("Web UI available at http://%s\n", addr)
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		return 1
	}

	return 0
}

// runWebServerWithSessions starts the web UI server with multi-session support.
// This allows multiple users to create, join, and share analysis sessions.
func runWebServerWithSessions(addr string, sessionName string, psrcs []pcap.IPacketSource) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		cancel()
	}()

	// Create session registry with sharkd backend factory
	registry := statemgr.NewRegistry(statemgr.RegistryConfig{
		BackendFactory: &sharkdBackendFactory{},
	})

	// If sources were provided, create an initial session with them
	if len(psrcs) > 0 {
		name := sessionName
		if name == "" {
			// Generate a default name from the source
			if len(psrcs) > 0 {
				name = psrcs[0].Name()
			} else {
				name = "Default"
			}
		}

		session, err := registry.CreateSession(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create initial session: %v\n", err)
			return 1
		}

		// Load sources into the session
		for _, src := range psrcs {
			switch s := src.(type) {
			case pcap.FileSource:
				if err := session.Manager.LoadFile(s.Filename); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to load pcap file: %v\n", err)
					return 1
				}
				fmt.Printf("Session '%s': Loaded %s\n", name, s.Filename)

			case pcap.InterfaceSource:
				if err := session.Manager.StartCapture(s.Iface, ""); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to start capture on %s: %v\n", s.Iface, err)
					return 1
				}
				fmt.Printf("Session '%s': Capturing on %s\n", name, s.Iface)
				fmt.Printf("Temp file: %s\n", session.Manager.GetCaptureFile())
			}
		}

		fmt.Printf("Created initial session: %s (ID: %s)\n", name, session.ID)
	}

	// Start web server with registry
	server := web.NewServerWithRegistry(addr, registry)
	fmt.Printf("Web UI available at http://%s\n", addr)
	fmt.Println("Multi-session mode enabled - users can create and join sessions")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		return 1
	}

	return 0
}

// syncLoaderToManager periodically syncs the PacketLoader state to the state.Manager.
// This runs in the background for the terminal UI to keep state consistent.
func syncLoaderToManager(backend *statemgr.TsharkBackend, manager *statemgr.Manager) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if !ui.IsRunning() {
			return
		}
		// Sync loader state to backend, which updates the manager
		backend.Sync()
	}
}

// sharkdBackendFactory implements statemgr.BackendFactory for creating sharkd backends.
type sharkdBackendFactory struct{}

func (f *sharkdBackendFactory) Create(ctx context.Context) (statemgr.Backend, error) {
	return statemgr.NewSharkdBackend(ctx)
}

func (f *sharkdBackendFactory) Name() string {
	return "sharkd"
}

func (f *sharkdBackendFactory) Available() bool {
	_, err := exec.LookPath("sharkd")
	return err == nil
}
