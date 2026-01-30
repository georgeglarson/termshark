// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gcla/termshark/v2"
	log "github.com/sirupsen/logrus"
)

// CaptureCoordinator manages live packet capture for the state manager.
// It coordinates dumpcap (capture), tail (follow), and the backend (analysis).
type CaptureCoordinator struct {
	mu sync.RWMutex

	// Configuration
	iface   string
	tmpFile string

	// Process management
	captureCmd *exec.Cmd
	tailCmd    *exec.Cmd
	ctx        context.Context
	cancel     context.CancelFunc

	// State tracking
	running           bool
	bytesWritten      int64
	bytesRead         int64
	packetsDiscovered int

	// Callbacks
	onPacketsAdded func(count int)
	onError        func(err error)
	onStopped      func()
}

// CaptureConfig configures a capture session.
type CaptureConfig struct {
	// Interface to capture on (e.g., "eth0", "wlan0")
	Interface string
	// CaptureFilter is the BPF filter for capture (optional)
	CaptureFilter string
	// TempFile is the path to write captured packets (optional, auto-generated if empty)
	TempFile string
}

// NewCaptureCoordinator creates a new capture coordinator.
func NewCaptureCoordinator() *CaptureCoordinator {
	return &CaptureCoordinator{}
}

// Start begins capturing packets on the specified interface.
func (c *CaptureCoordinator) Start(config CaptureConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("capture already running")
	}

	c.iface = config.Interface
	if config.TempFile != "" {
		c.tmpFile = config.TempFile
	} else {
		c.tmpFile = c.generateTempFile()
	}

	// Ensure temp directory exists
	if err := os.MkdirAll(filepath.Dir(c.tmpFile), 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.bytesWritten = 0
	c.bytesRead = 0
	c.packetsDiscovered = 0

	// Start capture process
	if err := c.startCapture(config.CaptureFilter); err != nil {
		c.cancel()
		return err
	}

	c.running = true

	// Start monitoring goroutine
	go c.monitor()

	log.Infof("Capture started on interface %s, writing to %s", c.iface, c.tmpFile)
	return nil
}

// Stop stops the current capture.
func (c *CaptureCoordinator) Stop() error {
	c.mu.Lock()

	if !c.running {
		c.mu.Unlock()
		return nil
	}

	// Cancel context to signal all goroutines and terminate CommandContext processes.
	// Note: exec.CommandContext automatically kills the process when context is cancelled,
	// so we don't call Wait() again here to avoid a double-wait race.
	if c.cancel != nil {
		c.cancel()
	}

	// For non-context captures, send SIGTERM as a graceful hint
	if c.captureCmd != nil && c.captureCmd.Process != nil {
		c.captureCmd.Process.Signal(syscall.SIGTERM)
	}

	// Stop tail if running
	if c.tailCmd != nil && c.tailCmd.Process != nil {
		c.tailCmd.Process.Kill()
	}

	// Reap child processes in background to prevent zombies.
	// These goroutines will exit once the processes terminate (which context
	// cancellation and SIGTERM/SIGKILL above guarantee).
	captureCmd := c.captureCmd
	tailCmd := c.tailCmd
	go func() {
		if captureCmd != nil {
			captureCmd.Wait()
		}
	}()
	go func() {
		if tailCmd != nil {
			tailCmd.Wait()
		}
	}()

	c.running = false
	callback := c.onStopped
	c.mu.Unlock()

	log.Info("Capture stopped")

	// Call callback outside the lock to avoid potential deadlock
	if callback != nil {
		callback()
	}

	return nil
}

// IsRunning returns whether capture is active.
func (c *CaptureCoordinator) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// TempFile returns the path to the capture file.
func (c *CaptureCoordinator) TempFile() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tmpFile
}

// Interface returns the capture interface.
func (c *CaptureCoordinator) Interface() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.iface
}

// PacketsDiscovered returns the number of packets found so far.
func (c *CaptureCoordinator) PacketsDiscovered() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.packetsDiscovered
}

// SetCallbacks sets the callback functions for capture events.
func (c *CaptureCoordinator) SetCallbacks(onPackets func(int), onError func(error), onStopped func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPacketsAdded = onPackets
	c.onError = onError
	c.onStopped = onStopped
}

// Cleanup removes the temporary capture file.
func (c *CaptureCoordinator) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tmpFile != "" {
		if err := os.Remove(c.tmpFile); err != nil && !os.IsNotExist(err) {
			return err
		}
		c.tmpFile = ""
	}
	return nil
}

// startCapture starts the dumpcap/tshark capture process.
func (c *CaptureCoordinator) startCapture(captureFilter string) error {
	// Try dumpcap first, fall back to tshark
	captureBin := termshark.CaptureBin()
	if captureBin == "" {
		return fmt.Errorf("no capture tool found (dumpcap or tshark)")
	}

	args := []string{"-i", c.iface, "-w", c.tmpFile}
	if captureFilter != "" {
		args = append(args, "-f", captureFilter)
	}

	c.captureCmd = exec.CommandContext(c.ctx, captureBin, args...)

	// Capture stderr for error reporting
	stderr, err := c.captureCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := c.captureCmd.Start(); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// Monitor stderr for errors
	go c.monitorStderr(stderr)

	return nil
}

// monitor watches the capture file and notifies of new packets.
func (c *CaptureCoordinator) monitor() {
	c.mu.RLock()
	tmpFile := c.tmpFile
	c.mu.RUnlock()

	// Wait for file to exist
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tmpFile); err == nil {
			break
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Use double-ticker pattern: fast initially, then slower
	fastTicker := time.NewTicker(100 * time.Millisecond)
	slowTicker := time.NewTicker(2 * time.Second)
	defer fastTicker.Stop()
	defer slowTicker.Stop()

	fastTicks := 0
	maxFastTicks := 10

	for {
		var ticker <-chan time.Time
		if fastTicks < maxFastTicks {
			ticker = fastTicker.C
		} else {
			ticker = slowTicker.C
		}

		select {
		case <-c.ctx.Done():
			return
		case <-ticker:
			fastTicks++
			c.checkForNewPackets()
		}
	}
}

// checkForNewPackets checks if the capture file has grown.
func (c *CaptureCoordinator) checkForNewPackets() {
	c.mu.RLock()
	tmpFile := c.tmpFile
	c.mu.RUnlock()

	info, err := os.Stat(tmpFile)
	if err != nil {
		return
	}

	c.mu.Lock()
	newSize := info.Size()
	if newSize > c.bytesWritten {
		c.bytesWritten = newSize
		callback := c.onPacketsAdded
		c.mu.Unlock()

		if callback != nil {
			callback(0)
		}
		return
	}
	c.mu.Unlock()
}

// monitorStderr reads and logs stderr from the capture process.
func (c *CaptureCoordinator) monitorStderr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		log.Debugf("Capture stderr: %s", line)
	}
}

// generateTempFile creates a unique temp file path for the capture.
func (c *CaptureCoordinator) generateTempFile() string {
	timestamp := time.Now().Format("2006-01-02--15-04-05")
	filename := fmt.Sprintf("%s--%s.pcap", c.iface, timestamp)

	// Use termshark's pcap directory if available
	pcapDir := termshark.PcapDir()
	if pcapDir == "" {
		pcapDir = os.TempDir()
	}

	return filepath.Join(pcapDir, filename)
}
