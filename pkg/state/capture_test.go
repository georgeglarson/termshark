// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCaptureCoordinator(t *testing.T) {
	c := NewCaptureCoordinator()
	assert.NotNil(t, c)
	assert.False(t, c.IsRunning())
}

func TestCaptureCoordinator_StartStop(t *testing.T) {
	// Skip if no capture tool available
	if os.Getenv("CI") != "" {
		t.Skip("Skipping capture test in CI environment")
	}

	c := NewCaptureCoordinator()

	// Can't actually start capture without permissions, but test the flow
	config := CaptureConfig{
		Interface: "lo", // loopback usually available
		TempFile:  filepath.Join(os.TempDir(), "test-capture.pcap"),
	}

	// This will likely fail due to permissions, but tests the code path
	err := c.Start(config)
	if err != nil {
		// Expected in most test environments
		t.Logf("Start failed (expected without permissions): %v", err)
		return
	}

	assert.True(t, c.IsRunning())
	assert.NotEmpty(t, c.TempFile())
	assert.Equal(t, "lo", c.Interface())

	// Stop
	err = c.Stop()
	assert.NoError(t, err)
	assert.False(t, c.IsRunning())

	// Cleanup
	c.Cleanup()
}

func TestCaptureCoordinator_IsRunning(t *testing.T) {
	c := NewCaptureCoordinator()
	assert.False(t, c.IsRunning())
}

func TestCaptureCoordinator_TempFile(t *testing.T) {
	c := NewCaptureCoordinator()
	assert.Empty(t, c.TempFile())
}

func TestCaptureCoordinator_Interface(t *testing.T) {
	c := NewCaptureCoordinator()
	assert.Empty(t, c.Interface())
}

func TestCaptureCoordinator_PacketsDiscovered(t *testing.T) {
	c := NewCaptureCoordinator()
	assert.Equal(t, 0, c.PacketsDiscovered())
}

func TestCaptureCoordinator_SetCallbacks(t *testing.T) {
	c := NewCaptureCoordinator()

	packetsAdded := 0
	errorOccurred := false
	stopped := false

	c.SetCallbacks(
		func(count int) { packetsAdded = count },
		func(err error) { errorOccurred = true },
		func() { stopped = true },
	)

	// Callbacks are set but not triggered in this test
	assert.Equal(t, 0, packetsAdded)
	assert.False(t, errorOccurred)
	assert.False(t, stopped)
}

func TestCaptureCoordinator_Cleanup(t *testing.T) {
	c := NewCaptureCoordinator()

	// Create a temp file to clean up
	tmpFile := filepath.Join(os.TempDir(), "test-cleanup.pcap")
	f, err := os.Create(tmpFile)
	assert.NoError(t, err)
	f.Close()

	c.mu.Lock()
	c.tmpFile = tmpFile
	c.mu.Unlock()

	// Cleanup should remove the file
	err = c.Cleanup()
	assert.NoError(t, err)

	// File should be gone
	_, err = os.Stat(tmpFile)
	assert.True(t, os.IsNotExist(err))
}

func TestCaptureCoordinator_StopNotRunning(t *testing.T) {
	c := NewCaptureCoordinator()

	// Stopping when not running should be fine
	err := c.Stop()
	assert.NoError(t, err)
}

func TestCaptureCoordinator_generateTempFile(t *testing.T) {
	c := NewCaptureCoordinator()
	c.iface = "eth0"

	tmpFile := c.generateTempFile()
	assert.Contains(t, tmpFile, "eth0")
	assert.Contains(t, tmpFile, ".pcap")
}

func TestCaptureConfig(t *testing.T) {
	config := CaptureConfig{
		Interface:     "wlan0",
		CaptureFilter: "port 80",
		TempFile:      "/tmp/test.pcap",
	}

	assert.Equal(t, "wlan0", config.Interface)
	assert.Equal(t, "port 80", config.CaptureFilter)
	assert.Equal(t, "/tmp/test.pcap", config.TempFile)
}

func TestManager_StartCapture(t *testing.T) {
	// Skip if no capture tool available
	if os.Getenv("CI") != "" {
		t.Skip("Skipping capture test in CI environment")
	}

	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	// This will likely fail due to permissions
	err := manager.StartCapture("lo", "")
	if err != nil {
		t.Logf("StartCapture failed (expected without permissions): %v", err)
		return
	}

	assert.True(t, manager.IsCapturing())

	err = manager.StopCapture()
	assert.NoError(t, err)
	assert.False(t, manager.IsCapturing())
}

func TestManager_StopCaptureNotRunning(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	// Stopping when not capturing should be fine
	err := manager.StopCapture()
	assert.NoError(t, err)
}

func TestManager_IsCapturing(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	assert.False(t, manager.IsCapturing())
}

func TestManager_GetCaptureFile(t *testing.T) {
	backend := &mockBackend{}
	manager := NewManager(backend)
	defer manager.Close()

	assert.Empty(t, manager.GetCaptureFile())
}

// Test double-ticker timing pattern
func TestDoubleTicker(t *testing.T) {
	// Simulate the double-ticker pattern
	fastTicks := 0
	maxFastTicks := 3
	totalTicks := 0

	fastTicker := time.NewTicker(10 * time.Millisecond)
	slowTicker := time.NewTicker(50 * time.Millisecond)
	defer fastTicker.Stop()
	defer slowTicker.Stop()

	timeout := time.After(200 * time.Millisecond)

	for {
		var ticker <-chan time.Time
		if fastTicks < maxFastTicks {
			ticker = fastTicker.C
		} else {
			ticker = slowTicker.C
		}

		select {
		case <-timeout:
			// Should have at least 3 fast ticks plus some slow ticks
			assert.GreaterOrEqual(t, totalTicks, maxFastTicks)
			return
		case <-ticker:
			fastTicks++
			totalTicks++
		}
	}
}
