// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSession(t *testing.T) {
	s := NewSession()
	assert.NotNil(t, s)
	assert.NotNil(t, s.subscribers)
}

func TestSession_GetStatus_Initial(t *testing.T) {
	s := NewSession()
	status := s.GetStatus()

	assert.Equal(t, "", status.Source)
	assert.Equal(t, SourceNone, status.SourceType)
	assert.Equal(t, 0, status.PacketCount)
	assert.Equal(t, "", status.DisplayFilter)
	assert.Equal(t, 0, status.FilteredCount)
	assert.False(t, status.CaptureRunning)
}

func TestSession_SetSource(t *testing.T) {
	s := NewSession()

	// Subscribe to receive notifications
	ch, unsub := s.Subscribe(10)
	defer unsub()

	s.SetSource("/path/to/test.pcap", SourceFile)

	status := s.GetStatus()
	assert.Equal(t, "/path/to/test.pcap", status.Source)
	assert.Equal(t, SourceFile, status.SourceType)

	// Check notification was sent
	select {
	case change := <-ch:
		assert.Equal(t, ChangeSourceChanged, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, "/path/to/test.pcap", data["source"])
		assert.Equal(t, "file", data["type"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_SetPacketCount(t *testing.T) {
	s := NewSession()

	ch, unsub := s.Subscribe(10)
	defer unsub()

	s.SetPacketCount(100)
	status := s.GetStatus()
	assert.Equal(t, 100, status.PacketCount)

	// Check notification for initial count
	select {
	case change := <-ch:
		assert.Equal(t, ChangePacketsAdded, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, 100, data["count"])
		assert.Equal(t, 100, data["added"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}

	// Increase count should send notification
	s.SetPacketCount(150)
	select {
	case change := <-ch:
		assert.Equal(t, ChangePacketsAdded, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, 150, data["count"])
		assert.Equal(t, 50, data["added"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}

	// Same count should not send notification
	s.SetPacketCount(150)
	select {
	case <-ch:
		t.Fatal("unexpected notification for same count")
	case <-time.After(50 * time.Millisecond):
		// Expected - no notification
	}
}

func TestSession_SetFilteredCount(t *testing.T) {
	s := NewSession()
	s.SetFilteredCount(50)
	assert.Equal(t, 50, s.GetStatus().FilteredCount)
}

func TestSession_SetColumns(t *testing.T) {
	s := NewSession()
	columns := []string{"No.", "Time", "Source", "Destination", "Protocol"}
	s.SetColumns(columns)
	assert.Equal(t, columns, s.GetStatus().Columns)
}

func TestSession_SetDuration(t *testing.T) {
	s := NewSession()
	s.SetDuration(123.456)
	assert.Equal(t, 123.456, s.GetStatus().Duration)
}

func TestSession_SetDisplayFilter(t *testing.T) {
	s := NewSession()

	ch, unsub := s.Subscribe(10)
	defer unsub()

	s.SetDisplayFilter("tcp.port == 80")
	assert.Equal(t, "tcp.port == 80", s.GetStatus().DisplayFilter)

	select {
	case change := <-ch:
		assert.Equal(t, ChangeFilterChanged, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, "tcp.port == 80", data["filter"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_SetSelectedPacket(t *testing.T) {
	s := NewSession()

	ch, unsub := s.Subscribe(10)
	defer unsub()

	s.SetSelectedPacket(42)
	assert.Equal(t, 42, s.GetSelectedPacket())

	select {
	case change := <-ch:
		assert.Equal(t, ChangeSelectionChanged, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, 42, data["packet"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_SetCaptureRunning(t *testing.T) {
	s := NewSession()

	ch, unsub := s.Subscribe(10)
	defer unsub()

	// Start capture
	s.SetCaptureRunning(true)
	assert.True(t, s.GetStatus().CaptureRunning)

	select {
	case change := <-ch:
		assert.Equal(t, ChangeCaptureStarted, change.Type)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}

	// Stop capture
	s.SetCaptureRunning(false)
	assert.False(t, s.GetStatus().CaptureRunning)

	select {
	case change := <-ch:
		assert.Equal(t, ChangeCaptureStopped, change.Type)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_CaptureFile(t *testing.T) {
	s := NewSession()

	s.SetCaptureFile("/tmp/capture.pcap")
	assert.Equal(t, "/tmp/capture.pcap", s.GetCaptureFile())
}

func TestSession_Clear(t *testing.T) {
	s := NewSession()

	// Set up some state
	s.SetSource("/path/to/test.pcap", SourceFile)
	s.SetPacketCount(100)
	s.SetDisplayFilter("tcp")
	s.SetSelectedPacket(42)
	s.SetCaptureRunning(true)

	ch, unsub := s.Subscribe(10)
	defer unsub()

	// Clear all state
	s.Clear()

	status := s.GetStatus()
	assert.Equal(t, "", status.Source)
	assert.Equal(t, SourceNone, status.SourceType)
	assert.Equal(t, 0, status.PacketCount)
	assert.Equal(t, "", status.DisplayFilter)
	assert.False(t, status.CaptureRunning)
	assert.Equal(t, 0, s.GetSelectedPacket())

	// Check notification
	select {
	case change := <-ch:
		assert.Equal(t, ChangePacketsCleared, change.Type)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_Subscribe_Unsubscribe(t *testing.T) {
	s := NewSession()

	ch1, unsub1 := s.Subscribe(10)
	ch2, unsub2 := s.Subscribe(10)

	// Both should receive
	s.SetDisplayFilter("test")

	select {
	case <-ch1:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch1 should receive")
	}

	select {
	case <-ch2:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch2 should receive")
	}

	// Unsubscribe ch1
	unsub1()

	// Only ch2 should receive
	s.SetDisplayFilter("test2")

	select {
	case <-ch2:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch2 should receive")
	}

	// ch1 should be closed
	_, ok := <-ch1
	assert.False(t, ok, "ch1 should be closed")

	unsub2()
}

func TestSession_NotifyError(t *testing.T) {
	s := NewSession()

	ch, unsub := s.Subscribe(10)
	defer unsub()

	s.NotifyError(assert.AnError)

	select {
	case change := <-ch:
		assert.Equal(t, ChangeError, change.Type)
		data := change.Data.(map[string]interface{})
		assert.Equal(t, assert.AnError.Error(), data["error"])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notification not received")
	}
}

func TestSession_Notify_ChannelFull(t *testing.T) {
	s := NewSession()

	// Create a subscriber with buffer size 1
	ch, unsub := s.Subscribe(1)
	defer unsub()

	// Fill the buffer
	s.SetDisplayFilter("filter1")

	// This should not block even though buffer is full
	done := make(chan bool)
	go func() {
		s.SetDisplayFilter("filter2")
		s.SetDisplayFilter("filter3")
		done <- true
	}()

	select {
	case <-done:
		// Good - didn't block
	case <-time.After(100 * time.Millisecond):
		t.Fatal("notify should not block on full channel")
	}

	// Drain the channel
	<-ch
}
