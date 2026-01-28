// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package lifecycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrackerGo(t *testing.T) {
	tracker := New()

	var counter int32
	for i := 0; i < 10; i++ {
		tracker.Go(func() {
			atomic.AddInt32(&counter, 1)
		})
	}

	tracker.Wait()

	if counter != 10 {
		t.Errorf("expected counter to be 10, got %d", counter)
	}
}

func TestTrackerGoWithContext(t *testing.T) {
	tracker := New()

	done := make(chan struct{})
	tracker.GoWithContext(func(ctx context.Context) {
		<-ctx.Done()
		close(done)
	})

	// Give the goroutine time to start
	time.Sleep(10 * time.Millisecond)

	tracker.Shutdown()

	select {
	case <-done:
		// Success - goroutine received shutdown signal
	case <-time.After(time.Second):
		t.Error("goroutine did not receive shutdown signal")
	}

	tracker.Wait()
}

func TestTrackerShutdownAndWait(t *testing.T) {
	tracker := New()

	var completed int32
	tracker.GoWithContext(func(ctx context.Context) {
		<-ctx.Done()
		atomic.StoreInt32(&completed, 1)
	})

	// Give the goroutine time to start
	time.Sleep(10 * time.Millisecond)

	tracker.ShutdownAndWait()

	if atomic.LoadInt32(&completed) != 1 {
		t.Error("goroutine did not complete")
	}
}

func TestTrackerWaitGroup(t *testing.T) {
	tracker := New()
	wg := tracker.WaitGroup()

	var counter int32

	// Use the WaitGroup directly (legacy pattern)
	wg.Add(1)
	go func() {
		defer wg.Done()
		atomic.AddInt32(&counter, 1)
	}()

	tracker.Wait()

	if counter != 1 {
		t.Errorf("expected counter to be 1, got %d", counter)
	}
}
