// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package lifecycle provides centralized goroutine lifecycle management.
// It replaces the distributed WaitGroup pattern with a single tracker
// that handles both goroutine tracking and shutdown signaling.
package lifecycle

import (
	"context"
	"sync"
)

// Tracker manages goroutine lifecycle with context-based cancellation.
// It replaces the pattern of injecting WaitGroups into multiple packages.
type Tracker struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new Tracker with a cancellable context.
func New() *Tracker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Tracker{
		ctx:    ctx,
		cancel: cancel,
	}
}

// Go starts a tracked goroutine. The goroutine will be tracked until it
// completes. Use t.Context() within the goroutine to detect shutdown.
func (t *Tracker) Go(fn func()) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		fn()
	}()
}

// GoWithContext starts a tracked goroutine and passes it the tracker's context.
// The goroutine should monitor ctx.Done() for shutdown signals.
func (t *Tracker) GoWithContext(fn func(ctx context.Context)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		fn(t.ctx)
	}()
}

// Context returns the tracker's context. Goroutines can use this to
// detect when shutdown has been initiated.
func (t *Tracker) Context() context.Context {
	return t.ctx
}

// Shutdown signals all goroutines to stop by cancelling the context.
// It does not wait for goroutines to complete - call Wait() for that.
func (t *Tracker) Shutdown() {
	t.cancel()
}

// Wait blocks until all tracked goroutines have completed.
func (t *Tracker) Wait() {
	t.wg.Wait()
}

// ShutdownAndWait signals shutdown and waits for all goroutines to complete.
func (t *Tracker) ShutdownAndWait() {
	t.cancel()
	t.wg.Wait()
}

// WaitGroup returns the underlying WaitGroup for compatibility with
// legacy code that uses TrackedGo(). This allows incremental migration.
//
// Deprecated: Use Go() or GoWithContext() instead.
func (t *Tracker) WaitGroup() *sync.WaitGroup {
	return &t.wg
}
