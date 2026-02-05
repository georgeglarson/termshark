// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchStopper_InitialState(t *testing.T) {
	s := &SearchStopper{}
	assert.False(t, s.Requested, "SearchStopper should start with Requested=false")
}

func TestSearchStopper_RequestStop(t *testing.T) {
	s := &SearchStopper{}
	s.RequestStop(nil)
	assert.True(t, s.Requested, "After RequestStop, Requested should be true")
}

func TestSearchStopper_DoIfStopped_WhenStopped(t *testing.T) {
	s := &SearchStopper{}
	s.RequestStop(nil)

	called := false
	s.DoIfStopped(func() {
		called = true
	})

	assert.True(t, called, "Callback should be called when Requested is true")
	assert.False(t, s.Requested, "DoIfStopped should reset Requested to false")
}

func TestSearchStopper_DoIfStopped_WhenNotStopped(t *testing.T) {
	s := &SearchStopper{}

	called := false
	s.DoIfStopped(func() {
		called = true
	})

	assert.False(t, called, "Callback should NOT be called when Requested is false")
}

func TestSearchStopper_DoIfStopped_OnlyFiresOnce(t *testing.T) {
	s := &SearchStopper{}
	s.RequestStop(nil)

	callCount := 0
	s.DoIfStopped(func() { callCount++ })
	s.DoIfStopped(func() { callCount++ })

	assert.Equal(t, 1, callCount, "Callback should only fire once after a single RequestStop")
}

func TestSearchStopper_ConcurrentAccess(t *testing.T) {
	s := &SearchStopper{}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: request stop
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.RequestStop(nil)
		}
	}()

	// Goroutine 2: check stop
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.DoIfStopped(func() {})
		}
	}()

	wg.Wait()
	// No race detector complaints = success
}
