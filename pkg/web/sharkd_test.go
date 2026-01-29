// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharkdClientStartStop(t *testing.T) {
	// Skip if sharkd not available
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := NewSharkdClient(ctx)
	require.NoError(t, err, "Failed to create sharkd client")
	defer client.Close()

	assert.NotEmpty(t, client.SocketPath(), "Socket path should not be empty")
}

func TestSharkdClientStatus(t *testing.T) {
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := NewSharkdClient(ctx)
	require.NoError(t, err)
	defer client.Close()

	// Call status method
	result, err := client.Call("status", nil)
	require.NoError(t, err, "Status call should succeed")

	// Parse result
	var status struct {
		Frames   int      `json:"frames"`
		Duration float64  `json:"duration"`
		Columns  []string `json:"columns"`
	}
	err = json.Unmarshal(result, &status)
	require.NoError(t, err, "Should parse status response")

	assert.Equal(t, 0, status.Frames, "No file loaded, frames should be 0")
	assert.NotEmpty(t, status.Columns, "Should have default columns")
}

func TestSharkdClientInfo(t *testing.T) {
	if _, err := exec.LookPath("sharkd"); err != nil {
		t.Skip("sharkd not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := NewSharkdClient(ctx)
	require.NoError(t, err)
	defer client.Close()

	// Call info method
	result, err := client.Call("info", nil)
	require.NoError(t, err, "Info call should succeed")

	// Should have some content
	assert.NotEmpty(t, result, "Info result should not be empty")
}
