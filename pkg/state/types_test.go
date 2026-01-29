// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSourceType_String(t *testing.T) {
	tests := []struct {
		name     string
		source   SourceType
		expected string
	}{
		{"none", SourceNone, "none"},
		{"file", SourceFile, "file"},
		{"interface", SourceInterface, "interface"},
		{"stdin", SourceStdin, "stdin"},
		{"unknown", SourceType(99), "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.String())
		})
	}
}

func TestChangeType_String(t *testing.T) {
	tests := []struct {
		name     string
		change   ChangeType
		expected string
	}{
		{"packetsAdded", ChangePacketsAdded, "packetsAdded"},
		{"packetsCleared", ChangePacketsCleared, "packetsCleared"},
		{"filterChanged", ChangeFilterChanged, "filterChanged"},
		{"selectionChanged", ChangeSelectionChanged, "selectionChanged"},
		{"captureStarted", ChangeCaptureStarted, "captureStarted"},
		{"captureStopped", ChangeCaptureStopped, "captureStopped"},
		{"sourceChanged", ChangeSourceChanged, "sourceChanged"},
		{"error", ChangeError, "error"},
		{"unknown", ChangeType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.change.String())
		})
	}
}
