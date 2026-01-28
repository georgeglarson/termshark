// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package theme

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
)

func TestMode_String(t *testing.T) {
	tests := []struct {
		mode     gowid.ColorMode
		expected string
	}{
		{gowid.Mode256Colors, "256"},
		{gowid.Mode88Colors, "88"},
		{gowid.Mode16Colors, "16"},
		{gowid.Mode8Colors, "8"},
		{gowid.ModeMonochrome, "mono"},
		{gowid.Mode24BitColors, "truecolor"},
		{gowid.ColorMode(999), "unknown"}, // Unknown mode
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			m := Mode(tt.mode)
			assert.Equal(t, tt.expected, m.String())
		})
	}
}

func TestLayer_Constants(t *testing.T) {
	// Verify the Layer constants have expected values
	assert.Equal(t, Layer(0), Foreground)
	assert.Equal(t, Layer(1), Background)
}
