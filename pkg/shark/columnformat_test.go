// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package shark

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestCF1(t *testing.T) {

	fields := &ColumnsFromTshark{}
	err := fields.InitNoCache()
	assert.NoError(t, err)

	cfmap := make(map[string]PsmlColumnSpec)
	for _, f := range fields.fields {
		fmt.Printf("GCLA: adding %v\n", f)
		cfmap[f.Field.Token] = f
	}

	m1, ok := cfmap["%At"]
	assert.Equal(t, true, ok)
	assert.Equal(t, "Absolute time", m1.Name)

	m2, ok := cfmap["%rs"]
	assert.Equal(t, true, ok)
	assert.Equal(t, "Src addr (resolved)", m2.Name)
}

func TestPsmlField_FullString(t *testing.T) {
	p := PsmlField{
		Token:      "%Cus",
		Filter:     "ip.src",
		Occurrence: 0,
	}
	assert.Equal(t, "%Cus:ip.src:0:R", p.FullString())
}

func TestPsmlField_String(t *testing.T) {
	// Simple token (no filter)
	p := PsmlField{Token: "%m"}
	assert.Equal(t, "%m", p.String())

	// Custom column with filter
	p = PsmlField{
		Token:      "%Cus",
		Filter:     "ip.src",
		Occurrence: 0,
	}
	assert.Equal(t, "%Cus:ip.src:0:R", p.String())
}

func TestPsmlField_FromString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError error
		expectField PsmlField
	}{
		{
			name:        "simple token",
			input:       "%m",
			expectError: nil,
			expectField: PsmlField{Token: "%m"},
		},
		{
			name:        "custom column with filter",
			input:       "%Cus:ip.src:0:R",
			expectError: nil,
			expectField: PsmlField{Token: "%Cus", Filter: "ip.src", Occurrence: 0},
		},
		{
			name:        "custom column with occurrence",
			input:       "%Cus:tcp.port:2:R",
			expectError: nil,
			expectField: PsmlField{Token: "%Cus", Filter: "tcp.port", Occurrence: 2},
		},
		{
			name:        "bare %Cus is invalid",
			input:       "%Cus",
			expectError: InvalidCustomColumnError,
		},
		{
			name:        "wrong number of fields",
			input:       "%Cus:ip.src",
			expectError: InvalidCustomColumnError,
		},
		{
			name:        "invalid occurrence number",
			input:       "%Cus:ip.src:abc:R",
			expectError: InvalidCustomColumnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p PsmlField
			err := p.FromString(tt.input)
			if tt.expectError != nil {
				assert.Equal(t, tt.expectError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectField, p)
			}
		})
	}
}

func TestPsmlColumnInfo_WithLongName(t *testing.T) {
	info := PsmlColumnInfo{
		Field: "%m",
		Short: "No.",
		Long:  "Number",
	}

	newInfo := info.WithLongName("Packet Number")
	assert.Equal(t, "Packet Number", newInfo.Long)
	// Original should be unchanged
	assert.Equal(t, "Number", info.Long)
}

func TestDefaultPsmlColumnSpec(t *testing.T) {
	// Verify default column spec has expected number of columns
	assert.Equal(t, 7, len(DefaultPsmlColumnSpec))

	// Check first and last
	assert.Equal(t, "No.", DefaultPsmlColumnSpec[0].Name)
	assert.Equal(t, "%m", DefaultPsmlColumnSpec[0].Field.Token)
	assert.Equal(t, "Info", DefaultPsmlColumnSpec[6].Name)
	assert.Equal(t, "%i", DefaultPsmlColumnSpec[6].Field.Token)
}

func TestBuiltInColumnFormats(t *testing.T) {
	// Check some known column formats exist
	m, ok := BuiltInColumnFormats["%m"]
	assert.True(t, ok)
	assert.Equal(t, "No.", m.Short)
	assert.Equal(t, "Number", m.Long)

	t2, ok := BuiltInColumnFormats["%t"]
	assert.True(t, ok)
	assert.Equal(t, "Time", t2.Short)

	// Check that comparators are set for numeric columns
	assert.NotNil(t, BuiltInColumnFormats["%m"].Comparator)
	assert.NotNil(t, BuiltInColumnFormats["%L"].Comparator)
}
