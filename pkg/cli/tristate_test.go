// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTriState_UnmarshalFlag(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedSet bool
		expectedVal bool
	}{
		// True values
		{"true lowercase", "true", true, true},
		{"TRUE uppercase", "TRUE", true, true},
		{"t lowercase", "t", true, true},
		{"T uppercase", "T", true, true},
		{"1", "1", true, true},
		{"y lowercase", "y", true, true},
		{"Y uppercase", "Y", true, true},
		{"yes lowercase", "yes", true, true},
		{"Yes mixed", "Yes", true, true},
		{"YES uppercase", "YES", true, true},

		// False values
		{"false lowercase", "false", true, false},
		{"FALSE uppercase", "FALSE", true, false},
		{"f lowercase", "f", true, false},
		{"F uppercase", "F", true, false},
		{"0", "0", true, false},
		{"n lowercase", "n", true, false},
		{"N uppercase", "N", true, false},
		{"no lowercase", "no", true, false},
		{"No mixed", "No", true, false},
		{"NO uppercase", "NO", true, false},

		// Unset values (anything else)
		{"empty string", "", false, false},
		{"random string", "random", false, false},
		{"maybe", "maybe", false, false},
		{"2", "2", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts TriState
			err := ts.UnmarshalFlag(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedSet, ts.Set, "Set mismatch")
			assert.Equal(t, tt.expectedVal, ts.Val, "Val mismatch")
		})
	}
}

func TestTriState_MarshalFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    TriState
		expected string
	}{
		{
			name:     "set to true",
			input:    TriState{Set: true, Val: true},
			expected: "true",
		},
		{
			name:     "set to false",
			input:    TriState{Set: true, Val: false},
			expected: "false",
		},
		{
			name:     "unset",
			input:    TriState{Set: false, Val: false},
			expected: "unset",
		},
		{
			name:     "unset with val true",
			input:    TriState{Set: false, Val: true},
			expected: "unset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.MarshalFlag()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTriState_RoundTrip(t *testing.T) {
	// Test that unmarshaling and marshaling preserves true/false values
	trueValues := []string{"true", "TRUE", "1", "yes", "y", "Y", "t", "T"}
	for _, v := range trueValues {
		var ts TriState
		ts.UnmarshalFlag(v)
		assert.Equal(t, "true", ts.MarshalFlag(), "round trip failed for %s", v)
	}

	falseValues := []string{"false", "FALSE", "0", "no", "n", "N", "f", "F"}
	for _, v := range falseValues {
		var ts TriState
		ts.UnmarshalFlag(v)
		assert.Equal(t, "false", ts.MarshalFlag(), "round trip failed for %s", v)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
