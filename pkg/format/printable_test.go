// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakePrintableString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "printable ASCII",
			input:    []byte("Hello, World!"),
			expected: "Hello, World!",
		},
		{
			name:     "with control characters",
			input:    []byte("Hello\x00\x01\x02World"),
			expected: "HelloWorld",
		},
		{
			name:     "newlines and tabs filtered",
			input:    []byte("Hello\n\tWorld"),
			expected: "HelloWorld", // unicode.IsPrint returns false for \n and \t
		},
		{
			name:     "only non-printable",
			input:    []byte{0x00, 0x01, 0x02, 0x03},
			expected: "",
		},
		{
			name:     "mixed binary and text",
			input:    []byte{0x48, 0x69, 0x00, 0xFF, 0x21},
			expected: "Hiÿ!", // 0xFF is printable (Latin-1 ÿ), 0x00 is not
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MakePrintableString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakePrintableStringWithNewlines(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "printable ASCII",
			input:    []byte("Hello"),
			expected: "Hello",
		},
		{
			name:     "with newline",
			input:    []byte("Hello\nWorld"),
			expected: "Hello\nWorld",
		},
		{
			name:     "with tab replaced by dot",
			input:    []byte("Hello\tWorld"),
			expected: "Hello.World",
		},
		{
			name:     "with control characters",
			input:    []byte("Hi\x00\x01!"),
			expected: "Hi..!",
		},
		{
			name:     "high bytes replaced",
			input:    []byte{0x48, 0x69, 0x80, 0xFF},
			expected: "Hi..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MakePrintableStringWithNewlines(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeEscapedString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x41},
			expected: `"\x41"`,
		},
		{
			name:     "multiple bytes under 16",
			input:    []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
			expected: `"\x48\x65\x6c\x6c\x6f"`,
		},
		{
			name:     "exactly 16 bytes",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			expected: `"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"`,
		},
		{
			name:  "more than 16 bytes wraps",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expected: `"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"` + " \\\n" +
				`"\x10"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MakeEscapedString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeHexStream(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x41},
			expected: "41",
		},
		{
			name:     "multiple bytes",
			input:    []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
			expected: "48656c6c6f",
		},
		{
			name:     "with leading zeros",
			input:    []byte{0x00, 0x0a, 0xff},
			expected: "000aff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MakeHexStream(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTranslateHexCodes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: nil, // regex ReplaceAllFunc returns nil for empty input
		},
		{
			name:     "no hex codes",
			input:    []byte("Hello World"),
			expected: []byte("Hello World"),
		},
		{
			name:     "single hex code",
			input:    []byte(`\x41`),
			expected: []byte("A"),
		},
		{
			name:     "multiple hex codes",
			input:    []byte(`\x48\x69`),
			expected: []byte("Hi"),
		},
		{
			name:     "mixed text and hex",
			input:    []byte(`Hello\x20World`),
			expected: []byte("Hello World"),
		},
		{
			name:     "lowercase hex",
			input:    []byte(`\x4a\x4b`),
			expected: []byte("JK"),
		},
		{
			name:     "uppercase hex",
			input:    []byte(`\x4A\x4B`),
			expected: []byte("JK"),
		},
		{
			name:     "mixed case hex",
			input:    []byte(`\x4a\x4B`),
			expected: []byte("JK"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TranslateHexCodes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
