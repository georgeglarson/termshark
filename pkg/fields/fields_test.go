// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package fields

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestFields1(t *testing.T) {

	fields := New()
	err := fields.InitNoCache()
	assert.NoError(t, err)

	m1, ok := fields.ser.Fields.(map[string]interface{})["tcp"]
	assert.Equal(t, true, ok)

	m2, ok := m1.(map[string]interface{})["port"]
	assert.Equal(t, true, ok)

	assert.IsType(t, Field{}, m2)
	assert.Equal(t, m2.(Field).Type, FT_UINT16)
}

func TestParseFieldType(t *testing.T) {
	tests := []struct {
		input    string
		expected FieldType
		ok       bool
	}{
		{"FT_NONE", FT_NONE, true},
		{"FT_PROTOCOL", FT_PROTOCOL, true},
		{"FT_BOOLEAN", FT_BOOLEAN, true},
		{"FT_UINT8", FT_UINT8, true},
		{"FT_UINT16", FT_UINT16, true},
		{"FT_UINT32", FT_UINT32, true},
		{"FT_UINT64", FT_UINT64, true},
		{"FT_INT8", FT_INT8, true},
		{"FT_INT16", FT_INT16, true},
		{"FT_INT32", FT_INT32, true},
		{"FT_INT64", FT_INT64, true},
		{"FT_FLOAT", FT_FLOAT, true},
		{"FT_DOUBLE", FT_DOUBLE, true},
		{"FT_STRING", FT_STRING, true},
		{"FT_IPv4", FT_IPv4, true},
		{"FT_IPv6", FT_IPv6, true},
		{"FT_ETHER", FT_ETHER, true},
		{"FT_BYTES", FT_BYTES, true},
		{"INVALID", FT_NONE, false},
		{"", FT_NONE, false},
	}

	for _, tt := range tests {
		res, ok := ParseFieldType(tt.input)
		assert.Equal(t, tt.ok, ok, "ParseFieldType(%q) ok", tt.input)
		if tt.ok {
			assert.Equal(t, tt.expected, res, "ParseFieldType(%q)", tt.input)
		}
	}
}

func TestFieldTypeMap(t *testing.T) {
	// Check that the map is complete
	assert.True(t, len(FieldTypeMap) > 40)

	// Check some specific entries
	assert.Equal(t, FT_NONE, FieldTypeMap["FT_NONE"])
	assert.Equal(t, FT_STRING, FieldTypeMap["FT_STRING"])
	assert.Equal(t, FT_IPv4, FieldTypeMap["FT_IPv4"])
}

func TestNew(t *testing.T) {
	f := New()
	assert.NotNil(t, f)
	assert.Nil(t, f.ser) // Not initialized yet
}

func TestLookupField(t *testing.T) {
	fields := New()
	err := fields.InitNoCache()
	assert.NoError(t, err)

	// Look up a known field
	found, field := fields.LookupField("tcp.port")
	assert.True(t, found)
	assert.Equal(t, "tcp.port", field.Name)
	assert.Equal(t, FT_UINT16, field.Type)

	// Look up another known field
	found, field = fields.LookupField("ip.src")
	assert.True(t, found)
	assert.Equal(t, "ip.src", field.Name)

	// Look up non-existent field
	found, _ = fields.LookupField("nonexistent.field")
	assert.False(t, found)

	// Look up partial path (not a leaf)
	found, _ = fields.LookupField("tcp")
	assert.False(t, found)
}

func TestFieldsAndProtos(t *testing.T) {
	f := &FieldsAndProtos{
		Fields:    make(map[string]interface{}),
		Protocols: make(map[string]struct{}),
	}
	assert.NotNil(t, f.Fields)
	assert.NotNil(t, f.Protocols)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
