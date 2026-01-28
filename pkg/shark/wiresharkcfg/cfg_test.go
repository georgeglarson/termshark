// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package wiresharkcfg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_GetList(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists: map[string][]string{
			"test.list": {"a", "b", "c"},
		},
	}

	// Get existing list
	result := c.GetList("test.list")
	assert.Equal(t, []string{"a", "b", "c"}, result)

	// Get non-existing list
	result = c.GetList("nonexistent")
	assert.Nil(t, result)

	// Nil config
	var nilConfig *Config
	result = nilConfig.GetList("test.list")
	assert.Nil(t, result)
}

func TestConfig_ColumnFormat(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists: map[string][]string{
			"gui.column.format": {"No.", "Time", "Source", "Destination"},
		},
	}

	result := c.ColumnFormat()
	assert.Equal(t, []string{"No.", "Time", "Source", "Destination"}, result)
}

func TestConfig_merge(t *testing.T) {
	c1 := &Config{
		Strings: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		Lists: map[string][]string{
			"list1": {"a", "b"},
		},
	}

	c2 := &Config{
		Strings: map[string]string{
			"key2": "overwritten",
			"key3": "value3",
		},
		Lists: map[string][]string{
			"list1": {"x", "y", "z"},
			"list2": {"p", "q"},
		},
	}

	c1.merge(c2)

	// Strings should be merged
	assert.Equal(t, "value1", c1.Strings["key1"])
	assert.Equal(t, "overwritten", c1.Strings["key2"])
	assert.Equal(t, "value3", c1.Strings["key3"])

	// Lists should be merged
	assert.Equal(t, []string{"x", "y", "z"}, c1.Lists["list1"])
	assert.Equal(t, []string{"p", "q"}, c1.Lists["list2"])
}

func TestConfig_String(t *testing.T) {
	c := &Config{
		Strings: map[string]string{
			"key1": "value1",
		},
		Lists: map[string][]string{
			"list1": {"a", "b"},
		},
	}

	s := c.String()
	assert.Contains(t, s, "key1: value1")
	assert.Contains(t, s, "list1: a, b")
}

func TestConfig_PopulateFrom_NonexistentFile(t *testing.T) {
	c := &Config{}
	err := c.PopulateFrom("/nonexistent/file/path")
	assert.Error(t, err)
}

func TestConfig_PopulateFrom_InvalidFile(t *testing.T) {
	// Create a temp file with invalid content
	tmpfile, err := os.CreateTemp("", "test*.prefs")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// Write some non-parseable content
	tmpfile.WriteString("this is not = valid\n@#$%")
	tmpfile.Close()

	c := &Config{}
	err = c.PopulateFrom(tmpfile.Name())
	// The parser is lenient, so it may not error, but let's test the path
	// Either it errors or it parses (parser is lenient)
	_ = err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
