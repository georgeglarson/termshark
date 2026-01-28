// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestConfStringFrom(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test default when key doesn't exist
	result := ConfStringFrom(v, vd, "nonexistent", "default")
	assert.Equal(t, "default", result)

	// Test value from primary viper
	v.Set("key1", "value1")
	result = ConfStringFrom(v, vd, "key1", "default")
	assert.Equal(t, "value1", result)

	// Test fallback to default viper
	vd.Set("key2", "value2")
	result = ConfStringFrom(v, vd, "key2", "default")
	assert.Equal(t, "value2", result)

	// Test primary takes precedence over default
	v.Set("key3", "primary")
	vd.Set("key3", "fallback")
	result = ConfStringFrom(v, vd, "key3", "default")
	assert.Equal(t, "primary", result)

	// Test empty string in primary falls back to default
	v.Set("key4", "")
	vd.Set("key4", "fallback")
	result = ConfStringFrom(v, vd, "key4", "default")
	assert.Equal(t, "fallback", result)
}

func TestConfKeyExistsIn(t *testing.T) {
	v := viper.New()

	assert.False(t, ConfKeyExistsIn(v, "nonexistent"))

	v.Set("exists", "value")
	assert.True(t, ConfKeyExistsIn(v, "exists"))
}

func TestConfInt(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test default
	result := confInt(v, vd, "nonexistent", 42)
	assert.Equal(t, 42, result)

	// Test set value
	v.Set("intkey", 100)
	result = confInt(v, vd, "intkey", 42)
	assert.Equal(t, 100, result)

	// Test fallback
	vd.Set("intkey2", 200)
	result = confInt(v, vd, "intkey2", 42)
	assert.Equal(t, 200, result)
}

func TestConfBool(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test default (no default provided - should be false)
	result := confBool(v, vd, "nonexistent")
	assert.False(t, result)

	// Test default provided
	result = confBool(v, vd, "nonexistent", true)
	assert.True(t, result)

	// Test set value
	v.Set("boolkey", true)
	result = confBool(v, vd, "boolkey", false)
	assert.True(t, result)

	// Test false value
	v.Set("boolkey2", false)
	result = confBool(v, vd, "boolkey2", true)
	assert.False(t, result)
}

func TestConfStringSliceFrom(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	defaultSlice := []string{"a", "b"}

	// Test default
	result := ConfStringSliceFrom(v, vd, "nonexistent", defaultSlice)
	assert.Equal(t, defaultSlice, result)

	// Test set value
	v.Set("slicekey", []string{"x", "y", "z"})
	result = ConfStringSliceFrom(v, vd, "slicekey", defaultSlice)
	assert.Equal(t, []string{"x", "y", "z"}, result)

	// Test fallback
	vd.Set("slicekey2", []string{"p", "q"})
	result = ConfStringSliceFrom(v, vd, "slicekey2", defaultSlice)
	assert.Equal(t, []string{"p", "q"}, result)
}

func TestSetConfIn(t *testing.T) {
	v := viper.New()

	SetConfIn(v, "testkey", "testvalue")
	assert.Equal(t, "testvalue", v.GetString("testkey"))

	SetConfIn(v, "intkey", 123)
	assert.Equal(t, 123, v.GetInt("intkey"))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
