// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"os"
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

func TestConfStrings(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test empty when key doesn't exist in either
	result := confStrings(v, vd, "nonexistent")
	assert.Empty(t, result)

	// Test value from primary viper
	v.Set("stringskey", []string{"a", "b", "c"})
	result = confStrings(v, vd, "stringskey")
	assert.Equal(t, []string{"a", "b", "c"}, result)

	// Test fallback to default viper
	vd.Set("stringskey2", []string{"x", "y"})
	result = confStrings(v, vd, "stringskey2")
	assert.Equal(t, []string{"x", "y"}, result)

	// Test primary takes precedence
	v.Set("stringskey3", []string{"primary"})
	vd.Set("stringskey3", []string{"fallback"})
	result = confStrings(v, vd, "stringskey3")
	assert.Equal(t, []string{"primary"}, result)

	// Test with nil primary viper
	result = confStrings(nil, vd, "stringskey2")
	assert.Equal(t, []string{"x", "y"}, result)
}

func TestConfStringFromNilVipers(t *testing.T) {
	vd := viper.New()
	vd.Set("key", "value")

	// Test with nil primary viper
	result := ConfStringFrom(nil, vd, "key", "default")
	assert.Equal(t, "value", result)

	// Test with nil primary and missing key
	result = ConfStringFrom(nil, vd, "missing", "default")
	assert.Equal(t, "default", result)
}

func TestConfIntNilVipers(t *testing.T) {
	vd := viper.New()
	vd.Set("intkey", 42)

	// Test with nil primary viper
	result := confInt(nil, vd, "intkey", 0)
	assert.Equal(t, 42, result)

	// Test with nil default viper
	v := viper.New()
	v.Set("intkey", 100)
	result = confInt(v, nil, "intkey", 0)
	assert.Equal(t, 100, result)

	// Test with both nil
	result = confInt(nil, nil, "intkey", 99)
	assert.Equal(t, 99, result)
}

func TestConfBoolNilVipers(t *testing.T) {
	vd := viper.New()
	vd.Set("boolkey", true)

	// Test with nil primary viper
	result := confBool(nil, vd, "boolkey")
	assert.True(t, result)

	// Test with nil default viper
	v := viper.New()
	v.Set("boolkey", true)
	result = confBool(v, nil, "boolkey")
	assert.True(t, result)

	// Test with both nil, no default
	result = confBool(nil, nil, "boolkey")
	assert.False(t, result)

	// Test with both nil, with default
	result = confBool(nil, nil, "boolkey", true)
	assert.True(t, result)
}

func TestConfStringSliceFromNilVipers(t *testing.T) {
	vd := viper.New()
	defaultSlice := []string{"default"}

	// Test with nil primary and nil default vipers
	result := ConfStringSliceFrom(nil, nil, "key", defaultSlice)
	assert.Equal(t, defaultSlice, result)

	// Test with nil primary, value in default
	vd.Set("key", []string{"from_default"})
	result = ConfStringSliceFrom(nil, vd, "key", defaultSlice)
	assert.Equal(t, []string{"from_default"}, result)

	// Test empty slice returns default
	v := viper.New()
	result = ConfStringSliceFrom(v, vd, "nonexistent", defaultSlice)
	assert.Equal(t, defaultSlice, result)
}

func TestConfIntZeroValue(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test that explicitly set 0 is returned (not default)
	v.Set("zerokey", 0)
	result := confInt(v, vd, "zerokey", 42)
	assert.Equal(t, 0, result)
}

func TestConfBoolFalseValue(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test that explicitly set false is returned (not default)
	v.Set("falsekey", false)
	result := confBool(v, vd, "falsekey", true)
	assert.False(t, result)
}

func TestDeleteConf(t *testing.T) {
	v := viper.New()

	// Set a value
	v.Set("toDelete", "value")
	assert.Equal(t, "value", v.GetString("toDelete"))

	// Delete it (sets to empty string)
	deleteConf(v, "toDelete")
	assert.Equal(t, "", v.GetString("toDelete"))
}

func TestConfStringEmptyDefault(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test empty string default
	result := ConfStringFrom(v, vd, "key", "")
	assert.Equal(t, "", result)

	// Test that empty string in default viper falls back to provided default
	vd.Set("key", "")
	result = ConfStringFrom(v, vd, "key", "provided")
	assert.Equal(t, "provided", result)
}

func TestConfStringSliceEmptySlice(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test with empty slice as default
	result := ConfStringSliceFrom(v, vd, "key", []string{})
	assert.Empty(t, result)

	// Test with nil as default
	result = ConfStringSliceFrom(v, vd, "key", nil)
	assert.Nil(t, result)
}

func TestDefault(t *testing.T) {
	// Default() should return a non-nil viper instance
	d := Default()
	assert.NotNil(t, d)

	// Should be able to set and get values
	d.Set("testkey", "testvalue")
	assert.Equal(t, "testvalue", d.GetString("testkey"))
}

func TestCurrent(t *testing.T) {
	// When no profile is loaded, Current() should return Default()
	// Save original state
	origProfile := vProfile
	origName := currentName
	defer func() {
		vProfile = origProfile
		currentName = origName
	}()

	// Clear profile
	vProfile = nil
	currentName = ""

	// Current should return Default when no profile
	assert.Equal(t, Default(), Current())

	// When profile is set, Current should return it
	testProfile := viper.New()
	testProfile.Set("profilekey", "profilevalue")
	vProfile = testProfile

	assert.Equal(t, testProfile, Current())
	assert.Equal(t, "profilevalue", Current().GetString("profilekey"))
}

func TestCurrentName(t *testing.T) {
	// Save original state
	origName := currentName
	defer func() {
		currentName = origName
	}()

	// When currentName is empty, should return "default"
	currentName = ""
	assert.Equal(t, "default", CurrentName())

	// When currentName is set, should return it
	currentName = "myprofile"
	assert.Equal(t, "myprofile", CurrentName())

	// When currentName is "default", should return "default"
	currentName = "default"
	assert.Equal(t, "default", CurrentName())
}

func TestConfKeyExists(t *testing.T) {
	// Save original state
	origProfile := vProfile
	origDefault := vDefault
	defer func() {
		vProfile = origProfile
		vDefault = origDefault
	}()

	// Set up test vipers
	vDefault = viper.New()
	vProfile = viper.New()

	// Key doesn't exist in either
	assert.False(t, ConfKeyExists("nonexistent"))

	// Key exists only in profile
	vProfile.Set("profileonly", "value")
	assert.True(t, ConfKeyExists("profileonly"))

	// Key exists only in default
	vDefault.Set("defaultonly", "value")
	assert.True(t, ConfKeyExists("defaultonly"))

	// Key exists in both
	vProfile.Set("both", "profile")
	vDefault.Set("both", "default")
	assert.True(t, ConfKeyExists("both"))
}

func TestWriteConfigAs(t *testing.T) {
	v := viper.New()
	v.Set("key", "value")

	// Create a temp file
	tmpFile, err := os.CreateTemp("", "termshark-test-*.toml")
	assert.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Write config
	err = writeConfigAs(v, tmpFile.Name())
	assert.NoError(t, err)

	// Verify file exists and has content
	content, err := os.ReadFile(tmpFile.Name())
	assert.NoError(t, err)
	assert.Contains(t, string(content), "key")
}

func TestConfStringPrecedence(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Test that primary empty string falls back to default which falls back to provided default
	v.Set("key", "")
	vd.Set("key", "")
	result := ConfStringFrom(v, vd, "key", "fallback")
	assert.Equal(t, "fallback", result)

	// Test that non-empty primary takes precedence
	v.Set("key2", "primary")
	vd.Set("key2", "default")
	result = ConfStringFrom(v, vd, "key2", "fallback")
	assert.Equal(t, "primary", result)
}

func TestConfIntPrecedence(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Primary takes precedence
	v.Set("key", 1)
	vd.Set("key", 2)
	result := confInt(v, vd, "key", 3)
	assert.Equal(t, 1, result)

	// Default used when primary doesn't have key
	vd.Set("key2", 2)
	result = confInt(v, vd, "key2", 3)
	assert.Equal(t, 2, result)
}

func TestConfBoolPrecedence(t *testing.T) {
	v := viper.New()
	vd := viper.New()

	// Primary takes precedence
	v.Set("key", true)
	vd.Set("key", false)
	result := confBool(v, vd, "key", false)
	assert.True(t, result)

	// Default used when primary doesn't have key
	vd.Set("key2", true)
	result = confBool(v, vd, "key2", false)
	assert.True(t, result)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
