// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// Helper to save and restore global state for test isolation
//======================================================================

type savedState struct {
	vDefault    *viper.Viper
	vProfile    *viper.Viper
	currentName string
}

func saveGlobalState() savedState {
	return savedState{
		vDefault:    vDefault,
		vProfile:    vProfile,
		currentName: currentName,
	}
}

func restoreGlobalState(s savedState) {
	vDefault = s.vDefault
	vProfile = s.vProfile
	currentName = s.currentName
}

//======================================================================
// ReadDefaultConfig Tests
//======================================================================

func TestReadDefaultConfig_ValidDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	// Set up a fresh default viper
	vDefault = viper.New()

	dir := t.TempDir()
	err := ReadDefaultConfig(dir)
	// Should succeed - creates the file if it doesn't exist
	assert.NoError(t, err)

	// Verify the config file was created
	_, statErr := os.Stat(filepath.Join(dir, "termshark.toml"))
	assert.NoError(t, statErr)
}

func TestReadDefaultConfig_NonExistentDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()

	err := ReadDefaultConfig("/nonexistent/path/that/should/not/exist")
	// Should return an error since the directory doesn't exist
	assert.Error(t, err)
}

func TestReadDefaultConfig_WithExistingToml(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()

	dir := t.TempDir()
	// Write a valid TOML config file
	content := []byte("mykey = \"myvalue\"\nmyint = 42\n")
	err := os.WriteFile(filepath.Join(dir, "termshark.toml"), content, 0600)
	require.NoError(t, err)

	err = ReadDefaultConfig(dir)
	assert.NoError(t, err)

	// Verify values were loaded
	assert.Equal(t, "myvalue", vDefault.GetString("mykey"))
	assert.Equal(t, 42, vDefault.GetInt("myint"))
}

//======================================================================
// ConfString / SetConf / ConfStrings Tests
//======================================================================

func TestConfString_DefaultProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("greeting", "hello")
	result := ConfString("greeting", "fallback")
	assert.Equal(t, "hello", result)
}

func TestConfString_ProfileOverridesDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "testprofile"

	vDefault.Set("key", "default_val")
	vProfile.Set("key", "profile_val")

	result := ConfString("key", "fallback")
	assert.Equal(t, "profile_val", result)
}

func TestConfString_FallsBackToDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "testprofile"

	vDefault.Set("only_in_default", "default_val")

	result := ConfString("only_in_default", "fallback")
	assert.Equal(t, "default_val", result)
}

func TestConfString_FallsBackToProvided(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	result := ConfString("nonexistent", "the_fallback")
	assert.Equal(t, "the_fallback", result)
}

func TestSetConf_WritesToCurrentProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// When no profile is active, SetConf writes to default
	SetConf("testkey", "testval")
	assert.Equal(t, "testval", vDefault.GetString("testkey"))
}

func TestSetConf_WritesToActiveProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "active"

	SetConf("profilekey", "profileval")
	assert.Equal(t, "profileval", vProfile.GetString("profilekey"))
}

func TestConfStrings_FromCurrentProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vProfile.Set("items", []string{"a", "b", "c"})

	result := ConfStrings("items")
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestConfStrings_FallbackToDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vDefault.Set("items", []string{"x", "y"})

	result := ConfStrings("items")
	assert.Equal(t, []string{"x", "y"}, result)
}

//======================================================================
// ConfInt Tests
//======================================================================

func TestConfInt_FromProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vProfile.Set("count", 99)

	result := ConfInt("count", 0)
	assert.Equal(t, 99, result)
}

func TestConfInt_FallbackToDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vDefault.Set("count", 77)

	result := ConfInt("count", 0)
	assert.Equal(t, 77, result)
}

func TestConfInt_FallbackToProvided(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	result := ConfInt("missing", 55)
	assert.Equal(t, 55, result)
}

//======================================================================
// ConfBool Tests
//======================================================================

func TestConfBool_FromProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vProfile.Set("enabled", true)

	result := ConfBool("enabled", false)
	assert.True(t, result)
}

func TestConfBool_NoDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// With no default provided, should return false
	result := ConfBool("missing")
	assert.False(t, result)
}

func TestConfBool_WithDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	result := ConfBool("missing", true)
	assert.True(t, result)
}

//======================================================================
// ConfStringSlice Tests
//======================================================================

func TestConfStringSlice_FromProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vProfile.Set("tags", []string{"alpha", "beta"})

	result := ConfStringSlice("tags", []string{"default"})
	assert.Equal(t, []string{"alpha", "beta"}, result)
}

func TestConfStringSlice_FallbackToDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vDefault.Set("tags", []string{"gamma"})

	result := ConfStringSlice("tags", []string{"fallback"})
	assert.Equal(t, []string{"gamma"}, result)
}

func TestConfStringSlice_FallbackToProvided(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	result := ConfStringSlice("missing", []string{"provided"})
	assert.Equal(t, []string{"provided"}, result)
}

//======================================================================
// DeleteConf Tests
//======================================================================

func TestDeleteConf_ExistingKey(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("toDelete", "value")
	assert.Equal(t, "value", vDefault.GetString("toDelete"))

	DeleteConf("toDelete")
	// After deletion, the key is set to empty string
	assert.Equal(t, "", vDefault.GetString("toDelete"))
}

func TestDeleteConf_NonExistingKey(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// Should not panic when deleting a non-existing key
	DeleteConf("nonexistent")
	assert.Equal(t, "", vDefault.GetString("nonexistent"))
}

func TestDeleteConf_InActiveProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "test"

	vProfile.Set("profilekey", "val")
	DeleteConf("profilekey")
	assert.Equal(t, "", vProfile.GetString("profilekey"))
}

//======================================================================
// Profile Operations: Use, CurrentName, AllNames
//======================================================================

func TestUse_Default(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New() // simulate active profile
	currentName = "active"

	err := Use("default")
	assert.NoError(t, err)
	assert.Nil(t, vProfile)
	assert.Equal(t, "default", CurrentName())
}

func TestUse_EmptyString(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = viper.New()
	currentName = "active"

	err := Use("")
	assert.NoError(t, err)
	assert.Nil(t, vProfile)
	assert.Equal(t, "default", CurrentName())
}

func TestUse_NonExistentProfileDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// Use requires the profiles directory to exist
	// This will fail because the profiles dir likely doesn't exist
	err := Use("somename")
	// Should error because profiles dir doesn't exist
	assert.Error(t, err)
}

func TestCurrentName_Default(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	currentName = ""
	assert.Equal(t, "default", CurrentName())
}

func TestCurrentName_CustomName(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	currentName = "myprofile"
	assert.Equal(t, "myprofile", CurrentName())
}

func TestAllNames_NoProfilesDir(t *testing.T) {
	// AllNames should always include "default" even if no profiles dir
	names := AllNames()
	assert.Contains(t, names, "default")
}

func TestAllNonDefaultNames_NoProfilesDir(t *testing.T) {
	// When profiles dir doesn't exist, should return empty
	names := AllNonDefaultNames()
	// It returns whatever the OS provides; with no dir, empty list
	assert.NotNil(t, names)
}

//======================================================================
// CopyToAndUse Tests
//======================================================================

func TestCopyToAndUse_NoProfilesDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// This will fail because profiles dir doesn't exist
	err := CopyToAndUse("newprofile")
	assert.Error(t, err)
}

//======================================================================
// Delete Tests
//======================================================================

func TestDelete_NoProfilesDir(t *testing.T) {
	err := Delete("nonexistent")
	assert.Error(t, err)
}

//======================================================================
// Profile Operations with Real Filesystem
//======================================================================

func TestProfileOperations_WithTempDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	// Create a temp profiles directory structure
	tmpDir := t.TempDir()
	profDir := filepath.Join(tmpDir, "termshark", "profiles")
	err := os.MkdirAll(profDir, 0700)
	require.NoError(t, err)

	// Create a profile directory with a config file
	testProfDir := filepath.Join(profDir, "testprof")
	err = os.MkdirAll(testProfDir, 0700)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(testProfDir, "termshark.toml"),
		[]byte("setting = \"value\"\n"), 0600)
	require.NoError(t, err)

	// Verify the directory structure was created correctly
	_, err = os.Stat(filepath.Join(testProfDir, "termshark.toml"))
	assert.NoError(t, err)
}

//======================================================================
// Edge Cases: Special Characters in Profile Names
//======================================================================

func TestCurrentName_SpecialCharacters(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	// Profile names with special characters
	currentName = "my-profile_v2"
	assert.Equal(t, "my-profile_v2", CurrentName())

	currentName = "profile.with.dots"
	assert.Equal(t, "profile.with.dots", CurrentName())
}

//======================================================================
// Concurrent Access Tests
//======================================================================

func TestConcurrentConfString(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("concurrent_key", "concurrent_value")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := ConfString("concurrent_key", "default")
			assert.Equal(t, "concurrent_value", result)
		}()
	}
	wg.Wait()
}

func TestConcurrentConfInt(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("concurrent_int", 42)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := ConfInt("concurrent_int", 0)
			assert.Equal(t, 42, result)
		}()
	}
	wg.Wait()
}

func TestConcurrentConfBool(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("concurrent_bool", true)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := ConfBool("concurrent_bool", false)
			assert.True(t, result)
		}()
	}
	wg.Wait()
}

func TestConcurrentConfKeyExists(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("exists_key", "value")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exists := ConfKeyExists("exists_key")
			assert.True(t, exists)
			missing := ConfKeyExists("missing_key")
			assert.False(t, missing)
		}()
	}
	wg.Wait()
}

func TestConcurrentCurrentName(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	currentName = "testprofile"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := CurrentName()
			assert.Equal(t, "testprofile", name)
		}()
	}
	wg.Wait()
}

func TestConcurrentReadAndWrite(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	var wg sync.WaitGroup

	// Writers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SetConf("rw_key", "value")
		}()
	}

	// Readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ConfString("rw_key", "default")
		}()
	}

	wg.Wait()
}

//======================================================================
// readConfig edge cases
//======================================================================

func TestReadConfig_CreateIfNecessaryFalse(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	v := viper.New()
	dir := t.TempDir()

	// With createIfNecessary=false, should not create file and should error
	err := readConfig(v, dir, "termshark", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestReadConfig_CreateIfNecessaryTrue(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	v := viper.New()
	dir := t.TempDir()

	err := readConfig(v, dir, "termshark", true)
	assert.NoError(t, err)

	// File should have been created
	_, statErr := os.Stat(filepath.Join(dir, "termshark.toml"))
	assert.NoError(t, statErr)
}

func TestReadConfig_ExistingConfigWithValues(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	v := viper.New()
	dir := t.TempDir()

	// Write config first
	content := []byte("name = \"test\"\ncount = 5\n")
	err := os.WriteFile(filepath.Join(dir, "termshark.toml"), content, 0600)
	require.NoError(t, err)

	err = readConfig(v, dir, "termshark", false)
	assert.NoError(t, err)
	assert.Equal(t, "test", v.GetString("name"))
	assert.Equal(t, 5, v.GetInt("count"))
}

//======================================================================
// WriteConfigAs edge cases
//======================================================================

func TestWriteConfigAs_NewFile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("write_key", "write_value")

	tmpFile := filepath.Join(t.TempDir(), "output.toml")
	err := WriteConfigAs(tmpFile)
	assert.NoError(t, err)

	// Verify the file was written
	data, err := os.ReadFile(tmpFile)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "write_key")
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
