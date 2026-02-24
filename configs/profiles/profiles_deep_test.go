// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// Helper: override xdg.ConfigHome for filesystem-dependent tests.
// Returns a cleanup function that restores the original value.
//======================================================================

func overrideXDGConfigHome(t *testing.T) (tmpRoot string, cleanup func()) {
	t.Helper()
	origConfigHome := xdg.ConfigHome
	tmpRoot = t.TempDir()
	xdg.ConfigHome = tmpRoot
	cleanup = func() {
		xdg.ConfigHome = origConfigHome
	}
	return tmpRoot, cleanup
}

// createProfilesDir creates the profiles directory tree inside tmpRoot
// and returns the path to .../termshark/profiles.
func createProfilesDir(t *testing.T, tmpRoot string) string {
	t.Helper()
	profDir := filepath.Join(tmpRoot, "termshark", "profiles")
	require.NoError(t, os.MkdirAll(profDir, 0700))
	return profDir
}

// createProfile creates a named profile with an optional TOML body.
func createProfile(t *testing.T, profDir, name, toml string) {
	t.Helper()
	dir := filepath.Join(profDir, name)
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "termshark.toml"), []byte(toml), 0600))
}

//======================================================================
// CopyToAndUse
//======================================================================

func TestCopyToAndUse_Success(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	_ = profDir // profiles dir exists now

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// CopyToAndUse should create the profile dir, write a config, and switch
	err := CopyToAndUse("newprof")
	assert.NoError(t, err)

	// Profile directory and config file should exist
	_, err = os.Stat(filepath.Join(profDir, "newprof", "termshark.toml"))
	assert.NoError(t, err)

	// The active profile should now be "newprof"
	assert.Equal(t, "newprof", CurrentName())
	assert.NotNil(t, vProfile)
}

func TestCopyToAndUse_WhenProfileAlreadyActive(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	createProfilesDir(t, tmpRoot)

	vDefault = viper.New()
	vDefault.Set("shared_key", "from_default")

	// Set up an existing active profile so current() != Default()
	vProfile = viper.New()
	vProfile.Set("existing_key", "existing_val")
	currentName = "oldprofile"

	// CopyToAndUse with an already-active profile should reuse vProfile
	err := CopyToAndUse("secondprof")
	assert.NoError(t, err)
	assert.Equal(t, "secondprof", CurrentName())
}

func TestCopyToAndUse_MkdirAllFail(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)

	// Create a file where the profile directory should be, so MkdirAll fails
	conflictPath := filepath.Join(profDir, "badprof")
	require.NoError(t, os.WriteFile(conflictPath, []byte("block"), 0600))

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	err := CopyToAndUse("badprof")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unexpected error making dir")
}

//======================================================================
// Use (non-default profiles)
//======================================================================

func TestUse_NonDefaultProfile_Success(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "myprof", "color = \"blue\"\n")

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	err := Use("myprof")
	assert.NoError(t, err)
	assert.Equal(t, "myprof", CurrentName())
	assert.NotNil(t, vProfile)
	// Values from the profile config should be loaded
	assert.Equal(t, "blue", vProfile.GetString("color"))
}

func TestUse_CreatesProfileDirIfMissing(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	createProfilesDir(t, tmpRoot)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// The profile directory does not exist yet; Use will create it via MkdirAll
	// but readConfig with createIfNecessary=false will fail since there is no
	// termshark.toml there.
	err := Use("brandnew")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// The directory should still have been created by MkdirAll
	_, statErr := os.Stat(filepath.Join(tmpRoot, "termshark", "profiles", "brandnew"))
	assert.NoError(t, statErr)
}

func TestUse_SwitchBackToDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "tempprof", "key = \"val\"\n")

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// Switch to a profile
	err := Use("tempprof")
	require.NoError(t, err)
	assert.Equal(t, "tempprof", CurrentName())
	assert.NotNil(t, vProfile)

	// Switch back to default
	err = Use("default")
	assert.NoError(t, err)
	assert.Nil(t, vProfile)
	assert.Equal(t, "default", CurrentName())
}

func TestUse_MkdirAllFail(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)

	// Block the profile directory creation with a file
	conflictPath := filepath.Join(profDir, "blocked")
	require.NoError(t, os.WriteFile(conflictPath, []byte("x"), 0600))

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	err := Use("blocked")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unexpected error making dir")
}

//======================================================================
// Delete
//======================================================================

func TestDelete_ExistingProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "deleteme", "x = 1\n")

	// Confirm it exists
	_, err := os.Stat(filepath.Join(profDir, "deleteme"))
	require.NoError(t, err)

	err = Delete("deleteme")
	assert.NoError(t, err)

	// Confirm it was removed
	_, err = os.Stat(filepath.Join(profDir, "deleteme"))
	assert.True(t, os.IsNotExist(err))
}

func TestDelete_NonExistentProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	createProfilesDir(t, tmpRoot)

	err := Delete("doesnotexist")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDelete_SymlinkRefused(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)

	// Create a real directory and a symlink in the profiles dir
	realDir := t.TempDir()
	symlinkPath := filepath.Join(profDir, "symprof")
	err := os.Symlink(realDir, symlinkPath)
	require.NoError(t, err)

	err = Delete("symprof")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Refusing to delete symlink")

	// The symlink should still exist (not deleted)
	_, err = os.Lstat(symlinkPath)
	assert.NoError(t, err)
}

func TestDelete_MissingProfilesDir(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	// Do NOT create the profiles dir - just have the tmpRoot
	_ = tmpRoot

	err := Delete("anything")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Could not find profiles dir")
}

//======================================================================
// AllNames / AllNonDefaultNames
//======================================================================

func TestAllNonDefaultNames_WithProfiles(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "alpha", "")
	createProfile(t, profDir, "beta", "x = 1\n")

	names := AllNonDefaultNames()
	assert.Contains(t, names, "alpha")
	assert.Contains(t, names, "beta")
	assert.NotContains(t, names, "default")
}

func TestAllNonDefaultNames_SkipsDefault(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "default", "")
	createProfile(t, profDir, "real", "")

	names := AllNonDefaultNames()
	assert.NotContains(t, names, "default")
	assert.Contains(t, names, "real")
}

func TestAllNonDefaultNames_SkipsSymlinks(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "legit", "")

	// Create a symlink that looks like a profile
	realDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(realDir, "termshark.toml"), []byte(""), 0600))
	require.NoError(t, os.Symlink(realDir, filepath.Join(profDir, "linked")))

	names := AllNonDefaultNames()
	assert.Contains(t, names, "legit")
	// Symlinks should be skipped - however, os.ReadDir on Linux may report
	// symlinks to directories as directories. The code checks entry.Type()
	// for ModeSymlink, which only works if the entry itself is a symlink
	// according to DirEntry.Type(). On Linux with ReadDir, symlinks
	// will have ModeSymlink set.
	assert.NotContains(t, names, "linked")
}

func TestAllNonDefaultNames_SkipsFiles(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "valid", "")

	// Create a regular file (not a directory) in the profiles dir
	require.NoError(t, os.WriteFile(
		filepath.Join(profDir, "notadir"), []byte("data"), 0600))

	names := AllNonDefaultNames()
	assert.Contains(t, names, "valid")
	assert.NotContains(t, names, "notadir")
}

func TestAllNonDefaultNames_SkipsDirWithoutConfig(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "withconfig", "")

	// Create a directory without termshark.toml
	require.NoError(t, os.MkdirAll(filepath.Join(profDir, "noconfig"), 0700))

	names := AllNonDefaultNames()
	assert.Contains(t, names, "withconfig")
	assert.NotContains(t, names, "noconfig")
}

func TestAllNames_WithProfiles(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "one", "")
	createProfile(t, profDir, "two", "")

	names := AllNames()
	assert.Contains(t, names, "one")
	assert.Contains(t, names, "two")
	assert.Contains(t, names, "default")
}

//======================================================================
// profilesDir
//======================================================================

func TestProfilesDir_Success(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	expected := createProfilesDir(t, tmpRoot)

	dir, err := profilesDir()
	assert.NoError(t, err)
	assert.Equal(t, expected, dir)
}

func TestProfilesDir_NotExist(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	_ = tmpRoot // profiles dir not created

	dir, err := profilesDir()
	assert.Error(t, err)
	assert.Equal(t, "", dir)
	assert.Contains(t, err.Error(), "Could not find profiles dir")
}

//======================================================================
// readConfig error paths
//======================================================================

func TestReadConfig_ReadOnlyDir_CreateTrue(t *testing.T) {
	// If the directory is read-only, OpenFile for creation will fail,
	// and ReadInConfig will also fail. The error wrapping path should fire.
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()
	// Make the directory read-only
	require.NoError(t, os.Chmod(dir, 0500))
	defer os.Chmod(dir, 0700) // restore so cleanup works

	v := viper.New()
	err := readConfig(v, dir, "termshark", true)
	// OpenFile fails, ReadInConfig also fails, so we get an error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestReadConfig_ReadOnlyDir_CreateFalse(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()

	v := viper.New()
	// No config file, createIfNecessary=false
	err := readConfig(v, dir, "termshark", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestReadConfig_InvalidToml(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()
	// Write invalid TOML
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "termshark.toml"),
		[]byte("this is not valid = = = toml [[["), 0600))

	v := viper.New()
	// readConfig should fail due to parse error
	// Actually, ReadInConfig may or may not fail with invalid TOML depending
	// on the parser. Let's test and see.
	err := readConfig(v, dir, "termshark", false)
	// With invalid TOML, ReadInConfig should fail, resulting in an error
	assert.Error(t, err)
}

func TestReadConfig_CustomBase(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "custom.toml"),
		[]byte("foo = \"bar\"\n"), 0600))

	v := viper.New()
	err := readConfig(v, dir, "custom", false)
	assert.NoError(t, err)
	assert.Equal(t, "bar", v.GetString("foo"))
}

//======================================================================
// WriteConfigAs edge cases
//======================================================================

func TestWriteConfigAs_InvalidPath(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	vDefault.Set("key", "value")

	// Write to a path that doesn't exist
	err := WriteConfigAs("/nonexistent/dir/file.toml")
	assert.Error(t, err)
}

func TestWriteConfigAs_WithActiveProfile(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "writetest", "original = \"yes\"\n")

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// Activate the profile
	err := Use("writetest")
	require.NoError(t, err)

	// Set a value in the active profile
	vProfile.Set("added", "newvalue")

	// WriteConfigAs should use the current (profile) viper
	outPath := filepath.Join(t.TempDir(), "exported.toml")
	err = WriteConfigAs(outPath)
	assert.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "added")
}

//======================================================================
// Full lifecycle: CopyToAndUse -> modify -> Delete
//======================================================================

func TestProfileLifecycle(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	// Step 1: create and use a new profile
	err := CopyToAndUse("lifecycle")
	require.NoError(t, err)
	assert.Equal(t, "lifecycle", CurrentName())

	// Step 2: the profile should appear in AllNames
	names := AllNames()
	assert.Contains(t, names, "lifecycle")
	assert.Contains(t, names, "default")

	nonDefault := AllNonDefaultNames()
	assert.Contains(t, nonDefault, "lifecycle")

	// Step 3: set a config value in the profile
	SetConf("lifecycle_key", "lifecycle_val")
	assert.Equal(t, "lifecycle_val", ConfString("lifecycle_key", ""))

	// Step 4: switch back to default
	err = Use("default")
	require.NoError(t, err)
	assert.Equal(t, "default", CurrentName())
	// The profile key should not be visible from default
	assert.Equal(t, "", ConfString("lifecycle_key", ""))

	// Step 5: delete the profile
	err = Delete("lifecycle")
	assert.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(profDir, "lifecycle"))
	assert.True(t, os.IsNotExist(statErr))

	// Step 6: it should no longer appear in AllNames
	names = AllNames()
	assert.NotContains(t, names, "lifecycle")
}

//======================================================================
// CopyToAndUse when default viper has values
//======================================================================

func TestCopyToAndUse_DefaultViperHasValues(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	createProfilesDir(t, tmpRoot)

	vDefault = viper.New()
	vDefault.Set("inherited", "from_default")
	vProfile = nil
	currentName = ""

	err := CopyToAndUse("inheritor")
	require.NoError(t, err)

	// The new profile is active but doesn't have the default's key directly.
	// ConfString should fall back to default.
	result := ConfString("inherited", "fallback")
	assert.Equal(t, "from_default", result)
}

//======================================================================
// Use with readConfig failure (no config file, createIfNecessary=false)
//======================================================================

func TestUse_ReadConfigFailure(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)

	// Create directory but no termshark.toml
	require.NoError(t, os.MkdirAll(filepath.Join(profDir, "emptyprof"), 0700))

	vDefault = viper.New()
	vProfile = nil
	currentName = ""

	err := Use("emptyprof")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	// vProfile should not have been set since readConfig failed
	assert.Nil(t, vProfile)
}

//======================================================================
// Delete with nested content
//======================================================================

func TestDelete_WithNestedContent(t *testing.T) {
	s := saveGlobalState()
	defer restoreGlobalState(s)

	tmpRoot, xdgCleanup := overrideXDGConfigHome(t)
	defer xdgCleanup()

	profDir := createProfilesDir(t, tmpRoot)
	createProfile(t, profDir, "nested", "key = \"val\"\n")

	// Add a subdirectory inside the profile directory
	subDir := filepath.Join(profDir, "nested", "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(subDir, "extra.txt"), []byte("data"), 0600))

	err := Delete("nested")
	assert.NoError(t, err)

	_, err = os.Stat(filepath.Join(profDir, "nested"))
	assert.True(t, os.IsNotExist(err))
}

//======================================================================
// readConfig: the error wrapping path where OpenFile fails AND
// ReadInConfig also fails
//======================================================================

func TestReadConfig_OpenFileFails_ReadInConfigFails(t *testing.T) {
	// This tests the branch: err != nil (from OpenFile) AND
	// ReadInConfig also fails => error wraps the original err.
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()
	// Make the dir read-only so file creation fails
	require.NoError(t, os.Chmod(dir, 0500))
	defer os.Chmod(dir, 0700)

	v := viper.New()
	err := readConfig(v, dir, "termshark", true)
	assert.Error(t, err)
	// This should be the "Profile %s not found. (%w)" branch
	assert.Contains(t, err.Error(), "not found")
}

func TestReadConfig_OpenFileSucceeds_ReadInConfigFails(t *testing.T) {
	// OpenFile with O_CREATE succeeds (file is created), but the file is
	// empty so viper can read it fine. Let's test with a file that
	// has content that confuses viper but still can be opened.
	s := saveGlobalState()
	defer restoreGlobalState(s)

	dir := t.TempDir()
	// Pre-create a file with invalid content, so OpenFile succeeds (O_RDONLY)
	// but ReadInConfig fails.
	fp := filepath.Join(dir, "termshark.toml")
	require.NoError(t, os.WriteFile(fp, []byte("[[[invalid"), 0600))

	v := viper.New()
	err := readConfig(v, dir, "termshark", true)
	// OpenFile succeeds (file exists), but ReadInConfig fails.
	// In the code: if v.ReadInConfig() == nil => no. Then err == nil (OpenFile
	// succeeded). So we go to the else branch: "Profile %s not found."
	assert.Error(t, err)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
