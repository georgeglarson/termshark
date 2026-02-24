// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package theme

import (
	"strings"
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Load() tests
//======================================================================

func TestLoad_BuiltInTheme_Default256(t *testing.T) {
	// Save and restore the package-level theme variable
	origTheme := theme
	defer func() { theme = origTheme }()

	// gwtest.D returns Mode256Colors, so Load("default", gwtest.D) should find
	// the built-in themes/default-256.toml
	err := Load("default", gwtest.D)
	assert.NoError(t, err)
	assert.NotNil(t, theme, "theme should be set after successful Load")
}

func TestLoad_BuiltInTheme_Dracula256(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	err := Load("dracula", gwtest.D)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

func TestLoad_BuiltInTheme_Solarized256(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	err := Load("solarized", gwtest.D)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

func TestLoad_BuiltInTheme_Base16(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	err := Load("base16", gwtest.D)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

func TestLoad_NonexistentTheme(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A theme name that doesn't exist should return an error
	err := Load("nonexistent_theme_xyz_12345", gwtest.D)
	assert.Error(t, err)
	// On error, theme should be set back to nil
	assert.Nil(t, theme, "theme should be nil after failed Load")
}

func TestLoad_EmptyName(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// An empty name should fail since there is no "-256.toml" file
	err := Load("", gwtest.D)
	assert.Error(t, err)
	assert.Nil(t, theme)
}

func TestLoad_SetsThemeToNilOnError(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// First load a valid theme
	err := Load("default", gwtest.D)
	assert.NoError(t, err)
	assert.NotNil(t, theme)

	// Now load an invalid theme - theme should be reset to nil
	err = Load("this_theme_does_not_exist", gwtest.D)
	assert.Error(t, err)
	assert.Nil(t, theme, "theme should be nil after a failed load, even if previously set")
}

//======================================================================
// Load() with truecolor mode fallback
//======================================================================

// truecolorApp is a mock IApp that reports Mode24BitColors
type truecolorApp struct {
	gowid.IApp
}

func (a *truecolorApp) GetColorMode() gowid.ColorMode {
	return gowid.Mode24BitColors
}

func (a *truecolorApp) CellStyler(name string) (gowid.ICellStyler, bool) {
	return nil, false
}

func (a *truecolorApp) RangeOverPalette(f func(name string, entry gowid.ICellStyler) bool) {
}

func TestLoad_TruecolorFallsBackTo256(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	app := &truecolorApp{}
	// There's no "default-truecolor.toml" built-in, so it should fall back
	// to "default-256.toml"
	err := Load("default", app)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

func TestLoad_TruecolorNonexistent(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	app := &truecolorApp{}
	err := Load("nonexistent_theme_truecolor_xyz", app)
	assert.Error(t, err)
	assert.Nil(t, theme)
}

//======================================================================
// Load() with various color modes
//======================================================================

type mode16App struct {
	gowid.IApp
}

func (a *mode16App) GetColorMode() gowid.ColorMode {
	return gowid.Mode16Colors
}

func (a *mode16App) CellStyler(name string) (gowid.ICellStyler, bool) {
	return nil, false
}

func (a *mode16App) RangeOverPalette(f func(name string, entry gowid.ICellStyler) bool) {
}

func TestLoad_Mode16_Default(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	app := &mode16App{}
	// Should find themes/default-16.toml
	err := Load("default", app)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

type mode8App struct {
	gowid.IApp
}

func (a *mode8App) GetColorMode() gowid.ColorMode {
	return gowid.Mode8Colors
}

func (a *mode8App) CellStyler(name string) (gowid.ICellStyler, bool) {
	return nil, false
}

func (a *mode8App) RangeOverPalette(f func(name string, entry gowid.ICellStyler) bool) {
}

func TestLoad_Mode8_Default(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	app := &mode8App{}
	// Should find themes/default-8.toml
	err := Load("default", app)
	assert.NoError(t, err)
	assert.NotNil(t, theme)
}

type monoApp struct {
	gowid.IApp
}

func (a *monoApp) GetColorMode() gowid.ColorMode {
	return gowid.ModeMonochrome
}

func (a *monoApp) CellStyler(name string) (gowid.ICellStyler, bool) {
	return nil, false
}

func (a *monoApp) RangeOverPalette(f func(name string, entry gowid.ICellStyler) bool) {
}

func TestLoad_Monochrome_NoBuiltIn(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	app := &monoApp{}
	// There's no "default-mono.toml" built-in, so this should fail
	err := Load("default", app)
	assert.Error(t, err)
	assert.Nil(t, theme)
}

//======================================================================
// Load() followed by MakeColorSafe integration
//======================================================================

func TestLoad_ThenMakeColorSafe(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// Load a real theme and then resolve colors through it
	err := Load("default", gwtest.D)
	assert.NoError(t, err)

	// After loading, the theme should have keys we can look up.
	// We don't know the exact keys, but we can verify that a hex color
	// still works as a pass-through.
	col, err := MakeColorSafe("#aabbcc", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
}

func TestLoad_ThenMakeColorSafe_InvalidKey(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	err := Load("default", gwtest.D)
	assert.NoError(t, err)

	// A key that doesn't exist in the theme and isn't a valid color name
	_, err = MakeColorSafe("totally_nonexistent_key_xyz", Foreground)
	assert.Error(t, err)
}

//======================================================================
// MakeColorSafe - additional edge cases for theme resolution
//======================================================================

func TestMakeColorSafe_SliceToStringChain(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// Test chain: key -> [fg, bg], where fg -> another key -> hex color
	loadTestThemeExtra(t, `
[colors]
  red = "#ff0000"
  blue = "#0000ff"

[dark]
  title = ["colors.red", "colors.blue"]
`)
	// Foreground: dark.title[0] -> colors.red -> #ff0000
	col, err := MakeColorSafe("dark.title", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.title", col.Id)

	// Background: dark.title[1] -> colors.blue -> #0000ff
	col, err = MakeColorSafe("dark.title", Background)
	assert.NoError(t, err)
	assert.Equal(t, "dark.title", col.Id)
}

func TestMakeColorSafe_NilSliceFromNonexistentKey(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// When GetStringSlice returns nil for a non-existent key, the code
	// should break out and try gowid.MakeColorSafe
	loadTestThemeExtra(t, `
somekey = "#ff0000"
`)
	// "missing" is not a key at all: GetString returns "" and GetStringSlice returns nil
	_, err := MakeColorSafe("missing", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_EmptyStringValue(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A key mapping to an empty string should be treated as not found
	loadTestThemeExtra(t, `
emptyval = ""
`)
	// empty string means GetString returns "" which is falsy, so it breaks
	// out of the loop and tries gowid.MakeColorSafe("emptyval") which fails
	_, err := MakeColorSafe("emptyval", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_ExactlyTenChainIterations(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// Chain of exactly 10: c0 -> c1 -> ... -> c9 -> "dark red"
	// The loop runs 10 times; on the 10th iteration it resolves c9 -> "dark red"
	// so cur becomes "dark red". Then loops becomes 0 and we break out.
	// Then gowid.MakeColorSafe("dark red") should succeed.
	loadTestThemeExtra(t, `
c0 = "c1"
c1 = "c2"
c2 = "c3"
c3 = "c4"
c4 = "c5"
c5 = "c6"
c6 = "c7"
c7 = "c8"
c8 = "c9"
c9 = "dark red"
`)
	col, err := MakeColorSafe("c0", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "c0", col.Id)
}

func TestMakeColorSafe_SelfReferentialKey(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A key that refers to itself creates an infinite loop, but the loop
	// limit prevents it
	loadTestThemeExtra(t, `
selfref = "selfref"
`)
	// After 10 iterations, cur is still "selfref"; gowid.MakeColorSafe("selfref") fails
	_, err := MakeColorSafe("selfref", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_MutuallyRecursiveKeys(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestThemeExtra(t, `
ping = "pong"
pong = "ping"
`)
	// Infinite loop broken by limit; neither is a valid color
	_, err := MakeColorSafe("ping", Foreground)
	assert.Error(t, err)
}

// loadTestThemeExtra is a helper for the extra test file (same as loadTestTheme in utils_test.go)
func loadTestThemeExtra(t *testing.T, toml string) {
	t.Helper()
	v := viper.New()
	v.SetConfigType("toml")
	err := v.ReadConfig(strings.NewReader(toml))
	assert.NoError(t, err)
	theme = v
}
