// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package theme

import (
	"strings"
	"testing"

	"github.com/gcla/gowid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Mode.String() tests
//======================================================================

func TestMode_String(t *testing.T) {
	tests := []struct {
		mode     gowid.ColorMode
		expected string
	}{
		{gowid.Mode256Colors, "256"},
		{gowid.Mode88Colors, "88"},
		{gowid.Mode16Colors, "16"},
		{gowid.Mode8Colors, "8"},
		{gowid.ModeMonochrome, "mono"},
		{gowid.Mode24BitColors, "truecolor"},
		{gowid.ColorMode(999), "unknown"}, // Unknown mode
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			m := Mode(tt.mode)
			assert.Equal(t, tt.expected, m.String())
		})
	}
}

//======================================================================
// Layer constant tests
//======================================================================

func TestLayer_Constants(t *testing.T) {
	// Verify the Layer constants have expected values
	assert.Equal(t, Layer(0), Foreground)
	assert.Equal(t, Layer(1), Background)
}

func TestLayer_ForegroundBeforeBackground(t *testing.T) {
	assert.True(t, Foreground < Background,
		"Foreground should have a lower numeric value than Background")
}

//======================================================================
// MakeColorSafe tests - with no theme loaded
//======================================================================

func TestMakeColorSafe_NoTheme_ValidUrwidColor(t *testing.T) {
	// Save and restore the package-level theme variable
	origTheme := theme
	defer func() { theme = origTheme }()
	theme = nil

	// With no theme loaded, MakeColorSafe should fall through to gowid.MakeColorSafe
	// "dark red" is a valid urwid color name
	col, err := MakeColorSafe("dark red", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
	assert.Equal(t, "dark red", col.Id)
}

func TestMakeColorSafe_NoTheme_InvalidColor(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()
	theme = nil

	// An invalid color string should return an error
	_, err := MakeColorSafe("not_a_real_color_at_all_xyz", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_NoTheme_HexColor(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()
	theme = nil

	// Hex color strings like "#ff0000" should be handled by gowid.MakeColorSafe
	col, err := MakeColorSafe("#ff0000", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
}

//======================================================================
// MakeColorSafe tests - with theme loaded from TOML
//======================================================================

// loadTestTheme sets the package-level theme variable from TOML content
func loadTestTheme(t *testing.T, toml string) {
	t.Helper()
	v := viper.New()
	v.SetConfigType("toml")
	err := v.ReadConfig(strings.NewReader(toml))
	assert.NoError(t, err)
	theme = v
}

func TestMakeColorSafe_SimpleStringLookup(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A simple key that maps to a valid color
	loadTestTheme(t, `
mycolor = "dark red"
`)
	col, err := MakeColorSafe("mycolor", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "mycolor", col.Id)
}

func TestMakeColorSafe_ChainedStringLookup(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// Keys can chain: a -> b -> actual color
	loadTestTheme(t, `
alias1 = "alias2"
alias2 = "dark blue"
`)
	col, err := MakeColorSafe("alias1", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "alias1", col.Id)
}

func TestMakeColorSafe_ChainedStringLookupMaxDepth(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// The loop limit is 10, so a chain of 11 should hit the limit
	// and then try gowid.MakeColorSafe on whatever the last resolved value was
	loadTestTheme(t, `
c0 = "c1"
c1 = "c2"
c2 = "c3"
c3 = "c4"
c4 = "c5"
c5 = "c6"
c6 = "c7"
c7 = "c8"
c8 = "c9"
c9 = "c10"
c10 = "dark green"
`)
	// After 10 iterations, we should end up at "c10" which is still a TOML key
	// not yet resolved. The function will try gowid.MakeColorSafe("c10") which fails,
	// then fallback to gowid.MakeColorSafe("c0") which also fails.
	_, err := MakeColorSafe("c0", Foreground)
	assert.Error(t, err, "Should fail when chain exceeds loop limit")
}

func TestMakeColorSafe_SliceLookup_Foreground(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
[dark]
  button = ["dark red", "dark blue"]
`)
	col, err := MakeColorSafe("dark.button", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.button", col.Id)
}

func TestMakeColorSafe_SliceLookup_Background(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
[dark]
  button = ["dark red", "dark blue"]
`)
	col, err := MakeColorSafe("dark.button", Background)
	assert.NoError(t, err)
	assert.Equal(t, "dark.button", col.Id)
}

func TestMakeColorSafe_NestedSectionLookup(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
[default]
  red = "#ff0000"
  blue = "#0000ff"

[dark]
  title = ["default.red", "default.blue"]
`)

	// Foreground should resolve dark.title[0] -> default.red -> #ff0000
	colFg, err := MakeColorSafe("dark.title", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.title", colFg.Id)

	// Background should resolve dark.title[1] -> default.blue -> #0000ff
	colBg, err := MakeColorSafe("dark.title", Background)
	assert.NoError(t, err)
	assert.Equal(t, "dark.title", colBg.Id)
}

func TestMakeColorSafe_SliceWithWrongLength(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A slice that doesn't have exactly 2 elements should be treated as
	// not found, so we break out and try gowid.MakeColorSafe
	loadTestTheme(t, `
[section]
  onecolor = ["dark red"]
`)

	// The key resolves to a single-element slice, which the code rejects.
	// Then it tries gowid.MakeColorSafe("section.onecolor") which fails,
	// then falls back to gowid.MakeColorSafe("section.onecolor") again.
	_, err := MakeColorSafe("section.onecolor", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_EmptySlice(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
[section]
  empty = []
`)
	_, err := MakeColorSafe("section.empty", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_MissingKey(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
somekey = "dark red"
`)
	// A key not in the theme should fall through to gowid.MakeColorSafe("nonexistent")
	_, err := MakeColorSafe("nonexistent", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_DirectHexWithTheme(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
somekey = "dark red"
`)
	// A hex color should still work even if a theme is loaded, since the key
	// won't match anything in the theme and gowid.MakeColorSafe handles hex
	col, err := MakeColorSafe("#00ff00", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
}

func TestMakeColorSafe_StringToSliceChain(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// A string key that resolves to another key which is a slice
	loadTestTheme(t, `
alias = "actual"

[section]
  actual = ["dark red", "dark blue"]
`)
	// "alias" -> "actual", then "actual" is not a string key at top level
	// (it is, but section.actual is a slice). The loop will go:
	// cur = "alias" -> next = "actual" (string) -> cur = "actual"
	// cur = "actual" -> next = "" (no top-level string "actual") -> try slice
	// GetStringSlice("actual") returns nil -> break
	// Then gowid.MakeColorSafe("actual") is tried, which fails for "actual"
	// Then gowid.MakeColorSafe("alias") is tried, which fails for "alias"
	_, err := MakeColorSafe("alias", Foreground)
	assert.Error(t, err)
}

//======================================================================
// Theme loading via TOML content tests
//======================================================================

func TestLoadThemeFromToml_ParsesCorrectly(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	toml := `
unused = "#79e11a"

[default]
  black = "#000000"
  white = "#ffffff"
  red = "#ff0000"

[dark]
  default = ["default.white", "default.black"]
  title = ["default.red", "unused"]
`
	loadTestTheme(t, toml)

	// Verify we can resolve colors through the theme
	col, err := MakeColorSafe("dark.default", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.default", col.Id)

	col, err = MakeColorSafe("dark.default", Background)
	assert.NoError(t, err)
	assert.Equal(t, "dark.default", col.Id)
}

func TestLoadThemeFromToml_TopLevelAlias(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	toml := `
unused = "#79e11a"

[dark]
  current-capture = ["#ffffff", "unused"]
`
	loadTestTheme(t, toml)

	// Foreground: dark.current-capture[0] -> #ffffff (direct hex)
	colFg, err := MakeColorSafe("dark.current-capture", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.current-capture", colFg.Id)

	// Background: dark.current-capture[1] -> "unused" -> "#79e11a"
	colBg, err := MakeColorSafe("dark.current-capture", Background)
	assert.NoError(t, err)
	assert.Equal(t, "dark.current-capture", colBg.Id)
}

func TestLoadThemeFromToml_LightAndDarkSections(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	toml := `
[default]
  black = "#000000"
  white = "#ffffff"

[dark]
  default = ["default.white", "default.black"]

[light]
  default = ["default.black", "default.white"]
`
	loadTestTheme(t, toml)

	// Dark foreground is white
	darkFg, err := MakeColorSafe("dark.default", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, darkFg)

	// Light foreground is black
	lightFg, err := MakeColorSafe("light.default", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, lightFg)

	// Dark background is black
	darkBg, err := MakeColorSafe("dark.default", Background)
	assert.NoError(t, err)
	assert.NotNil(t, darkBg)

	// Light background is white
	lightBg, err := MakeColorSafe("light.default", Background)
	assert.NoError(t, err)
	assert.NotNil(t, lightBg)
}

func TestLoadThemeFromToml_InvalidToml(t *testing.T) {
	v := viper.New()
	v.SetConfigType("toml")
	err := v.ReadConfig(strings.NewReader(`this is not valid toml {{{{`))
	assert.Error(t, err, "Invalid TOML should produce an error")
}

func TestLoadThemeFromToml_EmptyConfig(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	// An empty TOML file is technically valid
	loadTestTheme(t, "")

	// With an empty theme, lookups should fall through to gowid.MakeColorSafe
	col, err := MakeColorSafe("dark red", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
}

//======================================================================
// Layer used as index tests
//======================================================================

func TestLayer_UsedAsSliceIndex(t *testing.T) {
	// This verifies that Layer values work correctly as indices
	// into a two-element string slice, matching how the theme code uses them
	pair := []string{"foreground_color", "background_color"}
	assert.Equal(t, "foreground_color", pair[Foreground])
	assert.Equal(t, "background_color", pair[Background])
}

//======================================================================
// Mode conversion roundtrip tests
//======================================================================

func TestMode_AllModesHaveUniqueStrings(t *testing.T) {
	modes := []gowid.ColorMode{
		gowid.Mode256Colors,
		gowid.Mode88Colors,
		gowid.Mode16Colors,
		gowid.Mode8Colors,
		gowid.ModeMonochrome,
		gowid.Mode24BitColors,
	}

	seen := make(map[string]bool)
	for _, m := range modes {
		s := Mode(m).String()
		assert.False(t, seen[s], "Mode string %q appears more than once", s)
		seen[s] = true
	}
}

func TestMode_NegativeValue(t *testing.T) {
	m := Mode(gowid.ColorMode(-1))
	assert.Equal(t, "unknown", m.String())
}

//======================================================================
// MakeColorSafe with complex theme indirection
//======================================================================

func TestMakeColorSafe_MultiLevelIndirection(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	toml := `
[default]
  red = "#ff0000"

[dark]
  title = ["default.red", "default.red"]
`
	loadTestTheme(t, toml)

	// dark.title -> ["default.red", "default.red"]
	// Then default.red -> #ff0000
	// Multi-level: slice -> string -> hex
	col, err := MakeColorSafe("dark.title", Foreground)
	assert.NoError(t, err)
	assert.Equal(t, "dark.title", col.Id)
}

func TestMakeColorSafe_ThreeElementSliceIgnored(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
[section]
  triple = ["dark red", "dark blue", "dark green"]
`)
	// A 3-element slice should not be treated as a valid fg/bg pair
	_, err := MakeColorSafe("section.triple", Foreground)
	assert.Error(t, err)
}

func TestMakeColorSafe_PreservesIdOnSuccess(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
myalias = "#00ff00"
`)
	col, err := MakeColorSafe("myalias", Foreground)
	assert.NoError(t, err)
	// The returned Color's Id should be the original key, not the resolved value
	assert.Equal(t, "myalias", col.Id)
}

func TestMakeColorSafe_DirectUrwidColorWithTheme(t *testing.T) {
	origTheme := theme
	defer func() { theme = origTheme }()

	loadTestTheme(t, `
somekey = "#ff0000"
`)

	// If the key is not found in theme, it should still work as a direct urwid color
	col, err := MakeColorSafe("dark blue", Foreground)
	assert.NoError(t, err)
	assert.NotNil(t, col)
}
