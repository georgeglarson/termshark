// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/stretchr/testify/assert"
)

// mockPalette implements gowid.IPalette for testing
type mockPalette struct {
	name   string
	styles map[string]gowid.ICellStyler
}

func newMockPalette(name string, keys ...string) *mockPalette {
	m := &mockPalette{name: name, styles: make(map[string]gowid.ICellStyler)}
	for _, k := range keys {
		m.styles[k] = gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone)
	}
	return m
}

func (m *mockPalette) CellStyler(name string) (gowid.ICellStyler, bool) {
	s, ok := m.styles[name]
	return s, ok
}

func (m *mockPalette) RangeOverPalette(f func(key string, value gowid.ICellStyler) bool) {
	for k, v := range m.styles {
		if !f(k, v) {
			return
		}
	}
}

func TestPaletteSwitcher_ChooseOne(t *testing.T) {
	p1 := newMockPalette("dark", "bg")
	p2 := newMockPalette("light", "bg")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	// When ChooseOne is true, should use P1
	_, ok := ps.CellStyler("bg")
	assert.True(t, ok, "Should find 'bg' in P1")

	// When ChooseOne is false, should use P2
	chooseOne = false
	_, ok = ps.CellStyler("bg")
	assert.True(t, ok, "Should find 'bg' in P2")
}

func TestPaletteSwitcher_MissingSyler(t *testing.T) {
	p1 := newMockPalette("dark", "bg")
	p2 := newMockPalette("light", "fg")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	// P1 has "bg" but not "fg"
	_, ok := ps.CellStyler("fg")
	assert.False(t, ok, "P1 should not have 'fg'")

	// P2 has "fg" but not "bg"
	chooseOne = false
	_, ok = ps.CellStyler("bg")
	assert.False(t, ok, "P2 should not have 'bg'")
}

func TestPaletteSwitcher_RangeOverPalette(t *testing.T) {
	p1 := newMockPalette("dark", "a", "b")
	p2 := newMockPalette("light", "x", "y", "z")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	// Range over P1
	count := 0
	ps.RangeOverPalette(func(key string, value gowid.ICellStyler) bool {
		count++
		return true
	})
	assert.Equal(t, 2, count, "P1 should have 2 entries")

	// Range over P2
	chooseOne = false
	count = 0
	ps.RangeOverPalette(func(key string, value gowid.ICellStyler) bool {
		count++
		return true
	})
	assert.Equal(t, 3, count, "P2 should have 3 entries")
}

func TestPaletteSwitcher_RangeOverPalette_EarlyStop(t *testing.T) {
	p1 := newMockPalette("dark", "a", "b", "c")
	p2 := newMockPalette("light")

	chooseOne := true
	ps := PaletteSwitcher{P1: p1, P2: p2, ChooseOne: &chooseOne}

	count := 0
	ps.RangeOverPalette(func(key string, value gowid.ICellStyler) bool {
		count++
		return false // stop after first
	})
	assert.Equal(t, 1, count, "Should stop after first entry")
}

func TestPaletteSwitcher_ImplementsIPalette(t *testing.T) {
	chooseOne := true
	ps := PaletteSwitcher{
		P1:        newMockPalette("p1"),
		P2:        newMockPalette("p2"),
		ChooseOne: &chooseOne,
	}
	var _ gowid.IPalette = ps
	var _ gowid.IPalette = &ps
}
