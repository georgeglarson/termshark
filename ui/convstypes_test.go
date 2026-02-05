// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDirection_Constants(t *testing.T) {
	assert.Equal(t, Direction(0), Any)
	assert.Equal(t, Direction(1), To)
	assert.Equal(t, Direction(2), From)
}

func TestConvAddr_Constants(t *testing.T) {
	assert.Equal(t, ConvAddr(0), IPv4Addr)
	assert.Equal(t, ConvAddr(1), IPv6Addr)
	assert.Equal(t, ConvAddr(2), MacAddr)
}

func TestFilterMask_Constants(t *testing.T) {
	assert.Equal(t, FilterMask(0), AtfB)
	assert.Equal(t, FilterMask(1), AtB)
	assert.Equal(t, FilterMask(2), BtA)
	assert.Equal(t, FilterMask(3), AtfAny)
	assert.Equal(t, FilterMask(4), AtAny)
	assert.Equal(t, FilterMask(5), AnytA)
	assert.Equal(t, FilterMask(6), AnytfB)
	assert.Equal(t, FilterMask(7), AnytB)
	assert.Equal(t, FilterMask(8), BtAny)
}

func TestFilterCombinator_Constants(t *testing.T) {
	assert.Equal(t, FilterCombinator(0), Selected)
	assert.Equal(t, FilterCombinator(1), NotSelected)
	assert.Equal(t, FilterCombinator(2), AndSelected)
	assert.Equal(t, FilterCombinator(3), OrSelected)
	assert.Equal(t, FilterCombinator(4), AndNotSelected)
	assert.Equal(t, FilterCombinator(5), OrNotSelected)
}

func TestConvTypes_Registered(t *testing.T) {
	// Verify all expected conversation types are registered
	expectedTypes := []string{"eth", "ip", "ipv6", "udp", "tcp"}
	for _, typ := range expectedTypes {
		_, ok := convTypes[typ]
		assert.True(t, ok, "convTypes should contain %q", typ)
	}
}

func TestConvTypes_FilterBuilders(t *testing.T) {
	// Test that each registered filter builder implements IFilterBuilder
	for name, fb := range convTypes {
		assert.NotNil(t, fb, "FilterBuilder for %q should not be nil", name)
		// Verify String() doesn't panic
		_ = fb.String()
		// Verify index methods don't panic
		_ = fb.AIndex()
		_ = fb.BIndex()
	}
}
