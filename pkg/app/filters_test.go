// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCombineFilters_Selected(t *testing.T) {
	result := CombineFilters(CombSelected, "tcp.port == 80", "")
	assert.Equal(t, "tcp.port == 80", result)

	result = CombineFilters(CombSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "tcp.port == 80", result) // Selected replaces, ignores existing
}

func TestCombineFilters_NotSelected(t *testing.T) {
	result := CombineFilters(CombNotSelected, "tcp.port == 80", "")
	assert.Equal(t, "!(tcp.port == 80)", result)

	result = CombineFilters(CombNotSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "!(tcp.port == 80)", result) // NotSelected replaces, ignores existing
}

func TestCombineFilters_AndSelected(t *testing.T) {
	// With existing filter
	result := CombineFilters(CombAndSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "ip.addr == 1.2.3.4 && (tcp.port == 80)", result)

	// Without existing filter
	result = CombineFilters(CombAndSelected, "tcp.port == 80", "")
	assert.Equal(t, "tcp.port == 80", result)
}

func TestCombineFilters_OrSelected(t *testing.T) {
	// With existing filter
	result := CombineFilters(CombOrSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "ip.addr == 1.2.3.4 || (tcp.port == 80)", result)

	// Without existing filter
	result = CombineFilters(CombOrSelected, "tcp.port == 80", "")
	assert.Equal(t, "tcp.port == 80", result)
}

func TestCombineFilters_AndNotSelected(t *testing.T) {
	// With existing filter
	result := CombineFilters(CombAndNotSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "ip.addr == 1.2.3.4 && !(tcp.port == 80)", result)

	// Without existing filter
	result = CombineFilters(CombAndNotSelected, "tcp.port == 80", "")
	assert.Equal(t, "!tcp.port == 80", result)
}

func TestCombineFilters_OrNotSelected(t *testing.T) {
	// With existing filter
	result := CombineFilters(CombOrNotSelected, "tcp.port == 80", "ip.addr == 1.2.3.4")
	assert.Equal(t, "ip.addr == 1.2.3.4 || !(tcp.port == 80)", result)

	// Without existing filter
	result = CombineFilters(CombOrNotSelected, "tcp.port == 80", "")
	assert.Equal(t, "!tcp.port == 80", result)
}

func TestComputeConversationFilter(t *testing.T) {
	model := &SimpleFilterModel{
		AFilterAny:  "ip.addr == 1.2.3.4",
		AFilterFrom: "ip.src == 1.2.3.4",
		AFilterTo:   "ip.dst == 1.2.3.4",
		BFilterAny:  "ip.addr == 5.6.7.8",
		BFilterFrom: "ip.src == 5.6.7.8",
		BFilterTo:   "ip.dst == 5.6.7.8",
	}

	tests := []struct {
		name       string
		mask       FilterMask
		combinator FilterCombinator
		existing   string
		want       string
	}{
		{
			name:       "A <-> B selected",
			mask:       AtoFromB,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.addr == 1.2.3.4 && ip.addr == 5.6.7.8",
		},
		{
			name:       "A -> B selected",
			mask:       AtoB,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.src == 1.2.3.4 && ip.dst == 5.6.7.8",
		},
		{
			name:       "B -> A selected",
			mask:       BtoA,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.src == 5.6.7.8 && ip.dst == 1.2.3.4",
		},
		{
			name:       "A <-> Any selected",
			mask:       AtoFromAny,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.addr == 1.2.3.4",
		},
		{
			name:       "A -> Any selected",
			mask:       AtoAny,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.src == 1.2.3.4",
		},
		{
			name:       "Any -> A selected",
			mask:       AnytoA,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.dst == 1.2.3.4",
		},
		{
			name:       "Any <-> B selected",
			mask:       AnytoFromB,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.addr == 5.6.7.8",
		},
		{
			name:       "Any -> B selected",
			mask:       AnytoB,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.dst == 5.6.7.8",
		},
		{
			name:       "B -> Any selected",
			mask:       BtoAny,
			combinator: CombSelected,
			existing:   "",
			want:       "ip.src == 5.6.7.8",
		},
		{
			name:       "A <-> B AND existing",
			mask:       AtoFromB,
			combinator: CombAndSelected,
			existing:   "tcp",
			want:       "tcp && (ip.addr == 1.2.3.4 && ip.addr == 5.6.7.8)",
		},
		{
			name:       "A <-> B NOT selected",
			mask:       AtoFromB,
			combinator: CombNotSelected,
			existing:   "",
			want:       "!(ip.addr == 1.2.3.4 && ip.addr == 5.6.7.8)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeConversationFilter(tt.mask, tt.combinator, model, tt.existing)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestShouldReloadForFilter(t *testing.T) {
	assert.False(t, ShouldReloadForFilter("tcp", "tcp"))
	assert.True(t, ShouldReloadForFilter("tcp", "udp"))
	assert.True(t, ShouldReloadForFilter("", "tcp"))
	assert.True(t, ShouldReloadForFilter("tcp", ""))
	assert.False(t, ShouldReloadForFilter("", ""))
}

func TestIsFilterEmpty(t *testing.T) {
	assert.True(t, IsFilterEmpty(""))
	assert.True(t, IsFilterEmpty("   "))
	assert.True(t, IsFilterEmpty("\t\n\r"))
	assert.False(t, IsFilterEmpty("tcp"))
	assert.False(t, IsFilterEmpty(" tcp "))
}

func TestBuildFieldFilter(t *testing.T) {
	// Field only (no value)
	assert.Equal(t, "tcp.port", BuildFieldFilter("tcp.port", "", false))

	// Field with numeric value
	assert.Equal(t, "tcp.port == 80", BuildFieldFilter("tcp.port", "80", false))

	// Field with string value (needs quotes)
	assert.Equal(t, "http.host == \"example.com\"", BuildFieldFilter("http.host", "example.com", true))

	// Field with value containing backslash
	assert.Equal(t, "http.uri == \"path\\\\to\\\\file\"", BuildFieldFilter("http.uri", "path\\to\\file", true))
}

func TestEscapeBackslashes(t *testing.T) {
	assert.Equal(t, "normal", escapeBackslashes("normal"))
	assert.Equal(t, "path\\\\to\\\\file", escapeBackslashes("path\\to\\file"))
	assert.Equal(t, "\\\\\\\\", escapeBackslashes("\\\\"))
	assert.Equal(t, "", escapeBackslashes(""))
}

func TestSimpleFilterModel(t *testing.T) {
	model := &SimpleFilterModel{
		AFilterAny:  "any-a",
		AFilterFrom: "from-a",
		AFilterTo:   "to-a",
		BFilterAny:  "any-b",
		BFilterFrom: "from-b",
		BFilterTo:   "to-b",
	}

	assert.Equal(t, "any-a", model.GetAFilter(DirAny))
	assert.Equal(t, "from-a", model.GetAFilter(DirFrom))
	assert.Equal(t, "to-a", model.GetAFilter(DirTo))
	assert.Equal(t, "any-b", model.GetBFilter(DirAny))
	assert.Equal(t, "from-b", model.GetBFilter(DirFrom))
	assert.Equal(t, "to-b", model.GetBFilter(DirTo))
}

func TestFilterMaskValues(t *testing.T) {
	// Verify enum values match expected order (matching UI menu)
	assert.Equal(t, FilterMask(0), AtoFromB)
	assert.Equal(t, FilterMask(1), AtoB)
	assert.Equal(t, FilterMask(2), BtoA)
	assert.Equal(t, FilterMask(3), AtoFromAny)
	assert.Equal(t, FilterMask(4), AtoAny)
	assert.Equal(t, FilterMask(5), AnytoA)
	assert.Equal(t, FilterMask(6), AnytoFromB)
	assert.Equal(t, FilterMask(7), AnytoB)
	assert.Equal(t, FilterMask(8), BtoAny)
}

func TestFilterCombinatorValues(t *testing.T) {
	// Verify enum values match expected order (matching UI menu)
	assert.Equal(t, FilterCombinator(0), CombSelected)
	assert.Equal(t, FilterCombinator(1), CombNotSelected)
	assert.Equal(t, FilterCombinator(2), CombAndSelected)
	assert.Equal(t, FilterCombinator(3), CombOrSelected)
	assert.Equal(t, FilterCombinator(4), CombAndNotSelected)
	assert.Equal(t, FilterCombinator(5), CombOrNotSelected)
}

func TestDirectionValues(t *testing.T) {
	assert.Equal(t, Direction(0), DirAny)
	assert.Equal(t, Direction(1), DirTo)
	assert.Equal(t, Direction(2), DirFrom)
}
