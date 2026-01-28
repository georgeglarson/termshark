// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import "fmt"

//======================================================================
// Filter direction and combination types
//======================================================================

// Direction indicates the direction of traffic for filter construction.
type Direction int

const (
	// DirAny matches traffic in either direction.
	DirAny Direction = iota
	// DirTo matches traffic going to the address.
	DirTo
	// DirFrom matches traffic coming from the address.
	DirFrom
)

// FilterMask specifies which combination of A and B endpoints to filter.
type FilterMask int

const (
	// AtoFromB matches A <-> B (bidirectional).
	AtoFromB FilterMask = iota
	// AtoB matches A -> B only.
	AtoB
	// BtoA matches B -> A only.
	BtoA
	// AtoFromAny matches A <-> Any.
	AtoFromAny
	// AtoAny matches A -> Any.
	AtoAny
	// AnytoA matches Any -> A.
	AnytoA
	// AnytoFromB matches Any <-> B.
	AnytoFromB
	// AnytoB matches Any -> B.
	AnytoB
	// BtoAny matches B -> Any.
	BtoAny
)

// FilterCombinator specifies how to combine a new filter with an existing filter.
type FilterCombinator int

const (
	// CombSelected uses the filter as-is.
	CombSelected FilterCombinator = iota
	// CombNotSelected negates the filter: !(<filter>).
	CombNotSelected
	// CombAndSelected adds the filter with AND: existing && (<filter>).
	CombAndSelected
	// CombOrSelected adds the filter with OR: existing || (<filter>).
	CombOrSelected
	// CombAndNotSelected adds negated filter with AND: existing && !(<filter>).
	CombAndNotSelected
	// CombOrNotSelected adds negated filter with OR: existing || !(<filter>).
	CombOrNotSelected
)

//======================================================================
// Filter model interface
//======================================================================

// FilterModel provides filters for endpoints A and B in a conversation.
type FilterModel interface {
	// GetAFilter returns a filter expression for endpoint A in the given direction.
	GetAFilter(dir Direction) string
	// GetBFilter returns a filter expression for endpoint B in the given direction.
	GetBFilter(dir Direction) string
}

//======================================================================
// Filter computation functions
//======================================================================

// ComputeConversationFilter builds a filter expression for a conversation
// based on the specified direction mask and combination operator.
//
// Parameters:
//   - mask: specifies which endpoints and directions to filter
//   - combinator: specifies how to combine with existing filter
//   - model: provides the A and B endpoint filter expressions
//   - existingFilter: the current filter expression (may be empty)
//
// Returns the computed filter expression.
func ComputeConversationFilter(mask FilterMask, combinator FilterCombinator, model FilterModel, existingFilter string) string {
	var filter string

	switch mask {
	case AtoFromB:
		filter = fmt.Sprintf("%s && %s", model.GetAFilter(DirAny), model.GetBFilter(DirAny))
	case AtoB:
		filter = fmt.Sprintf("%s && %s", model.GetAFilter(DirFrom), model.GetBFilter(DirTo))
	case BtoA:
		filter = fmt.Sprintf("%s && %s", model.GetBFilter(DirFrom), model.GetAFilter(DirTo))
	case AtoFromAny:
		filter = model.GetAFilter(DirAny)
	case AtoAny:
		filter = model.GetAFilter(DirFrom)
	case AnytoA:
		filter = model.GetAFilter(DirTo)
	case AnytoFromB:
		filter = model.GetBFilter(DirAny)
	case AnytoB:
		filter = model.GetBFilter(DirTo)
	case BtoAny:
		filter = model.GetBFilter(DirFrom)
	}

	return CombineFilters(combinator, filter, existingFilter)
}

// CombineFilters combines a new filter with an existing filter using
// the specified combinator.
//
// Parameters:
//   - combinator: specifies how to combine the filters
//   - newFilter: the new filter expression to add
//   - existingFilter: the current filter expression (may be empty)
//
// Returns the combined filter expression.
func CombineFilters(combinator FilterCombinator, newFilter, existingFilter string) string {
	switch combinator {
	case CombNotSelected:
		return fmt.Sprintf("!(%s)", newFilter)
	case CombAndSelected:
		if existingFilter != "" {
			return fmt.Sprintf("%s && (%s)", existingFilter, newFilter)
		}
		return newFilter
	case CombOrSelected:
		if existingFilter != "" {
			return fmt.Sprintf("%s || (%s)", existingFilter, newFilter)
		}
		return newFilter
	case CombAndNotSelected:
		if existingFilter != "" {
			return fmt.Sprintf("%s && !(%s)", existingFilter, newFilter)
		}
		return fmt.Sprintf("!%s", newFilter)
	case CombOrNotSelected:
		if existingFilter != "" {
			return fmt.Sprintf("%s || !(%s)", existingFilter, newFilter)
		}
		return fmt.Sprintf("!%s", newFilter)
	default: // CombSelected
		return newFilter
	}
}

// ShouldReloadForFilter determines if a filter change requires reloading
// the packet data. Returns true if the filters are different.
func ShouldReloadForFilter(oldFilter, newFilter string) bool {
	return oldFilter != newFilter
}

// IsFilterEmpty returns true if the filter is empty or contains only whitespace.
func IsFilterEmpty(filter string) bool {
	for _, c := range filter {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

//======================================================================
// PDML filter building
//======================================================================

// BuildFieldFilter creates a filter expression for a PDML field.
// If value is empty, returns just the field name.
// If needsQuotes is true, the value will be quoted for string fields.
//
// Parameters:
//   - field: the field name (e.g., "tcp.port")
//   - value: the field value (e.g., "80")
//   - needsQuotes: true if the field type requires quoted string values
//
// Returns the filter expression (e.g., "tcp.port == 80" or "http.host == \"example.com\"").
func BuildFieldFilter(field, value string, needsQuotes bool) string {
	if value == "" {
		return field
	}

	if needsQuotes {
		// Escape backslashes in the value
		escapedValue := escapeBackslashes(value)
		return fmt.Sprintf("%s == \"%s\"", field, escapedValue)
	}

	return fmt.Sprintf("%s == %s", field, value)
}

// escapeBackslashes doubles backslashes for use in quoted strings.
func escapeBackslashes(s string) string {
	result := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			result = append(result, '\\', '\\')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

//======================================================================
// Convenience filter model implementations
//======================================================================

// SimpleFilterModel is a basic implementation of FilterModel for testing.
type SimpleFilterModel struct {
	AFilterAny  string
	AFilterFrom string
	AFilterTo   string
	BFilterAny  string
	BFilterFrom string
	BFilterTo   string
}

// GetAFilter implements FilterModel.
func (m *SimpleFilterModel) GetAFilter(dir Direction) string {
	switch dir {
	case DirFrom:
		return m.AFilterFrom
	case DirTo:
		return m.AFilterTo
	default:
		return m.AFilterAny
	}
}

// GetBFilter implements FilterModel.
func (m *SimpleFilterModel) GetBFilter(dir Direction) string {
	switch dir {
	case DirFrom:
		return m.BFilterFrom
	case DirTo:
		return m.BFilterTo
	default:
		return m.BFilterAny
	}
}
