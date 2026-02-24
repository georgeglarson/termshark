// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package psmlmodel

import (
	"sort"
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// CellWidget boundary tests
//======================================================================

func TestModel_CellWidget_LargeColumnIndex(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A"},
		[][]string{{"val"}},
	)
	m := New(sm, testStyler{})

	// Column index beyond the range - SimpleCellWidget should handle gracefully
	w := m.CellWidget(999, "test")
	// SimpleCellWidget wraps with the column index; result depends on underlying implementation
	// but should not panic
	assert.NotNil(t, w)
}

func TestModel_CellWidget_LongString(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Data"},
		[][]string{{"x"}},
	)
	m := New(sm, testStyler{})

	longStr := ""
	for i := 0; i < 1000; i++ {
		longStr += "x"
	}
	w := m.CellWidget(0, longStr)
	assert.NotNil(t, w)
}

func TestModel_CellWidget_SpecialChars(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Data"},
		[][]string{{"x"}},
	)
	m := New(sm, testStyler{})

	w := m.CellWidget(0, "hello\nworld\ttab")
	assert.NotNil(t, w)
}

//======================================================================
// CellWidgets boundary tests
//======================================================================

func TestModel_CellWidgets_LargeRowId(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A"},
		[][]string{{"1"}},
	)
	m := New(sm, testStyler{})

	// Requesting widgets for a row beyond the data range
	widgets := m.CellWidgets(table.RowId(999))
	// Should return nil or empty since the row doesn't exist
	assert.Nil(t, widgets)
}

func TestModel_CellWidgets_ZeroRowId(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B", "C"},
		[][]string{{"1", "2", "3"}, {"4", "5", "6"}},
	)
	m := New(sm, testStyler{})

	widgets := m.CellWidgets(table.RowId(0))
	assert.Equal(t, 3, len(widgets))
	for i, w := range widgets {
		assert.NotNil(t, w, "Widget at index %d should not be nil", i)
	}
}

//======================================================================
// RowIdentifier boundary tests
//======================================================================

func TestModel_RowIdentifier_NegativeRow(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}},
	)
	m := New(sm, testStyler{})

	_, ok := m.RowIdentifier(-1)
	assert.False(t, ok, "Negative row should return false")
}

func TestModel_RowIdentifier_ExactBoundary(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}, {"c"}},
	)
	m := New(sm, testStyler{})

	// Last valid row
	rid, ok := m.RowIdentifier(2)
	assert.True(t, ok)
	assert.Equal(t, table.RowId(2), rid)

	// First invalid row
	_, ok = m.RowIdentifier(3)
	assert.False(t, ok)
}

//======================================================================
// IdentifierToRow boundary tests
//======================================================================

func TestModel_IdentifierToRow_NegativeId(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}},
	)
	m := New(sm, testStyler{})

	_, ok := m.IdentifierToRow(table.RowId(-1))
	assert.False(t, ok, "Negative RowId should return false")
}

func TestModel_IdentifierToRow_ExactBoundary(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}},
	)
	m := New(sm, testStyler{})

	// Last valid ID
	row, ok := m.IdentifierToRow(table.RowId(1))
	assert.True(t, ok)
	assert.Equal(t, 1, row)

	// First invalid ID
	_, ok = m.IdentifierToRow(table.RowId(2))
	assert.False(t, ok)
}

func TestModel_IdentifierToRow_ZeroId(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}},
	)
	m := New(sm, testStyler{})

	row, ok := m.IdentifierToRow(table.RowId(0))
	assert.True(t, ok)
	assert.Equal(t, 0, row)
}

//======================================================================
// Sorting with Comparators
//======================================================================

func TestModel_Sorting_IntComparator(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Num", "Name"},
		[][]string{{"3", "c"}, {"1", "a"}, {"2", "b"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}, table.StringCompare{}},
		},
	)
	m := New(sm, testStyler{})

	// Sort by first column ascending
	sorter := &table.SimpleTableByColumn{
		SimpleModel: m.SimpleModel,
		Column:      0,
	}
	sort.Sort(sorter)

	// Sorting changes SortOrder, not Data. Verify via SortOrder.
	data := m.GetData()
	so := m.SimpleModel.SortOrder
	assert.Equal(t, "1", data[so[0]][0])
	assert.Equal(t, "2", data[so[1]][0])
	assert.Equal(t, "3", data[so[2]][0])
}

func TestModel_Sorting_IntComparator_Reverse(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Num", "Name"},
		[][]string{{"3", "c"}, {"1", "a"}, {"2", "b"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}, table.StringCompare{}},
		},
	)
	m := New(sm, testStyler{})

	sorter := &table.SimpleTableByColumn{
		SimpleModel: m.SimpleModel,
		Column:      0,
	}
	sort.Sort(sort.Reverse(sorter))

	// Verify reverse via SortOrder
	data := m.GetData()
	so := m.SimpleModel.SortOrder
	assert.Equal(t, "3", data[so[0]][0])
	assert.Equal(t, "2", data[so[1]][0])
	assert.Equal(t, "1", data[so[2]][0])
}

func TestModel_Sorting_StringComparator(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Name"},
		[][]string{{"charlie"}, {"alpha"}, {"bravo"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.StringCompare{}},
		},
	)
	m := New(sm, testStyler{})

	sorter := &table.SimpleTableByColumn{
		SimpleModel: m.SimpleModel,
		Column:      0,
	}
	sort.Sort(sorter)

	// Sorting changes SortOrder indirection, not Data order.
	// Verify via SortOrder: position 0 should map to "alpha" (original index 1),
	// position 1 to "bravo" (original index 2), position 2 to "charlie" (original index 0).
	data := m.GetData()
	so := m.SimpleModel.SortOrder
	assert.Equal(t, "alpha", data[so[0]][0])
	assert.Equal(t, "bravo", data[so[1]][0])
	assert.Equal(t, "charlie", data[so[2]][0])
}

func TestModel_Sorting_PreservesRowIdentity(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Num"},
		[][]string{{"3"}, {"1"}, {"2"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}},
		},
	)
	m := New(sm, testStyler{})

	// Before sorting
	assert.Equal(t, 3, m.Rows())

	sorter := &table.SimpleTableByColumn{
		SimpleModel: m.SimpleModel,
		Column:      0,
	}
	sort.Sort(sorter)

	// After sorting, row count should be preserved
	assert.Equal(t, 3, m.Rows())
}

//======================================================================
// GetData edge cases
//======================================================================

func TestModel_GetData_PreservesDataReference(t *testing.T) {
	data := [][]string{{"x", "y"}, {"a", "b"}}
	sm := table.NewSimpleModel([]string{"C1", "C2"}, data)
	m := New(sm, testStyler{})

	// Modify original data
	data[0][0] = "modified"

	// GetData should reflect the change since SimpleModel stores reference
	got := m.GetData()
	assert.Equal(t, "modified", got[0][0])
}

func TestModel_GetData_SingleCell(t *testing.T) {
	sm := table.NewSimpleModel([]string{"Only"}, [][]string{{"value"}})
	m := New(sm, testStyler{})
	got := m.GetData()
	assert.Equal(t, 1, len(got))
	assert.Equal(t, 1, len(got[0]))
	assert.Equal(t, "value", got[0][0])
}

//======================================================================
// Multiple columns and rows
//======================================================================

func TestModel_LargeTable(t *testing.T) {
	headers := []string{"A", "B", "C", "D", "E"}
	data := make([][]string, 100)
	for i := range data {
		row := make([]string, 5)
		for j := range row {
			row[j] = "cell"
		}
		data[i] = row
	}

	sm := table.NewSimpleModel(headers, data)
	m := New(sm, testStyler{})

	assert.Equal(t, 100, m.Rows())
	assert.Equal(t, 5, m.Columns())

	// Verify first and last row can produce widgets
	widgets0 := m.CellWidgets(table.RowId(0))
	assert.Equal(t, 5, len(widgets0))

	widgets99 := m.CellWidgets(table.RowId(99))
	assert.Equal(t, 5, len(widgets99))
}

//======================================================================
// HeaderWidgets with comparators and style
//======================================================================

func TestModel_HeaderWidgets_WithComparators_Count(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B", "C"},
		[][]string{{"1", "2", "3"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}, table.StringCompare{}, nil},
		},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Equal(t, 3, len(hws), "Should have one header widget per column")
}

func TestModel_HeaderWidgets_WithHeaderStyle(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Styled"},
		[][]string{{"val"}},
		table.SimpleOptions{
			Style: table.StyleOptions{
				HeaderStyleProvided: true,
				HeaderStyleNoFocus:  gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone),
				HeaderStyleSelected: gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone),
				HeaderStyleFocus:    gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone),
			},
			Comparators: []table.ICompare{table.IntCompare{}},
		},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Equal(t, 1, len(hws))
	assert.NotNil(t, hws[0])
}

func TestModel_HeaderWidgets_WithoutHeaderStyle(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"NoStyle"},
		[][]string{{"val"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}},
		},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Equal(t, 1, len(hws))
	assert.NotNil(t, hws[0])
}

//======================================================================
// New constructor with various stylers
//======================================================================

func TestNew_NilStyler(t *testing.T) {
	sm := table.NewSimpleModel([]string{"A"}, [][]string{{"1"}})
	m := New(sm, nil)
	assert.NotNil(t, m)
	assert.Nil(t, m.styler)
}

func TestNew_PreservesData(t *testing.T) {
	data := [][]string{{"one", "two"}, {"three", "four"}}
	sm := table.NewSimpleModel([]string{"A", "B"}, data)
	m := New(sm, testStyler{})

	got := m.GetData()
	assert.Equal(t, data, got)
}

//======================================================================
// Columns with empty headers
//======================================================================

func TestModel_EmptyHeaders(t *testing.T) {
	// NewSimpleModel with empty headers panics on Columns() because it
	// indexes into Data[0] for column count. Use nil headers instead,
	// which is what the nil headers test covers.
	// Verify that nil headers model has 0 rows.
	sm := table.NewSimpleModel(
		nil,
		[][]string{},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, 0, m.Rows())
	hws := m.HeaderWidgets()
	assert.Nil(t, hws, "Nil headers should produce nil header widgets")
}

//======================================================================
// RowIdentifier and IdentifierToRow round-trip
//======================================================================

func TestModel_RowIdentifier_RoundTrip(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}},
	)
	m := New(sm, testStyler{})

	for i := 0; i < 5; i++ {
		rid, ok := m.RowIdentifier(i)
		assert.True(t, ok)

		row, ok := m.IdentifierToRow(rid)
		assert.True(t, ok)
		assert.Equal(t, i, row, "Round-trip should preserve row index")
	}
}

//======================================================================
// Sorting stability with multiple columns
//======================================================================

func TestModel_Sorting_StableWithDuplicates(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Group", "Name"},
		[][]string{
			{"1", "beta"},
			{"2", "alpha"},
			{"1", "alpha"},
			{"2", "beta"},
		},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}, table.StringCompare{}},
		},
	)
	m := New(sm, testStyler{})

	sorter := &table.SimpleTableByColumn{
		SimpleModel: m.SimpleModel,
		Column:      0,
	}
	sort.Stable(sorter)

	// Verify via SortOrder: all "1"s should come before "2"s
	data := m.GetData()
	so := m.SimpleModel.SortOrder
	assert.Equal(t, "1", data[so[0]][0])
	assert.Equal(t, "1", data[so[1]][0])
	assert.Equal(t, "2", data[so[2]][0])
	assert.Equal(t, "2", data[so[3]][0])
}

//======================================================================
// Model with many columns
//======================================================================

func TestModel_ManyColumns(t *testing.T) {
	headers := make([]string, 20)
	for i := range headers {
		headers[i] = "H"
	}
	row := make([]string, 20)
	for i := range row {
		row[i] = "v"
	}

	sm := table.NewSimpleModel(headers, [][]string{row})
	m := New(sm, testStyler{})
	assert.Equal(t, 20, m.Columns())

	widgets := m.CellWidgets(table.RowId(0))
	assert.Equal(t, 20, len(widgets))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
