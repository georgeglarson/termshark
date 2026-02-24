package psmlmodel

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Helper: a simple styler that satisfies gowid.ICellStyler
//======================================================================

type testStyler struct{}

func (ts testStyler) GetStyle(ctx gowid.IRenderContext) (gowid.IColor, gowid.IColor, gowid.StyleAttrs) {
	return nil, nil, gowid.StyleNone
}

var _ gowid.ICellStyler = testStyler{}

//======================================================================
// New constructor tests
//======================================================================

func TestNew_ReturnsNonNil(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Col1", "Col2"},
		[][]string{{"a", "b"}, {"c", "d"}},
	)
	m := New(sm, testStyler{})
	assert.NotNil(t, m)
}

func TestNew_PreservesSimpleModel(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B", "C"},
		[][]string{{"1", "2", "3"}},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, sm, m.SimpleModel)
}

func TestNew_PreservesStyler(t *testing.T) {
	sm := table.NewSimpleModel([]string{"X"}, [][]string{{"v"}})
	st := testStyler{}
	m := New(sm, st)
	assert.Equal(t, st, m.styler)
}

//======================================================================
// Rows and Columns delegation
//======================================================================

func TestModel_Rows(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H1"},
		[][]string{{"r1"}, {"r2"}, {"r3"}},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, 3, m.Rows())
}

func TestModel_Rows_Empty(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H1"},
		[][]string{},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, 0, m.Rows())
}

func TestModel_Columns(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B", "C", "D"},
		[][]string{{"1", "2", "3", "4"}},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, 4, m.Columns())
}

func TestModel_Columns_SingleColumn(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Only"},
		[][]string{{"val"}},
	)
	m := New(sm, testStyler{})
	assert.Equal(t, 1, m.Columns())
}

//======================================================================
// GetData delegation
//======================================================================

func TestModel_GetData(t *testing.T) {
	data := [][]string{{"x", "y"}, {"a", "b"}}
	sm := table.NewSimpleModel([]string{"C1", "C2"}, data)
	m := New(sm, testStyler{})
	got := m.GetData()
	assert.Equal(t, data, got)
}

func TestModel_GetData_Empty(t *testing.T) {
	sm := table.NewSimpleModel([]string{"C1"}, [][]string{})
	m := New(sm, testStyler{})
	got := m.GetData()
	assert.Empty(t, got)
}

//======================================================================
// RowIdentifier and IdentifierToRow delegation
//======================================================================

func TestModel_RowIdentifier(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}, {"c"}},
	)
	m := New(sm, testStyler{})

	rid, ok := m.RowIdentifier(0)
	assert.True(t, ok)
	assert.Equal(t, table.RowId(0), rid)

	rid, ok = m.RowIdentifier(2)
	assert.True(t, ok)
	assert.Equal(t, table.RowId(2), rid)
}

func TestModel_RowIdentifier_OutOfRange(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}},
	)
	m := New(sm, testStyler{})

	_, ok := m.RowIdentifier(5)
	assert.False(t, ok)
}

func TestModel_IdentifierToRow(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}, {"b"}},
	)
	m := New(sm, testStyler{})

	row, ok := m.IdentifierToRow(table.RowId(1))
	assert.True(t, ok)
	assert.Equal(t, 1, row)
}

func TestModel_IdentifierToRow_Invalid(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"H"},
		[][]string{{"a"}},
	)
	m := New(sm, testStyler{})

	_, ok := m.IdentifierToRow(table.RowId(99))
	assert.False(t, ok)
}

//======================================================================
// CellWidget tests
//======================================================================

func TestModel_CellWidget_ValidCell(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Name", "Value"},
		[][]string{{"foo", "bar"}, {"baz", "qux"}},
	)
	m := New(sm, testStyler{})

	// CellWidget wraps with expander if non-nil
	w := m.CellWidget(0, "hello")
	assert.NotNil(t, w)
}

func TestModel_CellWidget_EmptyString(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A"},
		[][]string{{""}},
	)
	m := New(sm, testStyler{})

	// Even an empty string should produce a non-nil widget from SimpleCellWidget
	w := m.CellWidget(0, "")
	assert.NotNil(t, w)
}

//======================================================================
// CellWidgets tests
//======================================================================

func TestModel_CellWidgets_ValidRow(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B"},
		[][]string{{"1", "2"}, {"3", "4"}},
	)
	m := New(sm, testStyler{})

	widgets := m.CellWidgets(table.RowId(0))
	assert.Equal(t, 2, len(widgets))
}

func TestModel_CellWidgets_SecondRow(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"A", "B", "C"},
		[][]string{{"1", "2", "3"}, {"4", "5", "6"}},
	)
	m := New(sm, testStyler{})

	widgets := m.CellWidgets(table.RowId(1))
	assert.Equal(t, 3, len(widgets))
}

//======================================================================
// HeaderWidgets tests
//======================================================================

func TestModel_HeaderWidgets_WithHeaders(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"No.", "Time", "Source"},
		[][]string{{"1", "0.000", "10.0.0.1"}},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Equal(t, 3, len(hws))
}

func TestModel_HeaderWidgets_SingleHeader(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Only"},
		[][]string{{"val"}},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Equal(t, 1, len(hws))
}

func TestModel_HeaderWidgets_NilHeaders(t *testing.T) {
	sm := table.NewSimpleModel(
		nil,
		[][]string{},
	)
	m := New(sm, testStyler{})

	hws := m.HeaderWidgets()
	assert.Nil(t, hws)
}

//======================================================================
// Model with comparators (sorting support)
//======================================================================

func TestModel_WithComparators(t *testing.T) {
	sm := table.NewSimpleModel(
		[]string{"Num", "Text"},
		[][]string{{"2", "b"}, {"1", "a"}, {"3", "c"}},
		table.SimpleOptions{
			Comparators: []table.ICompare{table.IntCompare{}, nil},
		},
	)
	m := New(sm, testStyler{})

	// Should still produce header widgets with sort buttons for the first column
	hws := m.HeaderWidgets()
	assert.Equal(t, 2, len(hws))
}

//======================================================================
// Headers property
//======================================================================

func TestModel_Headers_AccessViaSimpleModel(t *testing.T) {
	headers := []string{"A", "B", "C"}
	sm := table.NewSimpleModel(headers, [][]string{{"1", "2", "3"}})
	m := New(sm, testStyler{})

	assert.Equal(t, headers, m.Headers)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
