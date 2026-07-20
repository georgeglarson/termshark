// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// psmlSummary tests
//======================================================================

func TestPsmlSummary_String_Empty(t *testing.T) {
	p := psmlSummary([]string{})
	assert.Equal(t, "", p.String())
}

func TestPsmlSummary_String_SingleElement(t *testing.T) {
	p := psmlSummary([]string{"42"})
	assert.Equal(t, "", p.String(), "Single element (packet number only) should return empty")
}

func TestPsmlSummary_String_TwoElements(t *testing.T) {
	p := psmlSummary([]string{"1", "0.000000"})
	assert.Equal(t, "0.000000", p.String())
}

func TestPsmlSummary_String_MultipleElements(t *testing.T) {
	p := psmlSummary([]string{"1", "0.000", "10.0.0.1", "10.0.0.2", "TCP", "SYN"})
	assert.Equal(t, "0.000 : 10.0.0.1 : 10.0.0.2 : TCP : SYN", p.String())
}

func TestPsmlSummary_String_Nil(t *testing.T) {
	p := psmlSummary(nil)
	assert.Equal(t, "", p.String())
}

//======================================================================
// Prog type tests
//======================================================================

func TestProg_Complete_True(t *testing.T) {
	p := Prog{cur: 100, max: 100}
	assert.True(t, p.Complete())
}

func TestProg_Complete_False(t *testing.T) {
	p := Prog{cur: 50, max: 100}
	assert.False(t, p.Complete())
}

func TestProg_Complete_Exceeded(t *testing.T) {
	p := Prog{cur: 150, max: 100}
	assert.True(t, p.Complete(), "cur > max should be considered complete")
}

func TestProg_Complete_ZeroMax(t *testing.T) {
	p := Prog{cur: 0, max: 0}
	assert.True(t, p.Complete())
}

func TestProg_String(t *testing.T) {
	p := Prog{cur: 42, max: 100}
	assert.Equal(t, "cur=42 max=100", p.String())
}

func TestProg_String_Zero(t *testing.T) {
	p := Prog{cur: 0, max: 0}
	assert.Equal(t, "cur=0 max=0", p.String())
}

func TestProg_Div(t *testing.T) {
	p := Prog{cur: 100, max: 200}
	result := p.Div(2)
	assert.Equal(t, int64(50), result.cur)
	assert.Equal(t, int64(200), result.max, "Div should only divide cur, not max")
}

func TestProg_Div_DoesNotMutate(t *testing.T) {
	p := Prog{cur: 100, max: 200}
	_ = p.Div(2)
	assert.Equal(t, int64(100), p.cur, "Div should not mutate the receiver")
}

func TestProg_Add(t *testing.T) {
	p1 := Prog{cur: 10, max: 50}
	p2 := Prog{cur: 20, max: 30}
	result := p1.Add(p2)
	assert.Equal(t, int64(30), result.cur)
	assert.Equal(t, int64(80), result.max)
}

func TestProg_Add_DoesNotMutate(t *testing.T) {
	p1 := Prog{cur: 10, max: 50}
	p2 := Prog{cur: 20, max: 30}
	_ = p1.Add(p2)
	assert.Equal(t, int64(10), p1.cur)
	assert.Equal(t, int64(50), p1.max)
}

func TestProg_Add_WithZero(t *testing.T) {
	p1 := Prog{cur: 10, max: 50}
	p2 := Prog{cur: 0, max: 0}
	result := p1.Add(p2)
	assert.Equal(t, int64(10), result.cur)
	assert.Equal(t, int64(50), result.max)
}

func TestProgRatio(t *testing.T) {
	p := Prog{cur: 50, max: 100}
	assert.InDelta(t, 0.5, progRatio(p), 0.001)
}

func TestProgRatio_ZeroMax(t *testing.T) {
	p := Prog{cur: 50, max: 0}
	assert.Equal(t, float64(0), progRatio(p))
}

func TestProgRatio_FullComplete(t *testing.T) {
	p := Prog{cur: 100, max: 100}
	assert.InDelta(t, 1.0, progRatio(p), 0.001)
}

func TestProgRatio_Zero(t *testing.T) {
	p := Prog{cur: 0, max: 100}
	assert.InDelta(t, 0.0, progRatio(p), 0.001)
}

func TestProgMin(t *testing.T) {
	small := Prog{cur: 10, max: 100} // 0.1
	big := Prog{cur: 90, max: 100}   // 0.9
	result := progMin(small, big)
	assert.Equal(t, small, result)
}

func TestProgMin_Equal(t *testing.T) {
	p1 := Prog{cur: 50, max: 100}
	p2 := Prog{cur: 25, max: 50} // same ratio
	// When equal, returns y
	result := progMin(p1, p2)
	assert.Equal(t, p2, result)
}

func TestProgMin_Reversed(t *testing.T) {
	small := Prog{cur: 10, max: 100}
	big := Prog{cur: 90, max: 100}
	result := progMin(big, small)
	assert.Equal(t, small, result)
}

func TestProgMax(t *testing.T) {
	small := Prog{cur: 10, max: 100}
	big := Prog{cur: 90, max: 100}
	result := progMax(small, big)
	assert.Equal(t, big, result)
}

func TestProgMax_Equal(t *testing.T) {
	p1 := Prog{cur: 50, max: 100}
	p2 := Prog{cur: 25, max: 50}
	// When equal, returns y
	result := progMax(p1, p2)
	assert.Equal(t, p2, result)
}

func TestProgMax_Reversed(t *testing.T) {
	small := Prog{cur: 10, max: 100}
	big := Prog{cur: 90, max: 100}
	result := progMax(big, small)
	assert.Equal(t, big, result)
}

//======================================================================
// CsvTableCopier tests
//======================================================================

func TestCsvTableCopier_CopyRow(t *testing.T) {
	c := CsvTableCopier{
		hdrs: []string{"Addr A", "Port A", "Addr B"},
		data: [][]string{
			{"10.0.0.1", "80", "10.0.0.2"},
			{"192.168.1.1", "443", "192.168.1.2"},
		},
	}

	results := c.CopyRow(0)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, "Copy conversation", results[0].ClipName())
	assert.Equal(t, "10.0.0.1,80,10.0.0.2", results[0].ClipValue())
}

func TestCsvTableCopier_CopyRow_SecondRow(t *testing.T) {
	c := CsvTableCopier{
		hdrs: []string{"A", "B"},
		data: [][]string{{"x", "y"}, {"a", "b"}},
	}

	results := c.CopyRow(1)
	assert.Equal(t, "a,b", results[0].ClipValue())
}

func TestCsvTableCopier_CopyTable(t *testing.T) {
	c := CsvTableCopier{
		hdrs: []string{"Name", "Value"},
		data: [][]string{{"foo", "1"}, {"bar", "2"}},
	}

	results := c.CopyTable()
	assert.Equal(t, 1, len(results))
	assert.Equal(t, "Copy all", results[0].ClipName())
	expected := "Name,Value\nfoo,1\nbar,2"
	assert.Equal(t, expected, results[0].ClipValue())
}

func TestCsvTableCopier_CopyTable_EmptyData(t *testing.T) {
	c := CsvTableCopier{
		hdrs: []string{"Name"},
		data: [][]string{},
	}

	results := c.CopyTable()
	assert.Equal(t, "Name", results[0].ClipValue())
}

func TestCsvTableCopier_CopyTable_SingleRow(t *testing.T) {
	c := CsvTableCopier{
		hdrs: []string{"X", "Y", "Z"},
		data: [][]string{{"1", "2", "3"}},
	}

	results := c.CopyTable()
	assert.Equal(t, "X,Y,Z\n1,2,3", results[0].ClipValue())
}

//======================================================================
// stripQuotes tests
//======================================================================

func TestStripQuotes_DoubleQuoted(t *testing.T) {
	assert.Equal(t, "hello", stripQuotes(`"hello"`))
}

func TestStripQuotes_NoQuotes(t *testing.T) {
	assert.Equal(t, "hello", stripQuotes("hello"))
}

func TestStripQuotes_EmptyString(t *testing.T) {
	assert.Equal(t, "", stripQuotes(""))
}

func TestStripQuotes_OnlyQuotes(t *testing.T) {
	assert.Equal(t, "", stripQuotes(`""`))
}

func TestStripQuotes_LeadingQuoteOnly(t *testing.T) {
	assert.Equal(t, "hello", stripQuotes(`"hello`))
}

func TestStripQuotes_TrailingQuoteOnly(t *testing.T) {
	assert.Equal(t, "hello", stripQuotes(`hello"`))
}

func TestStripQuotes_SingleQuote(t *testing.T) {
	assert.Equal(t, "", stripQuotes(`"`))
}

func TestStripQuotes_InternalQuotes(t *testing.T) {
	assert.Equal(t, `he"llo`, stripQuotes(`"he"llo"`))
}

//======================================================================
// RenderWeightUpTo tests
//======================================================================

func TestWeightupto(t *testing.T) {
	r := weightupto(5, 20)
	assert.Equal(t, 20, r.MaxUnits())
	assert.Equal(t, 5, r.W)
}

func TestWeightupto_ZeroMax(t *testing.T) {
	r := weightupto(1, 0)
	assert.Equal(t, 0, r.MaxUnits())
}

func TestUnits(t *testing.T) {
	u := units(42)
	assert.Equal(t, 42, u.U)
}

func TestWeight(t *testing.T) {
	w := weight(3)
	assert.Equal(t, 3, w.W)
}

func TestRatio(t *testing.T) {
	r := ratio(0.75)
	assert.InDelta(t, 0.75, r.R, 0.001)
}

func TestRatioupto(t *testing.T) {
	r := ratioupto(0.5, 100)
	assert.InDelta(t, 0.5, r.R, 0.001)
	assert.Equal(t, 100, r.MaxUnits())
}

func TestRatioUpTo_String(t *testing.T) {
	r := ratioupto(0.5, 100)
	s := r.String()
	assert.Contains(t, s, "upto")
	assert.Contains(t, s, "100")
}

//======================================================================
// WidgetOwner constants tests
//======================================================================

func TestWidgetOwner_Constants(t *testing.T) {
	assert.Equal(t, WidgetOwner(0), NoOwner)
	assert.Equal(t, WidgetOwner(1), LoaderOwns)
	assert.Equal(t, WidgetOwner(2), SearchOwns)
	assert.NotEqual(t, NoOwner, LoaderOwns)
	assert.NotEqual(t, LoaderOwns, SearchOwns)
}

//======================================================================
// textID tests
//======================================================================

func TestTextID_ID(t *testing.T) {
	tid := textID("test-id")
	assert.Equal(t, "test-id", tid.ID())
}

func TestTextID_ID_Empty(t *testing.T) {
	tid := textID("")
	assert.Equal(t, "", tid.ID())
}

//======================================================================
// ConvsModel.GetAFilter and GetBFilter tests
//======================================================================

// mockFilterBuilder is a test helper for ConvsModel tests
type mockFilterBuilder struct {
	name    string
	aIndex  []int
	bIndex  []int
	filters map[Direction]string
}

func (m mockFilterBuilder) String() string {
	return m.name
}

func (m mockFilterBuilder) FilterFrom(vals ...string) string {
	return "from:" + vals[0]
}

func (m mockFilterBuilder) FilterTo(vals ...string) string {
	return "to:" + vals[0]
}

func (m mockFilterBuilder) FilterAny(vals ...string) string {
	return "any:" + vals[0]
}

func (m mockFilterBuilder) AIndex() []int {
	return m.aIndex
}

func (m mockFilterBuilder) BIndex() []int {
	return m.bIndex
}

func makeTestConvsModel(data [][]string, proto IFilterBuilder) ConvsModel {
	// Use a simple psmlmodel.Model wrapper
	sm := table.NewSimpleModel(
		[]string{"Col1", "Col2"},
		data,
	)
	pm := psmlmodel.New(sm, gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone))
	return ConvsModel{
		Model: pm,
		proto: proto,
	}
}

func TestConvsModel_GetAFilter_Any(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetAFilter(0, Any)
	assert.Equal(t, "any:10.0.0.1", result)
}

func TestConvsModel_GetAFilter_To(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetAFilter(0, To)
	assert.Equal(t, "to:10.0.0.1", result)
}

func TestConvsModel_GetAFilter_From(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetAFilter(0, From)
	assert.Equal(t, "from:10.0.0.1", result)
}

func TestConvsModel_GetBFilter_Any(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetBFilter(0, Any)
	assert.Equal(t, "any:10.0.0.2", result)
}

func TestConvsModel_GetBFilter_To(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetBFilter(0, To)
	assert.Equal(t, "to:10.0.0.2", result)
}

func TestConvsModel_GetBFilter_From(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	result := m.GetBFilter(0, From)
	assert.Equal(t, "from:10.0.0.2", result)
}

func TestConvsModel_GetAFilter_MultipleRows(t *testing.T) {
	data := [][]string{
		{"10.0.0.1", "10.0.0.2"},
		{"192.168.1.1", "192.168.1.2"},
	}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	m := makeTestConvsModel(data, proto)
	assert.Equal(t, "any:10.0.0.1", m.GetAFilter(0, Any))
	assert.Equal(t, "any:192.168.1.1", m.GetAFilter(1, Any))
}

//======================================================================
// convsModelWithRow tests
//======================================================================

func TestConvsModelWithRow_GetAFilter(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}, {"1.2.3.4", "5.6.7.8"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	cm := makeTestConvsModel(data, proto)
	mr := &convsModelWithRow{model: &cm, row: 1}
	assert.Equal(t, "any:1.2.3.4", mr.GetAFilter(Any))
	assert.Equal(t, "to:1.2.3.4", mr.GetAFilter(To))
	assert.Equal(t, "from:1.2.3.4", mr.GetAFilter(From))
}

func TestConvsModelWithRow_GetBFilter(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}, {"1.2.3.4", "5.6.7.8"}}
	proto := mockFilterBuilder{
		name:   "test",
		aIndex: []int{0},
		bIndex: []int{1},
	}
	cm := makeTestConvsModel(data, proto)
	mr := &convsModelWithRow{model: &cm, row: 0}
	assert.Equal(t, "any:10.0.0.2", mr.GetBFilter(Any))
}

//======================================================================
// ConvsModel with real convs types
//======================================================================

func TestConvsModel_WithRealIPv4(t *testing.T) {
	data := [][]string{{"10.0.0.1", "10.0.0.2"}}
	sm := table.NewSimpleModel(
		[]string{"Addr A", "Addr B"},
		data,
	)
	pm := psmlmodel.New(sm, gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone))
	cm := ConvsModel{Model: pm, proto: convs.IPv4{}}

	assert.Equal(t, "ip.addr == 10.0.0.1", cm.GetAFilter(0, Any))
	assert.Equal(t, "ip.src == 10.0.0.1", cm.GetAFilter(0, From))
	assert.Equal(t, "ip.dst == 10.0.0.1", cm.GetAFilter(0, To))
	assert.Equal(t, "ip.addr == 10.0.0.2", cm.GetBFilter(0, Any))
}

func TestConvsModel_WithRealTCP(t *testing.T) {
	// TCP has 4 columns: addr_a, port_a, addr_b, port_b
	data := [][]string{{"192.168.1.1", "80", "192.168.1.2", "12345"}}
	sm := table.NewSimpleModel(
		[]string{"Addr A", "Port A", "Addr B", "Port B"},
		data,
	)
	pm := psmlmodel.New(sm, gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone))
	cm := ConvsModel{Model: pm, proto: convs.TCP{}}

	aFilter := cm.GetAFilter(0, From)
	assert.Contains(t, aFilter, "tcp.srcport == 80")
	assert.Contains(t, aFilter, "ip.src == 192.168.1.1")

	bFilter := cm.GetBFilter(0, Any)
	assert.Contains(t, bFilter, "tcp.port == 12345")
	assert.Contains(t, bFilter, "ip.addr == 192.168.1.2")
}

func TestConvsModel_WithRealEthernet(t *testing.T) {
	data := [][]string{{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}}
	sm := table.NewSimpleModel(
		[]string{"Addr A", "Addr B"},
		data,
	)
	pm := psmlmodel.New(sm, gowid.MakePaletteEntry(gowid.ColorNone, gowid.ColorNone))
	cm := ConvsModel{Model: pm, proto: convs.Ethernet{}}

	assert.Equal(t, "eth.addr == aa:bb:cc:dd:ee:ff", cm.GetAFilter(0, Any))
	assert.Equal(t, "eth.dst == 11:22:33:44:55:66", cm.GetBFilter(0, To))
}

//======================================================================
// ComputeConvFilterOp tests
//======================================================================

type simpleFilterModel struct {
	aFilters map[Direction]string
	bFilters map[Direction]string
}

func (m simpleFilterModel) GetAFilter(dir Direction) string {
	return m.aFilters[dir]
}

func (m simpleFilterModel) GetBFilter(dir Direction) string {
	return m.bFilters[dir]
}

func TestComputeConvFilterOp_Selected_AtfB(t *testing.T) {
	model := simpleFilterModel{
		aFilters: map[Direction]string{
			Any:  "ip.addr == 10.0.0.1",
			To:   "ip.dst == 10.0.0.1",
			From: "ip.src == 10.0.0.1",
		},
		bFilters: map[Direction]string{
			Any:  "ip.addr == 10.0.0.2",
			To:   "ip.dst == 10.0.0.2",
			From: "ip.src == 10.0.0.2",
		},
	}

	// AtfB means "A <-> B" => A any && B any
	result := ComputeConvFilterOp(AtfB, Selected, model, "")
	assert.Contains(t, result, "ip.addr == 10.0.0.1")
	assert.Contains(t, result, "ip.addr == 10.0.0.2")
}

func TestComputeConvFilterOp_AtB(t *testing.T) {
	model := simpleFilterModel{
		aFilters: map[Direction]string{
			Any:  "ip.addr == 10.0.0.1",
			To:   "ip.dst == 10.0.0.1",
			From: "ip.src == 10.0.0.1",
		},
		bFilters: map[Direction]string{
			Any:  "ip.addr == 10.0.0.2",
			To:   "ip.dst == 10.0.0.2",
			From: "ip.src == 10.0.0.2",
		},
	}

	// AtB means "A -> B" => A from && B to
	result := ComputeConvFilterOp(AtB, Selected, model, "")
	assert.Contains(t, result, "ip.src == 10.0.0.1")
	assert.Contains(t, result, "ip.dst == 10.0.0.2")
}

func TestComputeFilterCombOp_Selected(t *testing.T) {
	result := ComputeFilterCombOp(Selected, "tcp.port == 80", "")
	assert.Equal(t, "tcp.port == 80", result)
}

func TestComputeFilterCombOp_AndSelected(t *testing.T) {
	result := ComputeFilterCombOp(AndSelected, "tcp.port == 80", "ip.addr == 10.0.0.1")
	assert.Contains(t, result, "ip.addr == 10.0.0.1")
	assert.Contains(t, result, "tcp.port == 80")
	assert.Contains(t, result, "&&")
}

func TestComputeFilterCombOp_OrSelected(t *testing.T) {
	result := ComputeFilterCombOp(OrSelected, "tcp.port == 80", "ip.addr == 10.0.0.1")
	assert.Contains(t, result, "ip.addr == 10.0.0.1")
	assert.Contains(t, result, "tcp.port == 80")
	assert.Contains(t, result, "||")
}

func TestComputeFilterCombOp_NotSelected(t *testing.T) {
	result := ComputeFilterCombOp(NotSelected, "tcp.port == 80", "")
	assert.Contains(t, result, "!")
	assert.Contains(t, result, "tcp.port == 80")
}

//======================================================================
// filterModelAdapter tests
//======================================================================

func TestFilterModelAdapter_GetAFilter(t *testing.T) {
	model := simpleFilterModel{
		aFilters: map[Direction]string{
			Any:  "any-a",
			To:   "to-a",
			From: "from-a",
		},
		bFilters: map[Direction]string{
			Any:  "any-b",
			To:   "to-b",
			From: "from-b",
		},
	}

	adapter := filterModelAdapter{model: model}
	// app.Direction values mirror ui.Direction values
	assert.Equal(t, "any-a", adapter.GetAFilter(0))  // Any
	assert.Equal(t, "to-a", adapter.GetAFilter(1))   // To
	assert.Equal(t, "from-a", adapter.GetAFilter(2)) // From
}

func TestFilterModelAdapter_GetBFilter(t *testing.T) {
	model := simpleFilterModel{
		aFilters: map[Direction]string{
			Any: "any-a",
		},
		bFilters: map[Direction]string{
			Any:  "any-b",
			To:   "to-b",
			From: "from-b",
		},
	}

	adapter := filterModelAdapter{model: model}
	assert.Equal(t, "any-b", adapter.GetBFilter(0))
	assert.Equal(t, "to-b", adapter.GetBFilter(1))
	assert.Equal(t, "from-b", adapter.GetBFilter(2))
}

//======================================================================
// minibufferFn and quietMinibufferFn tests
//======================================================================

func TestMinibufferFn_OfferCompletion(t *testing.T) {
	fn := minibufferFn(func(app gowid.IApp, args ...string) error {
		return nil
	})
	assert.True(t, fn.OfferCompletion())
}

func TestMinibufferFn_Arguments(t *testing.T) {
	fn := minibufferFn(func(app gowid.IApp, args ...string) error {
		return nil
	})
	assert.Nil(t, fn.Arguments(nil, nil))
}

func TestQuietMinibufferFn_OfferCompletion(t *testing.T) {
	fn := quietMinibufferFn(func(app gowid.IApp, args ...string) error {
		return nil
	})
	assert.False(t, fn.OfferCompletion())
}

func TestQuietMinibufferFn_Arguments(t *testing.T) {
	fn := quietMinibufferFn(func(app gowid.IApp, args ...string) error {
		return nil
	})
	assert.Nil(t, fn.Arguments(nil, nil))
}

func TestMinibufferFn_Run(t *testing.T) {
	called := false
	var gotArgs []string
	fn := minibufferFn(func(app gowid.IApp, args ...string) error {
		called = true
		gotArgs = args
		return nil
	})
	err := fn.Run(nil, "arg1", "arg2")
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, []string{"arg1", "arg2"}, gotArgs)
}

func TestQuietMinibufferFn_Run(t *testing.T) {
	called := false
	fn := quietMinibufferFn(func(app gowid.IApp, args ...string) error {
		called = true
		return nil
	})
	err := fn.Run(nil, "test")
	assert.NoError(t, err)
	assert.True(t, called)
}

//======================================================================
// vdiv and frameRunes init tests
//======================================================================

func TestVdivInitialized(t *testing.T) {
	// vdiv should have been set by init() in convstypes.go
	assert.NotEmpty(t, vdiv, "vdiv should be initialized")
}

func TestFrameRunesInitialized(t *testing.T) {
	// frameRunes should have been set by init()
	assert.NotEqual(t, rune(0), frameRunes.Bl, "frameRunes bottom-left should be initialized")
	assert.NotEqual(t, rune(0), frameRunes.Br, "frameRunes bottom-right should be initialized")
}

//======================================================================
// LoadResult type tests
//======================================================================

func TestLoadResult_ZeroValue(t *testing.T) {
	lr := LoadResult{}
	assert.Nil(t, lr.packetTree)
	assert.Nil(t, lr.headers)
	assert.Nil(t, lr.packetList)
}

//======================================================================
// ManageConvsCache tests
//======================================================================

func TestManageConvsCache_OnNewSource(t *testing.T) {
	savedConvsView := convsView
	savedConvsPcapSize := convsPcapSize
	defer func() {
		convsView = savedConvsView
		convsPcapSize = savedConvsPcapSize
	}()

	convsPcapSize = 12345
	m := ManageConvsCache{}
	m.OnNewSource(0, nil)
	assert.Nil(t, convsView)
	assert.Equal(t, int64(0), convsPcapSize)
}

//======================================================================
// ManageStreamCache tests
//======================================================================

func TestManageStreamCache_OnNewSource(t *testing.T) {
	// Just verify it doesn't panic with nil state
	m := ManageStreamCache{}
	assert.NotPanics(t, func() {
		m.OnNewSource(0, nil)
	})
}

//======================================================================
// Prog edge cases
//======================================================================

func TestProg_Div_ByOne(t *testing.T) {
	p := Prog{cur: 42, max: 100}
	result := p.Div(1)
	assert.Equal(t, int64(42), result.cur)
}

func TestProg_Add_Negative(t *testing.T) {
	p1 := Prog{cur: 10, max: 50}
	p2 := Prog{cur: -5, max: -10}
	result := p1.Add(p2)
	assert.Equal(t, int64(5), result.cur)
	assert.Equal(t, int64(40), result.max)
}

func TestProgRatio_NegativeCur(t *testing.T) {
	p := Prog{cur: -50, max: 100}
	assert.InDelta(t, -0.5, progRatio(p), 0.001)
}

func TestProgMin_BothZeroMax(t *testing.T) {
	p1 := Prog{cur: 0, max: 0}
	p2 := Prog{cur: 0, max: 0}
	// Both have ratio 0, so should return y
	result := progMin(p1, p2)
	assert.Equal(t, p2, result)
}

func TestProgMax_BothZeroMax(t *testing.T) {
	p1 := Prog{cur: 0, max: 0}
	p2 := Prog{cur: 0, max: 0}
	result := progMax(p1, p2)
	assert.Equal(t, p2, result)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
