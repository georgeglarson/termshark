package withscrollbar

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Test helpers
//======================================================================

// fullScrollingListBox implements IScrollSubWidget with all optional interfaces
type fullScrollingListBox struct {
	*list.Widget
	scrollPos    int
	scrollLen    int
	upCalled     int
	downCalled   int
	upPageCalled int
	downPageCalled int
	homeCalled   bool
	endCalled    bool
	setPosCalled bool
	setPosVal    int
}

func (t *fullScrollingListBox) Up(lines int, size gowid.IRenderSize, app gowid.IApp) {
	t.upCalled += lines
	t.scrollPos -= lines
	if t.scrollPos < 0 {
		t.scrollPos = 0
	}
}

func (t *fullScrollingListBox) Down(lines int, size gowid.IRenderSize, app gowid.IApp) {
	t.downCalled += lines
	t.scrollPos += lines
	if t.scrollPos >= t.scrollLen {
		t.scrollPos = t.scrollLen - 1
	}
}

func (t *fullScrollingListBox) UpPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	t.upPageCalled += num
}

func (t *fullScrollingListBox) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	t.downPageCalled += num
}

func (t *fullScrollingListBox) GoHome(size gowid.IRenderSize, app gowid.IApp) {
	t.homeCalled = true
	t.scrollPos = 0
}

func (t *fullScrollingListBox) GoToEnd(size gowid.IRenderSize, app gowid.IApp) {
	t.endCalled = true
	t.scrollPos = t.scrollLen - 1
}

func (t *fullScrollingListBox) SetPos(pos list.IBoundedWalkerPosition, app gowid.IApp) {
	t.setPosCalled = true
	t.setPosVal = pos.(table.Position).ToInt()
}

func (t *fullScrollingListBox) ScrollLength() int {
	return t.scrollLen
}

func (t *fullScrollingListBox) ScrollPosition() int {
	return t.scrollPos
}

func makeFullScrollingList(numItems int) *fullScrollingListBox {
	bws := make([]gowid.IWidget, numItems)
	for i := range bws {
		bws[i] = button.NewBare(text.New(fmt.Sprintf("%03d", i)))
	}
	walker := list.NewSimpleListWalker(bws)
	return &fullScrollingListBox{
		Widget:    list.New(walker),
		scrollLen: numItems,
		scrollPos: 0,
	}
}

//======================================================================
// CalculateMenuRows tests
//======================================================================

func TestCalculateMenuRows_Basic(t *testing.T) {
	lbox := makeFullScrollingList(100)
	lbox.scrollPos = 0

	top, mid, bot := CalculateMenuRows(lbox, 20, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 0, top)
	assert.Equal(t, 1, mid)
	assert.Equal(t, 99, bot)
}

func TestCalculateMenuRows_MiddlePosition(t *testing.T) {
	lbox := makeFullScrollingList(100)
	lbox.scrollPos = 50

	top, mid, bot := CalculateMenuRows(lbox, 20, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 50, top)
	assert.Equal(t, 1, mid)
	assert.Equal(t, 49, bot)
}

func TestCalculateMenuRows_AtEnd(t *testing.T) {
	lbox := makeFullScrollingList(100)
	lbox.scrollPos = 99

	top, mid, bot := CalculateMenuRows(lbox, 20, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 99, top)
	assert.Equal(t, 1, mid)
	assert.Equal(t, 0, bot)
}

func TestCalculateMenuRows_SingleItem(t *testing.T) {
	lbox := makeFullScrollingList(1)
	lbox.scrollPos = 0

	top, mid, bot := CalculateMenuRows(lbox, 1, gowid.NotSelected, gwtest.D)
	assert.Equal(t, 0, top)
	assert.Equal(t, 1, mid)
	assert.Equal(t, 0, bot)
}

//======================================================================
// clickUp/clickDown/clickUpArrow/clickDownArrow tests
//======================================================================

func TestClickHandlers(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	// clickUp decrements pgUpDown
	sbox.clickUp(gwtest.D, nil)
	assert.Equal(t, -1, sbox.pgUpDown)

	sbox.clickUp(gwtest.D, nil)
	assert.Equal(t, -2, sbox.pgUpDown)

	// clickDown increments pgUpDown
	sbox.clickDown(gwtest.D, nil)
	assert.Equal(t, -1, sbox.pgUpDown)

	sbox.clickDown(gwtest.D, nil)
	assert.Equal(t, 0, sbox.pgUpDown)

	sbox.clickDown(gwtest.D, nil)
	assert.Equal(t, 1, sbox.pgUpDown)

	// clickUpArrow decrements goUpDown
	sbox.clickUpArrow(gwtest.D, nil)
	assert.Equal(t, -1, sbox.goUpDown)

	sbox.clickUpArrow(gwtest.D, nil)
	assert.Equal(t, -2, sbox.goUpDown)

	// clickDownArrow increments goUpDown
	sbox.clickDownArrow(gwtest.D, nil)
	assert.Equal(t, -1, sbox.goUpDown)

	sbox.clickDownArrow(gwtest.D, nil)
	assert.Equal(t, 0, sbox.goUpDown)

	sbox.clickDownArrow(gwtest.D, nil)
	assert.Equal(t, 1, sbox.goUpDown)
}

//======================================================================
// rightClick tests
//======================================================================

func TestRightClick(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	assert.False(t, sbox.fracSet)
	assert.Equal(t, float32(0), sbox.frac)

	sbox.rightClick(gwtest.D, nil, float32(0.5))
	assert.True(t, sbox.fracSet)
	assert.Equal(t, float32(0.5), sbox.frac)

	sbox.rightClick(gwtest.D, nil, float32(0.0))
	assert.True(t, sbox.fracSet)
	assert.Equal(t, float32(0.0), sbox.frac)

	sbox.rightClick(gwtest.D, nil, float32(1.0))
	assert.True(t, sbox.fracSet)
	assert.Equal(t, float32(1.0), sbox.frac)
}

//======================================================================
// Selectable tests
//======================================================================

func TestSelectable(t *testing.T) {
	lbox := makeFullScrollingList(8)
	sbox := New(lbox)
	// The underlying list widget should be selectable
	assert.Equal(t, lbox.Selectable(), sbox.Selectable())
}

//======================================================================
// contentFits tests
//======================================================================

func TestContentFits_Fits(t *testing.T) {
	lbox := makeFullScrollingList(5)
	sbox := New(lbox)

	// 5 items in 10 rows => fits
	size := gowid.MakeRenderBox(80, 10)
	assert.True(t, sbox.contentFits(size))
}

func TestContentFits_DoesNotFit(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	// 20 items in 10 rows => does not fit
	size := gowid.MakeRenderBox(80, 10)
	assert.False(t, sbox.contentFits(size))
}

func TestContentFits_ExactFit(t *testing.T) {
	lbox := makeFullScrollingList(8)
	sbox := New(lbox)

	// 8 items in 8 rows => fits exactly
	size := gowid.MakeRenderBox(80, 8)
	assert.True(t, sbox.contentFits(size))
}

//======================================================================
// RenderSize tests
//======================================================================

func TestRenderSize_Normal(t *testing.T) {
	lbox := &scrollingListBox{Widget: list.New(list.NewSimpleListWalker(makeWidgetSlice(8)))}
	sbox := New(lbox)

	size := gowid.MakeRenderBox(10, 8)
	rs := sbox.RenderSize(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, rs)
	assert.Equal(t, 10, rs.BoxColumns())
	assert.Equal(t, 8, rs.BoxRows())
}

func TestRenderSize_HideIfContentFits_Fits(t *testing.T) {
	lbox := &scrollingListBox{Widget: list.New(list.NewSimpleListWalker(makeWidgetSlice(5)))}
	sbox := New(lbox, Options{HideIfContentFits: true})

	size := gowid.MakeRenderBox(10, 8)
	rs := sbox.RenderSize(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, rs)
}

func TestRenderSize_HideIfContentFits_DoesNotFit(t *testing.T) {
	lbox := &scrollingListBox{Widget: list.New(list.NewSimpleListWalker(makeWidgetSlice(20)))}
	sbox := New(lbox, Options{HideIfContentFits: true})

	// content (20 items) does not fit in 8 rows
	size := gowid.MakeRenderBox(10, 8)
	rs := sbox.RenderSize(size, gowid.NotSelected, gwtest.D)
	assert.NotNil(t, rs)
}

func makeWidgetSlice(n int) []gowid.IWidget {
	bws := make([]gowid.IWidget, n)
	for i := range bws {
		bws[i] = button.NewBare(text.New(fmt.Sprintf("%03d", i)))
	}
	return bws
}

//======================================================================
// UserInput tests - PgUp/PgDn/Home/End
//======================================================================

func TestUserInput_PgUp(t *testing.T) {
	lbox := makeFullScrollingList(20)
	lbox.scrollPos = 10
	sbox := New(lbox)

	ev := tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone)
	size := gowid.MakeRenderBox(10, 5)
	handled := sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	assert.True(t, handled)
	assert.Equal(t, 1, lbox.upPageCalled)
}

func TestUserInput_PgDn(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	ev := tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone)
	size := gowid.MakeRenderBox(10, 5)
	handled := sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	assert.True(t, handled)
	assert.Equal(t, 1, lbox.downPageCalled)
}

func TestUserInput_Home(t *testing.T) {
	lbox := makeFullScrollingList(20)
	lbox.scrollPos = 10
	sbox := New(lbox)

	ev := tcell.NewEventKey(tcell.KeyHome, 0, tcell.ModNone)
	size := gowid.MakeRenderBox(10, 5)
	handled := sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	assert.True(t, handled)
	assert.True(t, lbox.homeCalled)
}

func TestUserInput_End(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	ev := tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone)
	size := gowid.MakeRenderBox(10, 5)
	handled := sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	assert.True(t, handled)
	assert.True(t, lbox.endCalled)
}

func TestUserInput_HideIfContentFits_ContentFits(t *testing.T) {
	lbox := makeFullScrollingList(5)
	sbox := New(lbox, Options{HideIfContentFits: true})

	// Content fits in 10 rows, so it delegates directly to the inner widget
	ev := tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone)
	size := gowid.MakeRenderBox(10, 10)
	// The inner widget may or may not handle this, but the code path is covered
	sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	// DownPage should NOT be called via the scrollbar logic since content fits
	assert.Equal(t, 0, lbox.downPageCalled)
}

func TestUserInput_RegularKey(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	// A regular character key should be delegated to the always widget
	ev := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	size := gowid.MakeRenderBox(10, 5)
	sbox.UserInput(ev, size, gowid.Focused, gwtest.D)
	// We just check it doesn't panic and the special keys weren't triggered
	assert.Equal(t, 0, lbox.upPageCalled)
	assert.Equal(t, 0, lbox.downPageCalled)
	assert.False(t, lbox.homeCalled)
	assert.False(t, lbox.endCalled)
}

//======================================================================
// Render tests - scrollbar arrow/page interactions processed during Render
//======================================================================

func TestRender_GoUpDown_Positive(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	// Simulate clicking the down arrow 3 times
	sbox.goUpDown = 3
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 3, lbox.downCalled, "Down should be called with the goUpDown value")
	assert.Equal(t, 0, sbox.goUpDown, "goUpDown should be reset after Render")
}

func TestRender_GoUpDown_Negative(t *testing.T) {
	lbox := makeFullScrollingList(20)
	lbox.scrollPos = 10
	sbox := New(lbox)

	// Simulate clicking the up arrow 2 times
	sbox.goUpDown = -2
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 2, lbox.upCalled, "Up should be called with the abs(goUpDown) value")
	assert.Equal(t, 0, sbox.goUpDown)
}

func TestRender_PgUpDown_Positive(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	sbox.pgUpDown = 2
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 2, lbox.downPageCalled)
	assert.Equal(t, 0, sbox.pgUpDown)
}

func TestRender_PgUpDown_Negative(t *testing.T) {
	lbox := makeFullScrollingList(20)
	lbox.scrollPos = 10
	sbox := New(lbox)

	sbox.pgUpDown = -1
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 1, lbox.upPageCalled)
	assert.Equal(t, 0, sbox.pgUpDown)
}

func TestRender_FracSet(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	sbox.frac = 0.5
	sbox.fracSet = true
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.True(t, lbox.setPosCalled)
	// Position should be int(float32(19) * 0.5) = 9
	assert.Equal(t, 9, lbox.setPosVal)
	assert.False(t, sbox.fracSet, "fracSet should be cleared after Render")
}

func TestRender_HideIfContentFits_ContentFits(t *testing.T) {
	lbox := makeFullScrollingList(5)
	sbox := New(lbox, Options{HideIfContentFits: true})

	// 5 items in 8 rows: content fits, should render without scrollbar
	canvas := sbox.Render(gowid.MakeRenderBox(10, 8), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
}

func TestRender_HideIfContentFits_ContentDoesNotFit(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox, Options{HideIfContentFits: true})

	// 20 items in 5 rows: content doesn't fit, scrollbar shown
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	// Scrollbar column should be present
	str := canvas.String()
	lines := strings.Split(str, "\n")
	assert.Equal(t, 5, len(lines))
}

//======================================================================
// Render with combined goUpDown and pgUpDown
//======================================================================

func TestRender_CombinedGoAndPg(t *testing.T) {
	lbox := makeFullScrollingList(20)
	sbox := New(lbox)

	// Both goUpDown and pgUpDown set at once
	sbox.goUpDown = 1
	sbox.pgUpDown = 1
	canvas := sbox.Render(gowid.MakeRenderBox(10, 5), gowid.NotSelected, gwtest.D)
	assert.NotNil(t, canvas)
	assert.Equal(t, 1, lbox.downCalled)
	assert.Equal(t, 1, lbox.downPageCalled)
	assert.Equal(t, 0, sbox.goUpDown)
	assert.Equal(t, 0, sbox.pgUpDown)
}

//======================================================================
// New with options
//======================================================================

func TestNew_DefaultOptions(t *testing.T) {
	lbox := &scrollingListBox{Widget: list.New(list.NewSimpleListWalker(makeWidgetSlice(5)))}
	sbox := New(lbox)
	assert.NotNil(t, sbox)
	assert.False(t, sbox.opt.HideIfContentFits)
}

func TestNew_HideIfContentFitsOption(t *testing.T) {
	lbox := &scrollingListBox{Widget: list.New(list.NewSimpleListWalker(makeWidgetSlice(5)))}
	sbox := New(lbox, Options{HideIfContentFits: true})
	assert.NotNil(t, sbox)
	assert.True(t, sbox.opt.HideIfContentFits)
}
