// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
)

//======================================================================

type LoadResult struct {
	packetTree []*pdmltree.Model
	headers    []string
	packetList [][]string
}

func IsProgressIndeterminate() bool {
	return progressHolder.SubWidget() == loadSpinner
}

func SetProgressDeterminateFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner == 0 || progressOwner == owner {
		progressOwner = owner
		progressHolder.SetSubWidget(loadProgress, app)
	}
}

func SetProgressIndeterminateFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner == 0 || progressOwner == owner {
		progressOwner = owner
		progressHolder.SetSubWidget(loadSpinner, app)
	}
}

func ClearProgressWidgetFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner != owner {
		return
	}

	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = nullw
	ds[progWidgetIdx] = fixed
	filterCols.SetSubWidgets(sw, app)
	filterCols.SetDimensions(ds, app)

	progressOwner = NoOwner
}

func createLoaderProgressWidget() (*button.Widget, *columns.Widget) {
	btn, cols := createProgressWidget()

	btn.OnClick(gowid.MakeWidgetCallback("loaderstop", func(app gowid.IApp, w gowid.IWidget) {
		Loader.StopLoadPsmlAndIface(NoHandlers{}) // psml and iface
	}))

	return btn, cols
}

func createProgressWidget() (*button.Widget, *columns.Widget) {
	stop := button.New(text.New("Stop"))
	stop2 := styled.NewExt(stop, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))

	prog := vpadding.New(progressHolder, gowid.VAlignTop{}, flow)
	prog2 := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: prog,
			D:       weight(1),
		},
		colSpace,
		&gowid.ContainerWidget{
			IWidget: stop2,
			D:       fixed,
		},
	})

	return stop, prog2
}

func SetProgressWidget(app gowid.IApp) {
	SetProgressWidgetCustom(app, loadProg, LoaderOwns)
}

func SetSearchProgressWidget(app gowid.IApp) {
	SetProgressWidgetCustom(app, searchProg, SearchOwns)
}

func SetProgressWidgetCustom(app gowid.IApp, c *columns.Widget, owner WidgetOwner) {

	if progressOwner != owner && progressOwner != 0 {
		return
	}

	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = c
	ds[progWidgetIdx] = weight(33)
	filterCols.SetSubWidgets(sw, app)
	filterCols.SetDimensions(ds, app)
}

//======================================================================

// Prog hold a progress model - a current value on the way up to the max value
type Prog struct {
	cur int64
	max int64
}

func (p Prog) Complete() bool {
	return p.cur >= p.max
}

func (p Prog) String() string {
	return fmt.Sprintf("cur=%d max=%d", p.cur, p.max)
}

func (p Prog) Div(y int64) Prog {
	p.cur /= y
	return p
}

func (p Prog) Add(y Prog) Prog {
	return Prog{cur: p.cur + y.cur, max: p.max + y.max}
}

func progRatio(p Prog) float64 {
	if p.max == 0 {
		return 0
	}
	return float64(p.cur) / float64(p.max)
}

func progMin(x, y Prog) Prog {
	if progRatio(x) < progRatio(y) {
		return x
	} else {
		return y
	}
}

func progMax(x, y Prog) Prog {
	if progRatio(x) > progRatio(y) {
		return x
	} else {
		return y
	}
}
