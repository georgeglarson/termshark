// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"bufio"
	"fmt"
	"slices"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
	"github.com/gcla/termshark/v2/ui/tableutil"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetable"
	"github.com/gcla/termshark/v2/widgets/enableselected"
	"github.com/gcla/termshark/v2/widgets/scrollabletable"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
)

func (w *ConvsUiWidget) OnCancel(app gowid.IApp) {
	for _, cw := range w.convs {
		cw.IWidget = cw.cancelledWidget
	}
}

func (w *ConvsUiWidget) OnData(data string, app gowid.IApp) {
	var hdrs []string
	var wids []gowid.IWidgetDimension
	var comps []table.ICompare
	var cur string
	var next string
	var ports bool = false

	var (
		addra      string
		porta      string
		addrb      string
		portb      string
		framesto   string
		bytesto    string
		framesfrom string
		bytesfrom  string
		frames     string
		bytes      string
		start      string
		durn       string
	)

	var datas [][]string

	saveConversation := func(cur string) {
		tblModel := table.NewSimpleModel(hdrs, datas, table.SimpleOptions{
			Comparators: comps,
			Style: table.StyleOptions{
				HorizontalSeparator: nil,
				TableSeparator:      divider.NewUnicode(),
				VerticalSeparator:   nil,
				CellStyleProvided:   true,
				CellStyleSelected:   gowid.MakePaletteRef("packet-list-cell-selected"),
				CellStyleFocus:      gowid.MakePaletteRef("packet-list-cell-focus"),
				HeaderStyleProvided: true,
				HeaderStyleFocus:    gowid.MakePaletteRef("packet-list-cell-focus"),
			},
			Layout: table.LayoutOptions{
				Widths: wids,
			},
		})

		ptblModel := psmlmodel.New(
			tblModel,
			gowid.MakePaletteRef("packet-list-row-focus"),
		)

		if currentShortName, ok := convs.OfficialNameToType[cur]; ok {

			model := &ConvsModel{
				Model: ptblModel,
				proto: convTypes[currentShortName],
			}

			tbl := &table.BoundedWidget{
				Widget: table.New(model),
			}

			boundedTbl := NewRowFocusTableWidget(
				tbl,
				"packet-list-row-selected",
				"packet-list-row-focus",
			)

			var _ list.IWalker = boundedTbl
			var _ gowid.IWidget = boundedTbl
			var _ table.IBoundedModel = tblModel

			w.convs[w.tabIndex[currentShortName]].IWidget = appkeys.New(
				enableselected.New(
					withscrollbar.New(
						scrollabletable.New(
							copymodetable.New(
								boundedTbl,
								CsvTableCopier{hdrs, datas},
								CsvTableCopier{hdrs, datas},
								"convstable",
								copyModePalette{},
							),
						),
						withscrollbar.Options{
							HideIfContentFits: true,
						},
					),
				),
				tableutil.GotoHandler(&tableutil.GoToAdapter{
					BoundedWidget: tbl,
					KeyState:      &keyState,
				}),
			)

			w.convs[w.tabIndex[currentShortName]].tbl = tbl
			w.convs[w.tabIndex[currentShortName]].model = model
			w.buttonLabels[currentShortName].SetText(fmt.Sprintf(" %s (%d) ", cur, len(datas)), app)
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(data))
	var n int
	var err error
	for scanner.Scan() {
		line := scanner.Text()
		r := strings.NewReader(line)
		n, err = fmt.Fscanf(r, "%s Conversations", &next)
		if err == nil && n == 1 {
			if cur != "" {
				saveConversation(cur)
			}

			datas = make([][]string, 0)
			cur = next

			ports = slices.Contains([]string{"UDP", "TCP"}, cur)
			ipv6 := (cur == "IPv6")

			var addrComp table.ICompare = termshark.IPCompare{}
			if slices.Contains([]string{"Ethernet"}, cur) {
				addrComp = termshark.MACCompare{}
			}

			var convComp table.ICompare = termshark.ConvPktsCompare{}

			if ports {
				hdrs = []string{
					"Addr A",
					"Port A",
					"Addr B",
					"Port B",
					"Pkts",
					"Bytes",
					"Pkts A→B",
					"Bytes A→B",
					"Pkts B→A",
					"Bytes B→A",
					"Start",
					"Durn",
				}
				wids = []gowid.IWidgetDimension{
					weightupto(400, 32), // addra
					weightupto(200, 7),  // port
					weightupto(400, 32), // addrb
					weightupto(200, 7),  // port
					weightupto(200, 8),  // pkts
					weightupto(200, 10),
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(500, 14), // start
					weightupto(200, 8),  // durn
				}
				comps = []table.ICompare{
					addrComp,
					table.IntCompare{},
					addrComp,
					table.IntCompare{},
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.FloatCompare{},
					table.FloatCompare{},
				}

			} else {
				hdrs = []string{
					"Addr A",
					"Addr B",
					"Pkts",
					"Bytes",
					"Pkts A→B",
					"Bytes A→B",
					"Pkts B→A",
					"Bytes B→A",
					"Start",
					"Durn",
				}

				wids = []gowid.IWidgetDimension{
					weightupto(400, 32), // addra
					weightupto(400, 32), // addrb
					weightupto(200, 8),  // pkts
					weightupto(200, 10),
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(500, 14), // start
					weightupto(200, 10), // durn
				}
				if ipv6 {
					wids[0] = weightupto(500, 42)
					wids[1] = weightupto(500, 42)
				}
				comps = []table.ICompare{
					addrComp,
					addrComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.FloatCompare{},
					table.FloatCompare{},
				}

			}

			continue
		}

		line = strings.ReplaceAll(line, " bytes", "")
		line = strings.ReplaceAll(line, "bytes", "")
		line = strings.ReplaceAll(line, " kB", "kB")
		line = strings.ReplaceAll(line, " MB", "MB")
		r = strings.NewReader(line)
		n, err = fmt.Fscanf(r, "%s <-> %s %s %s %s %s %s %s %s %s",
			&addra,
			&addrb,
			&framesto,
			&bytesto,
			&framesfrom,
			&bytesfrom,
			&frames,
			&bytes,
			&start,
			&durn,
		)
		if err == nil && n == 10 {
			bytesto = strings.ReplaceAll(bytesto, "kB", " kB")
			bytesfrom = strings.ReplaceAll(bytesfrom, "kB", " kB")
			bytes = strings.ReplaceAll(bytes, "kB", " kB")
			bytesto = strings.ReplaceAll(bytesto, "MB", " MB")
			bytesfrom = strings.ReplaceAll(bytesfrom, "MB", " MB")
			bytes = strings.ReplaceAll(bytes, "MB", " MB")
			if ports {
				// Use LastIndex to handle IPv6 addresses (e.g. "[::1]:80")
				lastColonA := strings.LastIndex(addra, ":")
				lastColonB := strings.LastIndex(addrb, ":")
				if lastColonA > 0 && lastColonB > 0 {
					porta = addra[lastColonA+1:]
					addra = addra[:lastColonA]
					portb = addrb[lastColonB+1:]
					addrb = addrb[:lastColonB]
					datas = append(datas, []string{addra, porta, addrb, portb, framesto, bytesto, framesfrom, bytesfrom, frames, bytes, start, durn})
				}
			} else {
				datas = append(datas, []string{addra, addrb, framesto, bytesto, framesfrom, bytesfrom, frames, bytes, start, durn})
			}
		}
	}

	saveConversation(cur)
}
