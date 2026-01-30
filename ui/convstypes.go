// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"fmt"
	"runtime"

	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/termshark/v2/pkg/convs"
)

type Direction int

const (
	Any  Direction = iota // 0
	To                    // 1
	From                  // 2
)

type ConvAddr int

const (
	IPv4Addr ConvAddr = iota // 0
	IPv6Addr                 // 1
	MacAddr                  // 2
)

type FilterMask int

const (
	AtfB   FilterMask = iota // 0
	AtB                      // 1
	BtA                      // 2
	AtfAny                   // 3
	AtAny                    // 4
	AnytA                    // 5
	AnytfB                   // 6
	AnytB                    // 7
	BtAny                    // 8
)

type FilterCombinator int

const (
	Selected       FilterCombinator = iota // 0
	NotSelected                            // 1
	AndSelected                            // 2
	OrSelected                             // 3
	AndNotSelected                         // 4
	OrNotSelected                          // 5
)

// Use to construct a string like "ip.addr == 1.2.3.4 && tcp.port == 12345"
type IFilterBuilder interface {
	fmt.Stringer
	FilterFrom(vals ...string) string
	FilterTo(vals ...string) string
	FilterAny(vals ...string) string
	AIndex() []int
	BIndex() []int
}

var convTypes = map[string]IFilterBuilder{}

func init() {
	convTypes[convs.Ethernet{}.Short()] = convs.Ethernet{}
	convTypes[convs.IPv4{}.Short()] = convs.IPv4{}
	convTypes[convs.IPv6{}.Short()] = convs.IPv6{}
	convTypes[convs.UDP{}.Short()] = convs.UDP{}
	convTypes[convs.TCP{}.Short()] = convs.TCP{}

	if runtime.GOOS == "windows" {
		vdiv = "│"
		frameRunes = framed.FrameRunes{Tl: '┌', Tr: '┐', Bl: '└', Br: '┘', T: 0, B: '─', L: '│', R: '│'}
	} else {
		vdiv = "┃"
		frameRunes = framed.FrameRunes{Tl: '┏', Tr: '┓', Bl: '┗', Br: '┛', T: 0, B: '━', L: '┃', R: '┃'}
	}
}
