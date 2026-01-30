// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"net"
	"strconv"
	"strings"

	"github.com/gcla/gowid/widgets/table"
)

//======================================================================

// IPCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing IP addresses.
type IPCompare struct{}

func (s IPCompare) Less(i, j string) bool {
	x := net.ParseIP(i)
	y := net.ParseIP(j)
	if x != nil && y != nil {
		if len(x) != len(y) {
			return len(x) < len(y)
		} else {
			for i := range len(x) {
				switch {
				case x[i] < y[i]:
					return true
				case y[i] < x[i]:
					return false
				}
			}
			return false
		}
	} else if x != nil {
		return true
	} else if y != nil {
		return false
	} else {
		return i < j
	}
}

var _ table.ICompare = IPCompare{}

//======================================================================

// MacCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing MAC addresses.
type MACCompare struct{}

func (s MACCompare) Less(i, j string) bool {
	x, errx := net.ParseMAC(i)
	y, erry := net.ParseMAC(j)
	if errx == nil && erry == nil {
		for i := range len(x) {
			switch {
			case x[i] < y[i]:
				return true
			case y[i] < x[i]:
				return false
			}
		}
		return false
	} else if errx == nil {
		return true
	} else if erry == nil {
		return false
	} else {
		return i < j
	}
}

var _ table.ICompare = MACCompare{}

//======================================================================

// ConvPktsCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing values emitted by the tshark -z conv,... e.g.
// "2,456 kB"
type ConvPktsCompare struct{}

func (s ConvPktsCompare) Less(i, j string) bool {

	mi := unitsRe.FindStringSubmatch(i)
	if len(mi) <= 2 {
		return false
	}
	mx, err := strconv.ParseUint(strings.ReplaceAll(mi[1], ",", ""), 10, 64)
	if err != nil {
		return false
	}
	if mi[2] == "kB" {
		mx *= 1024
	} else if mi[2] == "MB" {
		mx *= (1024 * 1024)
	}
	mj := unitsRe.FindStringSubmatch(j)
	if len(mj) <= 2 {
		return false
	}
	my, err := strconv.ParseUint(strings.ReplaceAll(mj[1], ",", ""), 10, 64)
	if err != nil {
		return false
	}
	if mj[2] == "kB" {
		my *= 1024
	} else if mj[2] == "MB" {
		my *= (1024 * 1024)
	}

	return mx < my
}

var _ table.ICompare = ConvPktsCompare{}
