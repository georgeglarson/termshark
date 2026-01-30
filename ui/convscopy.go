// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/widgets/copymodetable"
)

type CsvTableCopier struct {
	hdrs []string
	data [][]string
}

func (c CsvTableCopier) CopyRow(id table.RowId) []gowid.ICopyResult {
	row := strings.Join(c.data[id], ",")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy conversation",
			Val:  row,
		},
	}
}

func (c CsvTableCopier) CopyTable() []gowid.ICopyResult {
	res := make([]string, 0, len(c.data)+1)

	res = append(res, strings.Join(c.hdrs, ","))
	for _, d := range c.data {
		res = append(res, strings.Join(d, ","))
	}

	prt := strings.Join(res, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy all",
			Val:  prt,
		},
	}
}

var _ copymodetable.IRowCopier = CsvTableCopier{}
var _ copymodetable.ITableCopier = CsvTableCopier{}

//======================================================================
