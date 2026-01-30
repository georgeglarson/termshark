// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streamwidget

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/widgets/regexstyle"
)

type iClickIsActive interface {
	clickIsActive() bool
}

type iHighlight interface {
	highlightThis(pos table.Position) regexstyle.Highlight
}

type IFilterOut interface {
	PreviousFilter() string
	DisplayFilter() string
}

type IOnError interface {
	OnError(msg string, app gowid.IApp)
}

type iMapChunkToTableRow interface {
	MapChunkToTableRow(chunk int) (int, error)
}

// Supplied by user of widget - what UI changes to make when packet is clicked
type IChunkClicked interface {
	OnPacketClicked(pkt int, app gowid.IApp) error
	HandleError(row table.RowId, err error, app gowid.IApp)
}

// Used by widget - first map table click to packet number, then use IChunkClicked
type iChunkClicker interface {
	IChunkClicked
	iClickIsActive
	iMapChunkToTableRow
	iHighlight
}
