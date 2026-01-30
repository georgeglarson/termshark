// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streamwidget

import (
	"fmt"
	"regexp"

	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/pkg/streams"
)

type searchState struct {
	searchReTxt      string
	searchRe         *regexp.Regexp
	searchRow        table.Position
	searchOccurrence int
	maxOccurrences   gwutil.IntOption
}

func (s *searchState) initSearch(re *regexp.Regexp, txt string) {
	s.searchReTxt = txt
	s.searchRe = re
	s.searchRow = 0
}

func (s *searchState) goToSearchRow(row table.Position) {
	s.searchRow = row
	s.searchOccurrence = 0
	s.maxOccurrences = gwutil.NoneInt()
}

func (s *searchState) goToNextSearchRow() {
	s.goToSearchRow(s.searchRow + 1)
}

func (w searchState) String() string {
	return fmt.Sprintf("[re='%s' row=%d occ=%d maxocc=%v]", w.searchReTxt, w.searchRow, w.searchOccurrence, w.maxOccurrences)
}

//======================================================================

// Represents the view of the data from either both sides, client side or server side
type ViewData struct {
	subIndices  []int // [0,1,2,3,...] - index into pktIndices
	hexChunks   chunkList
	asciiChunks asciiChunkList
	rawChunks   rawChunkList
}

func newViewData(clicker IChunkClicked, ca iClickIsActive, mapper iMapChunkToTableRow, hiliter iHighlight) *ViewData {

	clickMapper := struct {
		IChunkClicked
		iClickIsActive
		iMapChunkToTableRow
		iHighlight
	}{
		IChunkClicked:       clicker,
		iClickIsActive:      ca,
		iMapChunkToTableRow: mapper,
		iHighlight:          hiliter,
	}

	res := &ViewData{
		subIndices: make([]int, 0, 16),
		hexChunks: chunkList{
			clicker: clickMapper,
			chunks:  make([]streams.IChunk, 0, 16),
		},
	}

	res.update()

	return res
}

func (v *ViewData) update() {
	v.asciiChunks = asciiChunkList{
		chunkList: &v.hexChunks,
	}
	v.rawChunks = rawChunkList{
		chunkList: &v.hexChunks,
	}
}

//======================================================================

// Represents all the streamed data
type Data struct {
	pktIndices   []int       // [0,2,5,12...] - frame numbers (-1) for each packet of this stream
	vdata        []*ViewData // for each of (a) whole view (b) client (c) server
	currentChunk int         // add to client or server view
	finished     bool
}

func newData(clicker IChunkClicked, ca iClickIsActive, mapper iMapChunkToTableRow, hiliter iHighlight) *Data {
	vdata := make([]*ViewData, 0, 3)
	for i := 0; i < 3; i++ {
		vdata = append(vdata, newViewData(clicker, ca, mapper, hiliter))
	}
	res := &Data{
		pktIndices: make([]int, 0, 16),
		vdata:      vdata,
	}
	return res
}
