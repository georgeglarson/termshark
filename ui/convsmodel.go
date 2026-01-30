// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"github.com/gcla/termshark/v2/pkg/app"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
)

//======================================================================

type ConvsModel struct {
	*psmlmodel.Model
	proto IFilterBuilder
}

func (m ConvsModel) GetAFilter(row int, dir Direction) string {
	line := m.Data[row]
	parms := []string{}
	for _, idx := range m.proto.AIndex() {
		parms = append(parms, line[idx])
	}
	switch dir {
	case To:
		return m.proto.FilterTo(parms...)
	case From:
		return m.proto.FilterFrom(parms...)
	default:
		return m.proto.FilterAny(parms...)
	}
}

func (m ConvsModel) GetBFilter(row int, dir Direction) string {
	line := m.Data[row]
	parms := []string{}
	for _, idx := range m.proto.BIndex() {
		parms = append(parms, line[idx])
	}
	switch dir {
	case To:
		return m.proto.FilterTo(parms...)
	case From:
		return m.proto.FilterFrom(parms...)
	default:
		return m.proto.FilterAny(parms...)
	}
}

//======================================================================

// convsModelWithRow is able to provide an A and a B for a conversation A <-> B. It looks
// up the model at a specific row to find the conversation.
type convsModelWithRow struct {
	model *ConvsModel
	row   int
}

var _ IFilterModel = (*convsModelWithRow)(nil)

func (c *convsModelWithRow) GetAFilter(dir Direction) string {
	return c.model.GetAFilter(c.row, dir)
}

func (c *convsModelWithRow) GetBFilter(dir Direction) string {
	return c.model.GetBFilter(c.row, dir)
}

type IFilterModel interface {
	GetAFilter(Direction) string
	GetBFilter(Direction) string
}

// filterModelAdapter wraps IFilterModel to implement app.FilterModel.
type filterModelAdapter struct {
	model IFilterModel
}

func (a filterModelAdapter) GetAFilter(dir app.Direction) string {
	return a.model.GetAFilter(Direction(dir))
}

func (a filterModelAdapter) GetBFilter(dir app.Direction) string {
	return a.model.GetBFilter(Direction(dir))
}

// ComputeConvFilterOp computes a conversation filter expression.
// Delegates to app.ComputeConversationFilter for the core logic.
func ComputeConvFilterOp(dirOp FilterMask, comb FilterCombinator, model IFilterModel, curFilter string) string {
	adapter := filterModelAdapter{model: model}
	return app.ComputeConversationFilter(
		app.FilterMask(dirOp),
		app.FilterCombinator(comb),
		adapter,
		curFilter,
	)
}

// ComputeFilterCombOp combines a new filter with an existing filter.
// Delegates to app.CombineFilters for the core logic.
func ComputeFilterCombOp(comb FilterCombinator, newFilter string, curFilter string) string {
	return app.CombineFilters(app.FilterCombinator(comb), newFilter, curFilter)
}
