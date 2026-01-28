// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculatePrefetchRequests(t *testing.T) {
	tests := []struct {
		name         string
		currentRow   int
		pktsPerLoad  int
		wantLen      int
		wantFirst    LoadRequest
		wantSecond   LoadRequest
	}{
		{
			name:        "row 0 with 1000 batch size",
			currentRow:  0,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 0, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 0, CancelCurrent: false}, // prev batch clamped to 0
		},
		{
			name:        "row 500 (middle of batch) prefetches prev",
			currentRow:  500,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 0, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 0, CancelCurrent: false},
		},
		{
			name:        "row 501 (just past middle) prefetches next",
			currentRow:  501,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 0, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 1000, CancelCurrent: false},
		},
		{
			name:        "row 750 (upper half) prefetches next",
			currentRow:  750,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 0, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 1000, CancelCurrent: false},
		},
		{
			name:        "row 1000 (second batch start) prefetches prev",
			currentRow:  1000,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 1000, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 0, CancelCurrent: false},
		},
		{
			name:        "row 1750 (upper half of second batch) prefetches next",
			currentRow:  1750,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 1000, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 2000, CancelCurrent: false},
		},
		{
			name:        "row 2500 (middle of third batch) prefetches prev",
			currentRow:  2500,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 2000, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 1000, CancelCurrent: false},
		},
		{
			name:        "small batch size - lower half",
			currentRow:  15,
			pktsPerLoad: 10,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 10, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 0, CancelCurrent: false}, // position 5 is not > 5, so prev
		},
		{
			name:        "small batch size - upper half",
			currentRow:  16,
			pktsPerLoad: 10,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 10, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 20, CancelCurrent: false}, // position 6 > 5, so next
		},
		{
			name:        "exactly at batch boundary upper",
			currentRow:  999,
			pktsPerLoad: 1000,
			wantLen:     2,
			wantFirst:   LoadRequest{Row: 0, CancelCurrent: true},
			wantSecond:  LoadRequest{Row: 1000, CancelCurrent: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePrefetchRequests(tt.currentRow, tt.pktsPerLoad)
			assert.Len(t, got, tt.wantLen)
			if tt.wantLen >= 1 {
				assert.Equal(t, tt.wantFirst, got[0])
			}
			if tt.wantLen >= 2 {
				assert.Equal(t, tt.wantSecond, got[1])
			}
		})
	}
}

func TestCalculatePrefetchRequests_InvalidInput(t *testing.T) {
	// Zero pktsPerLoad should return nil
	got := CalculatePrefetchRequests(100, 0)
	assert.Nil(t, got)

	// Negative pktsPerLoad should return nil
	got = CalculatePrefetchRequests(100, -1)
	assert.Nil(t, got)
}

func TestBatchStartForRow(t *testing.T) {
	tests := []struct {
		row         int
		pktsPerLoad int
		want        int
	}{
		{0, 1000, 0},
		{500, 1000, 0},
		{999, 1000, 0},
		{1000, 1000, 1000},
		{1500, 1000, 1000},
		{2000, 1000, 2000},
		{15, 10, 10},
		{5, 10, 0},
	}

	for _, tt := range tests {
		got := BatchStartForRow(tt.row, tt.pktsPerLoad)
		assert.Equal(t, tt.want, got, "BatchStartForRow(%d, %d)", tt.row, tt.pktsPerLoad)
	}

	// Invalid pktsPerLoad
	assert.Equal(t, 0, BatchStartForRow(100, 0))
	assert.Equal(t, 0, BatchStartForRow(100, -1))
}

func TestBatchIndexForRow(t *testing.T) {
	tests := []struct {
		row         int
		pktsPerLoad int
		want        int
	}{
		{0, 1000, 0},
		{999, 1000, 0},
		{1000, 1000, 1},
		{1999, 1000, 1},
		{2000, 1000, 2},
		{5, 10, 0},
		{15, 10, 1},
	}

	for _, tt := range tests {
		got := BatchIndexForRow(tt.row, tt.pktsPerLoad)
		assert.Equal(t, tt.want, got, "BatchIndexForRow(%d, %d)", tt.row, tt.pktsPerLoad)
	}
}

func TestPositionInBatch(t *testing.T) {
	tests := []struct {
		row         int
		pktsPerLoad int
		want        int
	}{
		{0, 1000, 0},
		{500, 1000, 500},
		{999, 1000, 999},
		{1000, 1000, 0},
		{1500, 1000, 500},
	}

	for _, tt := range tests {
		got := PositionInBatch(tt.row, tt.pktsPerLoad)
		assert.Equal(t, tt.want, got, "PositionInBatch(%d, %d)", tt.row, tt.pktsPerLoad)
	}
}

func TestIsInUpperHalfOfBatch(t *testing.T) {
	tests := []struct {
		row         int
		pktsPerLoad int
		want        bool
	}{
		{0, 1000, false},
		{499, 1000, false},
		{500, 1000, false}, // exactly at middle is NOT upper half
		{501, 1000, true},
		{999, 1000, true},
		{1000, 1000, false}, // start of new batch
		{1501, 1000, true},
	}

	for _, tt := range tests {
		got := IsInUpperHalfOfBatch(tt.row, tt.pktsPerLoad)
		assert.Equal(t, tt.want, got, "IsInUpperHalfOfBatch(%d, %d)", tt.row, tt.pktsPerLoad)
	}

	// Invalid pktsPerLoad
	assert.False(t, IsInUpperHalfOfBatch(100, 0))
}

func TestShouldPrefetchNext(t *testing.T) {
	// Same as IsInUpperHalfOfBatch
	assert.False(t, ShouldPrefetchNext(500, 1000))
	assert.True(t, ShouldPrefetchNext(501, 1000))
}

func TestCalculateAdjacentBatch(t *testing.T) {
	tests := []struct {
		row         int
		pktsPerLoad int
		want        int
	}{
		{0, 1000, 0},       // prev batch clamped to 0
		{500, 1000, 0},     // lower half -> prev batch
		{501, 1000, 1000},  // upper half -> next batch
		{1000, 1000, 0},    // start of batch 1 -> prev batch
		{1500, 1000, 0},    // lower half of batch 1 -> prev batch
		{1501, 1000, 2000}, // upper half of batch 1 -> next batch
	}

	for _, tt := range tests {
		got := CalculateAdjacentBatch(tt.row, tt.pktsPerLoad)
		assert.Equal(t, tt.want, got, "CalculateAdjacentBatch(%d, %d)", tt.row, tt.pktsPerLoad)
	}

	// Invalid pktsPerLoad
	assert.Equal(t, 0, CalculateAdjacentBatch(100, 0))
}
