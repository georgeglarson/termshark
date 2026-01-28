// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestAverageTracker_Empty(t *testing.T) {
	at := &averageTracker{}

	avg := at.average()
	assert.True(t, avg.IsNone(), "average of empty tracker should be None")
}

func TestAverageTracker_SingleValue(t *testing.T) {
	at := &averageTracker{}
	at.update(42)

	avg := at.average()
	assert.Equal(t, 42, avg.Val())
}

func TestAverageTracker_MultipleValues(t *testing.T) {
	at := &averageTracker{}
	at.update(10)
	at.update(20)
	at.update(30)

	avg := at.average()
	assert.Equal(t, 20, avg.Val()) // (10+20+30)/3 = 20
}

func TestAverageTracker_IntegerDivision(t *testing.T) {
	at := &averageTracker{}
	at.update(10)
	at.update(11)

	avg := at.average()
	assert.Equal(t, 10, avg.Val()) // (10+11)/2 = 10 (integer division)
}

func TestAverageTracker_LargeValues(t *testing.T) {
	at := &averageTracker{}
	at.update(1000000)
	at.update(2000000)

	avg := at.average()
	assert.Equal(t, 1500000, avg.Val())
}

func TestMaxTracker_Empty(t *testing.T) {
	mt := &maxTracker{}

	assert.Equal(t, 0, mt.max())
}

func TestMaxTracker_SingleValue(t *testing.T) {
	mt := &maxTracker{}
	mt.update(42)

	assert.Equal(t, 42, mt.max())
}

func TestMaxTracker_IncreasingValues(t *testing.T) {
	mt := &maxTracker{}
	mt.update(5)
	mt.update(10)
	mt.update(15)

	assert.Equal(t, 15, mt.max())
}

func TestMaxTracker_DecreasingValues(t *testing.T) {
	mt := &maxTracker{}
	mt.update(15)
	mt.update(10)
	mt.update(5)

	assert.Equal(t, 15, mt.max())
}

func TestMaxTracker_MixedValues(t *testing.T) {
	mt := &maxTracker{}
	mt.update(5)
	mt.update(100)
	mt.update(50)
	mt.update(1)

	assert.Equal(t, 100, mt.max())
}

func TestMaxTracker_NegativeValues(t *testing.T) {
	// maxTracker starts at 0, so negative-only updates don't change the max
	// This documents actual behavior - it's designed for positive values like packet sizes
	mt := &maxTracker{}
	mt.update(-10)
	mt.update(-5)
	mt.update(-20)

	assert.Equal(t, 0, mt.max())
}

func TestMaxTracker_MixedPositiveNegative(t *testing.T) {
	mt := &maxTracker{}
	mt.update(-10)
	mt.update(5)
	mt.update(-3)

	assert.Equal(t, 5, mt.max())
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
