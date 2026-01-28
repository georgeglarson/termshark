// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestLoaderState_String(t *testing.T) {
	assert.Equal(t, "loading", Loading.String())
	assert.Equal(t, "not-loading", NotLoading.String())
}

func TestProcessState_String(t *testing.T) {
	assert.Equal(t, "NotStarted", NotStarted.String())
	assert.Equal(t, "Started", Started.String())
	assert.Equal(t, "Terminated", Terminated.String())
	assert.Equal(t, "Unknown", ProcessState(99).String())
}

func TestProcessState_Constants(t *testing.T) {
	// Verify constant values
	assert.Equal(t, ProcessState(0), NotStarted)
	assert.Equal(t, ProcessState(1), Started)
	assert.Equal(t, ProcessState(2), Terminated)
}

func TestLoaderState_Constants(t *testing.T) {
	// Verify constant values
	assert.Equal(t, LoaderState(false), NotLoading)
	assert.Equal(t, LoaderState(true), Loading)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
