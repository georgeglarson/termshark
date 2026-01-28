// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package summary

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReaderEmpty(t *testing.T) {
	r := New(strings.NewReader(""))
	// Give the goroutine time to process
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, 0, len(summary))
}

func TestReaderOneLine(t *testing.T) {
	r := New(strings.NewReader("first line"))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, []string{"first line"}, summary)
}

func TestReaderTwoLines(t *testing.T) {
	r := New(strings.NewReader("first line\nsecond line"))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, []string{"first line", "second line"}, summary)
}

func TestReaderThreeLines(t *testing.T) {
	r := New(strings.NewReader("first\nsecond\nthird"))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, []string{"first", "second", "third"}, summary)
}

func TestReaderFourLines(t *testing.T) {
	r := New(strings.NewReader("first\nsecond\nthird\nfourth"))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, []string{"first", "second", "third", "fourth"}, summary)
}

func TestReaderFiveOrMoreLines(t *testing.T) {
	r := New(strings.NewReader("first\nsecond\nthird\nfourth\nfifth"))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	// Summary shows: first, second, ..., penultimate, last
	assert.Equal(t, []string{"first", "second", "...", "fourth", "fifth"}, summary)
}

func TestReaderManyLines(t *testing.T) {
	lines := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
		"line 5",
		"line 6",
		"line 7",
		"line 8",
		"line 9",
		"line 10",
	}
	r := New(strings.NewReader(strings.Join(lines, "\n")))
	time.Sleep(10 * time.Millisecond)

	summary := r.Summary()
	assert.Equal(t, []string{"line 1", "line 2", "...", "line 9", "line 10"}, summary)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
