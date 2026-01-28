// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package generic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilter(t *testing.T) {
	// Filter even numbers
	nums := []int{1, 2, 3, 4, 5, 6}
	evens := Filter(nums, func(n int) bool { return n%2 == 0 })
	assert.Equal(t, []int{2, 4, 6}, evens)

	// Filter empty slice
	empty := Filter([]int{}, func(n int) bool { return true })
	assert.Equal(t, []int{}, empty)

	// Filter with no matches
	noMatch := Filter(nums, func(n int) bool { return n > 10 })
	assert.Equal(t, []int{}, noMatch)

	// Filter strings
	words := []string{"apple", "banana", "cherry"}
	short := Filter(words, func(s string) bool { return len(s) < 6 })
	assert.Equal(t, []string{"apple"}, short)
}

func TestMap(t *testing.T) {
	// Double numbers
	nums := []int{1, 2, 3}
	doubled := Map(nums, func(n int) int { return n * 2 })
	assert.Equal(t, []int{2, 4, 6}, doubled)

	// Int to string
	strs := Map(nums, func(n int) string { return string(rune('a' + n - 1)) })
	assert.Equal(t, []string{"a", "b", "c"}, strs)

	// Empty slice
	empty := Map([]int{}, func(n int) int { return n })
	assert.Equal(t, []int{}, empty)
}

func TestContains(t *testing.T) {
	nums := []int{1, 2, 3, 4, 5}
	assert.True(t, Contains(nums, 3))
	assert.False(t, Contains(nums, 10))
	assert.False(t, Contains([]int{}, 1))

	words := []string{"apple", "banana"}
	assert.True(t, Contains(words, "apple"))
	assert.False(t, Contains(words, "cherry"))
}

func TestRemove(t *testing.T) {
	nums := []int{1, 2, 3, 2, 4}
	result := Remove(nums, 2)
	assert.Equal(t, []int{1, 3, 4}, result)

	// Remove non-existent
	result2 := Remove(nums, 10)
	assert.Equal(t, []int{1, 2, 3, 2, 4}, result2)

	// Remove from empty
	empty := Remove([]int{}, 1)
	assert.Equal(t, []int{}, empty)
}

func TestMoveToFront(t *testing.T) {
	nums := []int{1, 2, 3, 4, 5}
	result := MoveToFront(nums, 3)
	assert.Equal(t, []int{3, 1, 2, 4, 5}, result)

	// Move first element (should stay first)
	result2 := MoveToFront(nums, 1)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, result2)

	// Move last element
	result3 := MoveToFront(nums, 5)
	assert.Equal(t, []int{5, 1, 2, 3, 4}, result3)

	// Move non-existent (prepends it)
	result4 := MoveToFront(nums, 10)
	assert.Equal(t, []int{10, 1, 2, 3, 4, 5}, result4)

	// Works with strings
	words := []string{"a", "b", "c"}
	strResult := MoveToFront(words, "c")
	assert.Equal(t, []string{"c", "a", "b"}, strResult)
}

func TestFindIndex(t *testing.T) {
	nums := []int{1, 2, 3, 4, 5}
	idx := FindIndex(nums, func(n int) bool { return n > 3 })
	assert.Equal(t, 3, idx)

	// Not found
	idx2 := FindIndex(nums, func(n int) bool { return n > 10 })
	assert.Equal(t, -1, idx2)

	// Empty slice
	idx3 := FindIndex([]int{}, func(n int) bool { return true })
	assert.Equal(t, -1, idx3)
}

func TestFirst(t *testing.T) {
	nums := []int{1, 2, 3, 4, 5}
	val, found := First(nums, func(n int) bool { return n > 3 })
	assert.True(t, found)
	assert.Equal(t, 4, val)

	// Not found
	val2, found2 := First(nums, func(n int) bool { return n > 10 })
	assert.False(t, found2)
	assert.Equal(t, 0, val2)
}

func TestKeys(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	keys := Keys(m)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, "a")
	assert.Contains(t, keys, "b")
	assert.Contains(t, keys, "c")

	// Empty map
	emptyKeys := Keys(map[string]int{})
	assert.Len(t, emptyKeys, 0)
}

func TestValues(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	values := Values(m)
	assert.Len(t, values, 3)
	assert.Contains(t, values, 1)
	assert.Contains(t, values, 2)
	assert.Contains(t, values, 3)

	// Empty map
	emptyValues := Values(map[string]int{})
	assert.Len(t, emptyValues, 0)
}
