// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package generic provides type-safe generic utility functions for Go 1.18+.
package generic

// Filter returns a new slice containing only elements that satisfy the predicate.
func Filter[T any](slice []T, predicate func(T) bool) []T {
	result := make([]T, 0, len(slice))
	for _, v := range slice {
		if predicate(v) {
			result = append(result, v)
		}
	}
	return result
}

// Map transforms each element of the slice using the provided function.
func Map[T, U any](slice []T, transform func(T) U) []U {
	result := make([]U, len(slice))
	for i, v := range slice {
		result[i] = transform(v)
	}
	return result
}

// Contains returns true if the slice contains the given element.
func Contains[T comparable](slice []T, element T) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}
	return false
}

// Remove returns a new slice with all occurrences of the element removed.
func Remove[T comparable](slice []T, element T) []T {
	return Filter(slice, func(v T) bool {
		return v != element
	})
}

// MoveToFront removes all occurrences of element from the slice and prepends it.
// This is useful for "recently used" lists.
func MoveToFront[T comparable](slice []T, element T) []T {
	filtered := Remove(slice, element)
	return append([]T{element}, filtered...)
}

// FindIndex returns the index of the first element satisfying the predicate, or -1.
func FindIndex[T any](slice []T, predicate func(T) bool) int {
	for i, v := range slice {
		if predicate(v) {
			return i
		}
	}
	return -1
}

// First returns the first element satisfying the predicate, or the zero value.
func First[T any](slice []T, predicate func(T) bool) (T, bool) {
	for _, v := range slice {
		if predicate(v) {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// Keys returns the keys of a map as a slice.
func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Values returns the values of a map as a slice.
func Values[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}
