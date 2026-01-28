// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

// CalculatePrefetchRequests determines which packet batches should be loaded
// based on the current row position. It returns a list of LoadRequests, where
// the first request is for the current batch (with CancelCurrent=true) and
// the second request is for an adjacent batch for optimistic prefetching.
//
// The prefetch strategy is:
// - If the current position is in the lower half of a batch, prefetch the previous batch
// - If the current position is in the upper half of a batch, prefetch the next batch
//
// Parameters:
//   - currentRow: the current packet row index (0-based)
//   - pktsPerLoad: the number of packets loaded in each batch (e.g., 1000)
//
// Returns:
//   - A slice of LoadRequests to be processed
func CalculatePrefetchRequests(currentRow, pktsPerLoad int) []LoadRequest {
	if pktsPerLoad <= 0 {
		return nil
	}

	requests := make([]LoadRequest, 0, 2)

	// Calculate the starting row of the current batch
	batchIndex := currentRow / pktsPerLoad
	currentBatchStart := batchIndex * pktsPerLoad

	// First request: load the current batch with cancel flag
	requests = append(requests, LoadRequest{
		Row:           currentBatchStart,
		CancelCurrent: true,
	})

	// Calculate position within the current batch
	positionInBatch := currentRow % pktsPerLoad

	// Determine which adjacent batch to prefetch
	if positionInBatch > pktsPerLoad/2 {
		// In upper half of batch - prefetch the next batch
		nextBatchStart := (batchIndex + 1) * pktsPerLoad
		requests = append(requests, LoadRequest{
			Row:           nextBatchStart,
			CancelCurrent: false,
		})
	} else {
		// In lower half of batch - prefetch the previous batch
		prevBatchStart := (batchIndex - 1) * pktsPerLoad
		if prevBatchStart < 0 {
			prevBatchStart = 0
		}
		requests = append(requests, LoadRequest{
			Row:           prevBatchStart,
			CancelCurrent: false,
		})
	}

	return requests
}

// BatchStartForRow returns the starting row index for the batch containing
// the given row.
func BatchStartForRow(row, pktsPerLoad int) int {
	if pktsPerLoad <= 0 {
		return 0
	}
	return (row / pktsPerLoad) * pktsPerLoad
}

// BatchIndexForRow returns the batch index (0-based) for the given row.
func BatchIndexForRow(row, pktsPerLoad int) int {
	if pktsPerLoad <= 0 {
		return 0
	}
	return row / pktsPerLoad
}

// PositionInBatch returns the position (0-based) of the row within its batch.
func PositionInBatch(row, pktsPerLoad int) int {
	if pktsPerLoad <= 0 {
		return 0
	}
	return row % pktsPerLoad
}

// IsInUpperHalfOfBatch returns true if the row is in the upper half of its batch.
func IsInUpperHalfOfBatch(row, pktsPerLoad int) bool {
	if pktsPerLoad <= 0 {
		return false
	}
	return (row % pktsPerLoad) > pktsPerLoad/2
}

// ShouldPrefetchNext returns true if the prefetch strategy should load
// the next batch (as opposed to the previous batch).
func ShouldPrefetchNext(currentRow, pktsPerLoad int) bool {
	return IsInUpperHalfOfBatch(currentRow, pktsPerLoad)
}

// CalculateAdjacentBatch returns the starting row of the batch to prefetch.
// This is either the next or previous batch depending on the current position.
func CalculateAdjacentBatch(currentRow, pktsPerLoad int) int {
	if pktsPerLoad <= 0 {
		return 0
	}

	batchIndex := currentRow / pktsPerLoad

	if ShouldPrefetchNext(currentRow, pktsPerLoad) {
		return (batchIndex + 1) * pktsPerLoad
	}

	prevBatchStart := (batchIndex - 1) * pktsPerLoad
	if prevBatchStart < 0 {
		return 0
	}
	return prevBatchStart
}
