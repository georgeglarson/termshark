// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import "context"

// Backend defines the interface for packet analysis backends.
// Implementations include SharkdBackend (using sharkd) and TsharkBackend
// (using tshark directly with PSML/PDML parsing).
type Backend interface {
	// LoadFile loads a pcap file for analysis.
	LoadFile(ctx context.Context, path string) error

	// GetStatus returns the current status of the loaded file.
	GetStatus(ctx context.Context) (*Status, error)

	// GetPackets returns packet summaries for the given range.
	// If filter is non-empty, only matching packets are returned.
	// start is 0-based, count is the maximum number to return.
	GetPackets(ctx context.Context, filter string, start, count int) ([]PacketSummary, error)

	// GetPacketDetail returns the full detail for a single packet.
	// num is 1-based packet number.
	GetPacketDetail(ctx context.Context, num int) (*PacketDetail, error)

	// ValidateFilter checks if a display filter is valid.
	ValidateFilter(ctx context.Context, filter string) (*FilterValidation, error)

	// GetStreamInfo returns information about available streams.
	GetStreamInfo(ctx context.Context, protocol string) ([]StreamInfo, error)

	// FollowStream returns the reassembled data for a stream.
	FollowStream(ctx context.Context, protocol string, streamIndex int) ([]byte, error)

	// Close releases resources associated with the backend.
	Close() error
}

// BackendFactory creates Backend instances.
type BackendFactory interface {
	// Create creates a new Backend instance.
	Create(ctx context.Context) (Backend, error)

	// Name returns the name of this backend type.
	Name() string

	// Available returns true if this backend is available on the system.
	Available() bool
}
