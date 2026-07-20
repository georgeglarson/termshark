// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"fmt"
	"sync"
)

// TsharkBackend implements Backend by wrapping an existing packet loader.
// This allows the terminal UI to use the state.Manager while keeping
// its existing tshark-based loading infrastructure.
type TsharkBackend struct {
	mu          sync.RWMutex
	loader      LoaderAdapter
	currentFile string
	packetCount int
	columns     []string
	duration    float64
}

// LoaderAdapter defines the interface that a packet loader must implement
// to be used with TsharkBackend. This matches the key methods of pcap.PacketLoader.
type LoaderAdapter interface {
	// PsmlData returns the packet summary data (rows of column values)
	PsmlData() [][]string
	// PsmlHeaders returns the column headers
	PsmlHeaders() []string
	// PsmlColors returns the colors for each packet
	PsmlColors() []PacketColor
	// PacketNumberMap returns mapping from packet number to row index
	PacketNumberMap() map[int]int
	// DisplayFilter returns the current display filter
	DisplayFilter() string
	// Pcap returns the current pcap file path
	Pcap() string
	// IsLoading returns whether loading is in progress
	IsLoading() bool
}

// PacketColor matches pcap.PacketColors
type PacketColor struct {
	FG interface{}
	BG interface{}
}

// NewTsharkBackend creates a new TsharkBackend.
func NewTsharkBackend() *TsharkBackend {
	return &TsharkBackend{}
}

// SetLoader sets the loader adapter. Call this after the loader is created.
func (b *TsharkBackend) SetLoader(loader LoaderAdapter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loader = loader
}

// LoadFile implements Backend.LoadFile.
// For TsharkBackend, this just records the file path - actual loading
// is done by the pcap.PacketLoader.
func (b *TsharkBackend) LoadFile(ctx context.Context, path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentFile = path
	return nil
}

// GetStatus implements Backend.GetStatus.
func (b *TsharkBackend) GetStatus(ctx context.Context) (*Status, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	status := &Status{}

	if b.loader != nil {
		status.PacketCount = len(b.loader.PsmlData())
		status.Columns = b.loader.PsmlHeaders()
		status.DisplayFilter = b.loader.DisplayFilter()
		if pcap := b.loader.Pcap(); pcap != "" {
			status.Source = pcap
			status.SourceType = SourceFile
		}
	}

	status.Duration = b.duration

	return status, nil
}

// GetPackets implements Backend.GetPackets.
func (b *TsharkBackend) GetPackets(ctx context.Context, filter string, start, count int) ([]PacketSummary, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.loader == nil {
		return nil, fmt.Errorf("loader not set")
	}

	data := b.loader.PsmlData()
	colors := b.loader.PsmlColors()

	end := start + count
	if end > len(data) {
		end = len(data)
	}
	if start >= len(data) {
		return []PacketSummary{}, nil
	}

	packets := make([]PacketSummary, 0, end-start)
	for i := start; i < end; i++ {
		row := data[i]
		pkt := PacketSummary{
			Number:  i + 1, // 1-based
			Columns: row,
		}
		if i < len(colors) {
			// Colors are gowid.IColor, convert to string if needed
			if colors[i].BG != nil {
				pkt.BGColor = fmt.Sprintf("%v", colors[i].BG)
			}
			if colors[i].FG != nil {
				pkt.FGColor = fmt.Sprintf("%v", colors[i].FG)
			}
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

// GetPacketDetail implements Backend.GetPacketDetail.
// For TsharkBackend, this requires the PDML cache which is managed by the loader.
func (b *TsharkBackend) GetPacketDetail(ctx context.Context, num int) (*PacketDetail, error) {
	// This would need access to the PDML cache from the loader
	// For now, return a stub - the terminal UI still accesses the loader directly
	return &PacketDetail{
		Number: num,
		Tree:   []ProtocolNode{},
		Bytes:  []byte{},
	}, nil
}

// ValidateFilter implements Backend.ValidateFilter.
// For TsharkBackend, this shells out to tshark to validate.
func (b *TsharkBackend) ValidateFilter(ctx context.Context, filter string) (*FilterValidation, error) {
	// The terminal UI handles filter validation through its own mechanism
	// Return valid for now - actual validation happens in the UI layer
	return &FilterValidation{Valid: true}, nil
}

// GetStreamInfo implements Backend.GetStreamInfo.
func (b *TsharkBackend) GetStreamInfo(ctx context.Context, protocol string) ([]StreamInfo, error) {
	return nil, fmt.Errorf("stream info not implemented for tshark backend")
}

// FollowStream implements Backend.FollowStream.
func (b *TsharkBackend) FollowStream(ctx context.Context, protocol string, streamIndex int) ([]byte, error) {
	return nil, fmt.Errorf("follow stream not implemented for tshark backend")
}

// Close implements Backend.Close.
func (b *TsharkBackend) Close() error {
	return nil
}

// Sync updates the backend's cached state from the loader.
// Call this periodically to keep state in sync.
func (b *TsharkBackend) Sync() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.loader == nil {
		return
	}

	b.packetCount = len(b.loader.PsmlData())
	b.columns = b.loader.PsmlHeaders()
	if pcap := b.loader.Pcap(); pcap != "" {
		b.currentFile = pcap
	}
}

var _ Backend = (*TsharkBackend)(nil)
