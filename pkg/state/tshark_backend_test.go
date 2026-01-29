// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockLoaderAdapter implements LoaderAdapter for testing.
type mockLoaderAdapter struct {
	psmlData        [][]string
	psmlHeaders     []string
	psmlColors      []PacketColor
	packetNumberMap map[int]int
	displayFilter   string
	pcap            string
	isLoading       bool
}

func (m *mockLoaderAdapter) PsmlData() [][]string        { return m.psmlData }
func (m *mockLoaderAdapter) PsmlHeaders() []string       { return m.psmlHeaders }
func (m *mockLoaderAdapter) PsmlColors() []PacketColor   { return m.psmlColors }
func (m *mockLoaderAdapter) PacketNumberMap() map[int]int { return m.packetNumberMap }
func (m *mockLoaderAdapter) DisplayFilter() string       { return m.displayFilter }
func (m *mockLoaderAdapter) Pcap() string                { return m.pcap }
func (m *mockLoaderAdapter) IsLoading() bool             { return m.isLoading }

func TestNewTsharkBackend(t *testing.T) {
	backend := NewTsharkBackend()
	assert.NotNil(t, backend)
}

func TestTsharkBackend_SetLoader(t *testing.T) {
	backend := NewTsharkBackend()
	loader := &mockLoaderAdapter{pcap: "test.pcap"}

	backend.SetLoader(loader)

	status, err := backend.GetStatus(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "test.pcap", status.Source)
}

func TestTsharkBackend_GetStatus(t *testing.T) {
	backend := NewTsharkBackend()
	loader := &mockLoaderAdapter{
		psmlData:      [][]string{{"1", "0.0", "10.0.0.1"}, {"2", "0.1", "10.0.0.2"}},
		psmlHeaders:   []string{"No.", "Time", "Source"},
		displayFilter: "tcp",
		pcap:          "/path/to/file.pcap",
	}
	backend.SetLoader(loader)

	status, err := backend.GetStatus(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, status.PacketCount)
	assert.Equal(t, []string{"No.", "Time", "Source"}, status.Columns)
	assert.Equal(t, "tcp", status.DisplayFilter)
	assert.Equal(t, "/path/to/file.pcap", status.Source)
	assert.Equal(t, SourceFile, status.SourceType)
}

func TestTsharkBackend_GetPackets(t *testing.T) {
	backend := NewTsharkBackend()
	loader := &mockLoaderAdapter{
		psmlData: [][]string{
			{"1", "0.0", "10.0.0.1"},
			{"2", "0.1", "10.0.0.2"},
			{"3", "0.2", "10.0.0.3"},
		},
		psmlColors: []PacketColor{
			{FG: "white", BG: "blue"},
			{FG: "black", BG: "green"},
			{FG: nil, BG: nil},
		},
	}
	backend.SetLoader(loader)

	packets, err := backend.GetPackets(context.Background(), "", 0, 2)
	assert.NoError(t, err)
	assert.Len(t, packets, 2)
	assert.Equal(t, 1, packets[0].Number)
	assert.Equal(t, []string{"1", "0.0", "10.0.0.1"}, packets[0].Columns)
	assert.Equal(t, "blue", packets[0].BGColor)
}

func TestTsharkBackend_GetPackets_Pagination(t *testing.T) {
	backend := NewTsharkBackend()
	loader := &mockLoaderAdapter{
		psmlData: [][]string{
			{"1", "0.0", "10.0.0.1"},
			{"2", "0.1", "10.0.0.2"},
			{"3", "0.2", "10.0.0.3"},
		},
	}
	backend.SetLoader(loader)

	// Test offset
	packets, err := backend.GetPackets(context.Background(), "", 1, 2)
	assert.NoError(t, err)
	assert.Len(t, packets, 2)
	assert.Equal(t, 2, packets[0].Number)

	// Test beyond bounds
	packets, err = backend.GetPackets(context.Background(), "", 10, 5)
	assert.NoError(t, err)
	assert.Len(t, packets, 0)
}

func TestTsharkBackend_GetPackets_NoLoader(t *testing.T) {
	backend := NewTsharkBackend()

	_, err := backend.GetPackets(context.Background(), "", 0, 10)
	assert.Error(t, err)
}

func TestTsharkBackend_LoadFile(t *testing.T) {
	backend := NewTsharkBackend()

	err := backend.LoadFile(context.Background(), "/path/to/file.pcap")
	assert.NoError(t, err)
}

func TestTsharkBackend_ValidateFilter(t *testing.T) {
	backend := NewTsharkBackend()

	result, err := backend.ValidateFilter(context.Background(), "tcp")
	assert.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestTsharkBackend_Close(t *testing.T) {
	backend := NewTsharkBackend()
	err := backend.Close()
	assert.NoError(t, err)
}

func TestTsharkBackend_Sync(t *testing.T) {
	backend := NewTsharkBackend()
	loader := &mockLoaderAdapter{
		psmlData:    [][]string{{"1"}, {"2"}, {"3"}},
		psmlHeaders: []string{"No."},
		pcap:        "test.pcap",
	}
	backend.SetLoader(loader)

	backend.Sync()

	status, _ := backend.GetStatus(context.Background())
	assert.Equal(t, 3, status.PacketCount)
}
