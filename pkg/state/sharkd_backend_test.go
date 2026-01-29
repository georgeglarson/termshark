// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertTreeNode_Basic(t *testing.T) {
	node := sharkdTreeNode{
		Label:    "Ethernet II",
		Field:    "eth",
		HexRange: json.RawMessage(`[0, 14]`),
	}

	result := convertTreeNode(node)
	assert.Equal(t, "Ethernet II", result.Label)
	assert.Equal(t, "eth", result.Field)
	assert.Equal(t, 0, result.Position)
	assert.Equal(t, 14, result.Size)
	assert.Nil(t, result.Children)
}

func TestConvertTreeNode_WithChildren(t *testing.T) {
	node := sharkdTreeNode{
		Label:    "Internet Protocol",
		Field:    "ip",
		HexRange: json.RawMessage(`[14, 20]`),
		Children: []sharkdTreeNode{
			{
				Label:    "Source Address",
				Field:    "ip.src",
				HexRange: json.RawMessage(`[26, 4]`),
			},
			{
				Label:    "Destination Address",
				Field:    "ip.dst",
				HexRange: json.RawMessage(`[30, 4]`),
			},
		},
	}

	result := convertTreeNode(node)
	assert.Equal(t, "Internet Protocol", result.Label)
	assert.Equal(t, 14, result.Position)
	assert.Equal(t, 20, result.Size)

	require.Len(t, result.Children, 2)
	assert.Equal(t, "Source Address", result.Children[0].Label)
	assert.Equal(t, "ip.src", result.Children[0].Field)
	assert.Equal(t, 26, result.Children[0].Position)
	assert.Equal(t, 4, result.Children[0].Size)

	assert.Equal(t, "Destination Address", result.Children[1].Label)
	assert.Equal(t, 30, result.Children[1].Position)
}

func TestConvertTreeNode_NoHexRange(t *testing.T) {
	node := sharkdTreeNode{
		Label: "Frame",
		Field: "frame",
	}

	result := convertTreeNode(node)
	assert.Equal(t, "Frame", result.Label)
	assert.Equal(t, 0, result.Position)
	assert.Equal(t, 0, result.Size)
}

func TestConvertTreeNode_FourElementHexRange(t *testing.T) {
	// sharkd can return [offset, size, bit_offset, bit_size]
	node := sharkdTreeNode{
		Label:    "Version",
		Field:    "ip.version",
		HexRange: json.RawMessage(`[14, 1, 0, 4]`),
	}

	result := convertTreeNode(node)
	assert.Equal(t, 14, result.Position)
	assert.Equal(t, 1, result.Size)
}

func TestConvertTreeNode_InvalidHexRange(t *testing.T) {
	// Invalid JSON in HexRange should not crash
	node := sharkdTreeNode{
		Label:    "Bad Node",
		HexRange: json.RawMessage(`"not an array"`),
	}

	result := convertTreeNode(node)
	assert.Equal(t, "Bad Node", result.Label)
	assert.Equal(t, 0, result.Position)
	assert.Equal(t, 0, result.Size)
}

func TestConvertTreeNode_ShortHexRange(t *testing.T) {
	// HexRange with only one element (less than required 2)
	node := sharkdTreeNode{
		Label:    "Short",
		HexRange: json.RawMessage(`[42]`),
	}

	result := convertTreeNode(node)
	assert.Equal(t, 0, result.Position)
	assert.Equal(t, 0, result.Size)
}

func TestConvertTreeNode_EmptyHexRange(t *testing.T) {
	node := sharkdTreeNode{
		Label:    "Empty",
		HexRange: json.RawMessage(`[]`),
	}

	result := convertTreeNode(node)
	assert.Equal(t, 0, result.Position)
	assert.Equal(t, 0, result.Size)
}

func TestConvertTreeNode_DeepNesting(t *testing.T) {
	node := sharkdTreeNode{
		Label: "L1",
		Children: []sharkdTreeNode{
			{
				Label: "L2",
				Children: []sharkdTreeNode{
					{
						Label:    "L3",
						HexRange: json.RawMessage(`[100, 50]`),
					},
				},
			},
		},
	}

	result := convertTreeNode(node)
	require.Len(t, result.Children, 1)
	require.Len(t, result.Children[0].Children, 1)
	assert.Equal(t, "L3", result.Children[0].Children[0].Label)
	assert.Equal(t, 100, result.Children[0].Children[0].Position)
	assert.Equal(t, 50, result.Children[0].Children[0].Size)
}

func TestSharkdBackendFactory_Name(t *testing.T) {
	f := &SharkdBackendFactory{}
	assert.Equal(t, "sharkd", f.Name())
	// Available() depends on sharkd being in PATH, just ensure it doesn't crash
	_ = f.Available()
}
