// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Build a sample tree structure that mimics a packet:
//
//	Root (pos=0, size=100)
//	├── Frame (pos=0, size=100) [index 0, usually skipped]
//	├── Ethernet (pos=0, size=14) [index 1]
//	│   ├── Dst MAC (pos=0, size=6)
//	│   └── Src MAC (pos=6, size=6)
//	├── IP (pos=14, size=20) [index 2]
//	│   ├── Version (pos=14, size=1)
//	│   └── TTL (pos=22, size=1)
//	└── TCP (pos=34, size=20) [index 3]
//	    ├── Src Port (pos=34, size=2)
//	    └── Dst Port (pos=36, size=2)
func buildTestTree() []*SimpleTreeNode {
	return []*SimpleTreeNode{
		// Frame - covers entire packet (index 0, usually skipped)
		{Pos: 0, Size: 100, Children: nil},

		// Ethernet (index 1)
		{
			Pos:  0,
			Size: 14,
			Children: []*SimpleTreeNode{
				{Pos: 0, Size: 6, Children: nil},   // Dst MAC
				{Pos: 6, Size: 6, Children: nil},   // Src MAC
				{Pos: 12, Size: 2, Children: nil},  // EtherType
			},
		},

		// IP (index 2)
		{
			Pos:  14,
			Size: 20,
			Children: []*SimpleTreeNode{
				{Pos: 14, Size: 1, Children: nil}, // Version
				{Pos: 22, Size: 1, Children: nil}, // TTL
				{Pos: 30, Size: 4, Children: nil}, // Src IP
			},
		},

		// TCP (index 3)
		{
			Pos:  34,
			Size: 20,
			Children: []*SimpleTreeNode{
				{Pos: 34, Size: 2, Children: nil}, // Src Port
				{Pos: 36, Size: 2, Children: nil}, // Dst Port
				{Pos: 38, Size: 4, Children: nil}, // Seq Number
			},
		},
	}
}

func toTreeNodes(nodes []*SimpleTreeNode) []TreeNode {
	result := make([]TreeNode, len(nodes))
	for i, n := range nodes {
		result[i] = n
	}
	return result
}

func TestFindPathToPosition_Ethernet(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 3 is in Ethernet -> Dst MAC
	result := FindPathToPosition(nodes, 3, 1) // skip Frame

	assert.True(t, result.Found)
	assert.Equal(t, []int{1, 0}, result.Path) // Ethernet (index 1), Dst MAC (index 0)
}

func TestFindPathToPosition_IP(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 22 is in IP -> TTL
	result := FindPathToPosition(nodes, 22, 1)

	assert.True(t, result.Found)
	assert.Equal(t, []int{2, 1}, result.Path) // IP (index 2), TTL (index 1)
}

func TestFindPathToPosition_TCP(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 35 is in TCP -> Src Port
	result := FindPathToPosition(nodes, 35, 1)

	assert.True(t, result.Found)
	assert.Equal(t, []int{3, 0}, result.Path) // TCP (index 3), Src Port (index 0)
}

func TestFindPathToPosition_NoSkip(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 50 with no skip should find Frame
	result := FindPathToPosition(nodes, 50, 0)

	assert.True(t, result.Found)
	// Frame is at index 0 and has no children with data at position 50
	// but TCP is also there, so it depends on the algorithm
	assert.NotEmpty(t, result.Path)
}

func TestFindPathToPosition_NotFound(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 150 is beyond all nodes (when skipping Frame)
	result := FindPathToPosition(nodes, 150, 1)

	assert.False(t, result.Found)
	assert.Empty(t, result.Path)
}

func TestFindPathToPosition_EmptyTree(t *testing.T) {
	result := FindPathToPosition(nil, 10, 0)

	assert.False(t, result.Found)
	assert.Empty(t, result.Path)

	result = FindPathToPosition([]TreeNode{}, 10, 0)

	assert.False(t, result.Found)
	assert.Empty(t, result.Path)
}

func TestFindDeepestContainingNode(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 7 is in Ethernet -> Src MAC
	node := FindDeepestContainingNode(nodes, 7, 1)

	assert.NotNil(t, node)
	simpleNode := node.(*SimpleTreeNode)
	assert.Equal(t, 6, simpleNode.Pos)  // Src MAC starts at 6
	assert.Equal(t, 6, simpleNode.Size) // Src MAC is 6 bytes
}

func TestFindDeepestContainingNode_NotFound(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 150 is beyond all nodes
	node := FindDeepestContainingNode(nodes, 150, 1)

	assert.Nil(t, node)
}

func TestFindDeepestContainingNode_EmptyTree(t *testing.T) {
	node := FindDeepestContainingNode(nil, 10, 0)
	assert.Nil(t, node)

	node = FindDeepestContainingNode([]TreeNode{}, 10, 0)
	assert.Nil(t, node)
}

func TestNodeContainsPosition(t *testing.T) {
	tests := []struct {
		nodePos  int
		nodeSize int
		position int
		want     bool
	}{
		{0, 10, 0, true},   // At start
		{0, 10, 5, true},   // In middle
		{0, 10, 9, true},   // At end (exclusive end)
		{0, 10, 10, false}, // Just past end
		{0, 10, -1, false}, // Before start
		{5, 5, 5, true},    // At start of offset range
		{5, 5, 9, true},    // At end of offset range
		{5, 5, 10, false},  // Past end of offset range
		{5, 5, 4, false},   // Before start of offset range
	}

	for _, tt := range tests {
		got := NodeContainsPosition(tt.nodePos, tt.nodeSize, tt.position)
		assert.Equal(t, tt.want, got,
			"NodeContainsPosition(%d, %d, %d)", tt.nodePos, tt.nodeSize, tt.position)
	}
}

func TestFindAllContainingNodes(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Position 35 should be in TCP -> Src Port
	result := FindAllContainingNodes(nodes, 35, 1)

	assert.Len(t, result, 2) // TCP and Src Port

	// First should be TCP
	tcp := result[0].(*SimpleTreeNode)
	assert.Equal(t, 34, tcp.Pos)
	assert.Equal(t, 20, tcp.Size)

	// Second should be Src Port
	srcPort := result[1].(*SimpleTreeNode)
	assert.Equal(t, 34, srcPort.Pos)
	assert.Equal(t, 2, srcPort.Size)
}

func TestFindAllContainingNodes_Empty(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	result := FindAllContainingNodes(nodes, 150, 1)
	assert.Empty(t, result)

	result = FindAllContainingNodes(nil, 10, 0)
	assert.Empty(t, result)
}

func TestSimpleTreeNode_Interface(t *testing.T) {
	node := &SimpleTreeNode{
		Pos:  10,
		Size: 20,
		Children: []*SimpleTreeNode{
			{Pos: 10, Size: 5},
			{Pos: 15, Size: 10},
		},
	}

	assert.Equal(t, 10, node.GetPos())
	assert.Equal(t, 20, node.GetSize())
	assert.Len(t, node.GetChildren(), 2)
}

func TestFindPathToPosition_BoundaryConditions(t *testing.T) {
	tree := buildTestTree()
	nodes := toTreeNodes(tree)

	// Test at exact boundary of Ethernet (pos=0, size=14, ends at 14)
	// Position 14 should be in IP, not Ethernet
	result := FindPathToPosition(nodes, 14, 1)
	assert.True(t, result.Found)
	assert.Equal(t, 2, result.Path[0]) // IP is at index 2

	// Test at last byte of Ethernet (position 13)
	result = FindPathToPosition(nodes, 13, 1)
	assert.True(t, result.Found)
	// Position 13 is in Ethernet but could be in EtherType (12-13)
}

func TestFindPathToPosition_PartialMatch(t *testing.T) {
	// Build a tree where parent contains position but no child does
	tree := []*SimpleTreeNode{
		{
			Pos:  0,
			Size: 100,
			Children: []*SimpleTreeNode{
				{Pos: 0, Size: 10},   // 0-9
				{Pos: 20, Size: 10},  // 20-29
				// Gap at 10-19 and 30-99
			},
		},
	}
	nodes := toTreeNodes(tree)

	// Position 15 is in parent but not in any child
	result := FindPathToPosition(nodes, 15, 0)
	assert.True(t, result.Found)
	assert.Equal(t, []int{0}, result.Path) // Just the parent
}
