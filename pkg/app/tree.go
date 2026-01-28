// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package app

// TreeNode represents a node in a packet structure tree that has position and size
// information for finding nodes that contain a given byte offset.
type TreeNode interface {
	// GetPos returns the byte position in the packet where this node's data starts.
	GetPos() int
	// GetSize returns the size in bytes of this node's data.
	GetSize() int
	// GetChildren returns the child nodes.
	GetChildren() []TreeNode
}

// TreePathResult contains the result of finding a path to a position in the tree.
type TreePathResult struct {
	// Path contains the indices at each level of the tree to reach the target node.
	Path []int
	// Found indicates whether a node containing the position was found.
	Found bool
}

// FindPathToPosition finds the path through the tree to the deepest node
// that contains the given byte position. The algorithm starts at the root
// and descends through children until no child contains the position.
//
// The skipFirst parameter controls how many children to skip at the root level.
// This is typically 1 because the first node often covers the entire packet.
//
// Parameters:
//   - children: the child nodes to search through
//   - position: the byte offset position to find
//   - skipFirst: number of children to skip at the root level (usually 1)
//
// Returns:
//   - TreePathResult with the path indices and whether a match was found
func FindPathToPosition(children []TreeNode, position, skipFirst int) TreePathResult {
	result := TreePathResult{
		Path:  make([]int, 0),
		Found: false,
	}

	if len(children) == 0 {
		return result
	}

	currentChildren := children
	currentSkip := skipFirst

	for {
		chosenIdx := -1
		var chosenNode TreeNode

		// Search through children (after skip) for one that contains the position
		for i, child := range currentChildren[currentSkip:] {
			if child.GetPos() <= position && position < child.GetPos()+child.GetSize() {
				// Save the current best match, but keep looking - nodes may not be
				// sorted by position, so we want to find the best fit
				chosenNode = child
				chosenIdx = i
			}
		}

		if chosenNode == nil {
			// No child contains the position
			break
		}

		// Found a match - record the index (accounting for skipped children)
		result.Path = append(result.Path, chosenIdx+currentSkip)
		result.Found = true

		// Descend into this node
		currentChildren = chosenNode.GetChildren()
		currentSkip = 0 // Only skip at root level
	}

	return result
}

// FindDeepestContainingNode finds the deepest node in the tree that contains
// the given byte position. Returns nil if no node contains the position.
//
// Parameters:
//   - children: the child nodes to search through
//   - position: the byte offset position to find
//   - skipFirst: number of children to skip at the root level
func FindDeepestContainingNode(children []TreeNode, position, skipFirst int) TreeNode {
	if len(children) == 0 {
		return nil
	}

	var deepest TreeNode
	currentChildren := children
	currentSkip := skipFirst

	for {
		var chosenNode TreeNode

		for _, child := range currentChildren[currentSkip:] {
			if child.GetPos() <= position && position < child.GetPos()+child.GetSize() {
				chosenNode = child
			}
		}

		if chosenNode == nil {
			break
		}

		deepest = chosenNode
		currentChildren = chosenNode.GetChildren()
		currentSkip = 0
	}

	return deepest
}

// NodeContainsPosition returns true if the given position falls within
// the node's range [pos, pos+size).
func NodeContainsPosition(nodePos, nodeSize, position int) bool {
	return nodePos <= position && position < nodePos+nodeSize
}

// FindAllContainingNodes returns all nodes at any level that contain
// the given position. The result is ordered from root towards leaves.
//
// Parameters:
//   - children: the child nodes to search through
//   - position: the byte offset position to find
//   - skipFirst: number of children to skip at the root level
func FindAllContainingNodes(children []TreeNode, position, skipFirst int) []TreeNode {
	result := make([]TreeNode, 0)

	if len(children) == 0 {
		return result
	}

	currentChildren := children
	currentSkip := skipFirst

	for {
		var chosenNode TreeNode

		for _, child := range currentChildren[currentSkip:] {
			if NodeContainsPosition(child.GetPos(), child.GetSize(), position) {
				chosenNode = child
			}
		}

		if chosenNode == nil {
			break
		}

		result = append(result, chosenNode)
		currentChildren = chosenNode.GetChildren()
		currentSkip = 0
	}

	return result
}

// SimpleTreeNode is a simple implementation of TreeNode for testing.
type SimpleTreeNode struct {
	Pos      int
	Size     int
	Children []*SimpleTreeNode
}

// GetPos implements TreeNode.
func (n *SimpleTreeNode) GetPos() int {
	return n.Pos
}

// GetSize implements TreeNode.
func (n *SimpleTreeNode) GetSize() int {
	return n.Size
}

// GetChildren implements TreeNode.
func (n *SimpleTreeNode) GetChildren() []TreeNode {
	result := make([]TreeNode, len(n.Children))
	for i, c := range n.Children {
		result[i] = c
	}
	return result
}
