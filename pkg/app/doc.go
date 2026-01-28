// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

/*
Package app provides business logic extracted from the UI layer of termshark.

This package implements the separation of concerns between the presentation
layer (ui/) and the application logic, following the Unix principle of
"separation of policy from mechanism."

# Architecture

The package is organized into several components:

State (state.go) contains the application state that was previously scattered
across global variables in ui/ui.go. This includes:
  - Packet navigation state (current packet, struct position)
  - Marks for vim-like navigation (local and global)
  - Display settings (auto-scroll, dark mode, packet colors)
  - Loading state (current filter, current pcap)

Prefetch (prefetch.go) contains pure algorithms for calculating which packet
batches to load based on the current position. This enables optimistic loading
of adjacent batches for smoother navigation.

Tree (tree.go) contains pure algorithms for navigating the packet structure
tree, finding paths to positions, and determining which nodes contain a given
byte offset.

Filters (filters.go) contains pure functions for building and combining
display filter expressions, used by the conversations view and PDML context
menu.

Marks (marks.go) contains the logic for vim-like mark functionality,
including setting, jumping to, and managing local and global marks.

Controller (controller.go) provides the bridge between State and the UI layer.
It coordinates state changes and emits events that the UI can react to.

# Usage

The UI layer should create a Controller and register callbacks:

	c := app.NewController()
	c.SetOnStateChange(func(e app.StateChangeEvent) {
	    // Update UI based on state change
	})
	c.SetOnLoadRequest(func(e app.LoadRequestEvent) {
	    // Trigger packet data loading
	})

Then use the Controller methods to handle user actions:

	// When user navigates to a packet
	c.SetCurrentPacket(packetNum)

	// When user sets a mark
	c.SetMarkAtCurrentPacket('a', "packet summary")

	// When user jumps to a mark
	target, err := c.JumpToMark('a')

# Testing

All components in this package are designed to be testable without a terminal.
Pure functions can be tested directly:

	requests := app.CalculatePrefetchRequests(500, 1000)
	filter := app.CombineFilters(app.CombAndSelected, "tcp", "ip.addr == 1.2.3.4")

The Controller can be tested by inspecting events:

	c := app.NewController()
	var events []app.StateChangeEvent
	c.SetOnStateChange(func(e app.StateChangeEvent) {
	    events = append(events, e)
	})
	c.SetCurrentPacket(100)
	// Assert on events

# Migration from UI

This package extracts logic from the following ui/ globals and functions:
  - marksMap, globalMarksMap, lastJumpPos -> State.LocalMarks, State.GlobalMarks
  - AutoScroll, DarkMode, PacketColors -> State.AutoScroll, etc.
  - CacheRequests, prefetch logic -> CalculatePrefetchRequests
  - ComputeConvFilterOp, ComputeFilterCombOp -> ComputeConversationFilter, CombineFilters
  - expandStructWidgetAtPosition logic -> FindPathToPosition

The UI layer should gradually migrate to using the Controller instead of
direct global variable access.
*/
package app
