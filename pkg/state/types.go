// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package state provides centralized state management for termshark.
// Both terminal and web UIs connect to the state manager via JSON-RPC,
// ensuring consistent behavior regardless of UI technology.
package state

import "time"

// SourceType indicates the type of packet source.
type SourceType int

const (
	SourceNone SourceType = iota
	SourceFile
	SourceInterface
	SourceStdin
)

func (s SourceType) String() string {
	switch s {
	case SourceFile:
		return "file"
	case SourceInterface:
		return "interface"
	case SourceStdin:
		return "stdin"
	default:
		return "none"
	}
}

// PacketSummary represents a single row in the packet list (PSML).
type PacketSummary struct {
	Number  int      `json:"num"`
	Columns []string `json:"columns"`
	Marked  bool     `json:"marked,omitempty"`
	Ignored bool     `json:"ignored,omitempty"`
	BGColor string   `json:"bg,omitempty"`
	FGColor string   `json:"fg,omitempty"`
}

// PacketDetail represents the detailed view of a single packet (PDML + bytes).
type PacketDetail struct {
	Number int            `json:"num"`
	Tree   []ProtocolNode `json:"tree"`
	Bytes  []byte         `json:"bytes"`
}

// ProtocolNode represents a node in the packet detail tree.
type ProtocolNode struct {
	Label    string         `json:"label"`
	Field    string         `json:"field,omitempty"`
	Value    string         `json:"value,omitempty"`
	Position int            `json:"pos,omitempty"`
	Size     int            `json:"size,omitempty"`
	Children []ProtocolNode `json:"children,omitempty"`
}

// Status represents the current session status.
type Status struct {
	Source         string     `json:"source"`
	SourceType     SourceType `json:"sourceType"`
	PacketCount    int        `json:"packetCount"`
	DisplayFilter  string     `json:"displayFilter"`
	FilteredCount  int        `json:"filteredCount"`
	CaptureRunning bool       `json:"captureRunning"`
	Duration       float64    `json:"duration"`
	Columns        []string   `json:"columns"`
}

// ChangeType indicates the type of state change for subscribers.
type ChangeType int

const (
	ChangePacketsAdded ChangeType = iota
	ChangePacketsCleared
	ChangeFilterChanged
	ChangeSelectionChanged
	ChangeCaptureStarted
	ChangeCaptureStopped
	ChangeSourceChanged
	ChangeError
)

func (c ChangeType) String() string {
	switch c {
	case ChangePacketsAdded:
		return "packetsAdded"
	case ChangePacketsCleared:
		return "packetsCleared"
	case ChangeFilterChanged:
		return "filterChanged"
	case ChangeSelectionChanged:
		return "selectionChanged"
	case ChangeCaptureStarted:
		return "captureStarted"
	case ChangeCaptureStopped:
		return "captureStopped"
	case ChangeSourceChanged:
		return "sourceChanged"
	case ChangeError:
		return "error"
	default:
		return "unknown"
	}
}

// StateChange represents a change notification sent to subscribers.
type StateChange struct {
	Type      ChangeType  `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

// FilterValidation represents the result of validating a display filter.
type FilterValidation struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// StreamInfo represents information about a TCP/UDP stream.
type StreamInfo struct {
	Protocol    string `json:"protocol"`
	StreamIndex int    `json:"streamIndex"`
	ClientAddr  string `json:"clientAddr"`
	ServerAddr  string `json:"serverAddr"`
	ClientPort  int    `json:"clientPort"`
	ServerPort  int    `json:"serverPort"`
	Packets     int    `json:"packets"`
	Bytes       int    `json:"bytes"`
}
