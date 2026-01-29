// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package state

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/gcla/termshark/v2"
	log "github.com/sirupsen/logrus"
)

// SharkdBackend implements Backend using sharkd.
type SharkdBackend struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	socketPath string
	conn       net.Conn
	reader     *bufio.Reader
	requestID  int
	ctx        context.Context
	cancelFn   context.CancelFunc
}

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// jsonRPCError represents a JSON-RPC 2.0 error.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SharkdBackendFactory creates SharkdBackend instances.
type SharkdBackendFactory struct{}

var _ BackendFactory = (*SharkdBackendFactory)(nil)

// Name returns the backend name.
func (f *SharkdBackendFactory) Name() string {
	return "sharkd"
}

// Available returns true if sharkd is available.
func (f *SharkdBackendFactory) Available() bool {
	return termshark.SharkdBin() != ""
}

// Create creates a new SharkdBackend.
func (f *SharkdBackendFactory) Create(ctx context.Context) (Backend, error) {
	return NewSharkdBackend(ctx)
}

// NewSharkdBackend creates and starts a new sharkd subprocess.
func NewSharkdBackend(ctx context.Context) (*SharkdBackend, error) {
	// Create unique socket path in temp directory
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("termshark-sharkd-%d.sock", os.Getpid()))

	// Remove any existing socket file
	os.Remove(socketPath)

	clientCtx, cancelFn := context.WithCancel(ctx)

	backend := &SharkdBackend{
		socketPath: socketPath,
		ctx:        clientCtx,
		cancelFn:   cancelFn,
	}

	// Start sharkd process
	sharkdBin := termshark.SharkdBin()
	if sharkdBin == "" {
		return nil, fmt.Errorf("sharkd not found in PATH")
	}

	backend.cmd = exec.CommandContext(clientCtx, sharkdBin, fmt.Sprintf("unix:%s", socketPath))

	if err := backend.cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sharkd: %w", err)
	}

	// Wait for socket to become available (up to 5 seconds)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Connect to sharkd socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		backend.Close()
		return nil, fmt.Errorf("failed to connect to sharkd socket: %w", err)
	}

	backend.conn = conn
	backend.reader = bufio.NewReader(conn)

	log.Infof("sharkd backend started on %s", socketPath)
	return backend, nil
}

// call sends a JSON-RPC request to sharkd and returns the response.
func (b *SharkdBackend) call(method string, params interface{}) (json.RawMessage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn == nil {
		return nil, fmt.Errorf("sharkd connection closed")
	}

	b.requestID++
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      b.requestID,
		Method:  method,
		Params:  params,
	}

	// Send request
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqBytes = append(reqBytes, '\n')
	if _, err := b.conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	respLine, err := b.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var resp jsonRPCResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("sharkd error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return resp.Result, nil
}

// LoadFile loads a pcap file for analysis.
func (b *SharkdBackend) LoadFile(ctx context.Context, path string) error {
	_, err := b.call("load", map[string]string{"file": path})
	return err
}

// GetStatus returns the current status.
func (b *SharkdBackend) GetStatus(ctx context.Context) (*Status, error) {
	result, err := b.call("status", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Frames   int      `json:"frames"`
		Duration float64  `json:"duration"`
		Columns  []string `json:"columns"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse status: %w", err)
	}

	return &Status{
		PacketCount: resp.Frames,
		Duration:    resp.Duration,
		Columns:     resp.Columns,
	}, nil
}

// GetPackets returns packet summaries.
func (b *SharkdBackend) GetPackets(ctx context.Context, filter string, start, count int) ([]PacketSummary, error) {
	params := map[string]interface{}{
		"limit": count,
	}
	if start > 0 {
		params["skip"] = start
	}
	if filter != "" {
		params["filter"] = filter
	}

	result, err := b.call("frames", params)
	if err != nil {
		return nil, err
	}

	var frames []struct {
		Num int      `json:"num"`
		C   []string `json:"c"`
		Bg  string   `json:"bg,omitempty"`
		Fg  string   `json:"fg,omitempty"`
	}
	if err := json.Unmarshal(result, &frames); err != nil {
		return nil, fmt.Errorf("failed to parse frames: %w", err)
	}

	packets := make([]PacketSummary, len(frames))
	for i, f := range frames {
		packets[i] = PacketSummary{
			Number:  f.Num,
			Columns: f.C,
			BGColor: f.Bg,
			FGColor: f.Fg,
		}
	}

	return packets, nil
}

// GetPacketDetail returns the full detail for a single packet.
func (b *SharkdBackend) GetPacketDetail(ctx context.Context, num int) (*PacketDetail, error) {
	result, err := b.call("frame", map[string]interface{}{
		"frame": num,
		"proto": true,
		"bytes": true,
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Tree  []sharkdTreeNode `json:"tree"`
		Bytes string           `json:"bytes"` // base64 encoded
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse frame: %w", err)
	}

	// Convert tree
	tree := make([]ProtocolNode, len(resp.Tree))
	for i, n := range resp.Tree {
		tree[i] = convertTreeNode(n)
	}

	// Decode bytes
	var bytes []byte
	if resp.Bytes != "" {
		bytes, err = base64.StdEncoding.DecodeString(resp.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bytes: %w", err)
		}
	}

	return &PacketDetail{
		Number: num,
		Tree:   tree,
		Bytes:  bytes,
	}, nil
}

// sharkdTreeNode represents a node in sharkd's tree response.
type sharkdTreeNode struct {
	Label    string           `json:"l"`
	Field    string           `json:"f,omitempty"`
	Severity string           `json:"s,omitempty"`
	Type     string           `json:"t,omitempty"`
	HexRange json.RawMessage  `json:"h,omitempty"` // [offset, size] or [offset, size, bit_offset, bit_size]
	Children []sharkdTreeNode `json:"n,omitempty"`
}

// convertTreeNode converts a sharkd tree node to our ProtocolNode.
func convertTreeNode(n sharkdTreeNode) ProtocolNode {
	node := ProtocolNode{
		Label: n.Label,
		Field: n.Field,
	}

	// Parse hex range: "h" can be an array [offset, size, ...]
	if len(n.HexRange) > 0 {
		var hexRange []int
		if err := json.Unmarshal(n.HexRange, &hexRange); err == nil && len(hexRange) >= 2 {
			node.Position = hexRange[0]
			node.Size = hexRange[1]
		}
	}

	if len(n.Children) > 0 {
		node.Children = make([]ProtocolNode, len(n.Children))
		for i, child := range n.Children {
			node.Children[i] = convertTreeNode(child)
		}
	}

	return node
}

// ValidateFilter checks if a display filter is valid.
func (b *SharkdBackend) ValidateFilter(ctx context.Context, filter string) (*FilterValidation, error) {
	result, err := b.call("check", map[string]string{"filter": filter})
	if err != nil {
		// sharkd returns error for invalid filters
		return &FilterValidation{Valid: false, Message: err.Error()}, nil
	}

	var resp struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse check response: %w", err)
	}

	return &FilterValidation{Valid: resp.OK}, nil
}

// GetStreamInfo returns information about available streams.
func (b *SharkdBackend) GetStreamInfo(ctx context.Context, protocol string) ([]StreamInfo, error) {
	// sharkd doesn't have a direct streams list command
	// We would need to use taps for this
	return nil, fmt.Errorf("stream info not implemented for sharkd backend")
}

// FollowStream returns the reassembled data for a stream.
func (b *SharkdBackend) FollowStream(ctx context.Context, protocol string, streamIndex int) ([]byte, error) {
	result, err := b.call("follow", map[string]interface{}{
		"follow": protocol,
		"filter": fmt.Sprintf("%s.stream eq %d", protocol, streamIndex),
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Payloads []struct {
			Data string `json:"d"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse follow response: %w", err)
	}

	// Concatenate all payloads
	var data []byte
	for _, p := range resp.Payloads {
		decoded, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil {
			continue
		}
		data = append(data, decoded...)
	}

	return data, nil
}

// Close shuts down the sharkd process.
func (b *SharkdBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn != nil {
		// Send bye command to gracefully shutdown
		req := jsonRPCRequest{JSONRPC: "2.0", ID: 0, Method: "bye"}
		reqBytes, _ := json.Marshal(req)
		b.conn.Write(append(reqBytes, '\n'))
		b.conn.Close()
		b.conn = nil
	}

	if b.cancelFn != nil {
		b.cancelFn()
	}

	if b.cmd != nil && b.cmd.Process != nil {
		done := make(chan error, 1)
		go func() {
			done <- b.cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			b.cmd.Process.Kill()
		}
	}

	os.Remove(b.socketPath)
	return nil
}

var _ Backend = (*SharkdBackend)(nil)
