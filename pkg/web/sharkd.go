// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package web

import (
	"bufio"
	"context"
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

// SharkdClient manages a sharkd subprocess and communication via Unix socket.
type SharkdClient struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	socketPath string
	conn       net.Conn
	reader     *bufio.Reader
	requestID  int
	ctx        context.Context
	cancelFn   context.CancelFunc
}

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewSharkdClient creates and starts a new sharkd subprocess.
func NewSharkdClient(ctx context.Context) (*SharkdClient, error) {
	// Create unique socket path in temp directory
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("termshark-sharkd-%d.sock", os.Getpid()))

	// Remove any existing socket file
	os.Remove(socketPath)

	clientCtx, cancelFn := context.WithCancel(ctx)

	client := &SharkdClient{
		socketPath: socketPath,
		ctx:        clientCtx,
		cancelFn:   cancelFn,
	}

	// Start sharkd process
	sharkdBin := termshark.SharkdBin()
	if sharkdBin == "" {
		return nil, fmt.Errorf("sharkd not found in PATH")
	}

	client.cmd = exec.CommandContext(clientCtx, sharkdBin, fmt.Sprintf("unix:%s", socketPath))
	// Note: We don't capture stderr to avoid blocking issues on process cleanup
	// sharkd logs are typically not critical for operation

	if err := client.cmd.Start(); err != nil {
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
		client.Close()
		return nil, fmt.Errorf("failed to connect to sharkd socket: %w", err)
	}

	client.conn = conn
	client.reader = bufio.NewReader(conn)

	log.Infof("sharkd started successfully on %s", socketPath)
	return client, nil
}

// Call sends a JSON-RPC request to sharkd and returns the response.
func (c *SharkdClient) Call(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("sharkd connection closed")
	}

	c.requestID++
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      c.requestID,
		Method:  method,
		Params:  params,
	}

	// Send request
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqBytes = append(reqBytes, '\n')
	if _, err := c.conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	respLine, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("sharkd error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return resp.Result, nil
}

// Close shuts down the sharkd process and cleans up.
func (c *SharkdClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Send bye command to gracefully shutdown sharkd
		req := JSONRPCRequest{JSONRPC: "2.0", ID: 0, Method: "bye"}
		reqBytes, err := json.Marshal(req)
		if err != nil {
			log.Errorf("Failed to marshal bye request: %v", err)
			// Still try to close the connection
		}
		c.conn.Write(append(reqBytes, '\n'))
		c.conn.Close()
		c.conn = nil
	}

	// Cancel context to signal process termination
	if c.cancelFn != nil {
		c.cancelFn()
	}

	// Give process a moment to exit gracefully, then force kill
	if c.cmd != nil && c.cmd.Process != nil {
		// Use a goroutine with timeout to avoid blocking
		done := make(chan error, 1)
		go func() {
			done <- c.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(2 * time.Second):
			// Timeout, force kill
			c.cmd.Process.Kill()
		}
	}

	// Clean up socket file
	os.Remove(c.socketPath)

	return nil
}

// SocketPath returns the Unix socket path.
func (c *SharkdClient) SocketPath() string {
	return c.socketPath
}
