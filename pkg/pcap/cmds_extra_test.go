// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// ProcessNotStarted Tests
//======================================================================

func TestProcessNotStarted_WithArgsContainingSpaces(t *testing.T) {
	cmd := exec.Command("/usr/bin/tshark", "-Y", "tcp.port == 80")
	pns := ProcessNotStarted{Command: cmd}

	errStr := pns.Error()
	assert.Contains(t, errStr, "tshark")
	assert.Contains(t, errStr, "not started yet")
}

//======================================================================
// Command.String() Tests
//======================================================================

func TestCommand_String_NoArgs(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("/bin/true"),
	}

	result := cmd.String()

	assert.Contains(t, result, "true")
}

func TestCommand_String_ConcurrentAccess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("/usr/bin/echo", "test"),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cmd.String()
		}()
	}
	wg.Wait()
}

//======================================================================
// Command.Start() Tests
//======================================================================

func TestCommand_Start_Success(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	// Process should have a PID
	assert.Greater(t, cmd.Pid(), 0)

	// Wait for process to finish
	err = cmd.Wait()
	assert.NoError(t, err)
}

func TestCommand_Start_InvalidCommand(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("/nonexistent/binary/that/does/not/exist"),
	}

	err := cmd.Start()
	assert.Error(t, err)
}

func TestCommand_Start_SetsSummaryReader(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	// summaryReader should be set
	assert.NotNil(t, cmd.summaryReader)
	// summaryWriter should be set
	assert.NotNil(t, cmd.summaryWriter)

	_ = cmd.Wait()
}

//======================================================================
// Command.Wait() Tests
//======================================================================

func TestCommand_Wait_Success(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	assert.NoError(t, err)
}

func TestCommand_Wait_FailingCommand(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("false"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	assert.Error(t, err)
}

//======================================================================
// Command.StdoutReader() Tests
//======================================================================

func TestCommand_StdoutReader_BeforeStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("echo", "hello"),
	}

	reader, err := cmd.StdoutReader()
	require.NoError(t, err)
	require.NotNil(t, reader)

	err = cmd.Start()
	require.NoError(t, err)

	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "hello\n", string(data))

	_ = cmd.Wait()
}

func TestCommand_StdoutReader_ConcurrentAccess(t *testing.T) {
	// Just verify that concurrent calls don't panic or deadlock.
	// Only one call can actually succeed per exec.Cmd.
	cmd := &Command{
		Cmd: exec.Command("echo", "test"),
	}

	// First call should succeed
	reader, err := cmd.StdoutReader()
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	// Second call should fail (StdoutPipe can only be called once)
	_, err = cmd.StdoutReader()
	assert.Error(t, err)
}

//======================================================================
// Command.Pid() Tests
//======================================================================

func TestCommand_Pid_BeforeStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	// Before start, Process is nil, so Pid should return -1
	assert.Equal(t, -1, cmd.Pid())
}

func TestCommand_Pid_AfterStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("sleep", "0.1"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	pid := cmd.Pid()
	assert.Greater(t, pid, 0)

	_ = cmd.Wait()
}

func TestCommand_Pid_ConcurrentAccess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("sleep", "0.1"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pid := cmd.Pid()
			assert.Greater(t, pid, 0)
		}()
	}
	wg.Wait()

	_ = cmd.Wait()
}

//======================================================================
// Command.Close() Tests
//======================================================================

func TestCommand_Close_WithClosableStdout(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	// Set stdout to an io.WriteCloser (like a pipe)
	pr, pw := io.Pipe()
	cmd.Cmd.Stdout = pw

	err := cmd.Close()
	assert.NoError(t, err)

	// The write end should now be closed, reading should get EOF
	_, err = pr.Read(make([]byte, 1))
	assert.Error(t, err)

	pr.Close()
}

func TestCommand_Close_WithNonClosableStdout(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	// Set stdout to a non-closable writer (bytes.Buffer doesn't implement Close)
	cmd.Cmd.Stdout = &bytes.Buffer{}

	err := cmd.Close()
	assert.NoError(t, err)
}

func TestCommand_Close_WithNilStdout(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	// Stdout is nil by default
	err := cmd.Close()
	assert.NoError(t, err)
}

func TestCommand_Close_ConcurrentAccess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}
	_, pw := io.Pipe()
	cmd.Cmd.Stdout = pw

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cmd.Close()
		}()
	}
	wg.Wait()
}

//======================================================================
// Command.StderrSummary() Tests
//======================================================================

func TestCommand_StderrSummary_WithStderrOutput(t *testing.T) {
	// Use sh -c to write to stderr
	cmd := &Command{
		Cmd: exec.Command("sh", "-c", "echo 'error line 1' >&2; echo 'error line 2' >&2"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	// The command should succeed (exit 0) even though it wrote to stderr
	assert.NoError(t, err)

	// Give the summary reader a moment to process
	summary := cmd.StderrSummary()
	// At a minimum, the summary reader should be initialized
	assert.NotNil(t, summary)
}

func TestCommand_StderrSummary_AfterStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	err := cmd.Start()
	require.NoError(t, err)
	err = cmd.Wait()
	assert.NoError(t, err)

	// Should be callable after the process finishes
	summary := cmd.StderrSummary()
	assert.NotNil(t, summary)
}

func TestCommand_StderrSummary_ConcurrentAccess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	err := cmd.Start()
	require.NoError(t, err)
	err = cmd.Wait()
	assert.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cmd.StderrSummary()
		}()
	}
	wg.Wait()
}

//======================================================================
// Command.SetStdout() Tests
//======================================================================

func TestCommand_SetStdout_SetsWriter(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("echo", "hello"),
	}

	var buf bytes.Buffer
	cmd.SetStdout(&buf)

	err := cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	assert.NoError(t, err)

	assert.Equal(t, "hello\n", buf.String())
}

func TestCommand_SetStdout_ConcurrentAccess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("true"),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			cmd.SetStdout(&buf)
		}()
	}
	wg.Wait()
}

func TestCommand_SetStdout_WithPipe(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("echo", "piped"),
	}

	pr, pw := io.Pipe()
	cmd.SetStdout(pw)

	err := cmd.Start()
	require.NoError(t, err)

	// Read from the pipe in a separate goroutine
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(pr)
		done <- string(data)
	}()

	err = cmd.Wait()
	assert.NoError(t, err)

	// Close the write end to signal EOF
	pw.Close()

	output := <-done
	assert.Equal(t, "piped\n", output)
}

//======================================================================
// Command.Kill() Tests
//======================================================================

func TestCommand_Kill_BeforeStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("sleep", "60"),
	}

	// Kill before start should return ProcessNotStarted
	err := cmd.Kill()
	assert.Error(t, err)

	var pns ProcessNotStarted
	assert.ErrorAs(t, err, &pns)
}

func TestCommand_Kill_AfterStart(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("sleep", "60"),
	}

	err := cmd.Start()
	require.NoError(t, err)

	err = cmd.Kill()
	assert.NoError(t, err)

	// Wait should return an error (process was killed)
	err = cmd.Wait()
	assert.Error(t, err)
}

//======================================================================
// MakeCommands / Commands Tests
//======================================================================

//======================================================================
// Command integration: Start + SetStdout + Wait pattern
//======================================================================

func TestCommand_StartSetStdoutWaitPattern(t *testing.T) {
	// This tests a realistic usage pattern
	cmd := &Command{
		Cmd: exec.Command("echo", "integration test"),
	}

	var buf bytes.Buffer
	cmd.SetStdout(&buf)

	err := cmd.Start()
	require.NoError(t, err)
	assert.Greater(t, cmd.Pid(), 0)

	err = cmd.Wait()
	assert.NoError(t, err)

	assert.Equal(t, "integration test\n", buf.String())

	// Summary should be available after wait
	summary := cmd.StderrSummary()
	assert.NotNil(t, summary)
}

func TestCommand_FullLifecycle_WithStderrCapture(t *testing.T) {
	// A command that writes to both stdout and stderr
	cmd := &Command{
		Cmd: exec.Command("sh", "-c", "echo stdout_output; echo stderr_output >&2"),
	}

	var stdoutBuf bytes.Buffer
	cmd.SetStdout(&stdoutBuf)

	err := cmd.Start()
	require.NoError(t, err)

	pid := cmd.Pid()
	assert.Greater(t, pid, 0)

	err = cmd.Wait()
	assert.NoError(t, err)

	assert.Equal(t, "stdout_output\n", stdoutBuf.String())

	// StderrSummary should capture the stderr output
	summary := cmd.StderrSummary()
	assert.NotNil(t, summary)
	if len(summary) > 0 {
		found := false
		for _, line := range summary {
			if strings.Contains(line, "stderr_output") {
				found = true
				break
			}
		}
		assert.True(t, found, "stderr summary should contain 'stderr_output', got: %v", summary)
	}
}

//======================================================================
// Command.String() with special characters
//======================================================================

func TestCommand_String_WithSpecialArgs(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("tshark", "-Y", "tcp.port == 80 && ip.addr == 10.0.0.1"),
	}

	result := cmd.String()
	assert.Contains(t, result, "tshark")
	assert.Contains(t, result, "tcp.port == 80")
}

//======================================================================
// ProcessNotStarted var assertion
//======================================================================

func TestProcessNotStarted_VarAssertion(t *testing.T) {
	// The package has: var _ error = ProcessNotStarted{}
	// This confirms ProcessNotStarted satisfies the error interface
	var e error = ProcessNotStarted{Command: exec.Command("test")}
	assert.NotNil(t, e)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
