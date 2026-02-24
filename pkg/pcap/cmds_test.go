// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// MakeCommands Tests
//======================================================================

func TestMakeCommands_BasicConstruction(t *testing.T) {
	tests := []struct {
		name     string
		decodeAs []string
		args     []string
		pdml     []string
		psml     []string
		color    bool
	}{
		{
			name:     "empty everything",
			decodeAs: nil,
			args:     nil,
			pdml:     nil,
			psml:     nil,
			color:    false,
		},
		{
			name:     "with decode-as",
			decodeAs: []string{"tcp.port==8080,http"},
			args:     nil,
			pdml:     nil,
			psml:     nil,
			color:    false,
		},
		{
			name:     "with extra args",
			decodeAs: nil,
			args:     []string{"-n"},
			pdml:     nil,
			psml:     nil,
			color:    false,
		},
		{
			name:     "with pdml args",
			decodeAs: nil,
			args:     nil,
			pdml:     []string{"--disable-protocol", "http"},
			psml:     nil,
			color:    false,
		},
		{
			name:     "with psml args",
			decodeAs: nil,
			args:     nil,
			pdml:     nil,
			psml:     []string{"-t", "a"},
			color:    false,
		},
		{
			name:     "with color enabled",
			decodeAs: nil,
			args:     nil,
			pdml:     nil,
			psml:     nil,
			color:    true,
		},
		{
			name:     "all options populated",
			decodeAs: []string{"tcp.port==8080,http", "udp.port==53,dns"},
			args:     []string{"-n", "-t", "r"},
			pdml:     []string{"--disable-protocol", "http"},
			psml:     []string{"-t", "a"},
			color:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := MakeCommands(tt.decodeAs, tt.args, tt.pdml, tt.psml, tt.color)

			assert.Equal(t, tt.decodeAs, cmds.DecodeAs)
			assert.Equal(t, tt.args, cmds.Args)
			assert.Equal(t, tt.pdml, cmds.PdmlArgs)
			assert.Equal(t, tt.psml, cmds.PsmlArgs)
			assert.Equal(t, tt.color, cmds.Color)
		})
	}
}

func TestMakeCommands_ImplementsILoaderCmds(t *testing.T) {
	// Verify Commands implements ILoaderCmds
	var _ ILoaderCmds = Commands{}
}

//======================================================================
// ProcessNotStarted Tests
//======================================================================

func TestProcessNotStarted_Error(t *testing.T) {
	cmd := exec.Command("tshark", "-T", "psml")
	err := ProcessNotStarted{Command: cmd}

	errStr := err.Error()
	assert.Contains(t, errStr, "not started yet")
	assert.Contains(t, errStr, "tshark")
}

func TestProcessNotStarted_ImplementsError(t *testing.T) {
	var _ error = ProcessNotStarted{}
}

//======================================================================
// Command.String Tests
//======================================================================

func TestCommand_String(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("tshark", "-r", "test.pcap"),
	}

	s := cmd.String()
	assert.Contains(t, s, "tshark")
	assert.Contains(t, s, "test.pcap")
}

//======================================================================
// Command.Pid Tests
//======================================================================

func TestCommand_Pid_NoProcess(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("tshark"),
	}

	// Process is nil before Start
	assert.Equal(t, -1, cmd.Pid())
}

//======================================================================
// Command.Close Tests
//======================================================================

func TestCommand_Close_NonClosableStdout(t *testing.T) {
	cmd := &Command{
		Cmd: exec.Command("echo", "test"),
	}

	// stdout is nil by default, so Close() should do nothing
	err := cmd.Close()
	assert.NoError(t, err)
}

//======================================================================
// Commands.Pcap Tests
//======================================================================

func TestCommands_Pcap_BuildsCorrectArgs(t *testing.T) {
	tests := []struct {
		name          string
		pcap          string
		displayFilter string
		extraArgs     []string
		wantArgs      []string
	}{
		{
			name:          "basic pcap read",
			pcap:          "test.pcap",
			displayFilter: "",
			extraArgs:     nil,
			wantArgs:      []string{"-r", "test.pcap", "-x"},
		},
		{
			name:          "pcap with filter",
			pcap:          "capture.pcap",
			displayFilter: "tcp.port == 80",
			extraArgs:     nil,
			wantArgs:      []string{"-r", "capture.pcap", "-x", "-Y", "tcp.port == 80"},
		},
		{
			name:          "pcap with extra args",
			pcap:          "test.pcap",
			displayFilter: "",
			extraArgs:     []string{"-n"},
			wantArgs:      []string{"-r", "test.pcap", "-x", "-n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := Commands{Args: tt.extraArgs}
			result := cmds.Pcap(tt.pcap, tt.displayFilter)
			require.NotNil(t, result)

			// Extract the Command from the interface
			cmd, ok := result.(*Command)
			require.True(t, ok)
			// Check that the args contain expected elements
			for _, wantArg := range tt.wantArgs {
				assert.Contains(t, cmd.Cmd.Args, wantArg,
					"expected arg %q not found in %v", wantArg, cmd.Cmd.Args)
			}
		})
	}
}

//======================================================================
// Commands.Pdml Tests
//======================================================================

func TestCommands_Pdml_BuildsCorrectArgs(t *testing.T) {
	tests := []struct {
		name          string
		pcap          string
		displayFilter string
		decodeAs      []string
		color         bool
		pdmlArgs      []string
		args          []string
		wantArgs      []string
		dontWantArgs  []string
	}{
		{
			name:          "basic pdml",
			pcap:          "test.pcap",
			displayFilter: "",
			wantArgs:      []string{"-T", "pdml", "-r", "test.pcap"},
		},
		{
			name:          "pdml with filter",
			pcap:          "capture.pcap",
			displayFilter: "http",
			wantArgs:      []string{"-T", "pdml", "-r", "capture.pcap", "-Y", "http"},
		},
		{
			name:          "pdml with color",
			pcap:          "test.pcap",
			displayFilter: "",
			color:         true,
			wantArgs:      []string{"-T", "pdml", "-r", "test.pcap", "--color"},
		},
		{
			name:          "pdml without color",
			pcap:          "test.pcap",
			displayFilter: "",
			color:         false,
			wantArgs:      []string{"-T", "pdml", "-r", "test.pcap"},
			dontWantArgs:  []string{"--color"},
		},
		{
			name:          "pdml with decode-as",
			pcap:          "test.pcap",
			displayFilter: "",
			decodeAs:      []string{"tcp.port==8080,http"},
			wantArgs:      []string{"-T", "pdml", "-r", "test.pcap", "-d", "tcp.port==8080,http"},
		},
		{
			name:          "pdml with multiple decode-as",
			pcap:          "test.pcap",
			displayFilter: "",
			decodeAs:      []string{"tcp.port==8080,http", "udp.port==53,dns"},
			wantArgs:      []string{"-d", "tcp.port==8080,http", "-d", "udp.port==53,dns"},
		},
		{
			name:          "pdml with extra pdml args",
			pcap:          "test.pcap",
			displayFilter: "",
			pdmlArgs:      []string{"--disable-protocol", "foo"},
			wantArgs:      []string{"--disable-protocol", "foo"},
		},
		{
			name:     "pdml with extra general args",
			pcap:     "test.pcap",
			args:     []string{"-n"},
			wantArgs: []string{"-n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := Commands{
				DecodeAs: tt.decodeAs,
				Color:    tt.color,
				PdmlArgs: tt.pdmlArgs,
				Args:     tt.args,
			}
			result := cmds.Pdml(tt.pcap, tt.displayFilter)
			require.NotNil(t, result)

			cmd, ok := result.(*Command)
			require.True(t, ok)
			for _, wantArg := range tt.wantArgs {
				assert.Contains(t, cmd.Cmd.Args, wantArg,
					"expected arg %q not found in %v", wantArg, cmd.Cmd.Args)
			}
			for _, dontWant := range tt.dontWantArgs {
				assert.NotContains(t, cmd.Cmd.Args, dontWant,
					"unexpected arg %q found in %v", dontWant, cmd.Cmd.Args)
			}
		})
	}
}

//======================================================================
// Commands.Psml Tests
//======================================================================

func TestCommands_Psml_BuildsCorrectArgs_FileMode(t *testing.T) {
	tests := []struct {
		name          string
		pcap          string
		displayFilter string
		decodeAs      []string
		color         bool
		psmlArgs      []string
		args          []string
		wantArgs      []string
		dontWantArgs  []string
	}{
		{
			name:          "basic psml from file",
			pcap:          "test.pcap",
			displayFilter: "",
			wantArgs:      []string{"-T", "psml", "-r", "test.pcap"},
			dontWantArgs:  []string{"-l"}, // -l only for fifo/pipe
		},
		{
			name:          "psml with filter",
			pcap:          "test.pcap",
			displayFilter: "dns",
			wantArgs:      []string{"-T", "psml", "-Y", "dns"},
		},
		{
			name:          "psml with color",
			pcap:          "test.pcap",
			displayFilter: "",
			color:         true,
			wantArgs:      []string{"--color"},
		},
		{
			name:          "psml with decode-as",
			pcap:          "test.pcap",
			displayFilter: "",
			decodeAs:      []string{"tcp.port==8080,http"},
			wantArgs:      []string{"-d", "tcp.port==8080,http"},
		},
		{
			name:     "psml with extra psml args",
			pcap:     "test.pcap",
			psmlArgs: []string{"-t", "ad"},
			wantArgs: []string{"-t", "ad"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := Commands{
				DecodeAs: tt.decodeAs,
				Color:    tt.color,
				PsmlArgs: tt.psmlArgs,
				Args:     tt.args,
			}
			result := cmds.Psml(tt.pcap, tt.displayFilter)
			require.NotNil(t, result)

			cmd, ok := result.(*Command)
			require.True(t, ok)
			for _, wantArg := range tt.wantArgs {
				assert.Contains(t, cmd.Cmd.Args, wantArg,
					"expected arg %q not found in %v", wantArg, cmd.Cmd.Args)
			}
			for _, dontWant := range tt.dontWantArgs {
				assert.NotContains(t, cmd.Cmd.Args, dontWant,
					"unexpected arg %q found in %v", dontWant, cmd.Cmd.Args)
			}
		})
	}
}

func TestCommands_Psml_AlwaysHasNoColumn(t *testing.T) {
	// The PSML command should always include the No. column via gui.column.format
	cmds := Commands{}
	result := cmds.Psml("test.pcap", "")
	require.NotNil(t, result)

	cmd, ok := result.(*Command)
	require.True(t, ok)

	// Check that -o gui.column.format is present
	foundColumnFormat := false
	for _, arg := range cmd.Cmd.Args {
		if len(arg) > 18 && arg[:18] == "gui.column.format:" {
			foundColumnFormat = true
			assert.Contains(t, arg, "\"No.\"")
			assert.Contains(t, arg, "\"%m\"")
		}
	}
	assert.True(t, foundColumnFormat, "expected gui.column.format arg")
}

//======================================================================
// Commands.Iface Tests
//======================================================================

func TestCommands_Iface_BuildsCorrectArgs(t *testing.T) {
	tests := []struct {
		name          string
		ifaces        []string
		captureFilter string
		tmpfile       string
		wantArgs      []string
	}{
		{
			name:          "single interface",
			ifaces:        []string{"eth0"},
			captureFilter: "",
			tmpfile:       "/tmp/capture.pcap",
			wantArgs:      []string{"-i", "eth0", "-w", "/tmp/capture.pcap"},
		},
		{
			name:          "multiple interfaces",
			ifaces:        []string{"eth0", "wlan0"},
			captureFilter: "",
			tmpfile:       "/tmp/capture.pcap",
			wantArgs:      []string{"-i", "eth0", "-i", "wlan0", "-w", "/tmp/capture.pcap"},
		},
		{
			name:          "with capture filter",
			ifaces:        []string{"eth0"},
			captureFilter: "port 80",
			tmpfile:       "/tmp/capture.pcap",
			wantArgs:      []string{"-i", "eth0", "-w", "/tmp/capture.pcap", "-f", "port 80"},
		},
		{
			name:          "interface with special chars",
			ifaces:        []string{`\\.\Device\NPF_{ABC-123}`},
			captureFilter: "",
			tmpfile:       "/tmp/capture.pcap",
			wantArgs:      []string{"-i", `\\.\Device\NPF_{ABC-123}`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := Commands{}
			result := cmds.Iface(tt.ifaces, tt.captureFilter, tt.tmpfile)
			require.NotNil(t, result)

			cmd, ok := result.(*Command)
			require.True(t, ok)
			for _, wantArg := range tt.wantArgs {
				assert.Contains(t, cmd.Cmd.Args, wantArg,
					"expected arg %q not found in %v", wantArg, cmd.Cmd.Args)
			}
		})
	}
}

func TestCommands_Iface_NoCaptureFilter(t *testing.T) {
	cmds := Commands{}
	result := cmds.Iface([]string{"eth0"}, "", "/tmp/cap.pcap")
	require.NotNil(t, result)

	cmd, ok := result.(*Command)
	require.True(t, ok)
	assert.NotContains(t, cmd.Cmd.Args, "-f",
		"should not contain -f when capture filter is empty")
}

//======================================================================
// Commands.Tail Tests
//======================================================================

func TestCommands_Tail_ReturnsCommand(t *testing.T) {
	cmds := Commands{}
	result := cmds.Tail("/tmp/test.pcap")
	require.NotNil(t, result)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
