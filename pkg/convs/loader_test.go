// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package convs

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/stretchr/testify/assert"
)

//======================================================================
// Mock types for testing
//======================================================================

// mockPcapCommand implements pcap.IPcapCommand for testing without real processes.
type mockPcapCommand struct {
	args    []string
	pcapfile string
}

func (m *mockPcapCommand) String() string {
	return strings.Join(m.args, " ")
}

func (m *mockPcapCommand) Start() error {
	return nil
}

func (m *mockPcapCommand) Wait() error {
	return nil
}

func (m *mockPcapCommand) Pid() int {
	return -1
}

func (m *mockPcapCommand) Kill() error {
	return nil
}

func (m *mockPcapCommand) StderrSummary() []string {
	return nil
}

func (m *mockPcapCommand) StdoutReader() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

// mockLoaderCmds implements ILoaderCmds for testing, capturing the arguments
// that would be passed to a real tshark command.
type mockLoaderCmds struct {
	lastPcapfile string
	lastConvs    []string
	lastFilter   string
	lastAbs      bool
	lastResolve  bool
	callCount    int
}

func (m *mockLoaderCmds) Convs(pcapfile string, convs []string, filter string, abs bool, resolve bool) pcap.IPcapCommand {
	m.lastPcapfile = pcapfile
	m.lastConvs = convs
	m.lastFilter = filter
	m.lastAbs = abs
	m.lastResolve = resolve
	m.callCount++
	return &mockPcapCommand{
		pcapfile: pcapfile,
		args:     []string{"tshark", "-q", "-r", pcapfile},
	}
}

//======================================================================
// Command construction tests
//======================================================================

func TestConvsCommandBasic(t *testing.T) {
	// Test basic command construction with a single conversation type, no filter
	cmds := MakeCommands()
	cmd := cmds.Convs("test.pcap", []string{"tcp"}, "", false, false)

	// The command should be a *pcap.Command with embedded *exec.Cmd
	pcapCmd, ok := cmd.(*pcap.Command)
	assert.True(t, ok, "Convs should return a *pcap.Command")

	args := pcapCmd.Cmd.Args
	// exec.Command puts the binary path as Args[0]
	// The args should contain: -q -r test.pcap -n -z conv,tcp
	assert.Contains(t, args, "-q")
	assert.Contains(t, args, "-r")
	assert.Contains(t, args, "test.pcap")
	assert.Contains(t, args, "-n") // resolve=false => -n flag
	assert.Contains(t, args, "conv,tcp")
}

func TestConvsCommandWithFilter(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("capture.pcap", []string{"tcp"}, "ip.addr==10.0.0.1", false, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	assert.Contains(t, args, "-q")
	assert.Contains(t, args, "-r")
	assert.Contains(t, args, "capture.pcap")
	assert.Contains(t, args, "-n")
	// With a filter, the -z arg should be "conv,tcp,ip.addr==10.0.0.1"
	assert.Contains(t, args, "conv,tcp,ip.addr==10.0.0.1")
}

func TestConvsCommandAbsoluteTime(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("test.pcap", []string{"eth"}, "", true, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	assert.Contains(t, args, "-t")
	assert.Contains(t, args, "a")
	assert.Contains(t, args, "-n")
}

func TestConvsCommandWithResolve(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("test.pcap", []string{"ip"}, "", false, true)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	// resolve=true means -n should NOT be present
	for _, arg := range args {
		assert.NotEqual(t, "-n", arg, "resolve=true should not add -n flag")
	}
}

func TestConvsCommandMultipleConvTypes(t *testing.T) {
	cmds := MakeCommands()
	convTypes := []string{"eth", "ip", "tcp", "udp"}
	cmd := cmds.Convs("multi.pcap", convTypes, "", false, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	// Each conv type should generate a -z conv,<type> pair
	assert.Contains(t, args, "conv,eth")
	assert.Contains(t, args, "conv,ip")
	assert.Contains(t, args, "conv,tcp")
	assert.Contains(t, args, "conv,udp")

	// Count the number of -z flags
	zCount := 0
	for _, arg := range args {
		if arg == "-z" {
			zCount++
		}
	}
	assert.Equal(t, 4, zCount, "should have one -z flag per conversation type")
}

func TestConvsCommandMultipleConvTypesWithFilter(t *testing.T) {
	cmds := MakeCommands()
	convTypes := []string{"tcp", "udp"}
	filter := "ip.src==192.168.1.1"
	cmd := cmds.Convs("filtered.pcap", convTypes, filter, false, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	// Each conv type should have the filter appended
	assert.Contains(t, args, "conv,tcp,ip.src==192.168.1.1")
	assert.Contains(t, args, "conv,udp,ip.src==192.168.1.1")
}

func TestConvsCommandAllFlags(t *testing.T) {
	// Test with abs=true, resolve=true, filter, multiple conv types
	cmds := MakeCommands()
	cmd := cmds.Convs("all.pcap", []string{"tcp", "ip"}, "http", true, true)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	assert.Contains(t, args, "-q")
	assert.Contains(t, args, "-r")
	assert.Contains(t, args, "all.pcap")
	assert.Contains(t, args, "-t")
	assert.Contains(t, args, "a")
	assert.Contains(t, args, "conv,tcp,http")
	assert.Contains(t, args, "conv,ip,http")

	// resolve=true, so -n should NOT be present
	for _, arg := range args {
		assert.NotEqual(t, "-n", arg)
	}
}

func TestConvsCommandEmptyConvsList(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("empty.pcap", []string{}, "", false, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	// With empty convs slice, there should be no -z flags
	for _, arg := range args {
		assert.NotEqual(t, "-z", arg, "empty convs list should produce no -z flags")
	}
}

func TestConvsCommandArgOrder(t *testing.T) {
	// Verify the expected ordering of arguments: -q -r <pcap> [-t a] [-n] [-z conv,<type>[,<filter>]]...
	cmds := MakeCommands()
	cmd := cmds.Convs("order.pcap", []string{"tcp"}, "dns", true, false)

	pcapCmd := cmd.(*pcap.Command)
	args := pcapCmd.Cmd.Args

	// Find positions (skipping args[0] which is the binary path)
	qIdx := indexOf(args, "-q")
	rIdx := indexOf(args, "-r")
	tIdx := indexOf(args, "-t")
	nIdx := indexOf(args, "-n")
	zIdx := indexOf(args, "-z")

	assert.Greater(t, qIdx, 0, "-q should be present")
	assert.Greater(t, rIdx, 0, "-r should be present")
	assert.Greater(t, tIdx, 0, "-t should be present (abs=true)")
	assert.Greater(t, nIdx, 0, "-n should be present (resolve=false)")
	assert.Greater(t, zIdx, 0, "-z should be present")

	// -q and -r should come before -t, -n, and -z
	assert.Less(t, qIdx, tIdx)
	assert.Less(t, rIdx, tIdx)
	assert.Less(t, tIdx, nIdx)
	assert.Less(t, nIdx, zIdx)
}

//======================================================================
// MakeCommands tests
//======================================================================

func TestMakeCommands(t *testing.T) {
	cmds := MakeCommands()
	// MakeCommands should return a value that satisfies ILoaderCmds
	var _ ILoaderCmds = cmds
}

//======================================================================
// Loader tests
//======================================================================

func TestNewLoader(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	assert.NotNil(t, loader)
	assert.NotNil(t, loader.mainCtx)
	assert.NotNil(t, loader.mainCancelFn)
	assert.False(t, loader.SuppressErrors)
}

func TestNewLoaderStoresCommands(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	assert.Equal(t, mock, loader.cmds)
}

func TestStopLoadNilCancelFn(t *testing.T) {
	// StopLoad should not panic when convsCancelFn is nil
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	assert.Nil(t, loader.convsCancelFn)
	assert.NotPanics(t, func() {
		loader.StopLoad()
	})
}

func TestStopLoadCallsCancelFn(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	// Manually set up a cancellable context to simulate an active load
	childCtx, cancelFn := context.WithCancel(ctx)
	loader.convsCtx = childCtx
	loader.convsCancelFn = cancelFn

	// Before StopLoad, context should not be cancelled
	select {
	case <-childCtx.Done():
		t.Fatal("context should not be cancelled yet")
	default:
		// expected
	}

	loader.StopLoad()

	// After StopLoad, context should be cancelled
	select {
	case <-childCtx.Done():
		// expected
	default:
		t.Fatal("context should be cancelled after StopLoad")
	}
}

func TestLoaderMainContextCancellation(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx, cancel := context.WithCancel(context.Background())
	loader := NewLoader(mock, ctx)

	// Cancelling the parent context should propagate to the loader's main context
	cancel()

	select {
	case <-loader.mainCtx.Done():
		// expected
	default:
		t.Fatal("loader mainCtx should be cancelled when parent context is cancelled")
	}
}

func TestLoaderSuppressErrors(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	assert.False(t, loader.SuppressErrors)
	loader.SuppressErrors = true
	assert.True(t, loader.SuppressErrors)
}

//======================================================================
// Mock ILoaderCmds delegation tests
//======================================================================

func TestMockCmdsConvsDelegation(t *testing.T) {
	mock := &mockLoaderCmds{}
	ctx := context.Background()
	loader := NewLoader(mock, ctx)

	// Verify that the loader holds the mock commands
	assert.Equal(t, mock, loader.cmds)
	assert.Equal(t, 0, mock.callCount)
}

//======================================================================
// Conversation type integration with command construction
//======================================================================

func TestConvsCommandWithAllProtocolTypes(t *testing.T) {
	cmds := MakeCommands()

	tests := []struct {
		name      string
		convTypes []string
		expected  []string
	}{
		{
			name:      "ethernet only",
			convTypes: []string{Ethernet{}.Short()},
			expected:  []string{"conv,eth"},
		},
		{
			name:      "ipv4 only",
			convTypes: []string{IPv4{}.Short()},
			expected:  []string{"conv,ip"},
		},
		{
			name:      "ipv6 only",
			convTypes: []string{IPv6{}.Short()},
			expected:  []string{"conv,ipv6"},
		},
		{
			name:      "udp only",
			convTypes: []string{UDP{}.Short()},
			expected:  []string{"conv,udp"},
		},
		{
			name:      "tcp only",
			convTypes: []string{TCP{}.Short()},
			expected:  []string{"conv,tcp"},
		},
		{
			name:      "all protocols",
			convTypes: []string{Ethernet{}.Short(), IPv4{}.Short(), IPv6{}.Short(), UDP{}.Short(), TCP{}.Short()},
			expected:  []string{"conv,eth", "conv,ip", "conv,ipv6", "conv,udp", "conv,tcp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := cmds.Convs("test.pcap", tt.convTypes, "", false, false)
			pcapCmd := cmd.(*pcap.Command)
			args := pcapCmd.Cmd.Args

			for _, exp := range tt.expected {
				assert.Contains(t, args, exp)
			}
		})
	}
}

func TestConvsCommandWithAllProtocolTypesAndFilter(t *testing.T) {
	cmds := MakeCommands()
	filter := "frame.number < 100"

	tests := []struct {
		name     string
		convType string
		expected string
	}{
		{"ethernet", Ethernet{}.Short(), "conv,eth,frame.number < 100"},
		{"ipv4", IPv4{}.Short(), "conv,ip,frame.number < 100"},
		{"ipv6", IPv6{}.Short(), "conv,ipv6,frame.number < 100"},
		{"udp", UDP{}.Short(), "conv,udp,frame.number < 100"},
		{"tcp", TCP{}.Short(), "conv,tcp,frame.number < 100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := cmds.Convs("test.pcap", []string{tt.convType}, filter, false, false)
			pcapCmd := cmd.(*pcap.Command)
			assert.Contains(t, pcapCmd.Cmd.Args, tt.expected)
		})
	}
}

//======================================================================
// Edge case tests for command construction
//======================================================================

func TestConvsCommandWithSpecialCharactersInFilter(t *testing.T) {
	cmds := MakeCommands()
	filter := `ip.addr == 10.0.0.1 && tcp.port == 80`
	cmd := cmds.Convs("test.pcap", []string{"tcp"}, filter, false, false)

	pcapCmd := cmd.(*pcap.Command)
	expectedArg := "conv,tcp," + filter
	assert.Contains(t, pcapCmd.Cmd.Args, expectedArg)
}

func TestConvsCommandWithSpacesInPcapPath(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("/path/to/my capture.pcap", []string{"tcp"}, "", false, false)

	pcapCmd := cmd.(*pcap.Command)
	assert.Contains(t, pcapCmd.Cmd.Args, "/path/to/my capture.pcap")
}

func TestConvsCommandWithEmptyFilter(t *testing.T) {
	cmds := MakeCommands()
	cmd := cmds.Convs("test.pcap", []string{"tcp"}, "", false, false)

	pcapCmd := cmd.(*pcap.Command)
	// With empty filter, the -z arg should just be "conv,tcp" without trailing comma
	assert.Contains(t, pcapCmd.Cmd.Args, "conv,tcp")
	// Make sure there's no "conv,tcp," with trailing comma
	for _, arg := range pcapCmd.Cmd.Args {
		if strings.HasPrefix(arg, "conv,tcp") {
			assert.Equal(t, "conv,tcp", arg, "empty filter should not append a trailing comma")
		}
	}
}

//======================================================================
// Type-related filter tests with additional coverage
//======================================================================

func TestUDPFilterUsesIPv4(t *testing.T) {
	// UDP filters should compose with IPv4 filters
	udp := UDP{}
	filter := udp.FilterTo("10.0.0.1", "53")
	assert.Contains(t, filter, "ip.dst == 10.0.0.1")
	assert.Contains(t, filter, "udp.dstport == 53")
	assert.Contains(t, filter, "&&")
}

func TestTCPFilterUsesIPv4(t *testing.T) {
	// TCP filters should compose with IPv4 filters
	tcp := TCP{}
	filter := tcp.FilterFrom("172.16.0.1", "8080")
	assert.Contains(t, filter, "ip.src == 172.16.0.1")
	assert.Contains(t, filter, "tcp.srcport == 8080")
	assert.Contains(t, filter, "&&")
}

func TestAllTypesImplementStringAndShort(t *testing.T) {
	types := []struct {
		name     string
		short    string
		instance interface {
			String() string
			Short() string
		}
	}{
		{"Ethernet", "eth", Ethernet{}},
		{"IPv4", "ip", IPv4{}},
		{"IPv6", "ipv6", IPv6{}},
		{"UDP", "udp", UDP{}},
		{"TCP", "tcp", TCP{}},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.instance.String())
			assert.Equal(t, tt.short, tt.instance.Short())
			// Verify the map is consistent
			assert.Equal(t, tt.short, OfficialNameToType[tt.name])
		})
	}
}

func TestLayerTwoTypesHaveSingleIndex(t *testing.T) {
	// Layer 2/3 types (Ethernet, IPv4, IPv6) use single address indices
	assert.Len(t, Ethernet{}.AIndex(), 1)
	assert.Len(t, Ethernet{}.BIndex(), 1)
	assert.Len(t, IPv4{}.AIndex(), 1)
	assert.Len(t, IPv4{}.BIndex(), 1)
	assert.Len(t, IPv6{}.AIndex(), 1)
	assert.Len(t, IPv6{}.BIndex(), 1)
}

func TestLayerFourTypesHaveDoubleIndex(t *testing.T) {
	// Layer 4 types (UDP, TCP) use address+port indices
	assert.Len(t, UDP{}.AIndex(), 2)
	assert.Len(t, UDP{}.BIndex(), 2)
	assert.Len(t, TCP{}.AIndex(), 2)
	assert.Len(t, TCP{}.BIndex(), 2)
}

func TestOfficialNameToTypeHasNoExtraEntries(t *testing.T) {
	// Ensure the map has exactly the expected 5 entries
	expected := map[string]string{
		"Ethernet": "eth",
		"IPv4":     "ip",
		"IPv6":     "ipv6",
		"UDP":      "udp",
		"TCP":      "tcp",
	}
	assert.Equal(t, expected, OfficialNameToType)
}

func TestOfficialNameToTypeLookupMiss(t *testing.T) {
	// Non-existent keys should return empty string (zero value)
	assert.Equal(t, "", OfficialNameToType["nonexistent"])
	assert.Equal(t, "", OfficialNameToType[""])
	assert.Equal(t, "", OfficialNameToType["ethernet"]) // lowercase
	assert.Equal(t, "", OfficialNameToType["ipv4"])     // lowercase
}

//======================================================================
// Helper functions
//======================================================================

func indexOf(args []string, target string) int {
	for i, a := range args {
		if a == target {
			return i
		}
	}
	return -1
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
