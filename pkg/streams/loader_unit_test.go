// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// MakeCommands Tests
//======================================================================

func TestMakeCommands(t *testing.T) {
	cmds := MakeCommands()
	assert.NotNil(t, cmds)
}

func TestCommands_Stream(t *testing.T) {
	cmds := MakeCommands()

	cmd := cmds.Stream("/path/to/test.pcap", "tcp", 0)
	require.NotNil(t, cmd)

	// Check the command string contains expected arguments
	cmdStr := cmd.String()
	assert.Contains(t, cmdStr, "-r")
	assert.Contains(t, cmdStr, "/path/to/test.pcap")
	assert.Contains(t, cmdStr, "-q")
	assert.Contains(t, cmdStr, "-z")
	assert.Contains(t, cmdStr, "follow,tcp,raw,0")
}

func TestCommands_Stream_UDP(t *testing.T) {
	cmds := MakeCommands()

	cmd := cmds.Stream("/path/to/test.pcap", "udp", 5)
	require.NotNil(t, cmd)

	cmdStr := cmd.String()
	assert.Contains(t, cmdStr, "follow,udp,raw,5")
}

func TestCommands_Indexer(t *testing.T) {
	cmds := MakeCommands()

	cmd := cmds.Indexer("/path/to/test.pcap", "tcp", 0)
	require.NotNil(t, cmd)

	cmdStr := cmd.String()
	assert.Contains(t, cmdStr, "-T")
	assert.Contains(t, cmdStr, "pdml")
	assert.Contains(t, cmdStr, "-r")
	assert.Contains(t, cmdStr, "/path/to/test.pcap")
	assert.Contains(t, cmdStr, "-Y")
	assert.Contains(t, cmdStr, "tcp.stream eq 0")
}

func TestCommands_Indexer_UDP(t *testing.T) {
	cmds := MakeCommands()

	cmd := cmds.Indexer("/path/to/test.pcap", "udp", 3)
	require.NotNil(t, cmd)

	cmdStr := cmd.String()
	assert.Contains(t, cmdStr, "udp.stream eq 3")
}

//======================================================================
// NewLoader Tests
//======================================================================

func TestNewLoader(t *testing.T) {
	cmds := MakeCommands()
	ctx := context.Background()

	loader := NewLoader(cmds, ctx)

	require.NotNil(t, loader)
	assert.NotNil(t, loader.mainCtx)
	assert.NotNil(t, loader.mainCancelFn)
	assert.False(t, loader.SuppressErrors)
}

func TestNewLoader_WithCancelledContext(t *testing.T) {
	cmds := MakeCommands()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	loader := NewLoader(cmds, ctx)

	require.NotNil(t, loader)
	// The loader's context should also be cancelled
	assert.Error(t, loader.mainCtx.Err())
}

//======================================================================
// StopLoad Tests
//======================================================================

func TestStopLoad_NoActiveLoads(t *testing.T) {
	cmds := MakeCommands()
	ctx := context.Background()
	loader := NewLoader(cmds, ctx)

	// Should not panic when no loads are active
	loader.StopLoad()

	assert.True(t, loader.SuppressErrors)
}

func TestStopLoad_WithActiveContexts(t *testing.T) {
	cmds := MakeCommands()
	ctx := context.Background()
	loader := NewLoader(cmds, ctx)

	// Simulate active contexts
	loader.streamCtx, loader.streamCancelFn = context.WithCancel(loader.mainCtx)
	loader.indexerCtx, loader.indexerCancelFn = context.WithCancel(loader.mainCtx)

	loader.StopLoad()

	assert.True(t, loader.SuppressErrors)
	assert.Error(t, loader.streamCtx.Err())
	assert.Error(t, loader.indexerCtx.Err())
}

//======================================================================
// decodeStreamXml Tests - TCP
//======================================================================

func TestDecodeStreamXml_TCP_WithPayload(t *testing.T) {
	// TCP packets with tcp.len > 0 should be tracked
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="100"/>
  </proto>
</packet>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="0"/>
  </proto>
</packet>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="50"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Equal(t, []int{0, 2}, tracker.indices) // Packets 0 and 2 have payload
}

func TestDecodeStreamXml_TCP_NoPayload(t *testing.T) {
	// TCP packets with tcp.len == 0 should not be tracked
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="0"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices)
}

//======================================================================
// decodeStreamXml Tests - UDP
//======================================================================

func TestDecodeStreamXml_UDP_WithPayload(t *testing.T) {
	// UDP packets with udp.length > 0 should be tracked
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="udp">
    <field name="udp.length" show="100"/>
  </proto>
</packet>
<packet>
  <proto name="udp">
    <field name="udp.length" show="0"/>
  </proto>
</packet>
<packet>
  <proto name="udp">
    <field name="udp.length" show="200"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "udp", ctx, tracker)

	assert.True(t, result)
	assert.Equal(t, []int{0, 2}, tracker.indices) // Packets 0 and 2 have payload
}

func TestDecodeStreamXml_UDP_NoPayload(t *testing.T) {
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="udp">
    <field name="udp.length" show="0"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "udp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices)
}

//======================================================================
// decodeStreamXml Tests - Context Cancellation
//======================================================================

func TestDecodeStreamXml_ContextCancelled(t *testing.T) {
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="100"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.False(t, result) // Should return false due to cancellation
}

//======================================================================
// decodeStreamXml Tests - Edge Cases
//======================================================================

func TestDecodeStreamXml_EmptyPdml(t *testing.T) {
	pdml := `<?xml version="1.0"?><pdml></pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices)
}

func TestDecodeStreamXml_NoPackets(t *testing.T) {
	pdml := `<?xml version="1.0"?>
<pdml>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices)
}

func TestDecodeStreamXml_PacketWithoutTcp(t *testing.T) {
	// Packet without tcp proto should not be tracked even if we're looking for tcp
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="ip">
    <field name="ip.len" show="100"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices)
}

func TestDecodeStreamXml_MixedProtocols(t *testing.T) {
	// When looking for TCP, ignore UDP fields
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="100"/>
  </proto>
  <proto name="udp">
    <field name="udp.length" show="200"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Equal(t, []int{0}, tracker.indices)
}

func TestDecodeStreamXml_InvalidLength(t *testing.T) {
	// Invalid (non-numeric) length should be ignored
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" show="invalid"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices) // Invalid length means curDataLen stays 0
}

func TestDecodeStreamXml_MultiplePackets(t *testing.T) {
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp"><field name="tcp.len" show="10"/></proto>
</packet>
<packet>
  <proto name="tcp"><field name="tcp.len" show="20"/></proto>
</packet>
<packet>
  <proto name="tcp"><field name="tcp.len" show="0"/></proto>
</packet>
<packet>
  <proto name="tcp"><field name="tcp.len" show="30"/></proto>
</packet>
<packet>
  <proto name="tcp"><field name="tcp.len" show="0"/></proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Equal(t, []int{0, 1, 3}, tracker.indices)
}

func TestDecodeStreamXml_MissingShowAttribute(t *testing.T) {
	// Field without show attribute should be ignored
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="tcp">
    <field name="tcp.len" value="100"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices) // No show attribute means no value parsed
}

func TestDecodeStreamXml_NestedProto(t *testing.T) {
	// Real-world PDML has nested structures
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="frame"></proto>
  <proto name="eth"></proto>
  <proto name="ip"></proto>
  <proto name="tcp">
    <field name="tcp.srcport" show="12345"/>
    <field name="tcp.dstport" show="80"/>
    <field name="tcp.len" show="943"/>
  </proto>
  <proto name="http"></proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Equal(t, []int{0}, tracker.indices)
}

//======================================================================
// decodeStreamXml Tests - Proto Matching
//======================================================================

func TestDecodeStreamXml_WrongProtoForFilter(t *testing.T) {
	// Looking for TCP but packet only has UDP
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="udp">
    <field name="udp.length" show="100"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices) // Not looking for UDP
}

func TestDecodeStreamXml_TcpLenInUdpPacket(t *testing.T) {
	// tcp.len field in a UDP proto should be ignored
	pdml := `<?xml version="1.0"?>
<pdml>
<packet>
  <proto name="udp">
    <field name="tcp.len" show="100"/>
  </proto>
</packet>
</pdml>`

	tracker := &payloadTracker{}
	ctx := context.Background()

	result := decodeStreamXml(strings.NewReader(pdml), "tcp", ctx, tracker)

	assert.True(t, result)
	assert.Empty(t, tracker.indices) // inTCP is false, so tcp.len is ignored
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
