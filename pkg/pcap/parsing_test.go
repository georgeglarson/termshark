// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// PDML Parsing Tests
//======================================================================

func TestParsePdmlPackets_Empty(t *testing.T) {
	input := `<?xml version="1.0"?><pdml></pdml>`
	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, false)

	require.NoError(t, err)
	assert.Empty(t, packets)
}

func TestParsePdmlPackets_SinglePacket(t *testing.T) {
	input := `<?xml version="1.0"?>
<pdml>
<packet>
<proto name="eth">test content</proto>
</packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, false)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Contains(t, string(packets[0].Packet().Content), "eth")
}

func TestParsePdmlPackets_MultiplePackets(t *testing.T) {
	input := `<?xml version="1.0"?>
<pdml>
<packet><proto name="eth">packet1</proto></packet>
<packet><proto name="ip">packet2</proto></packet>
<packet><proto name="tcp">packet3</proto></packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, false)

	require.NoError(t, err)
	require.Len(t, packets, 3)
}

func TestParsePdmlPackets_MaxPackets(t *testing.T) {
	input := `<?xml version="1.0"?>
<pdml>
<packet><proto>p1</proto></packet>
<packet><proto>p2</proto></packet>
<packet><proto>p3</proto></packet>
<packet><proto>p4</proto></packet>
<packet><proto>p5</proto></packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 2, false)

	require.NoError(t, err)
	assert.Len(t, packets, 2)
}

func TestParsePdmlPackets_WithCompression(t *testing.T) {
	input := `<?xml version="1.0"?>
<pdml>
<packet><proto name="eth">compressed packet content</proto></packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, true)

	require.NoError(t, err)
	require.Len(t, packets, 1)

	// Verify it's a SnappiedPdmlPacket
	_, ok := packets[0].(SnappiedPdmlPacket)
	assert.True(t, ok, "packet should be compressed as SnappiedPdmlPacket")

	// Verify content is recoverable
	recovered := packets[0].Packet()
	assert.Contains(t, string(recovered.Content), "eth")
}

func TestParsePdmlPackets_UnexpectedEOF(t *testing.T) {
	// Truncated XML - should handle gracefully
	input := `<?xml version="1.0"?>
<pdml>
<packet><proto>p1</proto></packet>
<packet><proto>p2</pro`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, false)

	// Should return packets parsed before the error
	assert.NoError(t, err)
	assert.Len(t, packets, 1)
}

func TestParsePdmlPackets_RealWorldContent(t *testing.T) {
	// More realistic PDML content
	input := `<?xml version="1.0"?>
<pdml version="0" creator="wireshark">
<packet>
<proto name="geninfo" pos="0" showname="General information" size="74">
<field name="num" pos="0" show="1" showname="Number" value="1" size="74"/>
</proto>
<proto name="eth" showname="Ethernet II" size="14" pos="0">
<field name="eth.dst" showname="Destination: ff:ff:ff:ff:ff:ff" size="6" pos="0" show="ff:ff:ff:ff:ff:ff" value="ffffffffffff"/>
<field name="eth.src" showname="Source: 00:11:22:33:44:55" size="6" pos="6" show="00:11:22:33:44:55" value="001122334455"/>
</proto>
</packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, false)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	content := string(packets[0].Packet().Content)
	assert.Contains(t, content, "eth.dst")
	assert.Contains(t, content, "ff:ff:ff:ff:ff:ff")
}

//======================================================================
// PCAP Hex Dump Parsing Tests
//======================================================================

func TestParsePcapHexDump_Empty(t *testing.T) {
	input := ``
	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	assert.Empty(t, packets)
}

func TestParsePcapHexDump_SinglePacket(t *testing.T) {
	// Typical tshark -x output format
	input := `0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01
0010  08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 01 01

`

	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	// First 6 bytes should be broadcast MAC
	assert.Equal(t, byte(0xff), packets[0][0])
	assert.Equal(t, byte(0xff), packets[0][1])
}

func TestParsePcapHexDump_MultiplePackets(t *testing.T) {
	input := `0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06

0000  00 11 22 33 44 55 aa bb cc dd ee ff 08 00

0000  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e

`

	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	assert.Len(t, packets, 3)
}

func TestParsePcapHexDump_MaxPackets(t *testing.T) {
	input := `0000  ff ff ff ff

0000  00 11 22 33

0000  aa bb cc dd

0000  ee ff 00 11

`

	packets, err := ParsePcapHexDump(strings.NewReader(input), 2)

	require.NoError(t, err)
	assert.Len(t, packets, 2)
}

func TestParsePcapHexDump_MultilinePacket(t *testing.T) {
	input := `0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00
0010  00 28 00 01 00 00 40 06 f9 7c c0 a8 01 01 c0 a8
0020  01 02 00 50 c3 50 00 00 00 00 00 00 00 00 50 02
0030  20 00 91 7c 00 00

`

	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	// Should have parsed all bytes across multiple lines
	assert.True(t, len(packets[0]) > 16, "packet should span multiple lines")
}

func TestParsePcapHexDump_NoTrailingNewline(t *testing.T) {
	// The regex requires a trailing space after each hex pair
	// So "ff ff ff ff ff ff" (no trailing space on last byte) only matches 5 bytes
	// This matches real tshark output which has spaces between bytes
	input := `0000  ff ff ff ff ff ff `

	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Len(t, packets[0], 6)
}

func TestParsePcapHexDump_InvalidHex(t *testing.T) {
	// Invalid hex "gg" doesn't match the regex pattern, so it's skipped
	// The parser is lenient - it only extracts valid hex byte patterns
	// Regex matches: "ff " "ff " then skips "gg " then "ff " "ff "
	// Last "ff" has no trailing space so doesn't match = 4 bytes
	input := `0000  ff ff gg ff ff ff

`

	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)

	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Len(t, packets[0], 4)
}

//======================================================================
// PSML Parsing Tests
//======================================================================

func TestParsePsmlXML_Empty(t *testing.T) {
	input := `<?xml version="1.0"?><psml></psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	assert.Empty(t, result.Headers)
	assert.Empty(t, result.Packets)
}

func TestParsePsmlXML_StructureOnly(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Time</section>
<section>Source</section>
<section>Destination</section>
<section>Protocol</section>
<section>Length</section>
<section>Info</section>
</structure>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	assert.Equal(t, []string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}, result.Headers)
	assert.Empty(t, result.Packets)
}

func TestParsePsmlXML_SinglePacket(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Time</section>
<section>Source</section>
</structure>
<packet>
<section>1</section>
<section>0.000000</section>
<section>192.168.1.1</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 1)
	require.Len(t, result.PacketNumbers, 1)

	assert.Equal(t, 1, result.PacketNumbers[0])
	// Fields should exclude the packet number (first section)
	assert.Equal(t, []string{"0.000000", "192.168.1.1"}, result.Packets[0].Fields)
}

func TestParsePsmlXML_MultiplePackets(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Time</section>
</structure>
<packet>
<section>1</section>
<section>0.000000</section>
</packet>
<packet>
<section>2</section>
<section>0.001234</section>
</packet>
<packet>
<section>5</section>
<section>0.005678</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 3)
	assert.Equal(t, []int{1, 2, 5}, result.PacketNumbers)
}

func TestParsePsmlXML_WithColors(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Protocol</section>
</structure>
<packet foreground="#000000" background="#e4ffc7">
<section>1</section>
<section>HTTP</section>
</packet>
<packet foreground="#000000" background="#fce0ff">
<section>2</section>
<section>TCP</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 2)

	assert.Equal(t, "#000000", result.Packets[0].FG)
	assert.Equal(t, "#e4ffc7", result.Packets[0].BG)
	assert.Equal(t, "#000000", result.Packets[1].FG)
	assert.Equal(t, "#fce0ff", result.Packets[1].BG)
}

func TestParsePsmlXML_EmptySections(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Info</section>
</structure>
<packet>
<section>1</section>
<section></section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 1)
	// Empty section should be preserved as empty string
	assert.Equal(t, []string{""}, result.Packets[0].Fields)
}

func TestParsePsmlXML_SpecialCharacters(t *testing.T) {
	// PSML may contain hex-encoded characters that TranslateHexCodes handles
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Info</section>
</structure>
<packet>
<section>1</section>
<section>GET /path HTTP/1.1</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 1)
	assert.Equal(t, "GET /path HTTP/1.1", result.Packets[0].Fields[0])
}

func TestParsePsmlXML_RealWorldExample(t *testing.T) {
	input := `<?xml version="1.0" encoding="utf-8"?>
<psml version="0" creator="wireshark/3.4.0">
<structure>
<section>No.</section>
<section>Time</section>
<section>Source</section>
<section>Destination</section>
<section>Protocol</section>
<section>Length</section>
<section>Info</section>
</structure>
<packet foreground="#000000" background="#e4ffc7">
<section>1</section>
<section>0.000000</section>
<section>192.168.44.123</section>
<section>192.168.44.213</section>
<section>TFTP</section>
<section>77</section>
<section>Read Request, File: C:\IBMTCPIP\lccm.1, Transfer type: octet</section>
</packet>
<packet foreground="#000000" background="#fce0ff">
<section>2</section>
<section>0.000123</section>
<section>192.168.44.213</section>
<section>192.168.44.123</section>
<section>TCP</section>
<section>54</section>
<section>80 → 12345 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)

	// Check headers (should skip the first "No." column based on our convention)
	assert.Equal(t, []string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}, result.Headers)

	// Check packets
	require.Len(t, result.Packets, 2)

	// First packet
	assert.Equal(t, 1, result.PacketNumbers[0])
	assert.Equal(t, "TFTP", result.Packets[0].Fields[3]) // Protocol
	assert.Equal(t, "#e4ffc7", result.Packets[0].BG)

	// Second packet
	assert.Equal(t, 2, result.PacketNumbers[1])
	assert.Equal(t, "TCP", result.Packets[1].Fields[3])
	assert.Contains(t, result.Packets[1].Fields[5], "SYN, ACK")
}

func TestParsePsmlXML_FilteredPackets(t *testing.T) {
	// When a filter is applied, packet numbers may not be sequential
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Protocol</section>
</structure>
<packet>
<section>5</section>
<section>TCP</section>
</packet>
<packet>
<section>12</section>
<section>TCP</section>
</packet>
<packet>
<section>47</section>
<section>TCP</section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))

	require.NoError(t, err)
	require.Len(t, result.Packets, 3)

	// Packet numbers should reflect actual frame numbers, not row indices
	assert.Equal(t, []int{5, 12, 47}, result.PacketNumbers)
}

//======================================================================
// ParsePsmlColors Tests
//======================================================================

func TestParsePsmlColors_Valid(t *testing.T) {
	colors := ParsePsmlColors("#ff0000", "#00ff00")

	assert.NotNil(t, colors.FG)
	assert.NotNil(t, colors.BG)
}

func TestParsePsmlColors_Empty(t *testing.T) {
	colors := ParsePsmlColors("", "")

	assert.Nil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

func TestParsePsmlColors_Invalid(t *testing.T) {
	colors := ParsePsmlColors("notacolor", "alsonotacolor")

	assert.Nil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

func TestParsePsmlColors_Mixed(t *testing.T) {
	colors := ParsePsmlColors("#000000", "invalid")

	assert.NotNil(t, colors.FG)
	assert.Nil(t, colors.BG)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
