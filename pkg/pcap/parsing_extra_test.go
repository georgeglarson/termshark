// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// ParsePdmlPackets edge case tests
//======================================================================

func TestParsePdmlPackets_MalformedXML(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "completely invalid xml",
			input:     "this is not xml at all <<>>&&",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "empty string",
			input:     "",
			wantCount: 0,
			wantErr:   false, // EOF on empty input returns nil
		},
		{
			name:      "just whitespace",
			input:     "   \n\t  ",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "xml declaration only",
			input:     `<?xml version="1.0"?>`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "pdml tag with no closing",
			input:     `<?xml version="1.0"?><pdml>`,
			wantCount: 0,
			wantErr:   false, // unexpected EOF treated as graceful
		},
		{
			name:      "packet without closing tag",
			input:     `<?xml version="1.0"?><pdml><packet><proto name="eth">`,
			wantCount: 0,
			wantErr:   false, // unexpected EOF treated as graceful
		},
		{
			name:      "truncated in middle of packet attribute",
			input:     `<?xml version="1.0"?><pdml><packet><proto name="eth">data</proto></packet><packet><proto name="i`,
			wantCount: 1, // first packet parsed before truncation
			wantErr:   false,
		},
		{
			name:      "valid packet then truncated second",
			input:     `<?xml version="1.0"?><pdml><packet><proto>p1</proto></packet><packet><proto>p`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "non-packet elements ignored",
			input:     `<?xml version="1.0"?><pdml><creator>wireshark</creator><packet><proto>p1</proto></packet></pdml>`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "packet with many attributes",
			input: `<?xml version="1.0"?>
<pdml version="0" creator="wireshark/4.0.0">
<packet>
<proto name="geninfo" pos="0" showname="General information" size="74">
<field name="num" pos="0" show="1" showname="Number" value="1" size="74"/>
<field name="len" pos="0" show="74" showname="Frame Length" value="4a" size="74"/>
<field name="caplen" pos="0" show="74" showname="Capture Length" value="4a" size="74"/>
</proto>
</packet>
</pdml>`,
			wantCount: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets, err := ParsePdmlPackets(strings.NewReader(tt.input), 0, false)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCount, len(packets), "packet count mismatch")
		})
	}
}

func TestParsePdmlPackets_MaxPacketsBoundary(t *testing.T) {
	tests := []struct {
		name         string
		totalPackets int
		maxPackets   int
		wantCount    int
	}{
		{
			name:         "max equals total",
			totalPackets: 5,
			maxPackets:   5,
			wantCount:    5,
		},
		{
			name:         "max greater than total",
			totalPackets: 3,
			maxPackets:   10,
			wantCount:    3,
		},
		{
			name:         "max of 1",
			totalPackets: 5,
			maxPackets:   1,
			wantCount:    1,
		},
		{
			name:         "max of 0 means unlimited",
			totalPackets: 5,
			maxPackets:   0,
			wantCount:    5,
		},
		{
			name:         "negative max treated as 0 (unlimited)",
			totalPackets: 3,
			maxPackets:   -1,
			wantCount:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xml := generateLargePdmlXML(tt.totalPackets)
			packets, err := ParsePdmlPackets(strings.NewReader(xml), tt.maxPackets, false)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, len(packets))
		})
	}
}

func TestParsePdmlPackets_CompressedRoundtrip(t *testing.T) {
	input := `<?xml version="1.0"?>
<pdml>
<packet>
<proto name="eth" showname="Ethernet II">
<field name="eth.dst" show="ff:ff:ff:ff:ff:ff" value="ffffffffffff"/>
<field name="eth.src" show="00:11:22:33:44:55" value="001122334455"/>
</proto>
<proto name="ip">
<field name="ip.src" show="192.168.1.1"/>
<field name="ip.dst" show="10.0.0.1"/>
</proto>
</packet>
<packet>
<proto name="tcp">
<field name="tcp.srcport" show="12345"/>
<field name="tcp.dstport" show="80"/>
</proto>
</packet>
</pdml>`

	packets, err := ParsePdmlPackets(strings.NewReader(input), 0, true)
	require.NoError(t, err)
	require.Len(t, packets, 2)

	// Verify each compressed packet can be decompressed and has correct content
	p0 := packets[0].Packet()
	assert.Contains(t, string(p0.Content), "eth.dst")
	assert.Contains(t, string(p0.Content), "192.168.1.1")

	p1 := packets[1].Packet()
	assert.Contains(t, string(p1.Content), "tcp.srcport")
}

func TestParsePdmlPackets_LargePacketCount(t *testing.T) {
	xml := generateLargePdmlXML(50)
	packets, err := ParsePdmlPackets(strings.NewReader(xml), 0, false)
	require.NoError(t, err)
	assert.Len(t, packets, 50)
}

func TestParsePdmlPackets_ReaderError(t *testing.T) {
	// Use a reader that returns an error partway through
	errReader := &errorAfterNBytes{
		data:       []byte(`<?xml version="1.0"?><pdml><packet><proto>p1</proto></packet>`),
		failAtByte: 30,
		err:        fmt.Errorf("disk read error"),
	}
	packets, err := ParsePdmlPackets(errReader, 0, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disk read error")
	// May have parsed 0 packets depending on where the error occurs
	_ = packets
}

//======================================================================
// ParsePcapHexDump edge case tests
//======================================================================

func TestParsePcapHexDump_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		maxPackets    int
		wantCount     int
		wantFirstLen  int
		wantErr       bool
	}{
		{
			name:      "only blank lines",
			input:     "\n\n\n\n",
			maxPackets: 0,
			wantCount: 0,
		},
		{
			name:      "single hex line no trailing newline",
			input:     "0000  aa bb cc dd ",
			maxPackets: 0,
			wantCount: 1,
			wantFirstLen: 4,
		},
		{
			name: "multiple blank lines between packets",
			input: `0000  ff ff

0000  aa bb

`,
			maxPackets: 0,
			wantCount: 2,
		},
		{
			// The hex regex requires a trailing space after each byte pair.
			// The last byte on each line has no trailing space so is NOT matched.
			// Each line: 15 data bytes parsed (line number match skipped, last byte dropped).
			// 3 lines * 15 = 45 bytes.
			name: "large multi-line packet",
			input: `0000  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
0010  11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
0020  21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30

`,
			maxPackets: 0,
			wantCount: 1,
			wantFirstLen: 45,
		},
		{
			name: "max packets of 1 with 3 packets",
			input: `0000  ff ff

0000  aa bb

0000  cc dd

`,
			maxPackets: 1,
			wantCount: 1,
		},
		{
			// "0000  ff ff ff ff" without trailing space on last byte:
			// regex matches "00 ", "ff ", "ff ", "ff " (4 matches, first skipped = 3 data bytes).
			// The last "ff" has no trailing space so is not matched.
			name: "text lines interspersed (non-hex)",
			input: `some header text
0000  ff ff ff ff

`,
			maxPackets: 0,
			wantCount: 1,
			wantFirstLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets, err := ParsePcapHexDump(strings.NewReader(tt.input), tt.maxPackets)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCount, len(packets), "packet count mismatch")
			if tt.wantFirstLen > 0 && len(packets) > 0 {
				assert.Equal(t, tt.wantFirstLen, len(packets[0]), "first packet length mismatch")
			}
		})
	}
}

func TestParsePcapHexDump_ByteValues(t *testing.T) {
	// Verify all hex byte values parse correctly
	input := "0000  00 01 7f 80 fe ff \n\n"
	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}, packets[0])
}

func TestParsePcapHexDump_ReaderError(t *testing.T) {
	errReader := &errorAfterNBytes{
		data:       []byte("0000  ff ff ff ff \n\n0000  aa bb \n\n"),
		failAtByte: 15,
		err:        fmt.Errorf("io error"),
	}
	packets, err := ParsePcapHexDump(errReader, 0)
	assert.Error(t, err)
	// Should have partial results
	_ = packets
}

func TestParsePcapHexDump_RealTsharkOutput(t *testing.T) {
	// Simulate real tshark -x output with ASCII column
	input := `0000  30 fd 38 d2 76 12 e8 de 27 19 de 6c 08 00 45 00   0.8.v...'..l..E.
0010  00 73 7d ef 40 00 40 06 8a 64 c0 a8 56 f6 34 14   .s}.@.@..d..V.4.
0020  e6 7e a4 c8 01 bb 3e ad 82 88 17 e6 8f 97 80 18   .~....>.........

0000  e8 de 27 19 de 6c 30 fd 38 d2 76 12 08 00 45 00   ..'..l0.8.v...E.
0010  00 59 23 f9 40 00 ef 06 35 74 34 14 e6 7e c0 a8   .Y#.@...5t4..~..

`
	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)
	require.NoError(t, err)
	assert.Len(t, packets, 2)
	// First packet should start with 0x30
	assert.Equal(t, byte(0x30), packets[0][0])
	// Second packet should start with 0xe8
	assert.Equal(t, byte(0xe8), packets[1][0])
}

//======================================================================
// ParsePsmlXML edge case tests
//======================================================================

func TestParsePsmlXML_MalformedInputs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		wantHeaders int
		wantPackets int
	}{
		{
			name:        "completely invalid xml",
			input:       "<<not xml>>",
			wantErr:     true,
			wantHeaders: 0,
			wantPackets: 0,
		},
		{
			name:        "empty string",
			input:       "",
			wantErr:     false,
			wantHeaders: 0,
			wantPackets: 0,
		},
		{
			name:        "whitespace only",
			input:       "  \n \t ",
			wantErr:     false,
			wantHeaders: 0,
			wantPackets: 0,
		},
		{
			name:        "xml declaration only",
			input:       `<?xml version="1.0"?>`,
			wantErr:     false,
			wantHeaders: 0,
			wantPackets: 0,
		},
		{
			name: "structure with empty sections",
			input: `<?xml version="1.0"?>
<psml>
<structure>
<section></section>
<section></section>
</structure>
</psml>`,
			wantErr:     false,
			wantHeaders: 0, // empty char data sections produce no headers
			wantPackets: 0,
		},
		{
			name: "packet with no sections",
			input: `<?xml version="1.0"?>
<psml>
<structure><section>No.</section></structure>
<packet></packet>
</psml>`,
			wantErr:     false,
			wantHeaders: 1,
			wantPackets: 0, // empty curPsml means no packet added
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePsmlXML(strings.NewReader(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if result != nil {
				assert.Len(t, result.Headers, tt.wantHeaders)
				assert.Len(t, result.Packets, tt.wantPackets)
			}
		})
	}
}

func TestParsePsmlXML_PacketNumberExtraction(t *testing.T) {
	tests := []struct {
		name            string
		packetNumbers   []string
		wantNumbers     []int
		wantErr         bool
	}{
		{
			name:          "sequential numbers",
			packetNumbers: []string{"1", "2", "3"},
			wantNumbers:   []int{1, 2, 3},
		},
		{
			name:          "non-sequential (filtered)",
			packetNumbers: []string{"5", "12", "47", "100"},
			wantNumbers:   []int{5, 12, 47, 100},
		},
		{
			name:          "large packet numbers",
			packetNumbers: []string{"999999", "1000000"},
			wantNumbers:   []int{999999, 1000000},
		},
		{
			name:          "single packet",
			packetNumbers: []string{"42"},
			wantNumbers:   []int{42},
		},
		{
			name:          "non-numeric packet number causes error",
			packetNumbers: []string{"abc"},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			buf.WriteString(`<?xml version="1.0"?><psml><structure><section>No.</section><section>Info</section></structure>`)
			for _, num := range tt.packetNumbers {
				buf.WriteString(fmt.Sprintf(`<packet><section>%s</section><section>data</section></packet>`, num))
			}
			buf.WriteString(`</psml>`)

			result, err := ParsePsmlXML(strings.NewReader(buf.String()))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantNumbers, result.PacketNumbers)
			}
		})
	}
}

func TestParsePsmlXML_ColorVariations(t *testing.T) {
	tests := []struct {
		name   string
		fg     string
		bg     string
		wantFG string
		wantBG string
	}{
		{
			name:   "both colors set",
			fg:     `foreground="#ff0000"`,
			bg:     `background="#00ff00"`,
			wantFG: "#ff0000",
			wantBG: "#00ff00",
		},
		{
			name:   "only foreground",
			fg:     `foreground="#ffffff"`,
			bg:     "",
			wantFG: "#ffffff",
			wantBG: "",
		},
		{
			name:   "only background",
			fg:     "",
			bg:     `background="#000000"`,
			wantFG: "",
			wantBG: "#000000",
		},
		{
			name:   "neither color set",
			fg:     "",
			bg:     "",
			wantFG: "",
			wantBG: "",
		},
		{
			name:   "typical wireshark colors",
			fg:     `foreground="#000000"`,
			bg:     `background="#e4ffc7"`,
			wantFG: "#000000",
			wantBG: "#e4ffc7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ""
			if tt.fg != "" {
				attrs += " " + tt.fg
			}
			if tt.bg != "" {
				attrs += " " + tt.bg
			}
			input := fmt.Sprintf(`<?xml version="1.0"?>
<psml>
<structure><section>No.</section><section>Info</section></structure>
<packet%s>
<section>1</section>
<section>test</section>
</packet>
</psml>`, attrs)

			result, err := ParsePsmlXML(strings.NewReader(input))
			require.NoError(t, err)
			require.Len(t, result.Packets, 1)
			assert.Equal(t, tt.wantFG, result.Packets[0].FG)
			assert.Equal(t, tt.wantBG, result.Packets[0].BG)
		})
	}
}

func TestParsePsmlXML_MixedEmptyAndFilledSections(t *testing.T) {
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Time</section>
<section>Source</section>
<section>Dest</section>
</structure>
<packet>
<section>1</section>
<section></section>
<section>192.168.1.1</section>
<section></section>
</packet>
</psml>`

	result, err := ParsePsmlXML(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, result.Packets, 1)

	// Fields skip the first section (packet number)
	fields := result.Packets[0].Fields
	assert.Len(t, fields, 3)
	assert.Equal(t, "", fields[0])          // empty Time
	assert.Equal(t, "192.168.1.1", fields[1]) // Source
	assert.Equal(t, "", fields[2])          // empty Dest
}

func TestParsePsmlXML_TruncatedInput(t *testing.T) {
	// Truncated in the middle of PSML - should handle gracefully
	input := `<?xml version="1.0"?>
<psml>
<structure>
<section>No.</section>
<section>Info</section>
</structure>
<packet>
<section>1</section>
<section>first packet data</section>
</packet>
<packet>
<section>2</section>
<section>trunca`

	result, err := ParsePsmlXML(strings.NewReader(input))
	// May or may not return error depending on XML parser behavior
	// But the first packet should be parsed
	if err == nil {
		require.NotNil(t, result)
		assert.GreaterOrEqual(t, len(result.Packets), 1)
		assert.Equal(t, 1, result.PacketNumbers[0])
	}
}

func TestParsePsmlXML_HeaderFormats(t *testing.T) {
	tests := []struct {
		name        string
		headers     []string
		wantHeaders []string
	}{
		{
			name:        "standard wireshark headers",
			headers:     []string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"},
			wantHeaders: []string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"},
		},
		{
			name:        "custom column names",
			headers:     []string{"No.", "Frame Number", "Src IP", "Dst IP"},
			wantHeaders: []string{"No.", "Frame Number", "Src IP", "Dst IP"},
		},
		{
			name:        "single header",
			headers:     []string{"No.", "Data"},
			wantHeaders: []string{"No.", "Data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			buf.WriteString(`<?xml version="1.0"?><psml><structure>`)
			for _, h := range tt.headers {
				buf.WriteString(fmt.Sprintf("<section>%s</section>", h))
			}
			buf.WriteString(`</structure></psml>`)

			result, err := ParsePsmlXML(strings.NewReader(buf.String()))
			require.NoError(t, err)
			assert.Equal(t, tt.wantHeaders, result.Headers)
		})
	}
}

func TestParsePsmlXML_LargePacketCount(t *testing.T) {
	count := 200
	xml := generateLargePsmlXML(count)
	result, err := ParsePsmlXML(strings.NewReader(xml))
	require.NoError(t, err)
	assert.Len(t, result.Packets, count)
	assert.Len(t, result.PacketNumbers, count)
}

//======================================================================
// ParsePsmlColors additional tests
//======================================================================

func TestParsePsmlColors_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		fg         string
		bg         string
		wantFGNil  bool
		wantBGNil  bool
	}{
		{
			name:      "valid hex colors",
			fg:        "#ff0000",
			bg:        "#00ff00",
			wantFGNil: false,
			wantBGNil: false,
		},
		{
			name:      "both empty",
			fg:        "",
			bg:        "",
			wantFGNil: true,
			wantBGNil: true,
		},
		{
			name:      "fg valid bg empty",
			fg:        "#aabbcc",
			bg:        "",
			wantFGNil: false,
			wantBGNil: true,
		},
		{
			name:      "fg empty bg valid",
			fg:        "",
			bg:        "#112233",
			wantFGNil: true,
			wantBGNil: false,
		},
		{
			name:      "fg invalid bg valid",
			fg:        "red",
			bg:        "#000000",
			wantFGNil: true,
			wantBGNil: false,
		},
		{
			name:      "both invalid",
			fg:        "xyz",
			bg:        "abc",
			wantFGNil: true,
			wantBGNil: true,
		},
		{
			name:      "missing hash prefix",
			fg:        "ff0000",
			bg:        "00ff00",
			wantFGNil: true,
			wantBGNil: true,
		},
		{
			name:      "black colors",
			fg:        "#000000",
			bg:        "#000000",
			wantFGNil: false,
			wantBGNil: false,
		},
		{
			name:      "white colors",
			fg:        "#ffffff",
			bg:        "#ffffff",
			wantFGNil: false,
			wantBGNil: false,
		},
		{
			name:      "wireshark typical TCP background",
			fg:        "#000000",
			bg:        "#e4ffc7",
			wantFGNil: false,
			wantBGNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			colors := ParsePsmlColors(tt.fg, tt.bg)
			if tt.wantFGNil {
				assert.Nil(t, colors.FG)
			} else {
				assert.NotNil(t, colors.FG)
			}
			if tt.wantBGNil {
				assert.Nil(t, colors.BG)
			} else {
				assert.NotNil(t, colors.BG)
			}
		})
	}
}

//======================================================================
// ParsePcapHexDump with testdata fixtures
//======================================================================

func TestParsePcapHexDump_FromFixture(t *testing.T) {
	// Use the known fixture hex dump from testdata/1.hexdump
	input := `0000  30 fd 38 d2 76 12 e8 de 27 19 de 6c 08 00 45 00   0.8.v...'..l..E.
0010  00 73 7d ef 40 00 40 06 8a 64 c0 a8 56 f6 34 14   .s}.@.@..d..V.4.

0000  e8 de 27 19 de 6c 30 fd 38 d2 76 12 08 00 45 00   ..'..l0.8.v...E.
0010  00 59 23 f9 40 00 ef 06 35 74 34 14 e6 7e c0 a8   .Y#.@...5t4..~..

`
	packets, err := ParsePcapHexDump(strings.NewReader(input), 0)
	require.NoError(t, err)
	assert.Len(t, packets, 2)
	// Verify first byte of first packet
	assert.Equal(t, byte(0x30), packets[0][0])
	// Verify first packet has correct number of bytes (2 lines x 16 bytes = 32,
	// but second line starts at 0x0010 with only 3 bytes shown here)
	// Line 1: 0x30 to 0x45 0x00 = 16 bytes
	// Line 2: 0x00 to 0x34 0x14 = 16 bytes
	assert.Equal(t, 32, len(packets[0]))
}

//======================================================================
// PsmlPacketData tests
//======================================================================

func TestPsmlPacketData_FieldAccess(t *testing.T) {
	data := PsmlPacketData{
		Fields: []string{"0.000000", "192.168.1.1", "192.168.1.2", "TCP", "74", "SYN"},
		FG:     "#000000",
		BG:     "#e4ffc7",
	}

	assert.Len(t, data.Fields, 6)
	assert.Equal(t, "TCP", data.Fields[3])
	assert.Equal(t, "#000000", data.FG)
	assert.Equal(t, "#e4ffc7", data.BG)
}

func TestPsmlParseResult_EmptyResult(t *testing.T) {
	result := &PsmlParseResult{
		Headers:       make([]string, 0),
		Packets:       make([]PsmlPacketData, 0),
		PacketNumbers: make([]int, 0),
	}

	assert.Empty(t, result.Headers)
	assert.Empty(t, result.Packets)
	assert.Empty(t, result.PacketNumbers)
}

//======================================================================
// psmlColorToIColor additional tests
//======================================================================

func TestPsmlColorToIColor_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
	}{
		{"valid red", "#ff0000", false},
		{"valid green", "#00ff00", false},
		{"valid blue", "#0000ff", false},
		{"valid black", "#000000", false},
		{"valid white", "#ffffff", false},
		{"empty string", "", true},
		{"no hash", "ff0000", true},
		{"named color", "red", true},
		{"short hex is valid for gowid", "#fff", false},
		{"not hex", "#gggggg", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := psmlColorToIColor(tt.input)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

//======================================================================
// Helper types
//======================================================================

// errorAfterNBytes is a reader that returns an error after reading n bytes
type errorAfterNBytes struct {
	data       []byte
	failAtByte int
	err        error
	pos        int
}

func (r *errorAfterNBytes) Read(p []byte) (int, error) {
	if r.pos >= r.failAtByte {
		return 0, r.err
	}
	remaining := r.failAtByte - r.pos
	toRead := len(p)
	if toRead > remaining {
		toRead = remaining
	}
	if r.pos+toRead > len(r.data) {
		toRead = len(r.data) - r.pos
		if toRead <= 0 {
			return 0, io.EOF
		}
	}
	copy(p, r.data[r.pos:r.pos+toRead])
	r.pos += toRead
	if r.pos >= r.failAtByte {
		return toRead, r.err
	}
	return toRead, nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
