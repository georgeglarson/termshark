// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// Malformed Input Tests
//======================================================================

func TestParseReader_CompletelyGarbage(t *testing.T) {
	inp := "this is not valid stream data at all"
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

func TestParseReader_MissingSeparator(t *testing.T) {
	// Header without === separator lines
	inp := `Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
48454c4c4f
`
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

func TestParseReader_MissingFollowField(t *testing.T) {
	inp := `
===================================================================
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
===================================================================
`
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

func TestParseReader_MissingFilterField(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
===================================================================
`
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

func TestParseReader_MissingNode0(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 1: 192.168.1.2:80
===================================================================
`
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

func TestParseReader_MissingNode1(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
===================================================================
`
	_, err := ParseReader("test", strings.NewReader(inp))
	assert.Error(t, err)
}

//======================================================================
// Empty Data, Single-Byte Data, Very Long Data Tests
//======================================================================

func TestParseReader_EmptyDataSection(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	assert.Empty(t, fs.Bytes)
}

func TestParseReader_SingleByteClient(t *testing.T) {
	// Single byte of data (hex "41" = 'A')
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
41
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, Client, fs.Bytes[0].Dirn)
	assert.Equal(t, []byte("A"), fs.Bytes[0].Data)
}

func TestParseReader_SingleByteServer(t *testing.T) {
	// Single byte from server (tab-prefixed)
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	42
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, Server, fs.Bytes[0].Dirn)
	assert.Equal(t, []byte("B"), fs.Bytes[0].Data)
}

func TestParseReader_VeryLongData(t *testing.T) {
	// Generate a long hex string (1024 bytes = 2048 hex chars)
	var hexBuf bytes.Buffer
	for i := 0; i < 1024; i++ {
		hexBuf.WriteString("ab")
	}
	hexLine := hexBuf.String()

	inp := "\n===================================================================\n" +
		"Follow: tcp,raw\n" +
		"Filter: tcp.stream eq 0\n" +
		"Node 0: 192.168.1.1:1234\n" +
		"Node 1: 192.168.1.2:80\n" +
		hexLine + "\n" +
		"===================================================================\n"

	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, Client, fs.Bytes[0].Dirn)
	assert.Len(t, fs.Bytes[0].Data, 1024)
	// Verify each byte is 0xab
	for _, b := range fs.Bytes[0].Data {
		assert.Equal(t, byte(0xab), b)
	}
}

//======================================================================
// Truncated Hex String Tests
//======================================================================

func TestParseReader_OddLengthHex(t *testing.T) {
	// Odd number of hex chars - parser requires pairs
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4845a
===================================================================
`
	// The parser should fail because hex pairs are incomplete
	_, err := ParseReader("test", strings.NewReader(inp))
	// It should error because 'a' alone is not a complete hex pair before newline
	assert.Error(t, err)
}

func TestParseReader_OnlyOneSeparatorLine(t *testing.T) {
	// Missing the trailing separator
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4845
`
	// Missing trailing separator - parser may fail
	_, err := ParseReader("test", strings.NewReader(inp))
	// The parser requires a trailing separator
	assert.Error(t, err)
}

//======================================================================
// Chunk Reassembly with Various Interleaving Patterns
//======================================================================

func TestParseReader_ClientServerClientServer(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
48454c4c4f
	574f524c44
42594521
	4f4b2121
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 4)

	assert.Equal(t, Client, fs.Bytes[0].Dirn)
	assert.Equal(t, []byte("HELLO"), fs.Bytes[0].Data)

	assert.Equal(t, Server, fs.Bytes[1].Dirn)
	assert.Equal(t, []byte("WORLD"), fs.Bytes[1].Data)

	assert.Equal(t, Client, fs.Bytes[2].Dirn)
	assert.Equal(t, []byte("BYE!"), fs.Bytes[2].Data)

	assert.Equal(t, Server, fs.Bytes[3].Dirn)
	assert.Equal(t, []byte("OK!!"), fs.Bytes[3].Data)
}

func TestParseReader_MultipleConsecutiveServerChunks(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	4141
	4242
	4343
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 3)

	for _, chunk := range fs.Bytes {
		assert.Equal(t, Server, chunk.Dirn)
	}
	assert.Equal(t, []byte("AA"), fs.Bytes[0].Data)
	assert.Equal(t, []byte("BB"), fs.Bytes[1].Data)
	assert.Equal(t, []byte("CC"), fs.Bytes[2].Data)
}

func TestParseReader_MultipleConsecutiveClientChunks(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4141
4242
4343
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 3)

	for _, chunk := range fs.Bytes {
		assert.Equal(t, Client, chunk.Dirn)
	}
	assert.Equal(t, []byte("AA"), fs.Bytes[0].Data)
	assert.Equal(t, []byte("BB"), fs.Bytes[1].Data)
	assert.Equal(t, []byte("CC"), fs.Bytes[2].Data)
}

func TestParseReader_ServerThenManyClients(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 10.0.0.1:5000
Node 1: 10.0.0.2:8080
	48545450
6162
6364
6566
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 4)

	assert.Equal(t, Server, fs.Bytes[0].Dirn)
	assert.Equal(t, Client, fs.Bytes[1].Dirn)
	assert.Equal(t, Client, fs.Bytes[2].Dirn)
	assert.Equal(t, Client, fs.Bytes[3].Dirn)
}

//======================================================================
// Header Parsing and Node Values
//======================================================================

func TestParseReader_HeaderFieldExtraction(t *testing.T) {
	inp := `
===================================================================
Follow: udp,raw
Filter: udp.stream eq 5
Node 0: 10.0.0.1:53
Node 1: 8.8.8.8:53
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	assert.Equal(t, "udp,raw", fs.Follow)
	assert.Equal(t, "udp.stream eq 5", fs.Filter)
	assert.Equal(t, "10.0.0.1:53", fs.Node0)
	assert.Equal(t, "8.8.8.8:53", fs.Node1)
}

func TestParseReader_IPv6Nodes(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: [2001:db8::1]:443
Node 1: [2001:db8::2]:80
	4f4b
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	assert.Equal(t, "[2001:db8::1]:443", fs.Node0)
	assert.Equal(t, "[2001:db8::2]:80", fs.Node1)
}

//======================================================================
// Hex Case Variations
//======================================================================

func TestParseReader_UppercaseHex(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4142434445464748
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("ABCDEFGH"), fs.Bytes[0].Data)
}

func TestParseReader_LowercaseHex(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
6162636465666768
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("abcdefgh"), fs.Bytes[0].Data)
}

func TestParseReader_MixedCaseHex(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4F6b
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("Ok"), fs.Bytes[0].Data)
}

//======================================================================
// Line Ending Variations
//======================================================================

func TestParseReader_UnixLineEndings(t *testing.T) {
	// Standard \n line endings
	inp := "\n===================================================================\n" +
		"Follow: tcp,raw\n" +
		"Filter: tcp.stream eq 0\n" +
		"Node 0: 192.168.1.1:1234\n" +
		"Node 1: 192.168.1.2:80\n" +
		"4f4b\n" +
		"===================================================================\n"

	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("OK"), fs.Bytes[0].Data)
}

func TestParseReader_WindowsLineEndings(t *testing.T) {
	// \r\n line endings
	inp := "\r\n===================================================================\r\n" +
		"Follow: tcp,raw\r\n" +
		"Filter: tcp.stream eq 0\r\n" +
		"Node 0: 192.168.1.1:1234\r\n" +
		"Node 1: 192.168.1.2:80\r\n" +
		"4f4b\r\n" +
		"===================================================================\r\n"

	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("OK"), fs.Bytes[0].Data)
}

func TestParseReader_ServerDataWithCRLF(t *testing.T) {
	// Server data line with \r\n
	inp := "\n===================================================================\n" +
		"Follow: tcp,raw\n" +
		"Filter: tcp.stream eq 0\n" +
		"Node 0: 192.168.1.1:1234\n" +
		"Node 1: 192.168.1.2:80\n" +
		"\t4f4b\r\n" +
		"===================================================================\n"

	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, Server, fs.Bytes[0].Dirn)
	assert.Equal(t, []byte("OK"), fs.Bytes[0].Data)
}

//======================================================================
// Callback Tests with Chunk and Header Callbacks
//======================================================================

type extraChunkCollector struct {
	chunks  []IChunk
	headers []FollowHeader
}

func (m *extraChunkCollector) OnStreamChunk(chunk IChunk) {
	m.chunks = append(m.chunks, chunk)
}

func (m *extraChunkCollector) OnStreamHeader(header FollowHeader) {
	m.headers = append(m.headers, header)
}

func TestParseReader_CallbackChunkOrder(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	41
42
	43
===================================================================
`
	collector := &extraChunkCollector{}
	_, err := ParseReader("test", strings.NewReader(inp),
		GlobalStore("callbacks", collector))

	require.NoError(t, err)
	require.Len(t, collector.chunks, 3)

	// Verify order: Server, Client, Server
	assert.Equal(t, Server, collector.chunks[0].Direction())
	assert.Equal(t, Client, collector.chunks[1].Direction())
	assert.Equal(t, Server, collector.chunks[2].Direction())

	// Verify data
	assert.Equal(t, []byte("A"), collector.chunks[0].StreamData())
	assert.Equal(t, []byte("B"), collector.chunks[1].StreamData())
	assert.Equal(t, []byte("C"), collector.chunks[2].StreamData())
}

func TestParseReader_CallbackHeaderValues(t *testing.T) {
	inp := `
===================================================================
Follow: udp,raw
Filter: udp.stream eq 42
Node 0: 172.16.0.1:9999
Node 1: 172.16.0.2:53
===================================================================
`
	collector := &extraChunkCollector{}
	_, err := ParseReader("test", strings.NewReader(inp),
		GlobalStore("callbacks", collector))

	require.NoError(t, err)
	require.Len(t, collector.headers, 1)
	assert.Equal(t, "udp,raw", collector.headers[0].Follow)
	assert.Equal(t, "udp.stream eq 42", collector.headers[0].Filter)
	assert.Equal(t, "172.16.0.1:9999", collector.headers[0].Node0)
	assert.Equal(t, "172.16.0.2:53", collector.headers[0].Node1)
}

func TestParseReader_CallbackWithNoDataChunks(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
===================================================================
`
	collector := &extraChunkCollector{}
	_, err := ParseReader("test", strings.NewReader(inp),
		GlobalStore("callbacks", collector))

	require.NoError(t, err)
	assert.Len(t, collector.chunks, 0)
	assert.Len(t, collector.headers, 1)
}

//======================================================================
// Context Cancellation Tests
//======================================================================

func TestParseReader_ContextCancelDuringServerChunk(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.0.114:1137
Node 1: 192.168.0.193:21
	3232302050726f4654504420312e332e306120536572766572202850726f4654504420416e6f6e796d6f75732053657276657229205b3139322e3136382e312e3233315d0d0a
55534552206674700d0a
===================================================================
`
	// errContext returns an error, simulating cancellation
	_, err := ParseReader("test", strings.NewReader(inp),
		GlobalStore("context", errContext{}))
	assert.Error(t, err)
}

func TestParseReader_ContextNoCancelDuringParse(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.0.114:1137
Node 1: 192.168.0.193:21
	3232302050726f4654504420312e332e306120536572766572202850726f4654504420416e6f6e796d6f75732053657276657229205b3139322e3136382e312e3233315d0d0a
55534552206674700d0a
===================================================================
`
	_, err := ParseReader("test", strings.NewReader(inp),
		GlobalStore("context", noErrContext{}))
	assert.NoError(t, err)
}

//======================================================================
// Hex Decoding Accuracy Tests
//======================================================================

func TestParseReader_AllHexDigits(t *testing.T) {
	// Test all hex digit values 00-ff by using a subset
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
000102030405060708090a0b0c0d0e0f
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	expected := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	assert.Equal(t, expected, fs.Bytes[0].Data)
}

func TestParseReader_HighByteValues(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
===================================================================
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	expected := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	assert.Equal(t, expected, fs.Bytes[0].Data)
}

//======================================================================
// Parse function (vs ParseReader) Tests
//======================================================================

func TestParse_DirectBytes(t *testing.T) {
	inp := []byte(`
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
48454c4c4f
===================================================================
`)
	got, err := Parse("test", inp)
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("HELLO"), fs.Bytes[0].Data)
}

func TestParse_EmptyBytes(t *testing.T) {
	_, err := Parse("test", []byte{})
	assert.Error(t, err)
}

//======================================================================
// Multiple Separator Equals Signs
//======================================================================

func TestParseReader_MinimalSeparator(t *testing.T) {
	// The grammar requires one or more '=' chars
	inp := `
=
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
4f4b
=
`
	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("OK"), fs.Bytes[0].Data)
}

func TestParseReader_ExtraLongSeparator(t *testing.T) {
	sep := strings.Repeat("=", 200)
	inp := "\n" + sep + "\n" +
		"Follow: tcp,raw\n" +
		"Filter: tcp.stream eq 0\n" +
		"Node 0: 192.168.1.1:1234\n" +
		"Node 1: 192.168.1.2:80\n" +
		"4f4b\n" +
		sep + "\n"

	got, err := ParseReader("test", strings.NewReader(inp))
	require.NoError(t, err)
	require.NotNil(t, got)

	fs := got.(*FollowStream)
	require.Len(t, fs.Bytes, 1)
	assert.Equal(t, []byte("OK"), fs.Bytes[0].Data)
}

//======================================================================
// FollowStream String Representation
//======================================================================

func TestFollowStream_StringWithMultipleChunks(t *testing.T) {
	fs := FollowStream{
		FollowHeader: FollowHeader{
			Follow: "tcp,raw",
			Filter: "tcp.stream eq 0",
			Node0:  "10.0.0.1:1234",
			Node1:  "10.0.0.2:80",
		},
		Bytes: []Bytes{
			{Dirn: Client, Data: []byte("GET /")},
			{Dirn: Server, Data: []byte("200 OK")},
			{Dirn: Client, Data: []byte("POST /data")},
		},
	}

	s := fs.String()
	assert.Contains(t, s, "Follow: tcp,raw")
	assert.Contains(t, s, "Filter: tcp.stream eq 0")
	assert.Contains(t, s, "Direction: Client")
	assert.Contains(t, s, "Direction: Server")
}

func TestFollowStream_StringEmpty(t *testing.T) {
	fs := FollowStream{
		FollowHeader: FollowHeader{
			Follow: "tcp,raw",
			Filter: "tcp.stream eq 0",
			Node0:  "10.0.0.1:1234",
			Node1:  "10.0.0.2:80",
		},
		Bytes: []Bytes{},
	}

	s := fs.String()
	assert.Contains(t, s, "Follow: tcp,raw")
	assert.Contains(t, s, "Data:\n")
}

//======================================================================
// Bytes Struct Tests
//======================================================================

func TestBytes_EmptyData(t *testing.T) {
	b := Bytes{Dirn: Client, Data: []byte{}}
	assert.Equal(t, Client, b.Direction())
	assert.Empty(t, b.StreamData())
	s := b.String()
	assert.Contains(t, s, "Direction: Client")
}

func TestBytes_NilData(t *testing.T) {
	b := Bytes{Dirn: Server, Data: nil}
	assert.Equal(t, Server, b.Direction())
	assert.Nil(t, b.StreamData())
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
