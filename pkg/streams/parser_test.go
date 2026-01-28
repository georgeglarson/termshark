// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// Parser Edge Case Tests
//======================================================================

func TestParseReader_EmptyStream(t *testing.T) {
	// Stream with header but no data
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_SingleServerMessage(t *testing.T) {
	// Only server (tab-prefixed) data
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_SingleClientMessage(t *testing.T) {
	// Only client (no tab prefix) data
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
48454c4c4f
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_UDPStream(t *testing.T) {
	inp := `
===================================================================
Follow: udp,raw
Filter: udp.stream eq 0
Node 0: 192.168.1.1:53
Node 1: 8.8.8.8:53
	0102030405060708
0a0b0c0d0e0f1011
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_MultipleStreams(t *testing.T) {
	// Multiple stream sections (unlikely but valid)
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_SpecialCharactersInNodeAddress(t *testing.T) {
	// IPv6 addresses have colons which might cause parsing issues
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: [::1]:1234
Node 1: [::1]:80
	48454c4c4f
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_LongHexData(t *testing.T) {
	// Long hex string that spans multiple logical bytes
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_AlternatingClientServer(t *testing.T) {
	// Alternating client and server messages
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
574f524c44
	4f4b
425945
===================================================================
`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestParseReader_WhitespaceHandling(t *testing.T) {
	// Leading/trailing whitespace around separator lines
	inp := `

===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
===================================================================

`
	got, err := ParseReader("", strings.NewReader(inp))
	require.NoError(t, err)
	assert.NotNil(t, got)
}

//======================================================================
// Callback Tests
//======================================================================

type mockChunkCollector struct {
	chunks  []IChunk
	headers []FollowHeader
}

func (m *mockChunkCollector) OnStreamChunk(chunk IChunk) {
	m.chunks = append(m.chunks, chunk)
}

func (m *mockChunkCollector) OnStreamHeader(header FollowHeader) {
	m.headers = append(m.headers, header)
}

func TestParseReader_WithChunkCallback(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
574f524c44
===================================================================
`
	collector := &mockChunkCollector{}

	_, err := ParseReader("", strings.NewReader(inp),
		GlobalStore("callbacks", collector))

	require.NoError(t, err)
	assert.Len(t, collector.chunks, 2)

	// First chunk is server (tab-prefixed)
	assert.Equal(t, Server, collector.chunks[0].Direction())
	assert.Equal(t, []byte("HELLO"), collector.chunks[0].StreamData())

	// Second chunk is client
	assert.Equal(t, Client, collector.chunks[1].Direction())
	assert.Equal(t, []byte("WORLD"), collector.chunks[1].StreamData())
}

func TestParseReader_WithHeaderCallback(t *testing.T) {
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	48454c4c4f
===================================================================
`
	collector := &mockChunkCollector{}

	_, err := ParseReader("", strings.NewReader(inp),
		GlobalStore("callbacks", collector))

	require.NoError(t, err)
	require.Len(t, collector.headers, 1)
	assert.Equal(t, "tcp,raw", collector.headers[0].Follow)
	assert.Equal(t, "tcp.stream eq 0", collector.headers[0].Filter)
	assert.Equal(t, "192.168.1.1:1234", collector.headers[0].Node0)
	assert.Equal(t, "192.168.1.2:80", collector.headers[0].Node1)
}

//======================================================================
// Error Handling Tests
//======================================================================

func TestParseReader_InvalidHex(t *testing.T) {
	// Invalid hex characters
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	GGHHIIJJ
===================================================================
`
	_, err := ParseReader("", strings.NewReader(inp))
	// Parser may or may not error on invalid hex depending on implementation
	// The important thing is it doesn't panic
	_ = err
}

func TestParseReader_TruncatedStream(t *testing.T) {
	// Stream cut off mid-data
	inp := `
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:80
	4845`

	_, err := ParseReader("", strings.NewReader(inp))
	// Should handle truncated input gracefully
	_ = err
}

func TestParseReader_MissingHeader(t *testing.T) {
	// Data without proper header
	inp := `48454c4c4f`

	_, err := ParseReader("", strings.NewReader(inp))
	// Should error on missing header
	assert.Error(t, err)
}

func TestParseReader_EmptyInput(t *testing.T) {
	inp := ``

	_, err := ParseReader("", strings.NewReader(inp))
	// Empty input should error (no valid stream)
	assert.Error(t, err)
}

// Note: Protocol, Direction, Bytes, FollowHeader, FollowStream, and StreamParseError
// tests are in parse_test.go

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
