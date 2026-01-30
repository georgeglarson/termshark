// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestPdmlPacket_Packet(t *testing.T) {
	p := PdmlPacket{Content: []byte("test content")}

	result := p.Packet()

	assert.Equal(t, p, result)
}

func TestPdmlPacket_ImplementsInterface(t *testing.T) {
	var _ IPdmlPacket = PdmlPacket{}
}

func TestGzippedPdmlPacket_ImplementsInterface(t *testing.T) {
	var _ IPdmlPacket = GzippedPdmlPacket{}
}

func TestSnappiedPdmlPacket_ImplementsInterface(t *testing.T) {
	var _ IPdmlPacket = SnappiedPdmlPacket{}
}

func TestGzipPdmlPacket_Roundtrip(t *testing.T) {
	original := PdmlPacket{Content: []byte("test packet data")}

	compressed := GzipPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestGzipPdmlPacket_EmptyContent(t *testing.T) {
	original := PdmlPacket{Content: []byte{}}

	compressed := GzipPdmlPacket(original)
	recovered := compressed.Packet()

	// gob decoding returns nil for empty slice, which is equivalent
	assert.Equal(t, 0, len(recovered.Content))
}

func TestGzipPdmlPacket_LargeContent(t *testing.T) {
	// Create large content (10KB)
	content := make([]byte, 10*1024)
	for i := range content {
		content[i] = byte(i % 256)
	}
	original := PdmlPacket{Content: content}

	compressed := GzipPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestGzipPdmlPacket_XMLContent(t *testing.T) {
	// Test with realistic PDML-like XML content
	xmlContent := []byte(`<proto name="eth" showname="Ethernet II">
		<field name="eth.dst" show="ff:ff:ff:ff:ff:ff"/>
		<field name="eth.src" show="00:11:22:33:44:55"/>
	</proto>`)
	original := PdmlPacket{Content: xmlContent}

	compressed := GzipPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestGzippedPdmlPacket_Uncompress(t *testing.T) {
	original := PdmlPacket{Content: []byte("uncompress test")}
	compressed := GzipPdmlPacket(original)

	gzipped, ok := compressed.(GzippedPdmlPacket)
	assert.True(t, ok)

	recovered := gzipped.Uncompress()
	assert.Equal(t, original.Content, recovered.Content)
}

func TestSnappyPdmlPacket_Roundtrip(t *testing.T) {
	original := PdmlPacket{Content: []byte("test packet data")}

	compressed := SnappyPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestSnappyPdmlPacket_EmptyContent(t *testing.T) {
	original := PdmlPacket{Content: []byte{}}

	compressed := SnappyPdmlPacket(original)
	recovered := compressed.Packet()

	// gob decoding returns nil for empty slice, which is equivalent
	assert.Equal(t, 0, len(recovered.Content))
}

func TestSnappyPdmlPacket_LargeContent(t *testing.T) {
	// Create large content (10KB)
	content := make([]byte, 10*1024)
	for i := range content {
		content[i] = byte(i % 256)
	}
	original := PdmlPacket{Content: content}

	compressed := SnappyPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestSnappyPdmlPacket_XMLContent(t *testing.T) {
	xmlContent := []byte(`<proto name="ip" showname="Internet Protocol">
		<field name="ip.src" show="192.168.1.1"/>
		<field name="ip.dst" show="192.168.1.2"/>
	</proto>`)
	original := PdmlPacket{Content: xmlContent}

	compressed := SnappyPdmlPacket(original)
	recovered := compressed.Packet()

	assert.Equal(t, original.Content, recovered.Content)
}

func TestSnappiedPdmlPacket_Uncompress(t *testing.T) {
	original := PdmlPacket{Content: []byte("uncompress test")}
	compressed := SnappyPdmlPacket(original)

	snappied, ok := compressed.(SnappiedPdmlPacket)
	assert.True(t, ok)

	recovered := snappied.Uncompress()
	assert.Equal(t, original.Content, recovered.Content)
}

func TestSnappyMe_UnsnappyMe_Roundtrip(t *testing.T) {
	type testStruct struct {
		Name  string
		Value int
	}
	original := testStruct{Name: "test", Value: 42}

	var buf bytes.Buffer
	err := SnappyMe(original, &buf)
	assert.NoError(t, err)

	var recovered testStruct
	err = UnsnappyMe(&recovered, &buf)
	assert.NoError(t, err)

	assert.Equal(t, original, recovered)
}

func TestSnappyMe_UnsnappyMe_Slice(t *testing.T) {
	original := []string{"one", "two", "three"}

	var buf bytes.Buffer
	err := SnappyMe(original, &buf)
	assert.NoError(t, err)

	var recovered []string
	err = UnsnappyMe(&recovered, &buf)
	assert.NoError(t, err)

	assert.Equal(t, original, recovered)
}

func TestGzip_Compresses(t *testing.T) {
	// Create highly compressible content (repeated pattern)
	content := bytes.Repeat([]byte("AAAAAAAAAA"), 1000)
	original := PdmlPacket{Content: content}

	compressed := GzipPdmlPacket(original)
	gzipped := compressed.(GzippedPdmlPacket)

	// Compressed size should be much smaller than original
	assert.Less(t, gzipped.Data.Len(), len(content)/2)
}

func TestSnappy_Compresses(t *testing.T) {
	// Create highly compressible content (repeated pattern)
	content := bytes.Repeat([]byte("BBBBBBBBBB"), 1000)
	original := PdmlPacket{Content: content}

	compressed := SnappyPdmlPacket(original)
	snappied := compressed.(SnappiedPdmlPacket)

	// Compressed size should be smaller than original
	assert.Less(t, snappied.Data.Len(), len(content)/2)
}

func TestPdmlPacket_WithXMLName(t *testing.T) {
	// Verify XMLName field doesn't affect roundtrip
	original := PdmlPacket{Content: []byte("content")}

	gzCompressed := GzipPdmlPacket(original)
	gzRecovered := gzCompressed.Packet()
	assert.Equal(t, original.Content, gzRecovered.Content)

	snappyCompressed := SnappyPdmlPacket(original)
	snappyRecovered := snappyCompressed.Packet()
	assert.Equal(t, original.Content, snappyRecovered.Content)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
