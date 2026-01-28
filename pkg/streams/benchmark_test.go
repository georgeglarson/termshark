// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

//======================================================================
// Benchmark Helpers
//======================================================================

// generateStreamIndexerXML creates PDML-like XML for stream indexing benchmarks
func generateStreamIndexerXML(packetCount int, proto string) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0"?>` + "\n")
	buf.WriteString(`<pdml>` + "\n")

	lenField := "tcp.len"
	if proto == "udp" {
		lenField = "udp.length"
	}

	for i := 0; i < packetCount; i++ {
		buf.WriteString(`<packet>` + "\n")
		buf.WriteString(`<proto name="`)
		buf.WriteString(proto)
		buf.WriteString(`">` + "\n")
		buf.WriteString(`<field name="`)
		buf.WriteString(lenField)
		// Alternate between packets with and without payload
		if i%2 == 0 {
			buf.WriteString(`" show="100"/>` + "\n")
		} else {
			buf.WriteString(`" show="0"/>` + "\n")
		}
		buf.WriteString(`</proto>` + "\n")
		buf.WriteString(`</packet>` + "\n")
	}

	buf.WriteString(`</pdml>` + "\n")
	return buf.String()
}

// generateStreamData creates tshark stream follow output for parsing benchmarks
func generateStreamData(chunkCount int) string {
	var buf bytes.Buffer
	buf.WriteString("\n===================================================================\n")
	buf.WriteString("Follow: tcp,raw\n")
	buf.WriteString("Filter: tcp.stream eq 0\n")
	buf.WriteString("Node 0: 192.168.1.1:12345\n")
	buf.WriteString("Node 1: 192.168.1.2:80\n")

	// Generate alternating client/server messages
	// Each message is 32 bytes of hex (16 bytes of data)
	for i := 0; i < chunkCount; i++ {
		if i%2 == 0 {
			// Server message (tab-prefixed)
			buf.WriteString("\t48545450")
			buf.WriteString("2f312e31")
			buf.WriteString("20323030")
			buf.WriteString("204f4b0d")
			buf.WriteString("\n")
		} else {
			// Client message (no prefix)
			buf.WriteString("47455420")
			buf.WriteString("2f696e64")
			buf.WriteString("65782e68")
			buf.WriteString("746d6c20")
			buf.WriteString("\n")
		}
	}

	buf.WriteString("===================================================================\n")
	return buf.String()
}

//======================================================================
// Stream XML Decoding Benchmarks
//======================================================================

func BenchmarkDecodeStreamXml_TCP_10(b *testing.B) {
	xml := generateStreamIndexerXML(10, "tcp")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker := &payloadTracker{}
		decodeStreamXml(strings.NewReader(xml), "tcp", ctx, tracker)
	}
}

func BenchmarkDecodeStreamXml_TCP_100(b *testing.B) {
	xml := generateStreamIndexerXML(100, "tcp")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker := &payloadTracker{}
		decodeStreamXml(strings.NewReader(xml), "tcp", ctx, tracker)
	}
}

func BenchmarkDecodeStreamXml_TCP_1000(b *testing.B) {
	xml := generateStreamIndexerXML(1000, "tcp")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker := &payloadTracker{}
		decodeStreamXml(strings.NewReader(xml), "tcp", ctx, tracker)
	}
}

func BenchmarkDecodeStreamXml_UDP_100(b *testing.B) {
	xml := generateStreamIndexerXML(100, "udp")
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker := &payloadTracker{}
		decodeStreamXml(strings.NewReader(xml), "udp", ctx, tracker)
	}
}

//======================================================================
// Stream Parser Benchmarks
//======================================================================

func BenchmarkParseReader_10Chunks(b *testing.B) {
	data := generateStreamData(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseReader("", strings.NewReader(data))
	}
}

func BenchmarkParseReader_100Chunks(b *testing.B) {
	data := generateStreamData(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseReader("", strings.NewReader(data))
	}
}

func BenchmarkParseReader_1000Chunks(b *testing.B) {
	data := generateStreamData(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseReader("", strings.NewReader(data))
	}
}

//======================================================================
// Loader Creation Benchmarks
//======================================================================

func BenchmarkNewLoader(b *testing.B) {
	cmds := MakeCommands()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewLoader(cmds, ctx)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
