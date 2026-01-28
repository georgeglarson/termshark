// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"strings"
	"testing"
)

//======================================================================
// Benchmark Helpers
//======================================================================

// generateLargePdmlXML creates PDML XML with specified packet count for benchmarking
func generateLargePdmlXML(packetCount int) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0"?>` + "\n")
	buf.WriteString(`<pdml version="0" creator="wireshark">` + "\n")

	for i := 1; i <= packetCount; i++ {
		buf.WriteString(`<packet>` + "\n")
		buf.WriteString(`<proto name="geninfo" pos="0" showname="General information" size="74">` + "\n")
		buf.WriteString(`<field name="num" pos="0" show="`)
		buf.WriteString(string(rune('0' + (i % 10))))
		buf.WriteString(`" showname="Number" value="1" size="74"/>` + "\n")
		buf.WriteString(`</proto>` + "\n")
		buf.WriteString(`<proto name="eth" showname="Ethernet II" size="14" pos="0">` + "\n")
		buf.WriteString(`<field name="eth.dst" showname="Destination: ff:ff:ff:ff:ff:ff" size="6" pos="0" show="ff:ff:ff:ff:ff:ff" value="ffffffffffff"/>` + "\n")
		buf.WriteString(`<field name="eth.src" showname="Source: 00:11:22:33:44:55" size="6" pos="6" show="00:11:22:33:44:55" value="001122334455"/>` + "\n")
		buf.WriteString(`</proto>` + "\n")
		buf.WriteString(`<proto name="ip" showname="Internet Protocol" size="20" pos="14">` + "\n")
		buf.WriteString(`<field name="ip.src" showname="Source: 192.168.1.1" size="4" pos="26" show="192.168.1.1" value="c0a80101"/>` + "\n")
		buf.WriteString(`<field name="ip.dst" showname="Destination: 192.168.1.2" size="4" pos="30" show="192.168.1.2" value="c0a80102"/>` + "\n")
		buf.WriteString(`</proto>` + "\n")
		buf.WriteString(`<proto name="tcp" showname="TCP" size="20" pos="34">` + "\n")
		buf.WriteString(`<field name="tcp.srcport" showname="Source Port: 12345" size="2" pos="34" show="12345" value="3039"/>` + "\n")
		buf.WriteString(`<field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>` + "\n")
		buf.WriteString(`<field name="tcp.len" showname="TCP Segment Len: 100" size="1" pos="46" show="100" value="64"/>` + "\n")
		buf.WriteString(`</proto>` + "\n")
		buf.WriteString(`</packet>` + "\n")
	}

	buf.WriteString(`</pdml>` + "\n")
	return buf.String()
}

// generateLargePsmlXML creates PSML XML with specified packet count for benchmarking
func generateLargePsmlXML(packetCount int) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0"?>` + "\n")
	buf.WriteString(`<psml version="0" creator="wireshark">` + "\n")
	buf.WriteString(`<structure>` + "\n")
	buf.WriteString(`<section>No.</section>` + "\n")
	buf.WriteString(`<section>Time</section>` + "\n")
	buf.WriteString(`<section>Source</section>` + "\n")
	buf.WriteString(`<section>Destination</section>` + "\n")
	buf.WriteString(`<section>Protocol</section>` + "\n")
	buf.WriteString(`<section>Length</section>` + "\n")
	buf.WriteString(`<section>Info</section>` + "\n")
	buf.WriteString(`</structure>` + "\n")

	for i := 1; i <= packetCount; i++ {
		buf.WriteString(`<packet foreground="#000000" background="#e4ffc7">` + "\n")
		buf.WriteString(`<section>`)
		buf.WriteString(string(rune('0' + (i % 10))))
		buf.WriteString(`</section>` + "\n")
		buf.WriteString(`<section>0.000000</section>` + "\n")
		buf.WriteString(`<section>192.168.1.1</section>` + "\n")
		buf.WriteString(`<section>192.168.1.2</section>` + "\n")
		buf.WriteString(`<section>TCP</section>` + "\n")
		buf.WriteString(`<section>74</section>` + "\n")
		buf.WriteString(`<section>12345 → 80 [SYN] Seq=0 Win=65535 Len=0</section>` + "\n")
		buf.WriteString(`</packet>` + "\n")
	}

	buf.WriteString(`</psml>` + "\n")
	return buf.String()
}

//======================================================================
// PDML Parsing Benchmarks
//======================================================================

func BenchmarkParsePdmlPackets_10(b *testing.B) {
	xml := generateLargePdmlXML(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePdmlPackets(strings.NewReader(xml), 0, false)
	}
}

func BenchmarkParsePdmlPackets_100(b *testing.B) {
	xml := generateLargePdmlXML(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePdmlPackets(strings.NewReader(xml), 0, false)
	}
}

func BenchmarkParsePdmlPackets_1000(b *testing.B) {
	xml := generateLargePdmlXML(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePdmlPackets(strings.NewReader(xml), 0, false)
	}
}

func BenchmarkParsePdmlPackets_WithCompression_100(b *testing.B) {
	xml := generateLargePdmlXML(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePdmlPackets(strings.NewReader(xml), 0, true)
	}
}

//======================================================================
// PSML Parsing Benchmarks
//======================================================================

func BenchmarkParsePsmlXML_10(b *testing.B) {
	xml := generateLargePsmlXML(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePsmlXML(strings.NewReader(xml))
	}
}

func BenchmarkParsePsmlXML_100(b *testing.B) {
	xml := generateLargePsmlXML(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePsmlXML(strings.NewReader(xml))
	}
}

func BenchmarkParsePsmlXML_1000(b *testing.B) {
	xml := generateLargePsmlXML(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePsmlXML(strings.NewReader(xml))
	}
}

//======================================================================
// Hex Dump Parsing Benchmarks
//======================================================================

func BenchmarkParsePcapHexDump_10Packets(b *testing.B) {
	hex := generateHexDump(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePcapHexDump(strings.NewReader(hex), 0)
	}
}

func BenchmarkParsePcapHexDump_100Packets(b *testing.B) {
	hex := generateHexDump(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePcapHexDump(strings.NewReader(hex), 0)
	}
}

//======================================================================
// Compression Benchmarks
//======================================================================

func BenchmarkSnappyPdmlPacket_Small(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 100)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SnappyPdmlPacket(packet)
	}
}

func BenchmarkSnappyPdmlPacket_Medium(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 1024)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SnappyPdmlPacket(packet)
	}
}

func BenchmarkSnappyPdmlPacket_Large(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 10*1024)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SnappyPdmlPacket(packet)
	}
}

func BenchmarkSnappyRoundtrip_Medium(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 1024)}
	for i := range packet.Content {
		packet.Content[i] = byte(i % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressed := SnappyPdmlPacket(packet)
		_ = compressed.Packet()
	}
}

func BenchmarkGzipPdmlPacket_Medium(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 1024)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GzipPdmlPacket(packet)
	}
}

func BenchmarkGzipRoundtrip_Medium(b *testing.B) {
	packet := PdmlPacket{Content: make([]byte, 1024)}
	for i := range packet.Content {
		packet.Content[i] = byte(i % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressed := GzipPdmlPacket(packet)
		_ = compressed.Packet()
	}
}

//======================================================================
// Cache Operation Benchmarks
//======================================================================

func BenchmarkCacheOperations(b *testing.B) {
	cmds := NewMockLoaderCmds()
	runner := NewMockMainRunner(true)
	loader := NewPcapLoader(cmds, runner)

	pdmlData := make([]IPdmlPacket, 100)
	for i := range pdmlData {
		pdmlData[i] = PdmlPacket{Content: make([]byte, 500)}
	}
	pcapData := make([][]byte, 100)
	for i := range pcapData {
		pcapData[i] = make([]byte, 100)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row := i % 10000
		loader.PsmlLoader.updateCacheEntryWithPdml(row, pdmlData, true)
		loader.PsmlLoader.updateCacheEntryWithPcap(row, pcapData, true)
		_, _ = loader.PsmlLoader.CacheAt(row)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
