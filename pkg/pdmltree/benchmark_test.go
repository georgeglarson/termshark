// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pdmltree

import (
	"bytes"
	"encoding/xml"
	"testing"

	"github.com/gcla/gowid/widgets/tree"
)

//======================================================================
// Benchmark Data
//======================================================================

// Simple packet for basic benchmarks
var benchPacketSimple = `<packet>
  <proto name="frame" showname="Frame 1: 100 bytes" size="100" pos="0">
    <field name="frame.len" showname="Frame Length: 100" size="0" pos="0" show="100"/>
  </proto>
  <proto name="eth" showname="Ethernet II" size="14" pos="0">
    <field name="eth.dst" showname="Destination: ff:ff:ff:ff:ff:ff" size="6" pos="0" show="ff:ff:ff:ff:ff:ff"/>
    <field name="eth.src" showname="Source: 00:11:22:33:44:55" size="6" pos="6" show="00:11:22:33:44:55"/>
    <field name="eth.type" showname="Type: IPv4" size="2" pos="12" show="0x0800"/>
  </proto>
  <proto name="ip" showname="IPv4" size="20" pos="14">
    <field name="ip.src" showname="Source: 192.168.1.1" size="4" pos="26" show="192.168.1.1"/>
    <field name="ip.dst" showname="Destination: 192.168.1.2" size="4" pos="30" show="192.168.1.2"/>
  </proto>
  <proto name="tcp" showname="TCP" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 12345" size="2" pos="34" show="12345"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80"/>
    <field name="tcp.len" showname="Len: 46" size="0" pos="0" show="46"/>
  </proto>
</packet>`

// Generate a complex packet with many nested fields
func generateComplexPacket(protoCount, fieldsPerProto int) string {
	var buf bytes.Buffer
	buf.WriteString(`<packet>` + "\n")

	for p := 0; p < protoCount; p++ {
		buf.WriteString(`  <proto name="proto`)
		buf.WriteByte(byte('0' + (p % 10)))
		buf.WriteString(`" showname="Protocol `)
		buf.WriteByte(byte('0' + (p % 10)))
		buf.WriteString(`" size="50" pos="`)
		buf.WriteString(string(rune('0' + (p * 50 % 10))))
		buf.WriteString(`">` + "\n")

		for f := 0; f < fieldsPerProto; f++ {
			buf.WriteString(`    <field name="field`)
			buf.WriteByte(byte('0' + (f % 10)))
			buf.WriteString(`" showname="Field `)
			buf.WriteByte(byte('0' + (f % 10)))
			buf.WriteString(`" size="5" pos="`)
			buf.WriteString(string(rune('0' + (f * 5 % 10))))
			buf.WriteString(`" show="value"/>` + "\n")
		}

		buf.WriteString(`  </proto>` + "\n")
	}

	buf.WriteString(`</packet>` + "\n")
	return buf.String()
}

//======================================================================
// UnmarshalXML Benchmarks
//======================================================================

func BenchmarkUnmarshalXML_Simple(b *testing.B) {
	data := []byte(benchPacketSimple)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var model Model
		_ = xml.Unmarshal(data, &model)
	}
}

func BenchmarkUnmarshalXML_Complex_10Proto_10Fields(b *testing.B) {
	data := []byte(generateComplexPacket(10, 10))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var model Model
		_ = xml.Unmarshal(data, &model)
	}
}

func BenchmarkUnmarshalXML_Complex_20Proto_20Fields(b *testing.B) {
	data := []byte(generateComplexPacket(20, 20))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var model Model
		_ = xml.Unmarshal(data, &model)
	}
}

//======================================================================
// HexLayers Benchmarks
//======================================================================

func BenchmarkHexLayers_Simple(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(benchPacketSimple), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.HexLayers(20, false) // Position in the middle of eth header
	}
}

func BenchmarkHexLayers_Complex(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(generateComplexPacket(10, 10)), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.HexLayers(25, false)
	}
}

func BenchmarkHexLayers_AllPositions(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(benchPacketSimple), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate cursor moving through all positions
		for pos := 0; pos < 100; pos++ {
			_ = model.HexLayers(pos, false)
		}
	}
}

//======================================================================
// Tree Iteration Benchmarks
//======================================================================

func BenchmarkIterator_Simple(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(benchPacketSimple), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iter := model.Children()
		for iter.Next() {
			_ = iter.Value()
		}
	}
}

func BenchmarkIterator_Complex(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(generateComplexPacket(10, 10)), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iter := model.Children()
		for iter.Next() {
			child := iter.Value()
			childIter := child.Children()
			for childIter.Next() {
				_ = childIter.Value()
			}
		}
	}
}

//======================================================================
// ExpandByPosition Benchmarks
//======================================================================

func BenchmarkExpandByPosition_Simple(b *testing.B) {
	pos := tree.NewPosExt([]int{1, 0}) // Expand into second child's first grandchild

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create fresh model each iteration to avoid state accumulation
		var model Model
		_ = xml.Unmarshal([]byte(benchPacketSimple), &model)
		model.ExpandByPosition(pos)
	}
}

func BenchmarkExpandByPosition_Complex(b *testing.B) {
	pos := tree.NewPosExt([]int{5, 3}) // Expand into middle child

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var model Model
		_ = xml.Unmarshal([]byte(generateComplexPacket(10, 10)), &model)
		model.ExpandByPosition(pos)
	}
}

//======================================================================
// PathToRoot Benchmarks
//======================================================================

func BenchmarkPathToRoot(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(benchPacketSimple), &model)

	// Find a deep child
	var deepChild *Model
	if len(model.Children_) > 2 && len(model.Children_[2].Children_) > 0 {
		deepChild = model.Children_[2].Children_[0]
	} else {
		deepChild = &model
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deepChild.PathToRoot()
	}
}

//======================================================================
// String Methods Benchmarks
//======================================================================

func BenchmarkModel_String(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(benchPacketSimple), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.String()
	}
}

func BenchmarkModel_String_Complex(b *testing.B) {
	var model Model
	_ = xml.Unmarshal([]byte(generateComplexPacket(10, 10)), &model)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.String()
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
