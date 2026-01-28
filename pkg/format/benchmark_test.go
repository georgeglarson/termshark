// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package format

import (
	"testing"
)

//======================================================================
// Benchmark Helpers
//======================================================================

// generateMixedData creates byte data with a mix of printable and non-printable characters
func generateMixedData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		if i%4 == 0 {
			data[i] = byte(i % 32) // Non-printable control characters
		} else {
			data[i] = byte(65 + (i % 26)) // Printable ASCII letters
		}
	}
	return data
}

// generatePrintableData creates byte data with only printable ASCII
func generatePrintableData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(65 + (i % 26)) // A-Z
	}
	return data
}

// generateHexEncodedData creates data with hex escape sequences like \x41
func generateHexEncodedData(size int) []byte {
	// Create data that looks like "Hello\\x00World\\x01..."
	result := make([]byte, 0, size)
	for i := 0; i < size; i++ {
		if i%10 < 6 {
			result = append(result, byte(65+(i%26)))
		} else if i%10 == 6 {
			result = append(result, '\\', 'x', '4', '1') // \x41 = 'A'
			i += 3
		}
	}
	return result
}

//======================================================================
// MakePrintableString Benchmarks
//======================================================================

func BenchmarkMakePrintableString_100(b *testing.B) {
	data := generateMixedData(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableString(data)
	}
}

func BenchmarkMakePrintableString_1KB(b *testing.B) {
	data := generateMixedData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableString(data)
	}
}

func BenchmarkMakePrintableString_10KB(b *testing.B) {
	data := generateMixedData(10 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableString(data)
	}
}

func BenchmarkMakePrintableString_64KB(b *testing.B) {
	data := generateMixedData(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableString(data)
	}
}

//======================================================================
// MakePrintableStringWithNewlines Benchmarks
//======================================================================

func BenchmarkMakePrintableStringWithNewlines_1KB(b *testing.B) {
	data := generateMixedData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableStringWithNewlines(data)
	}
}

func BenchmarkMakePrintableStringWithNewlines_10KB(b *testing.B) {
	data := generateMixedData(10 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakePrintableStringWithNewlines(data)
	}
}

//======================================================================
// MakeHexStream Benchmarks
//======================================================================

func BenchmarkMakeHexStream_100(b *testing.B) {
	data := generatePrintableData(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeHexStream(data)
	}
}

func BenchmarkMakeHexStream_1KB(b *testing.B) {
	data := generatePrintableData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeHexStream(data)
	}
}

func BenchmarkMakeHexStream_10KB(b *testing.B) {
	data := generatePrintableData(10 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeHexStream(data)
	}
}

//======================================================================
// MakeEscapedString Benchmarks
//======================================================================

func BenchmarkMakeEscapedString_100(b *testing.B) {
	data := generateMixedData(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeEscapedString(data)
	}
}

func BenchmarkMakeEscapedString_1KB(b *testing.B) {
	data := generateMixedData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeEscapedString(data)
	}
}

//======================================================================
// TranslateHexCodes Benchmarks
//======================================================================

func BenchmarkTranslateHexCodes_NoHex(b *testing.B) {
	// Data without any hex codes - should be fast
	data := generatePrintableData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TranslateHexCodes(data)
	}
}

func BenchmarkTranslateHexCodes_WithHex(b *testing.B) {
	// Data with hex escape sequences
	data := generateHexEncodedData(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TranslateHexCodes(data)
	}
}

func BenchmarkTranslateHexCodes_ManyHex(b *testing.B) {
	// Data that's mostly hex codes
	data := []byte(`\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TranslateHexCodes(data)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
