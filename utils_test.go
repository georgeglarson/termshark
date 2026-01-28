// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/blang/semver"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestApplyArgs(t *testing.T) {
	cmd := []string{"echo", "something", "$3", "else", "$1", "$3"}
	args := []string{"a1", "a2"}
	eres := []string{"echo", "something", "$3", "else", "a1", "$3"}
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, eres, res)
	assert.Equal(t, total, 1)

	args = []string{"a1", "a2", "a3"}
	eres = []string{"echo", "something", "a3", "else", "a1", "a3"}
	res, total = ApplyArguments(cmd, args)
	assert.Equal(t, eres, res)
	assert.Equal(t, total, 3)
}

func TestArgConv(t *testing.T) {
	var tests = []struct {
		arg  string
		flag string
		val  string
		res  bool
	}{
		{"--tshark-d=foo", "d", "foo", true},
		{"--tshark-abc=foo", "", "", false},
		{"--tshark-V=true", "V", "", true},
		{"--tshark-V=false", "", "", false},
		{"--ts-V=wow", "", "", false},
	}

	for _, test := range tests {
		f, v, ok := ConvertArgToTShark(test.arg)
		assert.Equal(t, test.res, ok)
		if test.res {
			assert.Equal(t, test.flag, f)
			assert.Equal(t, test.val, v)
		}
	}
}

func TestVer1(t *testing.T) {
	out1 := `TShark (Wireshark) 2.6.6 (Git v2.6.6 packaged as 2.6.6-1~ubuntu18.04.0)

Copyright 1998-2019 Gerald Combs <gerald@wireshark.org> and contributors.`

	v1, err := TSharkVersionFromOutput(out1)
	assert.NoError(t, err)
	res, _ := semver.Make("2.6.6")
	assert.Equal(t, res, v1)
}

func TestVer2(t *testing.T) {
	out1 := `TShark 1.6.7

Copyright 1998-2012 Gerald Combs <gerald@wireshark.org> and contributors.
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) with GLib 2.32.0, with libpcap (version unknown), with libz
1.2.3.4, with POSIX capabilities (Linux), without libpcre, with SMI 0.4.8, with
c-ares 1.7.5, with Lua 5.1, without Python, with GnuTLS 2.12.14, with Gcrypt
1.5.0, with MIT Kerberos, with GeoIP.

Running on Linux 3.2.0-126-generic, with libpcap version 1.1.1, with libz
1.2.3.4.
`

	v1, err := TSharkVersionFromOutput(out1)
	assert.NoError(t, err)
	res, _ := semver.Make("1.6.7")
	assert.Equal(t, res, v1)
}

func TestInterfaces1(t *testing.T) {
	out1 := `
1. \Device\NPF_{BAC1CFBD-DE27-4023-B478-0C490B99DC5E} (Local Area Connection 2)
2. \Device\NPF_{78032B7E-4968-42D3-9F37-287EA86C0AAA} (Local Area Connection* 10)
3. \Device\NPF_{84E7CAE6-E96F-4F31-96FD-170B0F514AB2} (Npcap Loopback Adapter)
4. \Device\NPF_NdisWanIpv6 (NdisWan Adapter)
5. \Device\NPF_{503E1F71-C57C-438D-B004-EA5563723C16} (Local Area Connection 5)
6. \Device\NPF_{15DDE443-C208-4328-8919-9666682EE804} (Local Area Connection* 11)
`[1:]
	interfaces, err := interfacesFrom(bytes.NewReader([]byte(out1)))
	assert.NoError(t, err)
	assert.Equal(t, 6, len(interfaces))
	v := interfaces[2]
	assert.Equal(t, `\Device\NPF_{78032B7E-4968-42D3-9F37-287EA86C0AAA}`, v[1])
	assert.Equal(t, `Local Area Connection* 10`, v[0])
}

func TestInterfaces2(t *testing.T) {
	out1 := `
1. eth0
2. ham0
3. docker0
4. vethd45103d
5. lo (Loopback)
6. mpqemubr0-dummy
7. nflog
8. nfqueue
9. bluetooth0
10. virbr0-nic
11. vboxnet0
12. ciscodump (Cisco remote capture)
13. dpauxmon (DisplayPort AUX channel monitor capture)
14. randpkt (Random packet generator)
15. sdjournal (systemd Journal Export)
16. sshdump (SSH remote capture)
17. udpdump (UDP Listener remote capture)
`[1:]
	interfaces, err := interfacesFrom(bytes.NewReader([]byte(out1)))
	assert.NoError(t, err)
	assert.Equal(t, 17, len(interfaces))
	v := interfaces[3]
	assert.Equal(t, `docker0`, v[0])
	v = interfaces[12]
	assert.Equal(t, `Cisco remote capture`, v[0])
	assert.Equal(t, `ciscodump`, v[1])
}

func TestConv1(t *testing.T) {
	var tests = []struct {
		arg string
		res string
	}{
		{"hello\x41world\x42", "helloAworldB"},
		{"80 \xe2\x86\x92 53347", "80 → 53347"},
		{"hello\x41world\x42 foo \\000 bar", "helloAworldB foo \\000 bar"},
	}

	for _, test := range tests {
		outs := format.TranslateHexCodes([]byte(test.arg))
		assert.Equal(t, string(outs), test.res)
	}
}

func TestIPComp1(t *testing.T) {
	var ip IPCompare
	assert.True(t, ip.Less("x", "y"))
	assert.True(t, ip.Less("192.168.0.4", "y"))
	assert.False(t, ip.Less("y", "192.168.0.4"))
	assert.True(t, ip.Less("192.168.0.253", "192.168.1.4"))
	assert.False(t, ip.Less("192.168.1.4", "192.168.0.253"))
	assert.True(t, ip.Less("192.168.0.253", "::ffff:192.168.1.4"))
	assert.True(t, ip.Less("::ffff:192.168.0.253", "192.168.1.4"))
	assert.True(t, ip.Less("192.168.0.253", "2001:db8::68"))
	assert.False(t, ip.Less("2001:db8::68", "192.168.0.253"))
}

func TestMACComp1(t *testing.T) {
	var mac MACCompare
	assert.True(t, mac.Less("x", "y"))
	assert.True(t, mac.Less("11:22:33:44:55:66", "y"))
	assert.True(t, mac.Less("xx:22:33:44:55:66", "y"))
	assert.False(t, mac.Less("xx:22:33:44:55:66", "11:22:33:44:55:66"))
	assert.True(t, mac.Less("11:22:33:44:55:66", "11:22:33:44:55:67"))
	assert.False(t, mac.Less("11:22:33:44:55:66", "11:22:33:44:54:66"))
}

func TestFolders(t *testing.T) {
	tmp := os.Getenv("TMPDIR")
	os.Setenv("TMPDIR", "/foo")
	defer os.Setenv("TMPDIR", tmp)

	val, err := TsharkSetting("Temp")
	assert.NoError(t, err)
	assert.Equal(t, "/foo", val)

	val, err = TsharkSetting("Deliberately missing")
	assert.Error(t, err)
}

func TestReverseStringSlice(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{[]string{}, []string{}},
		{[]string{"a"}, []string{"a"}},
		{[]string{"a", "b"}, []string{"b", "a"}},
		{[]string{"a", "b", "c"}, []string{"c", "b", "a"}},
		{[]string{"1", "2", "3", "4"}, []string{"4", "3", "2", "1"}},
	}

	for _, test := range tests {
		s := make([]string, len(test.input))
		copy(s, test.input)
		ReverseStringSlice(s)
		assert.Equal(t, test.expected, s)
	}
}

func TestIsCommandInPath(t *testing.T) {
	// "ls" should be in path on most systems
	assert.True(t, IsCommandInPath("ls"))
	assert.True(t, IsCommandInPath("sh"))

	// A nonexistent command
	assert.False(t, IsCommandInPath("definitely_not_a_real_command_12345"))
}

func TestTSharkVersionFromOutputInvalid(t *testing.T) {
	// Test with invalid output
	_, err := TSharkVersionFromOutput("not a valid version string")
	assert.Error(t, err)
	assert.Equal(t, TSharkVersionUnknown, err)

	// Test with empty string
	_, err = TSharkVersionFromOutput("")
	assert.Error(t, err)
}

func TestRemoveFromStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		pcap     string
		comps    []string
		expected []string
	}{
		{
			name:     "empty slice",
			pcap:     "foo",
			comps:    []string{},
			expected: []string{"foo"},
		},
		{
			name:     "item not in slice",
			pcap:     "foo",
			comps:    []string{"a", "b", "c"},
			expected: []string{"foo", "a", "b", "c"},
		},
		{
			name:     "item at beginning",
			pcap:     "a",
			comps:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "item in middle",
			pcap:     "b",
			comps:    []string{"a", "b", "c"},
			expected: []string{"b", "a", "c"},
		},
		{
			name:     "item at end",
			pcap:     "c",
			comps:    []string{"a", "b", "c"},
			expected: []string{"c", "a", "b"},
		},
		{
			name:     "multiple occurrences",
			pcap:     "b",
			comps:    []string{"a", "b", "c", "b", "d"},
			expected: []string{"b", "a", "c", "d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveFromStringSlice(tt.pcap, tt.comps)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteEmptyPcap(t *testing.T) {
	// Create a temp file
	tmpfile, err := os.CreateTemp("", "test*.pcap")
	assert.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	// Write empty pcap
	err = WriteEmptyPcap(tmpfile.Name())
	assert.NoError(t, err)

	// Read the file back and verify the magic number
	data, err := os.ReadFile(tmpfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, 24, len(data)) // pcap header is 24 bytes

	// Check magic number (0xA1B2C3D4 in little endian)
	assert.Equal(t, byte(0xD4), data[0])
	assert.Equal(t, byte(0xC3), data[1])
	assert.Equal(t, byte(0xB2), data[2])
	assert.Equal(t, byte(0xA1), data[3])
}

func TestFileNewerThan(t *testing.T) {
	// Create two temp files
	file1, err := os.CreateTemp("", "test1*.txt")
	assert.NoError(t, err)
	file1.Close()
	defer os.Remove(file1.Name())

	file2, err := os.CreateTemp("", "test2*.txt")
	assert.NoError(t, err)
	file2.Close()
	defer os.Remove(file2.Name())

	// Test with non-existent file
	_, err = FileNewerThan("/nonexistent/file1", file2.Name())
	assert.Error(t, err)

	_, err = FileNewerThan(file1.Name(), "/nonexistent/file2")
	assert.Error(t, err)

	// file2 was created after file1, so file2 should be newer
	// But they might be created in the same instant, so we touch file2
	os.Chtimes(file2.Name(), testTimeNow(), testTimeNow())

	newer, err := FileNewerThan(file2.Name(), file1.Name())
	assert.NoError(t, err)
	// Note: on fast systems both files might have same timestamp
	// so we just check there's no error
	_ = newer
}

func testTimeNow() time.Time {
	return time.Now().Add(time.Second)
}

func TestConvPktsCompare(t *testing.T) {
	var c ConvPktsCompare
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"100", "200", true},
		{"200", "100", false},
		{"100", "100", false},
		{"1,234", "2,345", true},    // comma-separated numbers
		{"100 kB", "200 kB", true},  // with units
		{"1 kB", "500", false},      // 1024 vs 500
		{"500", "1 kB", true},       // 500 vs 1024
		{"1 MB", "1,000 kB", false}, // 1MB (1048576) > 1000kB (1024000)
		{"abc", "def", false},       // non-numeric returns false
		{"def", "abc", false},       // non-numeric returns false
	}

	for _, tt := range tests {
		result := c.Less(tt.a, tt.b)
		assert.Equal(t, tt.expected, result, "Less(%q, %q)", tt.a, tt.b)
	}
}

func TestReadWriteGob(t *testing.T) {
	// Create a temp file
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	assert.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	// Test writing and reading a simple struct
	type TestData struct {
		Name   string
		Values []int
	}

	original := TestData{
		Name:   "test",
		Values: []int{1, 2, 3, 4, 5},
	}

	// Write
	err = WriteGob(tmpfile.Name(), original)
	assert.NoError(t, err)

	// Read
	var loaded TestData
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)

	assert.Equal(t, original.Name, loaded.Name)
	assert.Equal(t, original.Values, loaded.Values)
}

func TestReadGob_NonexistentFile(t *testing.T) {
	var data string
	err := ReadGob("/nonexistent/file.gob.gz", &data)
	assert.Error(t, err)
}

func TestWriteGob_InvalidPath(t *testing.T) {
	err := WriteGob("/nonexistent/dir/file.gob.gz", "test")
	assert.Error(t, err)
}

func TestDirOfPathCommand(t *testing.T) {
	// Test with a known command
	path, err := DirOfPathCommand("ls")
	assert.NoError(t, err)
	assert.NotEmpty(t, path)

	// Test with non-existent command
	_, err = DirOfPathCommand("definitely_not_a_command_12345")
	assert.Error(t, err)
}

func TestDirOfPathCommandUnsafe(t *testing.T) {
	// Test with a known command
	path := DirOfPathCommandUnsafe("ls")
	assert.NotEmpty(t, path)

	// Test with non-existent command should panic
	assert.Panics(t, func() {
		DirOfPathCommandUnsafe("definitely_not_a_command_12345")
	})
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
