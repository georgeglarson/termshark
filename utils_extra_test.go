// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/blang/semver"
	"github.com/gcla/termshark/v2/pkg/lifecycle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// TSharkVersionFromOutput - comprehensive version parsing
//======================================================================

func TestTSharkVersionFromOutput_v1x(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected semver.Version
	}{
		{
			name:     "TShark 1.6.7",
			input:    "TShark 1.6.7\n\nCopyright 1998-2012",
			expected: semver.MustParse("1.6.7"),
		},
		{
			name:     "TShark 1.10.2",
			input:    "TShark 1.10.2\n\nmore text",
			expected: semver.MustParse("1.10.2"),
		},
		{
			name:     "TShark 1.0.0 minimal",
			input:    "TShark 1.0.0",
			expected: semver.MustParse("1.0.0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := TSharkVersionFromOutput(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, v)
		})
	}
}

func TestTSharkVersionFromOutput_v2x(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected semver.Version
	}{
		{
			name:     "TShark 2.6.6 with Git info",
			input:    "TShark (Wireshark) 2.6.6 (Git v2.6.6 packaged as 2.6.6-1~ubuntu18.04.0)\n\nCopyright 1998-2019 Gerald Combs",
			expected: semver.MustParse("2.6.6"),
		},
		{
			name:     "TShark 2.0.0",
			input:    "TShark (Wireshark) 2.0.0\n",
			expected: semver.MustParse("2.0.0"),
		},
		{
			name:     "TShark 2.4.10",
			input:    "TShark (Wireshark) 2.4.10 (v2.4.10)\n\nCopyright",
			expected: semver.MustParse("2.4.10"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := TSharkVersionFromOutput(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, v)
		})
	}
}

func TestTSharkVersionFromOutput_v3x(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected semver.Version
	}{
		{
			name:     "TShark 3.2.3",
			input:    "TShark (Wireshark) 3.2.3 (Git v3.2.3 packaged as 3.2.3-1)\n\nCopyright 1998-2020",
			expected: semver.MustParse("3.2.3"),
		},
		{
			name:     "TShark 3.6.14",
			input:    "TShark (Wireshark) 3.6.14 (wireshark-3.6.14)\n\nCopyright 1998-2023",
			expected: semver.MustParse("3.6.14"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := TSharkVersionFromOutput(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, v)
		})
	}
}

func TestTSharkVersionFromOutput_v4x(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected semver.Version
	}{
		{
			name:     "TShark 4.0.1",
			input:    "TShark (Wireshark) 4.0.1 (Git v4.0.1 packaged as 4.0.1-1~ubuntu22.04.0)\n\nCopyright",
			expected: semver.MustParse("4.0.1"),
		},
		{
			name:     "TShark 4.2.0",
			input:    "TShark (Wireshark) 4.2.0\nRunning on Linux 6.1",
			expected: semver.MustParse("4.2.0"),
		},
		{
			name:     "TShark 4.6.0",
			input:    "TShark (Wireshark) 4.6.0 (v4.6.0)\n",
			expected: semver.MustParse("4.6.0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := TSharkVersionFromOutput(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, v)
		})
	}
}

func TestTSharkVersionFromOutput_MalformedAndEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{"empty string", "", true},
		{"just whitespace", "   \n\t  ", true},
		{"no version number", "TShark (Wireshark) \n\nCopyright", true},
		{"partial version", "TShark 2.6", true},
		{"not tshark at all", "wireshark 3.2.1", true},
		{"random text", "hello world", true},
		{"only numbers", "1.2.3", true},
		{"version without TShark prefix", "Version 2.6.6", true},
		{"tshark lowercase", "tshark 2.6.6", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TSharkVersionFromOutput(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

//======================================================================
// Config path functions
//======================================================================

func TestConfFile(t *testing.T) {
	result := ConfFile("termshark.toml")
	assert.True(t, strings.HasSuffix(result, filepath.Join("termshark", "termshark.toml")))
	assert.True(t, filepath.IsAbs(result))
}

func TestConfFile_EmptyString(t *testing.T) {
	result := ConfFile("")
	assert.True(t, strings.HasSuffix(result, "termshark"))
}

func TestConfFile_NestedPath(t *testing.T) {
	result := ConfFile("subdir/file.toml")
	assert.Contains(t, result, "termshark")
	assert.True(t, strings.HasSuffix(result, filepath.Join("termshark", "subdir/file.toml")))
}

func TestCacheDir(t *testing.T) {
	result := CacheDir()
	assert.True(t, strings.HasSuffix(result, "termshark"))
	assert.True(t, filepath.IsAbs(result))
}

func TestCacheFile(t *testing.T) {
	result := CacheFile("empty.pcap")
	assert.True(t, strings.HasSuffix(result, filepath.Join("termshark", "empty.pcap")))
	assert.True(t, filepath.IsAbs(result))
}

func TestCacheFile_EmptyName(t *testing.T) {
	result := CacheFile("")
	// Should still return a valid path ending in termshark dir
	assert.True(t, strings.HasSuffix(result, "termshark"))
}

func TestDefaultPcapDir(t *testing.T) {
	result := DefaultPcapDir()
	assert.True(t, strings.HasSuffix(result, filepath.Join("termshark", "pcaps")))
	assert.True(t, filepath.IsAbs(result))
}

func TestDefaultPcapDir_ContainsCacheDir(t *testing.T) {
	cacheDir := CacheDir()
	pcapDir := DefaultPcapDir()
	assert.True(t, strings.HasPrefix(pcapDir, cacheDir),
		"PcapDir (%s) should be under CacheDir (%s)", pcapDir, cacheDir)
}

//======================================================================
// ApplyArguments - thorough edge cases
//======================================================================

func TestApplyArguments_EmptyCmd(t *testing.T) {
	res, total := ApplyArguments([]string{}, []string{"a1"})
	assert.Equal(t, []string{}, res)
	assert.Equal(t, 0, total)
}

func TestApplyArguments_EmptyArgs(t *testing.T) {
	cmd := []string{"echo", "$1", "$2"}
	res, total := ApplyArguments(cmd, []string{})
	assert.Equal(t, []string{"echo", "$1", "$2"}, res)
	assert.Equal(t, 0, total)
}

func TestApplyArguments_NilArgs(t *testing.T) {
	cmd := []string{"echo", "$1"}
	res, total := ApplyArguments(cmd, nil)
	assert.Equal(t, []string{"echo", "$1"}, res)
	assert.Equal(t, 0, total)
}

func TestApplyArguments_NoPlaceholders(t *testing.T) {
	cmd := []string{"echo", "hello", "world"}
	res, total := ApplyArguments(cmd, []string{"a1", "a2"})
	assert.Equal(t, []string{"echo", "hello", "world"}, res)
	assert.Equal(t, 0, total)
}

func TestApplyArguments_AllSubstituted(t *testing.T) {
	cmd := []string{"$1", "$2", "$3"}
	args := []string{"a", "b", "c"}
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, []string{"a", "b", "c"}, res)
	assert.Equal(t, 3, total)
}

func TestApplyArguments_HighIndex(t *testing.T) {
	cmd := []string{"echo", "$99"}
	args := make([]string, 100)
	for i := range args {
		args[i] = "x"
	}
	args[98] = "found"
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, "found", res[1])
	assert.Equal(t, 1, total)
}

func TestApplyArguments_NotArgPattern(t *testing.T) {
	// $0 is not valid (args are 1-indexed per regex)
	cmd := []string{"$0", "$1"}
	args := []string{"first"}
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, "$0", res[0])
	assert.Equal(t, "first", res[1])
	assert.Equal(t, 1, total)
}

func TestApplyArguments_DollarSignInText(t *testing.T) {
	// Dollar sign embedded in other text is not a placeholder
	cmd := []string{"price$1", "$1"}
	args := []string{"val"}
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, "price$1", res[0]) // not a standalone $1
	assert.Equal(t, "val", res[1])
	assert.Equal(t, 1, total)
}

//======================================================================
// RunForExitCode and RunForStderr
//======================================================================

func TestRunForExitCode_Success(t *testing.T) {
	exitCode, err := RunForExitCode("true", []string{}, nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRunForExitCode_Failure(t *testing.T) {
	exitCode, err := RunForExitCode("false", []string{}, nil)
	assert.Error(t, err)
	assert.Equal(t, 1, exitCode)
}

func TestRunForExitCode_NonExistentCommand(t *testing.T) {
	_, err := RunForExitCode("definitely_not_a_command_xyz123", []string{}, nil)
	assert.Error(t, err)
}

func TestRunForExitCode_WithEnv(t *testing.T) {
	exitCode, err := RunForExitCode("sh", []string{"-c", "exit 0"}, []string{"FOO=bar"})
	assert.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRunForExitCode_SpecificExitCode(t *testing.T) {
	exitCode, err := RunForExitCode("sh", []string{"-c", "exit 42"}, nil)
	assert.Error(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestRunForStderr_CapturesStderr(t *testing.T) {
	var stderr bytes.Buffer
	exitCode, err := RunForStderr("sh", []string{"-c", "echo errormsg >&2; exit 1"}, nil, &stderr)
	assert.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr.String(), "errormsg")
}

func TestRunForStderr_NoStderrOnSuccess(t *testing.T) {
	var stderr bytes.Buffer
	exitCode, err := RunForStderr("sh", []string{"-c", "echo stdout_only"}, nil, &stderr)
	assert.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "", stderr.String())
}

func TestRunForStderr_NonExistent(t *testing.T) {
	_, err := RunForStderr("definitely_not_a_command_xyz123", []string{}, nil, io.Discard)
	assert.Error(t, err)
}

//======================================================================
// SafePid and KillIfPossible
//======================================================================

type mockProcess struct {
	pid     int
	killErr error
}

func (m *mockProcess) Kill() error { return m.killErr }
func (m *mockProcess) Pid() int    { return m.pid }

func TestSafePid_NilProcess(t *testing.T) {
	assert.Equal(t, -1, SafePid(nil))
}

func TestSafePid_ValidProcess(t *testing.T) {
	p := &mockProcess{pid: 12345}
	assert.Equal(t, 12345, SafePid(p))
}

func TestSafePid_ZeroPid(t *testing.T) {
	p := &mockProcess{pid: 0}
	assert.Equal(t, 0, SafePid(p))
}

func TestKillIfPossible_NilProcess(t *testing.T) {
	err := KillIfPossible(nil)
	assert.NoError(t, err)
}

func TestKillIfPossible_AlreadyFinished(t *testing.T) {
	p := &mockProcess{killErr: os.ErrProcessDone}
	err := KillIfPossible(p)
	assert.NoError(t, err)
}

func TestKillIfPossible_OtherError(t *testing.T) {
	p := &mockProcess{killErr: os.ErrPermission}
	err := KillIfPossible(p)
	assert.Error(t, err)
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestKillIfPossible_Success(t *testing.T) {
	p := &mockProcess{killErr: nil}
	err := KillIfPossible(p)
	assert.NoError(t, err)
}

//======================================================================
// ConvertArgToTShark - additional edge cases
//======================================================================

func TestConvertArgToTShark_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		expectFlag string
		expectVal  string
		expectOk   bool
	}{
		{"valid single char flag", "--tshark-d=foo", "d", "foo", true},
		{"multi-char flag rejected", "--tshark-abc=foo", "", "", false},
		{"boolean true", "--tshark-V=true", "V", "", true},
		{"boolean false", "--tshark-V=false", "", "", false},
		{"wrong prefix", "--ts-V=wow", "", "", false},
		{"no equals", "--tshark-d", "", "", false},
		{"numeric flag", "--tshark-2=bar", "2", "bar", true},
		{"value with equals", "--tshark-o=key=val", "o", "key=val", true},
		{"value with spaces", "--tshark-Y=tcp port 80", "Y", "tcp port 80", true},
		{"empty string", "", "", "", false},
		{"just dashes", "--", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, v, ok := ConvertArgToTShark(tt.arg)
			assert.Equal(t, tt.expectOk, ok, "ok mismatch")
			if ok {
				assert.Equal(t, tt.expectFlag, f, "flag mismatch")
				assert.Equal(t, tt.expectVal, v, "val mismatch")
			}
		})
	}
}

//======================================================================
// interfacesFrom parsing
//======================================================================

func TestInterfacesFrom_EmptyInput(t *testing.T) {
	interfaces, err := interfacesFrom(strings.NewReader(""))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(interfaces))
}

func TestInterfacesFrom_SingleSimpleInterface(t *testing.T) {
	input := "1. eth0\n"
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(interfaces))
	assert.Equal(t, "eth0", interfaces[1][0])
}

func TestInterfacesFrom_InterfaceWithDescription(t *testing.T) {
	input := "1. lo (Loopback)\n"
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(interfaces))
	assert.Equal(t, "Loopback", interfaces[1][0])
	assert.Equal(t, "lo", interfaces[1][1])
}

func TestInterfacesFrom_MalformedLine(t *testing.T) {
	input := "not a valid interface line\n"
	_, err := interfacesFrom(strings.NewReader(input))
	assert.Error(t, err)
}

func TestInterfacesFrom_MultipleInterfaces(t *testing.T) {
	input := `1. eth0
2. wlan0
3. lo (Loopback)
`
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(interfaces))
	assert.Equal(t, "eth0", interfaces[1][0])
	assert.Equal(t, "wlan0", interfaces[2][0])
	assert.Equal(t, "Loopback", interfaces[3][0])
}

func TestInterfacesFrom_ExtcapInterfaces(t *testing.T) {
	input := `1. ciscodump (Cisco remote capture)
2. randpkt (Random packet generator)
3. sshdump (SSH remote capture)
`
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(interfaces))
	assert.Equal(t, "Cisco remote capture", interfaces[1][0])
	assert.Equal(t, "ciscodump", interfaces[1][1])
}

func TestInterfacesFrom_LargeIndex(t *testing.T) {
	input := "100. eth99\n"
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(interfaces))
	assert.Equal(t, "eth99", interfaces[100][0])
}

func TestInterfacesFrom_WindowsStyle(t *testing.T) {
	input := `1. \Device\NPF_{BAC1CFBD-DE27-4023-B478-0C490B99DC5E} (Local Area Connection 2)
`
	interfaces, err := interfacesFrom(strings.NewReader(input))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(interfaces))
	assert.Equal(t, "Local Area Connection 2", interfaces[1][0])
	assert.Equal(t, `\Device\NPF_{BAC1CFBD-DE27-4023-B478-0C490B99DC5E}`, interfaces[1][1])
}

//======================================================================
// IPCompare
//======================================================================

func TestIPCompare_BothValid(t *testing.T) {
	var ip IPCompare
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"a < b", "10.0.0.1", "10.0.0.2", true},
		{"a > b", "10.0.0.2", "10.0.0.1", false},
		{"equal", "10.0.0.1", "10.0.0.1", false},
		{"different octets", "10.0.1.0", "10.0.0.255", false},
		{"cross-boundary", "192.168.0.255", "192.168.1.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ip.Less(tt.a, tt.b))
		})
	}
}

func TestIPCompare_IPv6(t *testing.T) {
	var ip IPCompare
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"v6 less", "::1", "::2", true},
		{"v6 greater", "::2", "::1", false},
		{"v6 equal", "::1", "::1", false},
		{"v4 vs v6", "192.168.0.1", "2001:db8::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ip.Less(tt.a, tt.b))
		})
	}
}

func TestIPCompare_InvalidIPs(t *testing.T) {
	var ip IPCompare
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"both invalid lexicographic", "abc", "def", true},
		{"both invalid reverse", "def", "abc", false},
		{"a valid b invalid", "192.168.0.1", "invalid", true},
		{"a invalid b valid", "invalid", "192.168.0.1", false},
		{"both invalid same", "xxx", "xxx", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ip.Less(tt.a, tt.b))
		})
	}
}

//======================================================================
// MACCompare
//======================================================================

func TestMACCompare_Comprehensive(t *testing.T) {
	var mac MACCompare
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"a < b", "00:00:00:00:00:01", "00:00:00:00:00:02", true},
		{"a > b", "00:00:00:00:00:02", "00:00:00:00:00:01", false},
		{"equal", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", false},
		{"higher byte diff", "00:00:01:00:00:00", "00:00:00:ff:ff:ff", false},
		{"both invalid", "xxx", "yyy", true},
		{"a valid b invalid", "aa:bb:cc:dd:ee:ff", "invalid", true},
		{"a invalid b valid", "invalid", "aa:bb:cc:dd:ee:ff", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mac.Less(tt.a, tt.b))
		})
	}
}

//======================================================================
// ConvPktsCompare - additional edge cases
//======================================================================

func TestConvPktsCompare_AdditionalEdgeCases(t *testing.T) {
	var c ConvPktsCompare
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"bytes explicit unit", "100 bytes", "200 bytes", true},
		{"bytes reverse", "200 bytes", "100 bytes", false},
		{"kB equal", "1 kB", "1 kB", false},
		{"MB vs kB", "1 MB", "1 kB", false},
		{"kB vs MB", "1 kB", "1 MB", true},
		{"large comma number", "1,000,000 bytes", "2,000,000 bytes", true},
		{"zero", "0 bytes", "1 bytes", true},
		{"comma in kB", "1,024 kB", "2,048 kB", true},
		{"plain number no unit", "500", "600", true},
		{"empty string a", "", "100", false},
		{"empty string b", "100", "", false},
		{"both empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, c.Less(tt.a, tt.b))
		})
	}
}

//======================================================================
// ReverseStringSlice - additional edge cases
//======================================================================

func TestReverseStringSlice_NilSlice(t *testing.T) {
	// nil slice should not panic
	var s []string
	// nil has len 0, so the loop won't execute
	ReverseStringSlice(s)
	assert.Nil(t, s)
}

func TestReverseStringSlice_LargeSlice(t *testing.T) {
	s := make([]string, 1000)
	for i := range s {
		s[i] = strings.Repeat("a", i)
	}
	ReverseStringSlice(s)
	assert.Equal(t, strings.Repeat("a", 999), s[0])
	assert.Equal(t, "", s[999])
}

//======================================================================
// StringIsArgPrefixOf - additional edge cases
//======================================================================

func TestStringIsArgPrefixOf_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		list     []string
		expected bool
	}{
		{"nil list", "--flag=val", nil, false},
		{"empty arg empty list", "", []string{}, false},
		{"equals only", "=value", []string{""}, true},
		{"list with empty string", "--flag=val", []string{""}, false},
		{"partial match", "--fla=value", []string{"--flag"}, false},
		{"multiple matches first", "--flag=value", []string{"--flag", "--other"}, true},
		{"multiple matches second", "--other=value", []string{"--flag", "--other"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, StringIsArgPrefixOf(tt.arg, tt.list))
		})
	}
}

//======================================================================
// RemoveFromStringSlice
//======================================================================

func TestRemoveFromStringSlice_NilSlice(t *testing.T) {
	result := RemoveFromStringSlice("foo", nil)
	assert.Equal(t, []string{"foo"}, result)
}

func TestRemoveFromStringSlice_EmptyElement(t *testing.T) {
	result := RemoveFromStringSlice("", []string{"a", "", "b"})
	assert.Equal(t, "", result[0])
	assert.Contains(t, result, "a")
	assert.Contains(t, result, "b")
}

//======================================================================
// IndentPdml
//======================================================================

func TestIndentPdml_NestedElements(t *testing.T) {
	input := `<proto name="eth"><field name="src" show="00:11:22:33:44:55"><field name="addr" show="00:11:22"/></field></proto>`
	var out bytes.Buffer
	err := IndentPdml(bytes.NewReader([]byte(input)), &out)
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "eth")
	assert.Contains(t, out.String(), "src")
	assert.Contains(t, out.String(), "addr")
}

func TestIndentPdml_EmptyElement(t *testing.T) {
	input := `<proto name="empty"/>`
	var out bytes.Buffer
	err := IndentPdml(bytes.NewReader([]byte(input)), &out)
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "empty")
}

func TestIndentPdml_EmptyInput(t *testing.T) {
	var out bytes.Buffer
	err := IndentPdml(bytes.NewReader([]byte("")), &out)
	assert.Error(t, err)
}

func TestIndentPdml_BrokenXML(t *testing.T) {
	input := `<proto name="broken"><field`
	var out bytes.Buffer
	err := IndentPdml(bytes.NewReader([]byte(input)), &out)
	assert.Error(t, err)
}

//======================================================================
// RootCause
//======================================================================

type wrappedError struct {
	inner error
}

func (w wrappedError) Error() string { return "wrapped: " + w.inner.Error() }
func (w wrappedError) Cause() error  { return w.inner }

type doubleWrappedError struct {
	inner error
}

func (d doubleWrappedError) Error() string { return "double: " + d.inner.Error() }
func (d doubleWrappedError) Cause() error  { return d.inner }

func TestRootCause_SingleWrap(t *testing.T) {
	root := BadState
	wrapped := wrappedError{inner: root}
	assert.Equal(t, root, RootCause(wrapped))
}

func TestRootCause_DoubleWrap(t *testing.T) {
	root := BadCommand
	inner := wrappedError{inner: root}
	outer := doubleWrappedError{inner: inner}
	assert.Equal(t, root, RootCause(outer))
}

func TestRootCause_NoWrap(t *testing.T) {
	assert.Equal(t, BadState, RootCause(BadState))
}

func TestRootCause_Nil(t *testing.T) {
	assert.Nil(t, RootCause(nil))
}

//======================================================================
// Tracker and Go/GoWithContext/Context
//======================================================================

func TestSetTrackerAndGo(t *testing.T) {
	tracker := lifecycle.New()
	oldTracker := Tracker()
	defer SetTracker(oldTracker) // restore

	SetTracker(tracker)
	assert.Equal(t, tracker, Tracker())

	var ran bool
	var mu sync.Mutex
	Go(func() {
		mu.Lock()
		defer mu.Unlock()
		ran = true
	})
	tracker.Wait()
	mu.Lock()
	assert.True(t, ran)
	mu.Unlock()
}

func TestGoWithContext_ReceivesContext(t *testing.T) {
	tracker := lifecycle.New()
	oldTracker := Tracker()
	defer SetTracker(oldTracker)

	SetTracker(tracker)

	var received context.Context
	var mu sync.Mutex
	GoWithContext(func(ctx context.Context) {
		mu.Lock()
		defer mu.Unlock()
		received = ctx
	})
	tracker.Wait()
	mu.Lock()
	assert.NotNil(t, received)
	mu.Unlock()
}

func TestContext_WithTracker(t *testing.T) {
	tracker := lifecycle.New()
	oldTracker := Tracker()
	defer SetTracker(oldTracker)

	SetTracker(tracker)
	ctx := Context()
	assert.NotNil(t, ctx)
	// Should be the tracker's context
	assert.Equal(t, tracker.Context(), ctx)
}

func TestContext_WithoutTracker(t *testing.T) {
	oldTracker := Tracker()
	defer SetTracker(oldTracker)

	SetTracker(nil)
	ctx := Context()
	assert.NotNil(t, ctx)
	// Should be a background context
}

func TestGo_WithoutTracker(t *testing.T) {
	oldTracker := Tracker()
	defer SetTracker(oldTracker)

	SetTracker(nil)

	ch := make(chan bool, 1)
	Go(func() {
		ch <- true
	})
	assert.True(t, <-ch)
}

func TestGoWithContext_WithoutTracker(t *testing.T) {
	oldTracker := Tracker()
	defer SetTracker(oldTracker)

	SetTracker(nil)

	ch := make(chan bool, 1)
	GoWithContext(func(ctx context.Context) {
		ch <- true
	})
	assert.True(t, <-ch)
}

//======================================================================
// TrackedGo
//======================================================================

func TestTrackedGo_SingleWaitGroup(t *testing.T) {
	var wg sync.WaitGroup
	var ran bool
	var mu sync.Mutex

	TrackedGo(func() {
		mu.Lock()
		defer mu.Unlock()
		ran = true
	}, &wg)

	wg.Wait()
	mu.Lock()
	assert.True(t, ran)
	mu.Unlock()
}

func TestTrackedGo_MultipleWaitGroups(t *testing.T) {
	var wg1, wg2 sync.WaitGroup
	var ran bool
	var mu sync.Mutex

	TrackedGo(func() {
		mu.Lock()
		defer mu.Unlock()
		ran = true
	}, &wg1, &wg2)

	wg1.Wait()
	wg2.Wait()
	mu.Lock()
	assert.True(t, ran)
	mu.Unlock()
}

func TestTrackedGo_NoWaitGroups(t *testing.T) {
	ch := make(chan bool, 1)
	TrackedGo(func() {
		ch <- true
	})
	assert.True(t, <-ch)
}

//======================================================================
// WriteEmptyPcap
//======================================================================

func TestWriteEmptyPcap_ValidHeader(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.pcap")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	err = WriteEmptyPcap(tmpfile.Name())
	assert.NoError(t, err)

	data, err := os.ReadFile(tmpfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, 24, len(data))

	// Check pcap magic number (little-endian 0xA1B2C3D4)
	assert.Equal(t, byte(0xD4), data[0])
	assert.Equal(t, byte(0xC3), data[1])
	assert.Equal(t, byte(0xB2), data[2])
	assert.Equal(t, byte(0xA1), data[3])

	// Check version (2.4)
	assert.Equal(t, byte(2), data[4])
	assert.Equal(t, byte(0), data[5])
	assert.Equal(t, byte(4), data[6])
	assert.Equal(t, byte(0), data[7])
}

func TestWriteEmptyPcap_InvalidPath(t *testing.T) {
	err := WriteEmptyPcap("/nonexistent/dir/test.pcap")
	assert.Error(t, err)
}

//======================================================================
// FileSizeDifferentTo
//======================================================================

func TestFileSizeDifferentTo_Comprehensive(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString("12345")
	require.NoError(t, err)
	tmpfile.Close()

	tests := []struct {
		name     string
		size     int64
		wantDiff bool
		wantSize int64
	}{
		{"same size", 5, false, 5},
		{"different size smaller", 3, true, 5},
		{"different size larger", 10, true, 5},
		{"zero", 0, true, 5},
		{"negative", -1, true, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newSize, diff := FileSizeDifferentTo(tmpfile.Name(), tt.size)
			assert.Equal(t, tt.wantDiff, diff)
			assert.Equal(t, tt.wantSize, newSize)
		})
	}
}

func TestFileSizeDifferentTo_NonexistentFile(t *testing.T) {
	_, diff := FileSizeDifferentTo("/nonexistent/file.txt", 5)
	assert.True(t, diff)
}

func TestFileSizeDifferentTo_EmptyFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.txt")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	newSize, diff := FileSizeDifferentTo(tmpfile.Name(), 0)
	assert.False(t, diff)
	assert.Equal(t, int64(0), newSize)

	_, diff = FileSizeDifferentTo(tmpfile.Name(), 1)
	assert.True(t, diff)
}

//======================================================================
// ReadGob / WriteGob
//======================================================================

func TestReadWriteGob_ComplexStruct(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	type Inner struct {
		X int
		Y string
	}
	type Outer struct {
		Name  string
		Items []Inner
	}

	original := Outer{
		Name: "test",
		Items: []Inner{
			{X: 1, Y: "a"},
			{X: 2, Y: "b"},
			{X: 3, Y: "c"},
		},
	}

	err = WriteGob(tmpfile.Name(), original)
	require.NoError(t, err)

	var loaded Outer
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)
	assert.Equal(t, original, loaded)
}

func TestReadWriteGob_EmptySlice(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	original := []string{}
	err = WriteGob(tmpfile.Name(), original)
	require.NoError(t, err)

	var loaded []string
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)
	// gob decodes an empty slice as nil; both have len 0
	assert.Equal(t, 0, len(loaded))
}

func TestReadGob_CorruptFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	_, err = tmpfile.WriteString("this is not gzip data")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	var data string
	err = ReadGob(tmpfile.Name(), &data)
	assert.Error(t, err)
}

//======================================================================
// FileNewerThan
//======================================================================

func TestFileNewerThan_SameFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.txt")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	newer, err := FileNewerThan(tmpfile.Name(), tmpfile.Name())
	assert.NoError(t, err)
	assert.False(t, newer, "A file should not be newer than itself")
}

func TestFileNewerThan_BothNonexistent(t *testing.T) {
	_, err := FileNewerThan("/nonexistent/a", "/nonexistent/b")
	assert.Error(t, err)
}

//======================================================================
// Error types
//======================================================================

func TestBadStateError_Implements(t *testing.T) {
	var err error = BadStateError{}
	assert.Equal(t, "Bad state", err.Error())
}

func TestBadCommandError_Implements(t *testing.T) {
	var err error = BadCommandError{}
	assert.Equal(t, "Error running command", err.Error())
}

func TestConfigError_Implements(t *testing.T) {
	var err error = ConfigError{}
	assert.Equal(t, "Configuration error", err.Error())
}

func TestInternalError_Implements(t *testing.T) {
	var err error = InternalError{}
	assert.Equal(t, "Internal error", err.Error())
}

//======================================================================
// tsregexp FindStringSubmatchMap
//======================================================================

func TestTsregexp_MultipleNamedGroups(t *testing.T) {
	re := tsregexp{regexp.MustCompile(`(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})`)}
	result := re.FindStringSubmatchMap("2024-01-15")
	assert.Equal(t, "2024", result["year"])
	assert.Equal(t, "01", result["month"])
	assert.Equal(t, "15", result["day"])
}

func TestTsregexp_NoMatch(t *testing.T) {
	re := tsregexp{regexp.MustCompile(`(?P<num>\d+)`)}
	result := re.FindStringSubmatchMap("no digits here")
	assert.Empty(t, result)
}

func TestTsregexp_PartialCapture(t *testing.T) {
	re := tsregexp{regexp.MustCompile(`(?P<a>\d+)(?:-(?P<b>\d+))?`)}
	// Only first group matches
	result := re.FindStringSubmatchMap("123")
	assert.Equal(t, "123", result["a"])
	assert.Equal(t, "", result["b"])
}

func TestTsregexp_EmptyStringInput(t *testing.T) {
	re := tsregexp{regexp.MustCompile(`(?P<all>.*)`)}
	result := re.FindStringSubmatchMap("")
	assert.Equal(t, "", result["all"])
}

//======================================================================
// GlobalJumpPos
//======================================================================

func TestGlobalJumpPos_BaseWithDeepPath(t *testing.T) {
	g := GlobalJumpPos{
		JumpPos:  JumpPos{Summary: "test", Pos: 1},
		Filename: "/a/b/c/d/capture.pcap",
	}
	assert.Equal(t, "capture.pcap", g.Base())
}

func TestGlobalJumpPos_BaseEmpty(t *testing.T) {
	g := GlobalJumpPos{Filename: ""}
	assert.Equal(t, ".", g.Base())
}

func TestGlobalJumpPos_BaseRootFile(t *testing.T) {
	g := GlobalJumpPos{Filename: "/capture.pcap"}
	assert.Equal(t, "capture.pcap", g.Base())
}

//======================================================================
// Version constant
//======================================================================

func TestVersionIsSet(t *testing.T) {
	assert.NotEmpty(t, Version)
	// Should be a valid semver-ish format
	assert.Contains(t, Version, ".")
}

//======================================================================
// LocalIPs
//======================================================================

func TestLocalIPs(t *testing.T) {
	ips := LocalIPs()
	// We can't guarantee specific IPs, but the function should not panic
	assert.NotNil(t, ips)
	// On most systems there's at least one non-loopback IP
	// But in CI containers this may not be true, so just check it runs
}

//======================================================================
// RunningRemotely edge cases
//======================================================================

func TestRunningRemotely_EmptyString(t *testing.T) {
	orig := os.Getenv("SSH_TTY")
	defer os.Setenv("SSH_TTY", orig)

	os.Setenv("SSH_TTY", "")
	assert.False(t, RunningRemotely())
}

//======================================================================
// fixNewlines
//======================================================================

func TestFixNewlines_NoNewlines(t *testing.T) {
	input := []byte("no newlines at all")
	result := fixNewlines(input)
	assert.Equal(t, input, result)
}

func TestFixNewlines_MultipleNewlines(t *testing.T) {
	input := []byte("a\nb\nc\n")
	result := fixNewlines(input)
	// On Linux, should be unchanged
	assert.Equal(t, input, result)
}

func TestFixNewlines_EmptyInput(t *testing.T) {
	result := fixNewlines([]byte{})
	assert.Equal(t, []byte{}, result)
}

//======================================================================
// ConvTypes default
//======================================================================

func TestConvTypes_ReturnsDefaults(t *testing.T) {
	// Without specific config, should return defaults
	result := ConvTypes()
	assert.NotEmpty(t, result)
	// Defaults include these five
	defaults := []string{"eth", "ip", "ipv6", "tcp", "udp"}
	assert.Equal(t, defaults, result)
}

//======================================================================
// DateStringForFilename
//======================================================================

func TestDateStringForFilename_Format(t *testing.T) {
	s := DateStringForFilename()
	// Format is 2006-01-02--15-04-05
	parts := strings.Split(s, "--")
	assert.Equal(t, 2, len(parts))
	dateParts := strings.Split(parts[0], "-")
	assert.Equal(t, 3, len(dateParts))
	timeParts := strings.Split(parts[1], "-")
	assert.Equal(t, 3, len(timeParts))
}

//======================================================================
// TSharkBin, DumpcapBin, CapinfosBin, SharkdBin defaults
//======================================================================

func TestTSharkBin_Default(t *testing.T) {
	// Default should be "tshark"
	bin := TSharkBin()
	assert.NotEmpty(t, bin)
}

func TestDumpcapBin_Default(t *testing.T) {
	bin := DumpcapBin()
	assert.NotEmpty(t, bin)
}

func TestCapinfosBin_Default(t *testing.T) {
	bin := CapinfosBin()
	assert.NotEmpty(t, bin)
}

func TestSharkdBin_Default(t *testing.T) {
	bin := SharkdBin()
	assert.NotEmpty(t, bin)
}

//======================================================================
// TailCommand
//======================================================================

func TestTailCommand_Default(t *testing.T) {
	cmd := TailCommand()
	assert.NotEmpty(t, cmd)
	// On Linux, the default starts with "tail"
	assert.Equal(t, "tail", cmd[0])
	assert.Contains(t, cmd, "-f")
}

//======================================================================
// KeyState struct
//======================================================================

func TestKeyState_ZeroValue(t *testing.T) {
	ks := KeyState{}
	assert.Equal(t, 0, ks.NumberPrefix)
	assert.False(t, ks.PartialgCmd)
	assert.False(t, ks.PartialZCmd)
	assert.False(t, ks.PartialCtrlWCmd)
	assert.False(t, ks.PartialmCmd)
	assert.False(t, ks.PartialQuoteCmd)
}

//======================================================================
// PrivilegedBin
//======================================================================

func TestPrivilegedBin(t *testing.T) {
	bin := PrivilegedBin()
	assert.NotEmpty(t, bin)
}

//======================================================================
// ErrLogger
//======================================================================

func TestErrLogger_ReturnsWriter(t *testing.T) {
	w := ErrLogger("test-key", "test-val")
	assert.NotNil(t, w)
	w.Close()
}

//======================================================================
// IsCommandInPath additional
//======================================================================

func TestIsCommandInPath_EmptyString(t *testing.T) {
	assert.False(t, IsCommandInPath(""))
}

func TestIsCommandInPath_AbsPath(t *testing.T) {
	// /bin/sh should exist on Linux
	assert.True(t, IsCommandInPath("/bin/sh"))
}

//======================================================================
// WriteGob/ReadGob round-trip with various types
//======================================================================

func TestReadWriteGob_MapType(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	original := map[string]int{"a": 1, "b": 2, "c": 3}
	err = WriteGob(tmpfile.Name(), original)
	require.NoError(t, err)

	var loaded map[string]int
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)
	assert.Equal(t, original, loaded)
}

func TestReadWriteGob_StringType(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	original := "hello world"
	err = WriteGob(tmpfile.Name(), original)
	require.NoError(t, err)

	var loaded string
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)
	assert.Equal(t, original, loaded)
}

func TestReadWriteGob_IntType(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test*.gob.gz")
	require.NoError(t, err)
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	original := 42
	err = WriteGob(tmpfile.Name(), original)
	require.NoError(t, err)

	var loaded int
	err = ReadGob(tmpfile.Name(), &loaded)
	assert.NoError(t, err)
	assert.Equal(t, original, loaded)
}
