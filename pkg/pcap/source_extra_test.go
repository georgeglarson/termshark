// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//======================================================================
// FileSystemSources edge cases
//======================================================================

func TestFileSystemSources_NilInput(t *testing.T) {
	result := FileSystemSources(nil)
	assert.Empty(t, result)
}

func TestFileSystemSources_AllFiles(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "a.pcap"},
		FileSource{Filename: "b.pcap"},
		FileSource{Filename: "c.pcap"},
	}
	result := FileSystemSources(sources)
	assert.Len(t, result, 3)
}

func TestFileSystemSources_NoFiles(t *testing.T) {
	sources := []IPacketSource{
		InterfaceSource{Iface: "eth0"},
		FifoSource{Filename: "/tmp/fifo"},
		PipeSource{Descriptor: "stdin", Fd: 0},
	}
	result := FileSystemSources(sources)
	assert.Empty(t, result)
}

func TestFileSystemSources_TemporaryFileSource(t *testing.T) {
	// TemporaryFileSource embeds FileSource, so IsFile() returns true
	sources := []IPacketSource{
		TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/temp.pcap"}},
	}
	result := FileSystemSources(sources)
	assert.Len(t, result, 1)
	assert.Equal(t, "/tmp/temp.pcap", result[0].Name())
}

//======================================================================
// SourcesString edge cases
//======================================================================

func TestSourcesString_Empty(t *testing.T) {
	result := SourcesString(nil)
	assert.Equal(t, "", result)
}

func TestSourcesString_SingleSource(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "test.pcap"},
	}
	assert.Equal(t, "test.pcap", SourcesString(sources))
}

func TestSourcesString_ManySources(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "a.pcap"},
		InterfaceSource{Iface: "eth0"},
		FifoSource{Filename: "/tmp/fifo"},
	}
	assert.Equal(t, "a.pcap + eth0 + /tmp/fifo", SourcesString(sources))
}

//======================================================================
// SourcesNames edge cases
//======================================================================

func TestSourcesNames_Empty(t *testing.T) {
	result := SourcesNames(nil)
	// Returns empty slice, not nil
	assert.Len(t, result, 0)
}

func TestSourcesNames_PreservesOrder(t *testing.T) {
	sources := []IPacketSource{
		InterfaceSource{Iface: "wlan0"},
		FileSource{Filename: "first.pcap"},
		PipeSource{Descriptor: "fd3", Fd: 3},
	}
	names := SourcesNames(sources)
	assert.Equal(t, []string{"wlan0", "first.pcap", "fd3"}, names)
}

//======================================================================
// UIName edge cases
//======================================================================

func TestUIName_AllSourceTypes(t *testing.T) {
	tests := []struct {
		name   string
		source IPacketSource
		want   string
	}{
		{
			name:   "file source",
			source: FileSource{Filename: "/path/to/capture.pcap"},
			want:   "/path/to/capture.pcap",
		},
		{
			name:   "interface source",
			source: InterfaceSource{Iface: "eth0"},
			want:   "eth0",
		},
		{
			name:   "fifo source",
			source: FifoSource{Filename: "/tmp/myfifo"},
			want:   "/tmp/myfifo",
		},
		{
			name:   "pipe source shows stdin",
			source: PipeSource{Descriptor: "stdin", Fd: 0},
			want:   "<stdin>",
		},
		{
			name:   "pipe source with arbitrary descriptor",
			source: PipeSource{Descriptor: "/dev/fd/3", Fd: 3},
			want:   "<stdin>",
		},
		{
			name:   "temporary file source",
			source: TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/tmp.pcap"}},
			want:   "/tmp/tmp.pcap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, UIName(tt.source))
		})
	}
}

//======================================================================
// CanRestart edge cases
//======================================================================

func TestCanRestart_AllTypes(t *testing.T) {
	tests := []struct {
		name   string
		source IPacketSource
		want   bool
	}{
		{"file source can restart", FileSource{Filename: "test.pcap"}, true},
		{"interface source can restart", InterfaceSource{Iface: "eth0"}, true},
		{"fifo source cannot restart", FifoSource{Filename: "/tmp/fifo"}, false},
		{"pipe source cannot restart", PipeSource{Descriptor: "stdin", Fd: 0}, false},
		{"temp file source can restart", TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/x.pcap"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CanRestart(tt.source))
		})
	}
}

//======================================================================
// FileSource edge cases
//======================================================================

func TestFileSource_EmptyFilename(t *testing.T) {
	fs := FileSource{Filename: ""}
	assert.Equal(t, "", fs.Name())
	assert.True(t, fs.IsFile())
	assert.Equal(t, "File:", fs.String())
}

func TestFileSource_SpecialCharFilename(t *testing.T) {
	fs := FileSource{Filename: "/path/with spaces/file (1).pcap"}
	assert.Equal(t, "/path/with spaces/file (1).pcap", fs.Name())
	assert.Contains(t, fs.String(), "/path/with spaces/file (1).pcap")
}

//======================================================================
// InterfaceSource edge cases
//======================================================================

func TestInterfaceSource_SpecialNames(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		want  string
	}{
		{"simple name", "eth0", "Interface:eth0"},
		{"name with colon", "eth0:1", "Interface:eth0:1"},
		{"loopback", "lo", "Interface:lo"},
		{"any interface", "any", "Interface:any"},
		{"windows style", `\\.\Device\NPF_{ABC}`, `Interface:\\.\Device\NPF_{ABC}`},
		{"empty", "", "Interface:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := InterfaceSource{Iface: tt.iface}
			assert.Equal(t, tt.want, is.String())
			assert.Equal(t, tt.iface, is.Name())
			assert.True(t, is.IsInterface())
			assert.False(t, is.IsFile())
			assert.False(t, is.IsFifo())
			assert.False(t, is.IsPipe())
		})
	}
}

//======================================================================
// FifoSource edge cases
//======================================================================

func TestFifoSource_SpecialPaths(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"typical fifo", "/tmp/myfifo"},
		{"nested path", "/var/run/capture/fifo"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := FifoSource{Filename: tt.filename}
			assert.Equal(t, tt.filename, fs.Name())
			assert.False(t, fs.IsFile())
			assert.False(t, fs.IsInterface())
			assert.True(t, fs.IsFifo())
			assert.False(t, fs.IsPipe())
			assert.Contains(t, fs.String(), "Fifo:")
		})
	}
}

//======================================================================
// PipeSource edge cases
//======================================================================

func TestPipeSource_VariousFds(t *testing.T) {
	tests := []struct {
		name       string
		descriptor string
		fd         int
		wantString string
	}{
		{"stdin", "stdin", 0, "Pipe:stdin(0)"},
		{"fd 3", "/dev/fd/3", 3, "Pipe:/dev/fd/3(3)"},
		{"high fd", "/dev/fd/255", 255, "Pipe:/dev/fd/255(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := PipeSource{Descriptor: tt.descriptor, Fd: tt.fd}
			assert.Equal(t, tt.descriptor, ps.Name())
			assert.True(t, ps.IsPipe())
			assert.False(t, ps.IsFile())
			assert.False(t, ps.IsInterface())
			assert.False(t, ps.IsFifo())
			assert.Equal(t, tt.wantString, ps.String())
		})
	}
}

//======================================================================
// TemporaryFileSource Tests
//======================================================================

func TestTemporaryFileSource_Remove_Success(t *testing.T) {
	// Create a real temporary file to test removal
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pcap")
	err := os.WriteFile(tmpFile, []byte("test data"), 0644)
	require.NoError(t, err)

	tfs := TemporaryFileSource{FileSource: FileSource{Filename: tmpFile}}

	// File should exist
	_, err = os.Stat(tmpFile)
	require.NoError(t, err)

	// Remove should succeed
	err = tfs.Remove()
	assert.NoError(t, err)

	// File should no longer exist
	_, err = os.Stat(tmpFile)
	assert.True(t, os.IsNotExist(err))
}

func TestTemporaryFileSource_Remove_Nonexistent(t *testing.T) {
	tfs := TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/nonexistent_file_12345.pcap"}}

	err := tfs.Remove()
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func TestTemporaryFileSource_InheritsFileSourceBehavior(t *testing.T) {
	tfs := TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/test.pcap"}}

	// Should inherit IsFile() from FileSource
	assert.True(t, tfs.IsFile())
	assert.False(t, tfs.IsInterface())
	assert.False(t, tfs.IsFifo())
	assert.False(t, tfs.IsPipe())
	assert.Equal(t, "/tmp/test.pcap", tfs.Name())
}

func TestTemporaryFileSource_StringFormat(t *testing.T) {
	tfs := TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/test.pcap"}}
	// TemporaryFileSource overrides String() to use "TempFile:" prefix
	assert.Equal(t, "TempFile:/tmp/test.pcap", tfs.String())
	// FileSource.String() uses "File:" prefix
	assert.Equal(t, "File:/tmp/test.pcap", tfs.FileSource.String())
}

//======================================================================
// ISourceRemover interface test
//======================================================================

func TestTemporaryFileSource_ImplementsISourceRemover(t *testing.T) {
	var _ ISourceRemover = TemporaryFileSource{}
}

//======================================================================
// IPacketSource interface compliance
//======================================================================

func TestAllSourceTypes_ImplementIPacketSource(t *testing.T) {
	var _ IPacketSource = FileSource{}
	var _ IPacketSource = InterfaceSource{}
	var _ IPacketSource = FifoSource{}
	var _ IPacketSource = PipeSource{}
	var _ IPacketSource = TemporaryFileSource{}
}

//======================================================================
// Mixed source type tests
//======================================================================

func TestMixedSources_ComplexScenario(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "/captures/main.pcap"},
		InterfaceSource{Iface: "eth0"},
		FifoSource{Filename: "/tmp/capture_fifo"},
		PipeSource{Descriptor: "stdin", Fd: 0},
		TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/temp_capture.pcap"}},
	}

	// FileSystemSources should return FileSource and TemporaryFileSource
	fileSources := FileSystemSources(sources)
	assert.Len(t, fileSources, 2)
	assert.Equal(t, "/captures/main.pcap", fileSources[0].Name())
	assert.Equal(t, "/tmp/temp_capture.pcap", fileSources[1].Name())

	// SourcesNames should return all names
	names := SourcesNames(sources)
	assert.Len(t, names, 5)

	// SourcesString should join all names
	s := SourcesString(sources)
	assert.Contains(t, s, "/captures/main.pcap")
	assert.Contains(t, s, "eth0")
	assert.Contains(t, s, " + ")

	// CanRestart should be true for file and interface, false for fifo and pipe
	assert.True(t, CanRestart(sources[0]))  // file
	assert.True(t, CanRestart(sources[1]))  // interface
	assert.False(t, CanRestart(sources[2])) // fifo
	assert.False(t, CanRestart(sources[3])) // pipe
	assert.True(t, CanRestart(sources[4]))  // temp file (inherits file)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
