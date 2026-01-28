// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestFileSource(t *testing.T) {
	fs := FileSource{Filename: "/path/to/file.pcap"}

	assert.Equal(t, "/path/to/file.pcap", fs.Name())
	assert.True(t, fs.IsFile())
	assert.False(t, fs.IsInterface())
	assert.False(t, fs.IsFifo())
	assert.False(t, fs.IsPipe())
	assert.Equal(t, "File:/path/to/file.pcap", fs.String())
}

func TestInterfaceSource(t *testing.T) {
	is := InterfaceSource{Iface: "eth0"}

	assert.Equal(t, "eth0", is.Name())
	assert.False(t, is.IsFile())
	assert.True(t, is.IsInterface())
	assert.False(t, is.IsFifo())
	assert.False(t, is.IsPipe())
	assert.Equal(t, "Interface:eth0", is.String())
}

func TestFifoSource(t *testing.T) {
	fs := FifoSource{Filename: "/tmp/myfifo"}

	assert.Equal(t, "/tmp/myfifo", fs.Name())
	assert.False(t, fs.IsFile())
	assert.False(t, fs.IsInterface())
	assert.True(t, fs.IsFifo())
	assert.False(t, fs.IsPipe())
	assert.Equal(t, "Fifo:/tmp/myfifo", fs.String())
}

func TestPipeSource(t *testing.T) {
	ps := PipeSource{Descriptor: "stdin", Fd: 0}

	assert.Equal(t, "stdin", ps.Name())
	assert.False(t, ps.IsFile())
	assert.False(t, ps.IsInterface())
	assert.False(t, ps.IsFifo())
	assert.True(t, ps.IsPipe())
	assert.Equal(t, "Pipe:stdin(0)", ps.String())
}

func TestTemporaryFileSource(t *testing.T) {
	tfs := TemporaryFileSource{FileSource: FileSource{Filename: "/tmp/temp.pcap"}}

	assert.Equal(t, "/tmp/temp.pcap", tfs.Name())
	assert.True(t, tfs.IsFile())
	assert.Equal(t, "TempFile:/tmp/temp.pcap", tfs.String())
}

func TestFileSystemSources(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "file1.pcap"},
		InterfaceSource{Iface: "eth0"},
		FileSource{Filename: "file2.pcap"},
		FifoSource{Filename: "/tmp/fifo"},
		PipeSource{Descriptor: "stdin", Fd: 0},
	}

	fileSources := FileSystemSources(sources)

	assert.Equal(t, 2, len(fileSources))
	assert.Equal(t, "file1.pcap", fileSources[0].Name())
	assert.Equal(t, "file2.pcap", fileSources[1].Name())
}

func TestFileSystemSources_Empty(t *testing.T) {
	sources := []IPacketSource{
		InterfaceSource{Iface: "eth0"},
		PipeSource{Descriptor: "stdin", Fd: 0},
	}

	fileSources := FileSystemSources(sources)
	assert.Equal(t, 0, len(fileSources))
}

func TestSourcesNames(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "file.pcap"},
		InterfaceSource{Iface: "eth0"},
	}

	names := SourcesNames(sources)

	assert.Equal(t, []string{"file.pcap", "eth0"}, names)
}

func TestSourcesString(t *testing.T) {
	sources := []IPacketSource{
		FileSource{Filename: "file.pcap"},
		InterfaceSource{Iface: "eth0"},
	}

	s := SourcesString(sources)

	assert.Equal(t, "file.pcap + eth0", s)
}

func TestUIName(t *testing.T) {
	// File source
	fs := FileSource{Filename: "capture.pcap"}
	assert.Equal(t, "capture.pcap", UIName(fs))

	// Interface source
	is := InterfaceSource{Iface: "eth0"}
	assert.Equal(t, "eth0", UIName(is))

	// Pipe source should show <stdin>
	ps := PipeSource{Descriptor: "stdin", Fd: 0}
	assert.Equal(t, "<stdin>", UIName(ps))
}

func TestCanRestart(t *testing.T) {
	// File source can restart
	fs := FileSource{Filename: "file.pcap"}
	assert.True(t, CanRestart(fs))

	// Interface source can restart
	is := InterfaceSource{Iface: "eth0"}
	assert.True(t, CanRestart(is))

	// Fifo source cannot restart
	fifo := FifoSource{Filename: "/tmp/fifo"}
	assert.False(t, CanRestart(fifo))

	// Pipe source cannot restart
	ps := PipeSource{Descriptor: "stdin", Fd: 0}
	assert.False(t, CanRestart(ps))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
