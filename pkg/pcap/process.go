// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"fmt"
	"io"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
)

//======================================================================

type ProcessState int

const (
	NotStarted ProcessState = 0
	Started    ProcessState = 1
	Terminated ProcessState = 2
)

func (p ProcessState) String() string {
	switch p {
	case NotStarted:
		return "NotStarted"
	case Started:
		return "Started"
	case Terminated:
		return "Terminated"
	default:
		return "Unknown"
	}
}

//======================================================================

type IBasicCommand interface {
	fmt.Stringer
	Start() error
	Wait() error
	Pid() int
	Kill() error
	StderrSummary() []string
}

func MakeUsefulError(cmd IBasicCommand, err error) gowid.KeyValueError {
	return gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
		"command": cmd.String(),
		"error":   err,
		"stderr":  strings.Join(cmd.StderrSummary(), "\n"),
	})
}

type ITailCommand interface {
	IBasicCommand
	SetStdout(io.Writer) // set to the write side of a fifo, for example - the command will .Write() here
	Close() error        // closes stdout, which signals tshark -T psml
}

type IPcapCommand interface {
	IBasicCommand
	StdoutReader() (io.ReadCloser, error) // termshark will .Read() from result
}

type ILoaderCmds interface {
	Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand
	Tail(tmpfile string) ITailCommand
	Psml(pcap any, displayFilter string) IPcapCommand // pcap can be string (file) or IPacketSource (fifo)
	Pcap(pcap string, displayFilter string) IPcapCommand
	Pdml(pcap string, displayFilter string) IPcapCommand
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
