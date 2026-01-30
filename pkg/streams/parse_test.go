// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamParseError(t *testing.T) {
	err := StreamParseError{}
	assert.Equal(t, "Stream reassembly parse error", err.Error())

	// Verify it implements error interface
	var _ error = err
}

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		p        Protocol
		expected string
	}{
		{Unspecified, "Unspecified"},
		{TCP, "TCP"},
		{UDP, "UDP"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.p.String())
	}
}

func TestProtocol_StringPanic(t *testing.T) {
	assert.Panics(t, func() {
		_ = Protocol(999).String()
	})
}

func TestDirection_String(t *testing.T) {
	tests := []struct {
		d        Direction
		expected string
	}{
		{Client, "Client"},
		{Server, "Server"},
		{Direction(99), "Unknown!"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.d.String())
	}
}

func TestBytes_Direction(t *testing.T) {
	b := Bytes{Dirn: Client, Data: []byte("test")}
	assert.Equal(t, Client, b.Direction())

	b = Bytes{Dirn: Server, Data: []byte("test")}
	assert.Equal(t, Server, b.Direction())
}

func TestBytes_StreamData(t *testing.T) {
	data := []byte("hello world")
	b := Bytes{Dirn: Client, Data: data}
	assert.Equal(t, data, b.StreamData())
}

func TestBytes_String(t *testing.T) {
	b := Bytes{Dirn: Client, Data: []byte("Hi")}
	s := b.String()
	assert.Contains(t, s, "Direction: Client")
	assert.Contains(t, s, "48 69") // "Hi" in hex
}

func TestFollowHeader_String(t *testing.T) {
	h := FollowHeader{
		Follow: "tcp.stream eq 0",
		Filter: "tcp.stream eq 0",
		Node0:  "192.168.1.1:12345",
		Node1:  "192.168.1.2:80",
	}
	s := h.String()
	assert.Contains(t, s, "client:192.168.1.1:12345")
	assert.Contains(t, s, "server:192.168.1.2:80")
	assert.Contains(t, s, "follow:tcp.stream eq 0")
	assert.Contains(t, s, "filter:tcp.stream eq 0")
}

func TestFollowStream_String(t *testing.T) {
	fs := FollowStream{
		FollowHeader: FollowHeader{
			Follow: "tcp",
			Filter: "tcp.stream eq 0",
			Node0:  "client:1234",
			Node1:  "server:80",
		},
		Bytes: []Bytes{
			{Dirn: Client, Data: []byte("GET / HTTP/1.1")},
			{Dirn: Server, Data: []byte("HTTP/1.1 200 OK")},
		},
	}

	s := fs.String()
	assert.True(t, strings.HasPrefix(s, "Follow: tcp"))
	assert.Contains(t, s, "Filter: tcp.stream eq 0")
	assert.Contains(t, s, "Node0: client:1234")
	assert.Contains(t, s, "Node1: server:80")
	assert.Contains(t, s, "Direction: Client")
	assert.Contains(t, s, "Direction: Server")
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
