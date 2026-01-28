// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package convs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEthernet(t *testing.T) {
	eth := Ethernet{}

	assert.Equal(t, "Ethernet", eth.String())
	assert.Equal(t, "eth", eth.Short())
	assert.Equal(t, []int{0}, eth.AIndex())
	assert.Equal(t, []int{1}, eth.BIndex())

	assert.Equal(t, "eth.dst == aa:bb:cc:dd:ee:ff", eth.FilterTo("aa:bb:cc:dd:ee:ff"))
	assert.Equal(t, "eth.src == aa:bb:cc:dd:ee:ff", eth.FilterFrom("aa:bb:cc:dd:ee:ff"))
	assert.Equal(t, "eth.addr == aa:bb:cc:dd:ee:ff", eth.FilterAny("aa:bb:cc:dd:ee:ff"))
}

func TestIPv4(t *testing.T) {
	ip := IPv4{}

	assert.Equal(t, "IPv4", ip.String())
	assert.Equal(t, "ip", ip.Short())
	assert.Equal(t, []int{0}, ip.AIndex())
	assert.Equal(t, []int{1}, ip.BIndex())

	assert.Equal(t, "ip.dst == 192.168.1.1", ip.FilterTo("192.168.1.1"))
	assert.Equal(t, "ip.src == 192.168.1.1", ip.FilterFrom("192.168.1.1"))
	assert.Equal(t, "ip.addr == 192.168.1.1", ip.FilterAny("192.168.1.1"))
}

func TestIPv6(t *testing.T) {
	ip := IPv6{}

	assert.Equal(t, "IPv6", ip.String())
	assert.Equal(t, "ipv6", ip.Short())
	assert.Equal(t, []int{0}, ip.AIndex())
	assert.Equal(t, []int{1}, ip.BIndex())

	assert.Equal(t, "ipv6.dst == 2001:db8::1", ip.FilterTo("2001:db8::1"))
	assert.Equal(t, "ipv6.src == 2001:db8::1", ip.FilterFrom("2001:db8::1"))
	assert.Equal(t, "ipv6.addr == 2001:db8::1", ip.FilterAny("2001:db8::1"))
}

func TestUDP(t *testing.T) {
	udp := UDP{}

	assert.Equal(t, "UDP", udp.String())
	assert.Equal(t, "udp", udp.Short())
	assert.Equal(t, []int{0, 1}, udp.AIndex())
	assert.Equal(t, []int{2, 3}, udp.BIndex())

	assert.Equal(t, "ip.dst == 192.168.1.1 && udp.dstport == 53", udp.FilterTo("192.168.1.1", "53"))
	assert.Equal(t, "ip.src == 192.168.1.1 && udp.srcport == 53", udp.FilterFrom("192.168.1.1", "53"))
	assert.Equal(t, "ip.addr == 192.168.1.1 && udp.port == 53", udp.FilterAny("192.168.1.1", "53"))
}

func TestTCP(t *testing.T) {
	tcp := TCP{}

	assert.Equal(t, "TCP", tcp.String())
	assert.Equal(t, "tcp", tcp.Short())
	assert.Equal(t, []int{0, 1}, tcp.AIndex())
	assert.Equal(t, []int{2, 3}, tcp.BIndex())

	assert.Equal(t, "ip.dst == 192.168.1.1 && tcp.dstport == 443", tcp.FilterTo("192.168.1.1", "443"))
	assert.Equal(t, "ip.src == 192.168.1.1 && tcp.srcport == 443", tcp.FilterFrom("192.168.1.1", "443"))
	assert.Equal(t, "ip.addr == 192.168.1.1 && tcp.port == 443", tcp.FilterAny("192.168.1.1", "443"))
}

func TestOfficialNameToType(t *testing.T) {
	assert.Equal(t, "eth", OfficialNameToType["Ethernet"])
	assert.Equal(t, "ip", OfficialNameToType["IPv4"])
	assert.Equal(t, "ipv6", OfficialNameToType["IPv6"])
	assert.Equal(t, "udp", OfficialNameToType["UDP"])
	assert.Equal(t, "tcp", OfficialNameToType["TCP"])
	assert.Equal(t, 5, len(OfficialNameToType))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
