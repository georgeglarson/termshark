package convs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================
// Ethernet filter edge cases
//======================================================================

func TestEthernet_FilterTo_BroadcastAddress(t *testing.T) {
	eth := Ethernet{}
	assert.Equal(t, "eth.dst == ff:ff:ff:ff:ff:ff", eth.FilterTo("ff:ff:ff:ff:ff:ff"))
}

func TestEthernet_FilterFrom_EmptyAddress(t *testing.T) {
	eth := Ethernet{}
	// The function doesn't validate, it just formats
	assert.Equal(t, "eth.src == ", eth.FilterFrom(""))
}

func TestEthernet_FilterAny_MulticastAddress(t *testing.T) {
	eth := Ethernet{}
	assert.Equal(t, "eth.addr == 01:00:5e:00:00:01", eth.FilterAny("01:00:5e:00:00:01"))
}

//======================================================================
// IPv4 filter edge cases
//======================================================================

func TestIPv4_FilterTo_LoopbackAddress(t *testing.T) {
	ip := IPv4{}
	assert.Equal(t, "ip.dst == 127.0.0.1", ip.FilterTo("127.0.0.1"))
}

func TestIPv4_FilterFrom_BroadcastAddress(t *testing.T) {
	ip := IPv4{}
	assert.Equal(t, "ip.src == 255.255.255.255", ip.FilterFrom("255.255.255.255"))
}

func TestIPv4_FilterAny_SubnetNotation(t *testing.T) {
	ip := IPv4{}
	// tshark display filters can use CIDR notation
	assert.Equal(t, "ip.addr == 10.0.0.0/8", ip.FilterAny("10.0.0.0/8"))
}

//======================================================================
// IPv6 filter edge cases
//======================================================================

func TestIPv6_FilterTo_LoopbackAddress(t *testing.T) {
	ip := IPv6{}
	assert.Equal(t, "ipv6.dst == ::1", ip.FilterTo("::1"))
}

func TestIPv6_FilterFrom_LinkLocalAddress(t *testing.T) {
	ip := IPv6{}
	assert.Equal(t, "ipv6.src == fe80::1", ip.FilterFrom("fe80::1"))
}

func TestIPv6_FilterAny_FullAddress(t *testing.T) {
	ip := IPv6{}
	assert.Equal(t, "ipv6.addr == 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		ip.FilterAny("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
}

//======================================================================
// UDP filter edge cases
//======================================================================

func TestUDP_FilterTo_WellKnownPort(t *testing.T) {
	udp := UDP{}
	assert.Equal(t, "ip.dst == 8.8.8.8 && udp.dstport == 53", udp.FilterTo("8.8.8.8", "53"))
}

func TestUDP_FilterFrom_HighPort(t *testing.T) {
	udp := UDP{}
	assert.Equal(t, "ip.src == 10.0.0.1 && udp.srcport == 65535", udp.FilterFrom("10.0.0.1", "65535"))
}

func TestUDP_FilterAny_ZeroPort(t *testing.T) {
	udp := UDP{}
	assert.Equal(t, "ip.addr == 10.0.0.1 && udp.port == 0", udp.FilterAny("10.0.0.1", "0"))
}

//======================================================================
// TCP filter edge cases
//======================================================================

func TestTCP_FilterTo_HTTPSPort(t *testing.T) {
	tcp := TCP{}
	assert.Equal(t, "ip.dst == 93.184.216.34 && tcp.dstport == 443", tcp.FilterTo("93.184.216.34", "443"))
}

func TestTCP_FilterFrom_SSHPort(t *testing.T) {
	tcp := TCP{}
	assert.Equal(t, "ip.src == 192.168.1.100 && tcp.srcport == 22", tcp.FilterFrom("192.168.1.100", "22"))
}

func TestTCP_FilterAny_EphemeralPort(t *testing.T) {
	tcp := TCP{}
	assert.Equal(t, "ip.addr == 172.16.0.5 && tcp.port == 49152", tcp.FilterAny("172.16.0.5", "49152"))
}

//======================================================================
// Index tests - validate exact values and independence
//======================================================================

func TestAIndex_BIndex_DoNotOverlap_Ethernet(t *testing.T) {
	eth := Ethernet{}
	for _, a := range eth.AIndex() {
		for _, b := range eth.BIndex() {
			assert.NotEqual(t, a, b, "AIndex and BIndex should not overlap for Ethernet")
		}
	}
}

func TestAIndex_BIndex_DoNotOverlap_IPv4(t *testing.T) {
	ip := IPv4{}
	for _, a := range ip.AIndex() {
		for _, b := range ip.BIndex() {
			assert.NotEqual(t, a, b, "AIndex and BIndex should not overlap for IPv4")
		}
	}
}

func TestAIndex_BIndex_DoNotOverlap_IPv6(t *testing.T) {
	ip := IPv6{}
	for _, a := range ip.AIndex() {
		for _, b := range ip.BIndex() {
			assert.NotEqual(t, a, b, "AIndex and BIndex should not overlap for IPv6")
		}
	}
}

func TestAIndex_BIndex_DoNotOverlap_UDP(t *testing.T) {
	udp := UDP{}
	aSet := make(map[int]bool)
	for _, a := range udp.AIndex() {
		aSet[a] = true
	}
	for _, b := range udp.BIndex() {
		assert.False(t, aSet[b], "AIndex and BIndex should not overlap for UDP")
	}
}

func TestAIndex_BIndex_DoNotOverlap_TCP(t *testing.T) {
	tcp := TCP{}
	aSet := make(map[int]bool)
	for _, a := range tcp.AIndex() {
		aSet[a] = true
	}
	for _, b := range tcp.BIndex() {
		assert.False(t, aSet[b], "AIndex and BIndex should not overlap for TCP")
	}
}

//======================================================================
// OfficialNameToType map edge cases
//======================================================================

func TestOfficialNameToType_CaseSensitive(t *testing.T) {
	// The map is case-sensitive: lowercase versions should not exist
	_, ok := OfficialNameToType["ethernet"]
	assert.False(t, ok)
	_, ok = OfficialNameToType["ipv4"]
	assert.False(t, ok)
	_, ok = OfficialNameToType["IPV6"]
	assert.False(t, ok)
	_, ok = OfficialNameToType["tcp"]
	assert.False(t, ok)
	_, ok = OfficialNameToType["Udp"]
	assert.False(t, ok)
}

func TestOfficialNameToType_ConsistentWithTypes(t *testing.T) {
	// Verify each type's String() output maps to its Short() output
	types := []struct {
		strMethod   string
		shortMethod string
	}{
		{Ethernet{}.String(), Ethernet{}.Short()},
		{IPv4{}.String(), IPv4{}.Short()},
		{IPv6{}.String(), IPv6{}.Short()},
		{UDP{}.String(), UDP{}.Short()},
		{TCP{}.String(), TCP{}.Short()},
	}
	for _, tt := range types {
		val, ok := OfficialNameToType[tt.strMethod]
		assert.True(t, ok, "should find %q in OfficialNameToType", tt.strMethod)
		assert.Equal(t, tt.shortMethod, val)
	}
}

//======================================================================
// Composite filter construction verification
//======================================================================

func TestUDP_FiltersComposeWithIPv4(t *testing.T) {
	udp := UDP{}
	ipv4 := IPv4{}

	// UDP FilterTo should start with IPv4's FilterTo
	result := udp.FilterTo("1.2.3.4", "80")
	expected := ipv4.FilterTo("1.2.3.4")
	assert.Contains(t, result, expected)
}

func TestTCP_FiltersComposeWithIPv4(t *testing.T) {
	tcp := TCP{}
	ipv4 := IPv4{}

	// TCP FilterFrom should start with IPv4's FilterFrom
	result := tcp.FilterFrom("1.2.3.4", "443")
	expected := ipv4.FilterFrom("1.2.3.4")
	assert.Contains(t, result, expected)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
