package ipv6guard

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func fixtureFrame(next byte, body []byte) []byte {
	frame := make([]byte, 14+40+len(body))
	copy(frame[:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	p := frame[14:]
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(body)))
	p[6] = next
	p[7] = 255
	src, dst := netip.MustParseAddr("fe80::a").As16(), netip.MustParseAddr("ff02::1").As16()
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	copy(p[40:], body)
	var sum uint32
	for i := 8; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	sum += uint32(len(body)) + uint32(next)
	for i := 0; i+1 < len(body); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(body[i : i+2]))
	}
	if len(body)%2 != 0 {
		sum += uint32(body[len(body)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	offset := 42
	if next == 17 {
		offset = 46
	}
	binary.BigEndian.PutUint16(p[offset:offset+2], ^uint16(sum))
	return frame
}
func routerAdvertisement() []byte {
	body := make([]byte, 72)
	body[0] = 134
	binary.BigEndian.PutUint16(body[6:8], 1800)
	body[16] = 3
	body[17] = 4
	body[18] = 64
	body[19] = 0xc0
	binary.BigEndian.PutUint32(body[20:24], 3600)
	binary.BigEndian.PutUint32(body[24:28], 1800)
	prefix := netip.MustParseAddr("2001:db8:1::").As16()
	copy(body[32:48], prefix[:])
	body[48] = 25
	body[49] = 3
	binary.BigEndian.PutUint32(body[52:56], 300)
	dns := netip.MustParseAddr("2001:db8::53").As16()
	copy(body[56:], dns[:])
	return fixtureFrame(58, body)
}
func TestRouterAdvertisementRetainsObservedEvidence(t *testing.T) {
	o, err := ParseFrame(routerAdvertisement(), "eth0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind != "router_advertisement" || o.Source != "fe80::a%eth0" || len(o.Prefixes) != 1 || o.Prefixes[0] != "2001:db8:1::/64" || !o.Autonomous || len(o.DNS) != 1 {
		t.Fatalf("lost evidence: %+v", o)
	}
}
func TestMalformedAndUnverifiablePacketsAreRejected(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { return p[:len(p)-1] },
		func(p []byte) []byte { p[21] = 64; return p },
		func(p []byte) []byte { p[len(p)-1] ^= 1; return p },
	} {
		if _, err := ParseFrame(mutate(routerAdvertisement()), "eth0", time.Now()); err == nil {
			t.Fatal("accepted invalid packet")
		}
	}
	body := make([]byte, 24)
	body[0] = 134
	body[16] = 3
	body[17] = 0
	if _, err := ParseFrame(fixtureFrame(58, body), "eth0", time.Now()); err == nil {
		t.Fatal("accepted zero-length ND option")
	}
}
func TestDHCPv6ReplyRetainsDNSServer(t *testing.T) {
	body := make([]byte, 38)
	binary.BigEndian.PutUint16(body[:2], 547)
	binary.BigEndian.PutUint16(body[2:4], 546)
	binary.BigEndian.PutUint16(body[4:6], 38)
	body[8] = 7
	binary.BigEndian.PutUint16(body[12:14], 23)
	binary.BigEndian.PutUint16(body[14:16], 16)
	dns := netip.MustParseAddr("2001:db8::53").As16()
	copy(body[16:32], dns[:])
	binary.BigEndian.PutUint16(body[32:34], 2)
	binary.BigEndian.PutUint16(body[34:36], 2)
	body[37] = 1
	o, err := ParseFrame(fixtureFrame(17, body), "eth0", time.Now())
	if err != nil || o.Kind != "dhcpv6_server" || len(o.DNS) != 1 {
		t.Fatalf("%+v %v", o, err)
	}
}
func FuzzParseFrame(f *testing.F) {
	f.Add(routerAdvertisement())
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, p []byte) { _, _ = ParseFrame(p, "fixture", time.Unix(1, 0)) })
}

func TestInfrastructureRejectsNonUnicastSourceMAC(t *testing.T) {
	for _, mac := range [][]byte{{0, 0, 0, 0, 0, 0}, {0x33, 0x33, 0, 0, 0, 1}} {
		frame := routerAdvertisement()
		copy(frame[6:12], mac)
		if _, err := ParseFrame(frame, "fixture", time.Now()); err == nil {
			t.Fatal("unverifiable sender accepted")
		}
	}
}
