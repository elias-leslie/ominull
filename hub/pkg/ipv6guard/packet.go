// Package ipv6guard observes IPv6 infrastructure; it never transmits packets or
// changes routing, DNS, addressing or containment state.
package ipv6guard

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Observation struct {
	ServerID       string    `json:"server_id,omitempty"`
	Kind           string    `json:"kind"`
	Interface      string    `json:"interface"`
	Source         string    `json:"source"`
	Destination    string    `json:"destination"`
	MAC            string    `json:"mac"`
	Prefixes       []string  `json:"prefixes,omitempty"`
	Addresses      []string  `json:"addresses,omitempty"`
	DNS            []string  `json:"dns,omitempty"`
	Domains        []string  `json:"domains,omitempty"`
	RouterLifetime uint16    `json:"router_lifetime,omitempty"`
	Managed        bool      `json:"managed,omitempty"`
	Autonomous     bool      `json:"autonomous,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Count          int64     `json:"count"`
}

var ErrMalformed = errors.New("malformed or unverifiable IPv6 infrastructure packet")

// ParseFrame accepts complete Ethernet/IPv6 packets. Fragments and encrypted
// headers are deliberately not reassembled; a partial packet is not evidence.
func ParseFrame(frame []byte, iface string, at time.Time) (Observation, error) {
	o := Observation{Interface: iface, FirstSeen: at, LastSeen: at, Count: 1}
	if len(frame) < 14 {
		return o, ErrMalformed
	}
	offset := 14
	ether := binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; ether == 0x8100 || ether == 0x88a8; tags++ {
		if tags == 2 || len(frame) < offset+4 {
			return o, ErrMalformed
		}
		ether = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if ether != 0x86dd {
		return o, nil
	}
	if frame[6]&1 != 0 || [6]byte(frame[6:12]) == [6]byte{} {
		return o, ErrMalformed
	}
	if len(frame) < offset+40 {
		return o, ErrMalformed
	}
	p := frame[offset:]
	length := int(binary.BigEndian.Uint16(p[4:6]))
	if p[0]>>4 != 6 || length == 0 || len(p) < 40+length {
		return o, ErrMalformed
	}
	p = p[:40+length]
	src := netip.AddrFrom16([16]byte(p[8:24]))
	dst := netip.AddrFrom16([16]byte(p[24:40]))
	o.Source = src.String()
	o.Destination = dst.String()
	o.MAC = net.HardwareAddr(frame[6:12]).String()
	if src.IsLinkLocalUnicast() {
		o.Source = src.WithZone(iface).String()
	}
	if dst.IsLinkLocalUnicast() {
		o.Destination = dst.WithZone(iface).String()
	}
	next, pos := p[6], 40
	for steps := 0; next == 0 || next == 60; steps++ {
		if steps == 8 || pos+2 > len(p) {
			return o, ErrMalformed
		}
		size := (int(p[pos+1]) + 1) * 8
		if pos+size > len(p) {
			return o, ErrMalformed
		}
		next = p[pos]
		pos += size
	}
	if next != 58 && next != 17 {
		return o, nil
	}
	body := p[pos:]
	if len(body) >= 8 && next == 17 {
		sourcePort, destinationPort := binary.BigEndian.Uint16(body[:2]), binary.BigEndian.Uint16(body[2:4])
		if destinationPort != 53 && !((sourcePort == 547 && destinationPort == 546) || (sourcePort == 546 && destinationPort == 547)) {
			return o, nil
		}
		if binary.BigEndian.Uint16(body[6:8]) == 0 {
			return o, ErrMalformed
		}
	}
	if len(body) < 8 || !validChecksum(p[8:40], next, body) {
		return o, ErrMalformed
	}
	if next == 58 {
		if body[0] != 133 && body[0] != 134 && body[0] != 135 && body[0] != 136 {
			return o, nil
		}
		if p[7] != 255 || body[1] != 0 {
			return o, ErrMalformed
		}
		switch body[0] {
		case 133:
			if !src.IsUnspecified() && !src.IsLinkLocalUnicast() {
				return o, ErrMalformed
			}
			o.Kind = "router_solicitation"
			body = body[8:]
		case 134:
			if !src.IsLinkLocalUnicast() || len(body) < 16 {
				return o, ErrMalformed
			}
			o.Kind = "router_advertisement"
			o.Managed = body[5]&0x80 != 0
			o.RouterLifetime = binary.BigEndian.Uint16(body[6:8])
			body = body[16:]
		case 135, 136:
			if len(body) < 24 || (body[0] == 136 && src.IsUnspecified()) {
				return o, ErrMalformed
			}
			o.Kind = "neighbor_discovery"
			target := netip.AddrFrom16([16]byte(body[8:24]))
			if target.IsMulticast() || target.IsUnspecified() {
				return o, ErrMalformed
			}
			o.Addresses = []string{target.String()}
			body = body[24:]
		}
		for len(body) > 0 {
			if len(body) < 2 || body[1] == 0 {
				return o, ErrMalformed
			}
			n := int(body[1]) * 8
			if n > len(body) {
				return o, ErrMalformed
			}
			option := body[:n]
			switch option[0] {
			case 3:
				if o.Kind != "router_advertisement" {
					break
				}
				if n != 32 || option[2] > 128 || binary.BigEndian.Uint32(option[8:12]) > binary.BigEndian.Uint32(option[4:8]) {
					return o, ErrMalformed
				}
				prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte(option[16:32])), int(option[2])).Masked()
				if prefix.Addr().IsMulticast() || prefix.Addr().IsLinkLocalUnicast() {
					return o, ErrMalformed
				}
				o.Prefixes = append(o.Prefixes, prefix.String())
				o.Autonomous = o.Autonomous || (option[3]&0x40 != 0 && option[2] == 64)
			case 25:
				if o.Kind != "router_advertisement" {
					break
				}
				if n < 24 || (n-8)%16 != 0 {
					return o, ErrMalformed
				}
				for i := 8; i < n; i += 16 {
					o.DNS = append(o.DNS, netip.AddrFrom16([16]byte(option[i:i+16])).String())
				}
			}
			body = body[n:]
		}
		return o, nil
	}
	sourcePort, destinationPort := binary.BigEndian.Uint16(body[:2]), binary.BigEndian.Uint16(body[2:4])
	n := int(binary.BigEndian.Uint16(body[4:6]))
	if n < 8 || n != len(body) {
		return o, ErrMalformed
	}
	if destinationPort == 53 {
		var message dns.Msg
		if message.Unpack(body[8:]) != nil || message.Response {
			return o, nil
		}
		for _, q := range message.Question {
			name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
			if name == "wpad" || strings.HasPrefix(name, "wpad.") {
				o.Kind = "wpad_query"
				o.Domains = append(o.Domains, name)
			}
		}
		return o, nil
	}
	if !((sourcePort == 547 && destinationPort == 546) || (sourcePort == 546 && destinationPort == 547)) {
		return o, nil
	}
	body = body[8:]
	if len(body) < 4 {
		return o, ErrMalformed
	}
	switch body[0] {
	case 1, 3, 4, 5, 6, 8, 9, 11:
		o.Kind = "dhcpv6_client"
	case 2, 7, 10:
		if sourcePort != 547 {
			return o, ErrMalformed
		}
		o.Kind = "dhcpv6_server"
	default:
		return o, nil
	}
	if err := dhcpOptions(body[4:], &o, 0); err != nil {
		return o, err
	}
	if o.Kind == "dhcpv6_server" && o.ServerID == "" {
		return o, ErrMalformed
	}
	return o, nil
}

func dhcpOptions(body []byte, o *Observation, depth int) error {
	if depth > 2 {
		return ErrMalformed
	}
	for len(body) > 0 {
		if len(body) < 4 {
			return ErrMalformed
		}
		code, n := binary.BigEndian.Uint16(body[:2]), int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if n > len(body) {
			return ErrMalformed
		}
		value := body[:n]
		switch code {
		case 2:
			if depth != 0 || n < 2 || n > 128 {
				return ErrMalformed
			}
			o.ServerID = hex.EncodeToString(value)
		case 23:
			if n == 0 || n%16 != 0 {
				return ErrMalformed
			}
			for i := 0; i < n; i += 16 {
				o.DNS = append(o.DNS, netip.AddrFrom16([16]byte(value[i:i+16])).String())
			}
		case 3:
			if n < 12 {
				return ErrMalformed
			}
			if err := dhcpOptions(value[12:], o, depth+1); err != nil {
				return err
			}
		case 5:
			if n < 24 || binary.BigEndian.Uint32(value[16:20]) > binary.BigEndian.Uint32(value[20:24]) {
				return ErrMalformed
			}
			o.Addresses = append(o.Addresses, netip.AddrFrom16([16]byte(value[:16])).String())
		case 24:
			for i := 0; i < n; {
				name, next, err := dns.UnpackDomainName(value, i)
				if err != nil || next <= i {
					return ErrMalformed
				}
				o.Domains = append(o.Domains, strings.TrimSuffix(name, "."))
				i = next
			}
		}
		body = body[n:]
	}
	return nil
}

func validChecksum(addresses []byte, next byte, body []byte) bool {
	var sum uint32
	add := func(p []byte) {
		for len(p) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(p[:2]))
			p = p[2:]
		}
		if len(p) > 0 {
			sum += uint32(p[0]) << 8
		}
	}
	add(addresses)
	sum += uint32(len(body)>>16) + uint32(len(body)&0xffff) + uint32(next)
	add(body)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

// Rule violations name what was observed, not a proved attacker or compromise.
func (o Observation) Summary() string {
	return fmt.Sprintf("%s from %s (%s) on %s", strings.ReplaceAll(o.Kind, "_", " "), o.Source, o.MAC, o.Interface)
}
