//go:build linux || darwin

package scanner

import (
	"encoding/binary"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// ------------------------------------------------------------- measured TTL

// measureTTL reads the initial hop limit a host set on a packet it sent us, by
// sending an ICMP echo on an unprivileged datagram socket and reading the TTL
// out of the reply's ancillary data.
//
// This is the fix for the defect that mattered most: the scanner declared
// `ttl := 64` and never measured anything, while the matcher awarded a fifth of
// its points for a TTL match. Every host on the network was told it looked like
// Linux before a single packet was examined.
//
// It returns 0 when the measurement is unavailable - no permission for the
// socket, no reply - and 0 means "not measured", which the matcher now scores
// as no evidence rather than as evidence for 64.
// TTLMeasurable reports whether this process can open the socket measureTTL
// needs, and why not when it cannot. The scanner shows the answer rather than
// silently reporting every hop limit as unknown: "hop limits are not being
// measured" is a fact an operator can act on, and a blank column is not.
func TTLMeasurable() (bool, string) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return false, "this process cannot open an unprivileged ICMP socket (" + err.Error() +
			"). Add its group to net.ipv4.ping_group_range, or give the service CAP_NET_RAW. " +
			"Hop limits are reported as unmeasured until then, and contribute nothing to an identification."
	}
	_ = unix.Close(fd)
	return true, ""
}

func measureTTL(ip string) int {
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0
	}
	v4 := addr.To4()
	if v4 == nil {
		return 0 // IPv6 hop limits are read the same way; not needed yet.
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		// net.ipv4.ping_group_range does not include this process's group. The
		// alternative is a raw socket, which needs a capability the hub is not
		// given, so the honest answer is that the TTL is unknown.
		return 0
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1); err != nil {
		return 0
	}
	tv := unix.NsecToTimeval(int64(probeTimeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	id := uint16(os.Getpid() & 0xffff)
	pkt := icmpEcho(id, 1)
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], v4)
	if err := unix.Sendto(fd, pkt, 0, &sa); err != nil {
		return 0
	}

	buf := make([]byte, 1500)
	oob := make([]byte, 256)
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
	if err != nil || n == 0 {
		return 0
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0
	}
	for _, c := range cmsgs {
		if c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_TTL && len(c.Data) >= 1 {
			return int(c.Data[0])
		}
	}
	return 0
}

// icmpEcho builds an echo request. A datagram ICMP socket rewrites the
// identifier, so the sequence number is what a reply is matched on - and since
// this sends exactly one probe per socket, any reply that arrives is ours.
func icmpEcho(id, seq uint16) []byte {
	b := make([]byte, 16)
	b[0] = 8 // echo request
	b[1] = 0
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], "ominull")
	binary.BigEndian.PutUint16(b[2:4], icmpChecksum(b))
	return b
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
