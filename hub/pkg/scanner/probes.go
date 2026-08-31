package scanner

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// The probes in this file exist because the scanner had almost nothing to
// identify a host with. It opened TCP ports, read whatever the service happened
// to say first, and then handed a hard-coded TTL of 64 to a weighted matcher.
// Every one of these asks a question whose answer is the host's own description
// of itself, and every one of them is unprivileged.

const probeTimeout = 700 * time.Millisecond

// probeExtras gathers the identity evidence that is not a TCP banner. Each
// probe is independent and a failure is simply an absent string: a host that
// does not speak SSDP is not an error.
func probeExtras(ip string, hostname string) []string {
	type multi struct {
		idx int
		v   []string
	}
	out := make(chan multi, 3)
	go func() { out <- multi{0, []string{probeNetBIOS(ip)}} }()
	go func() { out <- multi{1, probeMDNS(ip, hostname)} }()
	go func() { out <- multi{2, []string{probeSSDP(ip)}} }()

	slots := make([][]string, 3)
	for i := 0; i < 3; i++ {
		r := <-out
		slots[r.idx] = r.v
	}
	var extras []string
	for _, group := range slots {
		for _, s := range group {
			if strings.TrimSpace(s) != "" {
				extras = append(extras, s)
			}
		}
	}
	return extras
}

// ------------------------------------------------------- NetBIOS NBSTAT

// probeNetBIOS sends a node status request and returns the host's own name
// table. A host that answers is running an SMB stack, and the name it gives is
// the name its own administrator typed - which beats a reverse DNS entry that
// may not exist and may not be current.
func probeNetBIOS(ip string) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), probeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	req := make([]byte, 0, 50)
	var txid [2]byte
	binary.BigEndian.PutUint16(txid[:], uint16(rand.Intn(0xffff)))
	req = append(req, txid[0], txid[1])
	req = append(req, 0x00, 0x00) // flags: query, broadcast off
	req = append(req, 0x00, 0x01) // one question
	req = append(req, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	req = append(req, 0x20) // encoded name length, always 32
	req = append(req, encodeNetBIOSName("*")...)
	req = append(req, 0x00)       // root label
	req = append(req, 0x00, 0x21) // QTYPE NBSTAT
	req = append(req, 0x00, 0x01) // QCLASS IN

	if _, err := conn.Write(req); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	return "netbios:" + parseNodeStatus(buf[:n])
}

// encodeNetBIOSName applies first-level encoding: the 16-byte name is split
// into nibbles and each is offset by 'A'.
func encodeNetBIOSName(name string) []byte {
	padded := make([]byte, 16)
	copy(padded, strings.ToUpper(name))
	for i := len(name); i < 15; i++ {
		padded[i] = ' '
	}
	if len(name) < 16 {
		padded[15] = 0x00
	}
	out := make([]byte, 32)
	for i, b := range padded {
		out[i*2] = 'A' + (b >> 4)
		out[i*2+1] = 'A' + (b & 0x0f)
	}
	return out
}

// parseNodeStatus walks past the echoed question to the name table.
func parseNodeStatus(b []byte) string {
	// header 12 + encoded name 34 (1 length + 32 + 1 root) + type 2 + class 2
	// + ttl 4 + rdlength 2 = 56, then the name count.
	const off = 56
	if len(b) <= off {
		return ""
	}
	count := int(b[off])
	pos := off + 1
	var names []string
	for i := 0; i < count && pos+18 <= len(b); i++ {
		raw := strings.TrimRight(string(b[pos:pos+15]), " \x00")
		suffix := b[pos+15]
		flags := binary.BigEndian.Uint16(b[pos+16 : pos+18])
		group := ""
		if flags&0x8000 != 0 {
			group = " group"
		}
		if raw != "" {
			names = append(names, fmt.Sprintf("%s<%02X>%s", raw, suffix, group))
		}
		pos += 18
	}
	if len(names) > 6 {
		names = names[:6]
	}
	return strings.Join(names, " ")
}

// -------------------------------------------------- mDNS _device-info._tcp

// probeMDNS asks a host, directly, three questions its own responder will
// answer: what it calls itself, what services it publishes, and - for Apple
// hardware - its model identifier.
//
// The queries are unicast to the host's port 5353 with the unicast-response bit
// set, so this identifies one host rather than flooding the segment with
// multicast the way a discovery browser would.
func probeMDNS(ip, hostname string) []string {
	var out []string

	// The instance name has to be known before _device-info can be asked for,
	// because Apple publishes the TXT record under the host's own name and not
	// under the bare service. A reverse lookup over mDNS supplies it, and is
	// itself worth having: a host that answers is running an mDNS responder.
	local := mdnsLocalName(hostname)
	if local == "" {
		if rev := reverseARPAName(ip); rev != "" {
			if name := mdnsQueryName(ip, rev, 0x000c); name != "" {
				local = mdnsLocalName(name)
			}
		}
	}
	if local != "" {
		out = append(out, "mdns-name:"+local+".local")
	}

	if services := mdnsQueryNames(ip, "_services._dns-sd._udp.local", 0x000c); len(services) > 0 {
		out = append(out, "mdns-services:"+strings.Join(services, " "))
	}

	if local != "" {
		if txt := mdnsQueryTXT(ip, local+"._device-info._tcp.local"); txt != "" {
			out = append(out, txt)
		}
	}
	return out
}

// mdnsLocalName reduces whatever name we have to the single label a Bonjour
// instance is published under.
func mdnsLocalName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	name = strings.TrimSuffix(name, ".local")
	if i := strings.Index(name, "."); i > 0 {
		name = name[:i]
	}
	return name
}

func reverseARPAName(ip string) string {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
}

// mdnsAsk sends one question and returns the raw reply.
func mdnsAsk(ip, name string, qtype uint16) []byte {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), probeTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := conn.Write(buildMDNSQuery(name, qtype)); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n <= 12 {
		return nil
	}
	return buf[:n]
}

// mdnsQueryName returns the first DNS name in the answer section.
func mdnsQueryName(ip, name string, qtype uint16) string {
	names := decodeNames(mdnsAsk(ip, name, qtype), name)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func mdnsQueryNames(ip, name string, qtype uint16) []string {
	return decodeNames(mdnsAsk(ip, name, qtype), name)
}

func mdnsQueryTXT(ip, name string) string {
	return extractTXTStrings(mdnsAsk(ip, name, 0x0010))
}

// buildMDNSQuery writes one question with the unicast-response bit set, which
// is what makes a directed query legal rather than a multicast the whole
// segment has to read.
func buildMDNSQuery(name string, qtype uint16) []byte {
	msg := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0x80, 0x01) // QU bit set, class IN
	return msg
}

// decodeNames pulls dotted names out of a reply without implementing a full
// name decompressor: labels are length-prefixed and printable, and a compressed
// pointer is skipped rather than followed. The question's own name is dropped,
// because it is echoed back and is not an answer.
func decodeNames(b []byte, question string) []string {
	if len(b) <= 12 {
		return nil
	}
	var out []string
	seen := map[string]bool{strings.ToLower(strings.TrimSuffix(question, ".")): true}
	for i := 12; i < len(b); {
		labels, next, ok := readLabels(b, i)
		if !ok || len(labels) == 0 {
			i++
			continue
		}
		name := strings.Join(labels, ".")
		key := strings.ToLower(name)
		if len(name) > 3 && !seen[key] {
			seen[key] = true
			out = append(out, name)
		}
		i = next
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

// readLabels reads a run of length-prefixed printable labels starting at i.
func readLabels(b []byte, i int) ([]string, int, bool) {
	var labels []string
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			return labels, i + 1, len(labels) > 0
		}
		if l&0xc0 == 0xc0 {
			// A compression pointer. Everything before it is still a valid run.
			return labels, i + 2, len(labels) > 0
		}
		if l > 63 || i+1+l > len(b) {
			return labels, i + 1, false
		}
		s := string(b[i+1 : i+1+l])
		if !isPrintable(s) {
			return labels, i + 1 + l, false
		}
		labels = append(labels, s)
		i += 1 + l
	}
	return labels, i, false
}

// extractTXTStrings pulls readable key=value pairs out of a response without
// implementing a full DNS name decompressor. A TXT record is a sequence of
// length-prefixed strings, and the ones worth having all contain '='.
func extractTXTStrings(b []byte) string {
	var found []string
	for i := 12; i < len(b); {
		l := int(b[i])
		if l == 0 || l > 63 || i+1+l > len(b) {
			i++
			continue
		}
		s := string(b[i+1 : i+1+l])
		if strings.Contains(s, "=") && isPrintable(s) {
			found = append(found, s)
			i += 1 + l
			continue
		}
		i++
	}
	if len(found) == 0 {
		return ""
	}
	if len(found) > 8 {
		found = found[:8]
	}
	return strings.Join(found, " ")
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------ SSDP search

// probeSSDP sends a directed M-SEARCH. The SERVER header of the reply carries,
// by convention, the operating system and the product serving UPnP.
func probeSSDP(ip string) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "1900"), probeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	req := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(buf[:n])
}
