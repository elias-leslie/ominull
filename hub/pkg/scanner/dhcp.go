package scanner

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// DHCPPacket represents a decoded RFC-2131 DHCP message
type DHCPPacket struct {
	Op          byte
	HType       byte
	HLen        byte
	XID         uint32
	CIAddr      net.IP
	YIAddr      net.IP
	SIAddr      net.IP
	GIAddr      net.IP
	CHAddr      net.HardwareAddr
	Hostname    string
	VendorClass string
	Params      []byte
	MessageType byte
}

// DHCPSnooper passively listens for DHCP broadcast traffic on the local segment
type DHCPSnooper struct {
	scanner   *Scanner
	conn      net.PacketConn
	stopChan  chan struct{}
	mu        sync.Mutex
	isServing bool
}

func NewDHCPSnooper(scanner *Scanner) *DHCPSnooper {
	return &DHCPSnooper{
		scanner:  scanner,
		stopChan: make(chan struct{}),
	}
}

// Start launches the passive DHCP listener if port 67 is accessible
func (d *DHCPSnooper) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isServing {
		return nil
	}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:67")
	if err != nil {
		d.isServing = false
		return err
	}

	d.conn = conn
	d.stopChan = make(chan struct{})
	d.isServing = true
	go d.listenLoop()
	return nil
}

// Stop shuts down the DHCP listener
func (d *DHCPSnooper) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isServing {
		return
	}
	close(d.stopChan)
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
	d.isServing = false
}

// IsServing returns whether the DHCP listener is actively bound and listening
func (d *DHCPSnooper) IsServing() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isServing
}

func (d *DHCPSnooper) listenLoop() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-d.stopChan:
			return
		default:
		}

		_ = d.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := d.conn.ReadFrom(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		if n < 240 {
			continue
		}

		pkt := parseDHCPPacket(buf[:n])
		if pkt == nil || len(pkt.CHAddr) == 0 {
			continue
		}

		mac := pkt.CHAddr.String()
		ip := ""
		if pkt.YIAddr != nil && !pkt.YIAddr.IsUnspecified() {
			ip = pkt.YIAddr.String()
		} else if pkt.CIAddr != nil && !pkt.CIAddr.IsUnspecified() {
			ip = pkt.CIAddr.String()
		}

		if mac == "" {
			continue
		}

		// Perform passive classification
		d.scanner.RecordPassiveDHCP(ip, mac, pkt.Hostname, pkt.VendorClass, pkt.Params)
	}
}

func parseDHCPPacket(b []byte) *DHCPPacket {
	if len(b) < 240 {
		return nil
	}

	// Check magic cookie: 0x63, 0x82, 0x53, 0x63
	if b[236] != 0x63 || b[237] != 0x82 || b[238] != 0x53 || b[239] != 0x63 {
		return nil
	}

	hlen := int(b[2])
	if hlen <= 0 || hlen > 16 || hlen > len(b[28:]) {
		hlen = 6
	}

	pkt := &DHCPPacket{
		Op:     b[0],
		HType:  b[1],
		HLen:   b[2],
		XID:    binary.BigEndian.Uint32(b[4:8]),
		CIAddr: net.IPv4(b[12], b[13], b[14], b[15]),
		YIAddr: net.IPv4(b[16], b[17], b[18], b[19]),
		SIAddr: net.IPv4(b[20], b[21], b[22], b[23]),
		GIAddr: net.IPv4(b[24], b[25], b[26], b[27]),
		CHAddr: net.HardwareAddr(b[28 : 28+hlen]),
	}

	// Parse DHCP Options starting at offset 240
	opts := b[240:]
	for i := 0; i < len(opts); {
		tag := opts[i]
		if tag == 255 { // End of options
			break
		}
		if tag == 0 { // Pad
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if i+2+optLen > len(opts) {
			break
		}
		val := opts[i+2 : i+2+optLen]

		switch tag {
		case 53: // DHCP Message Type
			if len(val) > 0 {
				pkt.MessageType = val[0]
			}
		case 12: // Hostname
			pkt.Hostname = strings.TrimSpace(string(val))
		case 60: // Vendor Class Identifier
			pkt.VendorClass = strings.TrimSpace(string(val))
		case 55: // Parameter Request List
			pkt.Params = append([]byte{}, val...)
		}

		i += 2 + optLen
	}

	return pkt
}
