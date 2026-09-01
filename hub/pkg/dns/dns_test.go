package dns

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

func TestDNSParseQuestion(t *testing.T) {
	// Query for "google.com" type A (0x0001)
	req := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCount = 1
		0x00, 0x00, // ANCount = 0
		0x00, 0x00, // NSCount = 0
		0x00, 0x00, // ARCount = 0
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	qname, qtype, err := parseQuestion(req)
	if err != nil {
		t.Fatalf("parseQuestion: %v", err)
	}
	if qname != "google.com" {
		t.Errorf("expected google.com, got %s", qname)
	}
	if qtype != 1 {
		t.Errorf("expected qtype 1, got %d", qtype)
	}
}

func TestDNSSinkholeResponse(t *testing.T) {
	req := []byte{
		0xaa, 0xbb, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCount = 1
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x07, 'm', 'a', 'l', 'w', 'a', 'r', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	resp := buildSinkholeResponse(req, 0xaabb, 1)
	if len(resp) < 12 {
		t.Fatalf("response too short: %d", len(resp))
	}

	// Check Transaction ID matches
	if binary.BigEndian.Uint16(resp[0:2]) != 0xaabb {
		t.Errorf("mismatched tx id: %x", resp[0:2])
	}
	// Check Flags (0x8180 = QR=1, RCODE=0)
	if binary.BigEndian.Uint16(resp[2:4]) != 0x8180 {
		t.Errorf("mismatched flags: %x", resp[2:4])
	}
	// Check ANCount = 1
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Errorf("expected 1 answer, got %d", binary.BigEndian.Uint16(resp[6:8]))
	}

	// Last 4 bytes of A record must be 0.0.0.0
	ipBytes := resp[len(resp)-4:]
	if ipBytes[0] != 0 || ipBytes[1] != 0 || ipBytes[2] != 0 || ipBytes[3] != 0 {
		t.Errorf("expected 0.0.0.0, got %v", ipBytes)
	}
}

func TestDNSServerLiveQuery(t *testing.T) {
	st, err := storage.New(filepath.Join(t.TempDir(), "dns_test.db"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer st.Close()

	ti := threatintel.New(st)

	// Listen on ephemeral local port
	srv := NewServer("127.0.0.1:0", []string{"1.1.1.1:53"}, st, ti)
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Stop()

	clientAddr := srv.udpConn.LocalAddr().String()

	// Query google.com
	conn, err := net.Dial("udp", clientAddr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	req := []byte{
		0x55, 0x66,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write query: %v", err)
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n < 12 {
		t.Fatalf("response too short: %d", n)
	}

	if binary.BigEndian.Uint16(resp[0:2]) != 0x5566 {
		t.Errorf("expected txID 0x5566, got %x", resp[0:2])
	}
}
