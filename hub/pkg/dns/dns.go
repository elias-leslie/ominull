package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

type CacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
}

type Server struct {
	listenAddr string
	upstreams  []string
	store      *storage.Store
	ti         *threatintel.Manager

	mu       sync.RWMutex
	cache    map[string]CacheEntry
	udpConn  *net.UDPConn
	tcpLn    net.Listener
	stopChan chan struct{}
}

func NewServer(listenAddr string, upstreams []string, store *storage.Store, ti *threatintel.Manager) *Server {
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	return &Server{
		listenAddr: listenAddr,
		upstreams:  upstreams,
		store:      store,
		ti:         ti,
		cache:      make(map[string]CacheEntry),
		stopChan:   make(chan struct{}),
	}
}

func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.listenAddr, err)
	}
	s.udpConn = udpConn

	tcpLn, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("listen tcp %s: %w", s.listenAddr, err)
	}
	s.tcpLn = tcpLn

	log.Printf("[+] Ominull DNS Forwarder & Threat Sinkhole active on %s (UDP/TCP)", s.listenAddr)

	go s.serveUDP()
	go s.serveTCP()
	go s.cleanupCacheLoop()

	return nil
}

func (s *Server) Stop() {
	close(s.stopChan)
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		go func(data []byte, addr *net.UDPAddr) {
			resp := s.handleQuery(data, addr.IP.String(), "udp")
			if resp != nil {
				_, _ = s.udpConn.WriteToUDP(resp, addr)
			}
		}(req, clientAddr)
	}
}

func (s *Server) serveTCP() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var lenBuf [2]byte
			if _, err := c.Read(lenBuf[:]); err != nil {
				return
			}
			msgLen := binary.BigEndian.Uint16(lenBuf[:])
			if msgLen == 0 || msgLen > 4096 {
				return
			}
			buf := make([]byte, msgLen)
			if _, err := c.Read(buf); err != nil {
				return
			}

			clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			resp := s.handleQuery(buf, clientIP, "tcp")
			if resp != nil {
				var outLen [2]byte
				binary.BigEndian.PutUint16(outLen[:], uint16(len(resp)))
				_, _ = c.Write(outLen[:])
				_, _ = c.Write(resp)
			}
		}(conn)
	}
}

func (s *Server) handleQuery(req []byte, clientIP, proto string) []byte {
	if len(req) < 12 {
		return nil
	}

	txID := binary.BigEndian.Uint16(req[0:2])
	qname, qtype, err := parseQuestion(req)
	if err != nil || qname == "" {
		return s.forwardUpstream(req)
	}

	// 1. Threat Intel Sinkhole Guardrail
	isThreat := false
	var threatReason string
	if s.ti != nil {
		if ioc, match := s.ti.CheckThreat(qname); match {
			isThreat = true
			threatReason = fmt.Sprintf("Threat Intel hit: %s (%s)", ioc.Value, ioc.ThreatType)
		}
	}

	if isThreat {
		log.Printf("[!] SINKHOLE BLOCK: %s requested malicious domain %s (%s)", clientIP, qname, threatReason)
		s.recordTelemetry(clientIP, qname, "BLOCK", proto)
		return buildSinkholeResponse(req, txID, qtype)
	}

	// 2. Cache Lookup
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(qname), qtype)
	s.mu.RLock()
	entry, found := s.cache[cacheKey]
	s.mu.RUnlock()

	if found && time.Now().Before(entry.ExpiresAt) {
		resp := make([]byte, len(entry.Response))
		copy(resp, entry.Response)
		binary.BigEndian.PutUint16(resp[0:2], txID)
		s.recordTelemetry(clientIP, qname, "PERMIT", proto)
		return resp
	}

	// 3. Upstream Forwarding
	resp := s.forwardUpstream(req)
	if resp != nil && len(resp) >= 12 {
		// Cache successful response for 60 seconds
		s.mu.Lock()
		s.cache[cacheKey] = CacheEntry{
			Response:  resp,
			ExpiresAt: time.Now().Add(60 * time.Second),
		}
		s.mu.Unlock()
	}

	s.recordTelemetry(clientIP, qname, "PERMIT", proto)
	return resp
}

func (s *Server) forwardUpstream(req []byte) []byte {
	for _, upstream := range s.upstreams {
		conn, err := net.DialTimeout("udp", upstream, 1500*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, err = conn.Write(req)
		if err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n > 0 {
			out := make([]byte, n)
			copy(out, buf[:n])
			return out
		}
	}
	return nil
}

func parseQuestion(req []byte) (string, uint16, error) {
	if len(req) < 12 {
		return "", 0, fmt.Errorf("packet too short")
	}
	qdcount := binary.BigEndian.Uint16(req[4:6])
	if qdcount == 0 {
		return "", 0, fmt.Errorf("no question")
	}

	offset := 12
	var labels []string
	for offset < len(req) {
		length := int(req[offset])
		offset++
		if length == 0 {
			break
		}
		if offset+length > len(req) {
			return "", 0, fmt.Errorf("malformed qname")
		}
		labels = append(labels, string(req[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(req) {
		return "", 0, fmt.Errorf("malformed question header")
	}
	qtype := binary.BigEndian.Uint16(req[offset : offset+2])
	return strings.Join(labels, "."), qtype, nil
}

func buildSinkholeResponse(req []byte, txID uint16, qtype uint16) []byte {
	var buf bytes.Buffer
	// Header: 12 bytes
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	// Flags: 0x8180 (Standard query response, No error, Recursion Available)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	// QDCount: 1, ANCount: 1
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	buf.Write(hdr[:])

	// Copy question section from request
	qEnd := 12
	for qEnd < len(req) && req[qEnd] != 0 {
		qEnd += int(req[qEnd]) + 1
	}
	qEnd += 5 // 0x00 + 2 bytes qtype + 2 bytes qclass
	if qEnd <= len(req) {
		buf.Write(req[12:qEnd])
	} else {
		return nil
	}

	// Answer Section: Name pointer (0xc00c)
	buf.Write([]byte{0xc0, 0x0c})
	if qtype == 28 { // AAAA query -> return :: (16 zeros)
		buf.Write([]byte{0x00, 0x1c, 0x00, 0x01}) // Type AAAA, Class IN
		buf.Write([]byte{0x00, 0x00, 0x00, 0x3c}) // TTL 60s
		buf.Write([]byte{0x00, 0x10})             // Length 16
		buf.Write(make([]byte, 16))
	} else { // A query -> return 0.0.0.0
		buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // Type A, Class IN
		buf.Write([]byte{0x00, 0x00, 0x00, 0x3c}) // TTL 60s
		buf.Write([]byte{0x00, 0x04})             // Length 4
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // 0.0.0.0
	}

	return buf.Bytes()
}

func (s *Server) recordTelemetry(clientIP, domain, action, proto string) {
	if s.store == nil || clientIP == "" || domain == "" {
		return
	}
	now := time.Now().UTC()
	go func() {
		ev := storage.Event{
			TenantID:    "default",
			EndpointID:  "dns-gateway-" + clientIP,
			Timestamp:   now,
			Layer:       "dns-forwarder-v1",
			Action:      action,
			Direction:   "INBOUND",
			Protocol:    17, // UDP
			SrcIP:       clientIP,
			DstIP:       "192.168.86.58",
			SrcPort:     53,
			DstPort:     53,
			Domain:      domain,
			ProcessPath: "/opt/ominull/bin/dns-proxy",
		}
		_ = s.store.InsertEvent(ev)
	}()
}

func (s *Server) cleanupCacheLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, v := range s.cache {
				if now.After(v.ExpiresAt) {
					delete(s.cache, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
