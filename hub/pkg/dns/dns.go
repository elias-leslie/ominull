package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

type ServerState string

const (
	StateDisabled   ServerState = "disabled"
	StateStarting   ServerState = "starting"
	StateForwarding ServerState = "forwarding"
	StateProtecting ServerState = "protecting"
	StateDegraded   ServerState = "degraded"
	StateFailed     ServerState = "failed"
)

type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Server struct {
	listenAddr string
	upstreams  []string
	store      *storage.Store
	ti         *threatintel.Manager

	mu        sync.RWMutex
	cache     map[string]CacheEntry
	maxCache  int
	allowlist map[string]bool   // normalized domain -> true
	blocklist map[string]string // normalized domain -> reason

	udpServer    *dns.Server
	tcpServer    *dns.Server
	stopChan     chan struct{}
	eventChan    chan storage.DNSEvent
	state        ServerState
	queriesTotal int64
	cacheHits    int64
	blockedTotal int64
	errorsTotal  int64

	concurrencySem chan struct{}
}

func NewServer(listenAddr string, upstreams []string, store *storage.Store, ti *threatintel.Manager) *Server {
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	cleanUpstreams := make([]string, 0, len(upstreams))
	for _, u := range upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !strings.Contains(u, ":") {
			u = u + ":53"
		}
		cleanUpstreams = append(cleanUpstreams, u)
	}

	return &Server{
		listenAddr:     listenAddr,
		upstreams:      cleanUpstreams,
		store:          store,
		ti:             ti,
		cache:          make(map[string]CacheEntry),
		maxCache:       10000,
		allowlist:      make(map[string]bool),
		blocklist:      make(map[string]string),
		stopChan:       make(chan struct{}),
		eventChan:      make(chan storage.DNSEvent, 2048),
		state:          StateStarting,
		concurrencySem: make(chan struct{}, 1024),
	}
}

func (s *Server) Start() error {
	if s.listenAddr == "" || s.listenAddr == "off" || s.listenAddr == "disabled" {
		s.state = StateDisabled
		return nil
	}

	// 1. Loop detection
	if err := s.detectForwardingLoop(); err != nil {
		s.state = StateFailed
		return fmt.Errorf("dns forwarding loop detected: %w", err)
	}

	// 2. Load policies & threat intel domains
	s.ReloadRules()

	// 3. Setup DNS Handler
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	s.udpServer = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: mux,
		UDPSize: 4096,
	}

	s.tcpServer = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "tcp",
		Handler: mux,
	}

	errChan := make(chan error, 2)

	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
			errChan <- fmt.Errorf("udp listener: %w", err)
		}
	}()

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
			errChan <- fmt.Errorf("tcp listener: %w", err)
		}
	}()

	// Brief check to confirm bind
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-errChan:
		s.state = StateFailed
		return err
	default:
	}

	s.updateState()
	log.Printf("[+] Ominull RFC-Compliant DNS Forwarder active on %s (UDP/TCP) [State: %s]", s.listenAddr, s.state)

	go s.eventLoggerLoop()
	go s.cacheCleanupLoop()

	return nil
}

func (s *Server) Stop() {
	close(s.stopChan)
	if s.udpServer != nil {
		_ = s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		_ = s.tcpServer.Shutdown()
	}
	s.state = StateDisabled
}

func (s *Server) ReloadRules() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.allowlist = make(map[string]bool)
	s.blocklist = make(map[string]string)

	// A. Load from storage
	if s.store != nil {
		rules, err := s.store.ListDNSRules("")
		if err == nil {
			for _, r := range rules {
				norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
				if norm == "" {
					continue
				}
				if r.Action == "ALLOW" {
					s.allowlist[norm] = true
				} else {
					s.blocklist[norm] = "Policy rule: " + r.Source + " " + r.Comment
				}
			}
		}
	}

	// B. Load domain indicators from threat intelligence
	if s.ti != nil {
		domains := s.ti.GetActiveDomainIndicators()
		for _, d := range domains {
			norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if norm != "" && !s.allowlist[norm] {
				s.blocklist[norm] = "Threat Intel feed match"
			}
		}
	}

	s.updateStateLocked()
}

func (s *Server) updateState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateStateLocked()
}

func (s *Server) updateStateLocked() {
	if s.state == StateDisabled || s.state == StateFailed {
		return
	}
	if len(s.blocklist) > 0 {
		s.state = StateProtecting
	} else if len(s.upstreams) > 0 {
		s.state = StateForwarding
	} else {
		s.state = StateDegraded
	}
}

func (s *Server) detectForwardingLoop() error {
	listenHost, listenPort, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		if strings.HasPrefix(s.listenAddr, ":") {
			listenHost = "0.0.0.0"
			listenPort = strings.TrimPrefix(s.listenAddr, ":")
		} else {
			return nil
		}
	}
	if listenPort == "" {
		listenPort = "53"
	}

	for _, up := range s.upstreams {
		upHost, upPort, err := net.SplitHostPort(up)
		if err != nil {
			upHost = up
			upPort = "53"
		}
		if (upHost == "127.0.0.1" || upHost == "localhost" || upHost == listenHost || upHost == "::1" || upHost == "0.0.0.0") && upPort == listenPort {
			return fmt.Errorf("upstream %s is the local listener", up)
		}
	}
	return nil
}

func (s *Server) handleDNSQuery(w dns.ResponseWriter, req *dns.Msg) {
	atomic.AddInt64(&s.queriesTotal, 1)

	// Bound concurrency
	select {
	case s.concurrencySem <- struct{}{}:
		defer func() { <-s.concurrencySem }()
	default:
		// Queue full -> return SERVFAIL
		atomic.AddInt64(&s.errorsTotal, 1)
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(resp)
		return
	}

	start := time.Now()
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	clientHost, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	q := req.Question[0]
	rawDomain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	qtypeStr := dns.TypeToString[q.Qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", q.Qtype)
	}

	// 1. Policy Evaluation (Allowlist > Blocklist)
	isAllowed, isBlocked, blockReason := s.evaluateDomain(rawDomain)

	if isBlocked && !isAllowed {
		atomic.AddInt64(&s.blockedTotal, 1)
		resp := s.buildSinkholeResponse(req, q)
		_ = w.WriteMsg(resp)

		latency := time.Since(start).Microseconds()
		s.emitEvent(storage.DNSEvent{
			ClientIP:     clientHost,
			Domain:       rawDomain,
			QType:        qtypeStr,
			Action:       "BLOCK",
			Status:       "BLOCKED",
			ResponseCode: dns.RcodeToString[resp.Rcode],
			LatencyUs:    latency,
			Transport:    transport,
			BlockReason:  blockReason,
		})
		return
	}

	// 2. Cache Lookup
	cacheKey := fmt.Sprintf("%s:%d:%t", rawDomain, q.Qtype, req.CheckingDisabled)
	if entry, found := s.getCache(cacheKey); found {
		atomic.AddInt64(&s.cacheHits, 1)
		resp := entry.Msg.Copy()
		resp.Id = req.Id
		s.adjustCachedTTLs(resp, entry.ExpiresAt)

		// Honor EDNS buffer
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}

		_ = w.WriteMsg(resp)
		latency := time.Since(start).Microseconds()
		action := "PERMIT"
		if isAllowed {
			action = "ALLOWLIST"
		}
		s.emitEvent(storage.DNSEvent{
			ClientIP:     clientHost,
			Domain:       rawDomain,
			QType:        qtypeStr,
			Action:       action,
			Status:       "HIT",
			ResponseCode: dns.RcodeToString[resp.Rcode],
			LatencyUs:    latency,
			Transport:    transport,
		})
		return
	}

	// 3. Forward Upstream
	resp, upstreamUsed, err := s.forwardUpstream(req)
	latency := time.Since(start).Microseconds()

	if err != nil || resp == nil {
		atomic.AddInt64(&s.errorsTotal, 1)
		failResp := new(dns.Msg)
		failResp.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(failResp)

		s.emitEvent(storage.DNSEvent{
			ClientIP:     clientHost,
			Domain:       rawDomain,
			QType:        qtypeStr,
			Action:       "PERMIT",
			Status:       "ERROR",
			ResponseCode: "SERVFAIL",
			LatencyUs:    latency,
			Transport:    transport,
			BlockReason:  fmt.Sprintf("Upstream failure: %v", err),
		})
		return
	}

	// Check for UDP truncation vs client buffer
	if transport == "udp" {
		maxSize := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			maxSize = int(opt.UDPSize())
		}
		if resp.Len() > maxSize {
			resp.Truncated = true
			resp.Answer = nil
			resp.Ns = nil
			resp.Extra = nil
		}
	}

	_ = w.WriteMsg(resp)

	// 4. Cache valid responses
	if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
		ttl := s.calculateMinTTL(resp)
		if ttl > 0 {
			s.putCache(cacheKey, resp, ttl)
		}
	}

	action := "PERMIT"
	if isAllowed {
		action = "ALLOWLIST"
	}
	s.emitEvent(storage.DNSEvent{
		ClientIP:     clientHost,
		Domain:       rawDomain,
		QType:        qtypeStr,
		Action:       action,
		Status:       "MISS",
		ResponseCode: dns.RcodeToString[resp.Rcode],
		LatencyUs:    latency,
		Upstream:     upstreamUsed,
		Transport:    transport,
	})
}

func (s *Server) evaluateDomain(domain string) (allowed bool, blocked bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	labels := strings.Split(domain, ".")

	// Check allowlist exact + subdomains
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if s.allowlist[candidate] {
			return true, false, ""
		}
	}

	// Check blocklist exact + subdomains
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if r, found := s.blocklist[candidate]; found {
			return false, true, r
		}
	}

	return false, false, ""
}

func (s *Server) buildSinkholeResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  dns.ClassINET,
		Ttl:    60,
	}

	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: hdr,
				A:   net.IPv4zero,
			},
		}
	case dns.TypeAAAA:
		resp.Answer = []dns.RR{
			&dns.AAAA{
				Hdr:  hdr,
				AAAA: net.IPv6zero,
			},
		}
	default:
		// Return NOERROR with empty answer (NODATA)
		resp.Rcode = dns.RcodeSuccess
	}

	return resp
}

func (s *Server) forwardUpstream(req *dns.Msg) (*dns.Msg, string, error) {
	var lastErr error

	for _, upstream := range s.upstreams {
		c := &dns.Client{
			Net:     "udp",
			Timeout: 1500 * time.Millisecond,
		}

		resp, _, err := c.Exchange(req, upstream)
		if err == nil && resp != nil {
			// If upstream returned truncated UDP and request was over TCP or client allows, retry over TCP
			if resp.Truncated {
				tcpClient := &dns.Client{
					Net:     "tcp",
					Timeout: 2000 * time.Millisecond,
				}
				tcpResp, _, tcpErr := tcpClient.Exchange(req, upstream)
				if tcpErr == nil && tcpResp != nil {
					return tcpResp, upstream, nil
				}
			}
			return resp, upstream, nil
		}
		lastErr = err
	}

	return nil, "", lastErr
}

func (s *Server) calculateMinTTL(msg *dns.Msg) time.Duration {
	minTTL := uint32(3600)
	hasRecords := false

	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		hasRecords = true
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		hasRecords = true
	}

	if !hasRecords || minTTL == 0 {
		return 30 * time.Second
	}
	if minTTL < 5 {
		minTTL = 5
	}
	if minTTL > 86400 {
		minTTL = 86400
	}
	return time.Duration(minTTL) * time.Second
}

func (s *Server) adjustCachedTTLs(msg *dns.Msg, expiresAt time.Time) {
	remaining := time.Until(expiresAt)
	if remaining < 0 {
		remaining = 0
	}
	remSecs := uint32(remaining.Seconds())
	if remSecs == 0 {
		remSecs = 1
	}

	for _, rr := range msg.Answer {
		rr.Header().Ttl = remSecs
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = remSecs
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = remSecs
		}
	}
}

func (s *Server) getCache(key string) (CacheEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, found := s.cache[key]
	if !found {
		return CacheEntry{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		return CacheEntry{}, false
	}
	return entry, true
}

func (s *Server) putCache(key string, msg *dns.Msg, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.cache) >= s.maxCache {
		// Evict oldest 10%
		now := time.Now()
		count := 0
		for k, v := range s.cache {
			if now.After(v.ExpiresAt) || count < s.maxCache/10 {
				delete(s.cache, k)
				count++
			}
		}
	}

	s.cache[key] = CacheEntry{
		Msg:       msg.Copy(),
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}
}

func (s *Server) cacheCleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.cache {
				if now.After(v.ExpiresAt) {
					delete(s.cache, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) emitEvent(ev storage.DNSEvent) {
	select {
	case s.eventChan <- ev:
	default:
		// Queue full; do not block resolution
	}
}

func (s *Server) eventLoggerLoop() {
	for {
		select {
		case <-s.stopChan:
			return
		case ev := <-s.eventChan:
			if s.store != nil {
				_ = s.store.RecordDNSEvent(ev)
			}
		}
	}
}

// Status returns current runtime status, counters, and upstreams.
func (s *Server) Status() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	qTotal := atomic.LoadInt64(&s.queriesTotal)
	cHits := atomic.LoadInt64(&s.cacheHits)
	bTotal := atomic.LoadInt64(&s.blockedTotal)
	eTotal := atomic.LoadInt64(&s.errorsTotal)

	hitRatio := 0.0
	if qTotal > 0 {
		hitRatio = float64(cHits) / float64(qTotal)
	}

	return map[string]interface{}{
		"state":           string(s.state),
		"listen_addr":     s.listenAddr,
		"upstreams":       s.upstreams,
		"allow_rules":     len(s.allowlist),
		"block_rules":     len(s.blocklist),
		"cache_entries":   len(s.cache),
		"queries_total":   qTotal,
		"cache_hits":      cHits,
		"cache_hit_ratio": hitRatio,
		"blocked_total":   bTotal,
		"errors_total":    eTotal,
	}
}

// TestPolicy tests how a given domain resolves against current allow/block rules.
func (s *Server) TestPolicy(domain string) map[string]interface{} {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	isAllowed, isBlocked, reason := s.evaluateDomain(norm)

	verdict := "PERMIT"
	if isAllowed {
		verdict = "ALLOWLIST"
	} else if isBlocked {
		verdict = "BLOCK"
	}

	return map[string]interface{}{
		"domain":       norm,
		"verdict":      verdict,
		"is_allowed":   isAllowed,
		"is_blocked":   isBlocked,
		"block_reason": reason,
	}
}

// ValidateShadowListener starts a temporary shadow server on tempAddr, verifies resolution, and shuts down.
func ValidateShadowListener(tempAddr string, upstreams []string, testDomain string) error {
	srv := NewServer(tempAddr, upstreams, nil, nil)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start shadow listener on %s: %w", tempAddr, err)
	}
	defer srv.Stop()

	srv.mu.Lock()
	srv.blocklist["blocked.test"] = "Shadow verification block"
	srv.allowlist["allowed.test"] = true
	srv.updateStateLocked()
	srv.mu.Unlock()

	// Give listener a moment to settle
	time.Sleep(30 * time.Millisecond)

	// Query blocked domain
	c := &dns.Client{Timeout: 1 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("blocked.test.", dns.TypeA)
	resp, _, err := c.Exchange(m, tempAddr)
	if err != nil {
		return fmt.Errorf("shadow query to blocked domain failed: %w", err)
	}
	if len(resp.Answer) == 0 {
		return fmt.Errorf("shadow blocked domain returned no answer")
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		return fmt.Errorf("shadow blocked domain did not return 0.0.0.0, got: %v", resp.Answer[0])
	}

	return nil
}
