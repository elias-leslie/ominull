package dns

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

type recordingResponseWriter struct {
	remote net.Addr
	msg    *mdns.Msg
}

func newRecordingResponseWriter(network string) *recordingResponseWriter {
	if network == "tcp" {
		return &recordingResponseWriter{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53000}}
	}
	return &recordingResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53000}}
}

func (w *recordingResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}
}

func (w *recordingResponseWriter) RemoteAddr() net.Addr { return w.remote }

func (w *recordingResponseWriter) WriteMsg(msg *mdns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *recordingResponseWriter) Write(raw []byte) (int, error) { return len(raw), nil }
func (w *recordingResponseWriter) Close() error                  { return nil }
func (w *recordingResponseWriter) TsigStatus() error             { return nil }
func (w *recordingResponseWriter) TsigTimersOnly(bool)           {}
func (w *recordingResponseWriter) Hijack()                       {}

func startTestUpstream(t *testing.T, handler mdns.Handler) string {
	t.Helper()

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake DNS upstream: %v", err)
	}
	listenAddr := packetConn.LocalAddr().String()
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("listen for fake TCP DNS upstream: %v", err)
	}
	udpServer := &mdns.Server{
		PacketConn: packetConn,
		Handler:    handler,
		UDPSize:    mdns.MaxMsgSize,
	}
	tcpServer := &mdns.Server{
		Listener: listener,
		Handler:  handler,
	}
	go func() {
		_ = udpServer.ActivateAndServe()
	}()
	go func() {
		_ = tcpServer.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return listenAddr
}

func exchangeThroughHandler(t *testing.T, server *Server, req *mdns.Msg, network string) *mdns.Msg {
	t.Helper()

	w := newRecordingResponseWriter(network)
	server.handleDNSQuery(w, req)
	if w.msg == nil {
		t.Fatal("DNS handler wrote no response")
	}
	return w.msg
}

func largeTXTResponse(req *mdns.Msg) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	for i := 0; i < 80; i++ {
		resp.Answer = append(resp.Answer, &mdns.TXT{
			Hdr: mdns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: mdns.TypeTXT,
				Class:  req.Question[0].Qclass,
				Ttl:    300,
			},
			Txt: []string{fmt.Sprintf("record-%02d-%s", i, strings.Repeat("x", 72))},
		})
	}
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
	return resp
}

func writeUpstreamResponse(w mdns.ResponseWriter, req, resp *mdns.Msg) {
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		limit := mdns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			limit = int(opt.UDPSize())
		}
		resp.Truncate(limit)
	}
	_ = w.WriteMsg(resp)
}

func packedLen(t *testing.T, msg *mdns.Msg) int {
	t.Helper()
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS response: %v", err)
	}
	return len(raw)
}

func TestLegacyUDPResponseIsTruncatedOnCacheMissAndHit(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		writeUpstreamResponse(w, req, largeTXTResponse(req))
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	for i, phase := range []string{"miss", "hit"} {
		req := new(mdns.Msg)
		req.SetQuestion("legacy-device.example.", mdns.TypeTXT)
		req.Id = uint16(100 + i)
		resp := exchangeThroughHandler(t, server, req, "udp")
		if got := packedLen(t, resp); got > mdns.MinMsgSize {
			t.Errorf("%s response is %d bytes; non-EDNS UDP limit is %d", phase, got, mdns.MinMsgSize)
		}
		if !resp.Truncated {
			t.Errorf("%s response omitted no records and did not set TC", phase)
		}
		if resp.IsEdns0() != nil {
			t.Errorf("%s response added an OPT record for a non-EDNS client", phase)
		}
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d; want one UDP/TCP miss followed by one cache hit", got)
	}
}

func TestEDNSUDPResponseRespectsSafeAndAdvertisedLimits(t *testing.T) {
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		writeUpstreamResponse(w, req, largeTXTResponse(req))
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	for _, tc := range []struct {
		name       string
		advertised uint16
		wantMax    int
	}{
		{name: "large client buffer is capped", advertised: 4096, wantMax: 1232},
		{name: "smaller client buffer is honored", advertised: 700, wantMax: 700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := new(mdns.Msg)
			req.SetQuestion(tc.name+".example.", mdns.TypeTXT)
			req.SetEdns0(tc.advertised, false)
			resp := exchangeThroughHandler(t, server, req, "udp")
			if got := packedLen(t, resp); got > tc.wantMax {
				t.Errorf("response is %d bytes; negotiated safe limit is %d", got, tc.wantMax)
			}
			if !resp.Truncated {
				t.Error("oversized response did not set TC")
			}
			if opt := resp.IsEdns0(); opt == nil || opt.UDPSize() != uint16(tc.wantMax) {
				t.Errorf("response OPT = %v; want server response size %d", opt, tc.wantMax)
			}
		})
	}
}

func TestTCPResponseIsNotUDPTruncated(t *testing.T) {
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		writeUpstreamResponse(w, req, largeTXTResponse(req))
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	req := new(mdns.Msg)
	req.SetQuestion("tcp-client.example.", mdns.TypeTXT)
	resp := exchangeThroughHandler(t, server, req, "tcp")
	if resp.Truncated {
		t.Fatal("TCP response was marked truncated")
	}
	if got := packedLen(t, resp); got <= 1232 {
		t.Fatalf("test response is only %d bytes; it does not prove TCP avoided the UDP limit", got)
	}
}

func TestCacheSeparatesDNSSECStateAndQueryClass(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		opt := req.IsEdns0()
		do := opt != nil && opt.Do()
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.TXT{
			Hdr: mdns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: mdns.TypeTXT,
				Class:  req.Question[0].Qclass,
				Ttl:    300,
			},
			Txt: []string{fmt.Sprintf("class=%d do=%t", req.Question[0].Qclass, do)},
		}}
		if opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
		_ = w.WriteMsg(resp)
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	requests := []*mdns.Msg{new(mdns.Msg), new(mdns.Msg), new(mdns.Msg)}
	requests[0].SetQuestion("cache-profile.example.", mdns.TypeTXT)
	requests[1].SetQuestion("cache-profile.example.", mdns.TypeTXT)
	requests[1].SetEdns0(1232, true)
	requests[2].SetQuestion("cache-profile.example.", mdns.TypeTXT)
	requests[2].Question[0].Qclass = mdns.ClassCHAOS

	want := []string{"class=1 do=false", "class=1 do=true", "class=3 do=false"}
	for i, req := range requests {
		resp := exchangeThroughHandler(t, server, req, "udp")
		txt, ok := resp.Answer[0].(*mdns.TXT)
		if !ok || len(txt.Txt) != 1 || txt.Txt[0] != want[i] {
			t.Fatalf("response %d = %v; want %q", i, resp.Answer, want[i])
		}
	}
	if got := upstreamCalls.Load(); got != 3 {
		t.Fatalf("upstream calls = %d; DO state and query class need distinct cache entries", got)
	}
}

func TestEDNSCacheEntryIsCleanedForLegacyClient(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.80"),
		}}
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
		_ = w.WriteMsg(resp)
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	ednsReq := new(mdns.Msg)
	ednsReq.SetQuestion("mixed-clients.example.", mdns.TypeA)
	ednsReq.SetEdns0(1232, false)
	if resp := exchangeThroughHandler(t, server, ednsReq, "udp"); resp.IsEdns0() == nil {
		t.Fatal("EDNS client did not receive an OPT record")
	}

	legacyReq := new(mdns.Msg)
	legacyReq.SetQuestion("mixed-clients.example.", mdns.TypeA)
	if resp := exchangeThroughHandler(t, server, legacyReq, "udp"); resp.IsEdns0() != nil {
		t.Fatal("legacy client received the cached EDNS OPT record")
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d; EDNS size alone should not split the cache", got)
	}
}

func TestCacheHitUsesCurrentRequestIdentity(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.81"),
		}}
		_ = w.WriteMsg(resp)
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	first := new(mdns.Msg)
	first.SetQuestion("Cache-Identity.example.", mdns.TypeA)
	first.Id = 101
	exchangeThroughHandler(t, server, first, "udp")

	second := new(mdns.Msg)
	second.SetQuestion("cache-identity.example.", mdns.TypeA)
	second.Id = 202
	resp := exchangeThroughHandler(t, server, second, "udp")
	if resp.Id != second.Id {
		t.Fatalf("cache-hit response ID = %d; want current request ID %d", resp.Id, second.Id)
	}
	if len(resp.Question) != 1 || resp.Question[0] != second.Question[0] {
		t.Fatalf("cache-hit question = %v; want current request question %v", resp.Question, second.Question)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d; want one miss followed by one cache hit", got)
	}
}

func TestEDNSOptionsBypassSharedCache(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		call := upstreamCalls.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.TXT{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
			Txt: []string{fmt.Sprintf("upstream-call=%d", call)},
		}}
		_ = w.WriteMsg(resp)
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	for i := 0; i < 2; i++ {
		req := new(mdns.Msg)
		req.SetQuestion("option-state.example.", mdns.TypeTXT)
		req.SetEdns0(1232, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, &mdns.EDNS0_NSID{Code: mdns.EDNS0NSID})
		exchangeThroughHandler(t, server, req, "udp")
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d; EDNS option requests must bypass shared cache", got)
	}
	if len(server.cache) != 0 {
		t.Fatalf("EDNS option requests created %d shared cache entries", len(server.cache))
	}
}

func TestMultipleQuestionsAreRejectedBeforeForwarding(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := startTestUpstream(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	}))
	server := NewServer("disabled", []string{upstream}, nil, nil)

	req := new(mdns.Msg)
	req.Question = []mdns.Question{
		{Name: "first.example.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
		{Name: "second.example.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
	}
	resp := exchangeThroughHandler(t, server, req, "udp")
	if resp.Rcode != mdns.RcodeFormatError {
		t.Fatalf("rcode = %s; want FORMERR", mdns.RcodeToString[resp.Rcode])
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("malformed query reached upstream %d time(s)", got)
	}
	if len(server.cache) != 0 {
		t.Fatalf("malformed query created %d cache entries", len(server.cache))
	}
}
