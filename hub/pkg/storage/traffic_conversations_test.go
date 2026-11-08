package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func conversationStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "conversations.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func convEvent(at time.Time, path, src string, sport int, dst string, dport int, action string) Event {
	return Event{
		Timestamp: at, TenantID: "default", EndpointID: "ep-1", Layer: "test", Action: action, Direction: "OUTBOUND", Protocol: 6,
		SrcIP: src, SrcPort: uint16(sport), DstIP: dst, DstPort: uint16(dport), ProcessPath: path,
		BytesIn: 100, BytesOut: 50, Country: "US",
	}
}

func findConversation(t *testing.T, rows []TrafficConversation, process, peer string) TrafficConversation {
	t.Helper()
	for _, c := range rows {
		if c.Process == process && c.PeerIP == peer {
			return c
		}
	}
	t.Fatalf("no conversation %s -> %s in %+v", process, peer, rows)
	return TrafficConversation{}
}

// One row per program, peer and service port, marked with what makes it worth
// a look: a finding about it, a peer first reached inside the window, blocked
// flows. A listener's replies fold into one inbound row on its service port.
func TestTrafficConversationsFoldAndMark(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	if err := store.UpsertEndpoint(Endpoint{ID: "ep-1", TenantID: "default", Hostname: "web-01", IP: "10.0.0.10", Status: "online"}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	batches := [][]Event{
		// Seen two days ago: curl to the update server is not new.
		{convEvent(old, "/usr/bin/curl", "10.0.0.10", 50000, "192.0.2.1", 443, "PERMIT")},
		{
			convEvent(now.Add(-10*time.Minute), "/usr/bin/curl", "10.0.0.10", 50001, "192.0.2.1", 443, "PERMIT"),
			convEvent(now.Add(-9*time.Minute), "/usr/bin/curl", "10.0.0.10", 50002, "192.0.2.1", 443, "PERMIT"),
			// First time ever: new.
			convEvent(now.Add(-8*time.Minute), "/usr/bin/python3", "10.0.0.10", 50003, "198.51.100.22", 443, "PERMIT"),
			// sshd answering two client sockets of one client: one inbound row on 22.
			convEvent(now.Add(-7*time.Minute), "/usr/sbin/sshd", "10.0.0.10", 22, "10.0.0.5", 50123, "PERMIT"),
			convEvent(now.Add(-6*time.Minute), "/usr/sbin/sshd", "10.0.0.10", 22, "10.0.0.5", 50124, "PERMIT"),
			// Blocked.
			convEvent(now.Add(-5*time.Minute), "/usr/bin/smbclient", "10.0.0.10", 50004, "203.0.113.9", 445, "BLOCK"),
		},
	}
	for _, b := range batches {
		if err := store.InsertTelemetryBatch(b, "web-01", ""); err != nil {
			t.Fatalf("InsertTelemetryBatch: %v", err)
		}
	}
	alerts := []AnomalyAlert{
		{ID: "f-open", TenantID: "default", EndpointID: "ep-1", AnomalyType: "C2_BEACONING", Severity: "HIGH", Title: "Beaconing",
			ProcessPath: "/usr/bin/python3", DstIP: "198.51.100.22", DstPort: 443, Timestamp: now.Add(-4 * time.Minute)},
		// Another program to the same peer: not this conversation's finding.
		{ID: "f-other", TenantID: "default", EndpointID: "ep-1", AnomalyType: "C2_BEACONING", Severity: "CRITICAL", Title: "Other program",
			ProcessPath: "/usr/bin/wget", DstIP: "198.51.100.22", DstPort: 443, Timestamp: now.Add(-4 * time.Minute)},
		// A recorded (held) finding on the curl row.
		{ID: "f-held", TenantID: "default", EndpointID: "ep-1", AnomalyType: "UNUSUAL_PORT", Severity: "LOW", Title: "Recorded",
			ProcessPath: "/usr/bin/curl", DstIP: "192.0.2.1", DstPort: 443, HeldReason: HeldHunt, Timestamp: now.Add(-3 * time.Minute)},
	}
	for _, a := range alerts {
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatalf("CreateAnomalyAlert: %v", err)
		}
	}

	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	if !res.NewKnown {
		t.Fatalf("profiles reach back two days; new must be known")
	}
	if got := len(res.Conversations); got != 4 {
		t.Fatalf("want 4 conversations, got %d: %+v", got, res.Conversations)
	}
	first := res.Conversations[0]
	if first.Process != "python3" || first.Findings == nil || first.Findings.Open != 1 || first.Findings.Count != 1 || first.Findings.IDs[0] != "f-open" {
		t.Fatalf("the open finding's conversation leads, with only its own finding: %+v %+v", first, first.Findings)
	}
	if !first.New || first.Hostname != "web-01" {
		t.Fatalf("python3 to a never-seen peer is new and named: %+v", first)
	}
	curl := findConversation(t, res.Conversations, "curl", "192.0.2.1")
	if curl.New || curl.Flows != 2 || curl.Findings == nil || curl.Findings.Open != 0 || curl.Findings.HeldReason != HeldHunt {
		t.Fatalf("curl: known peer, two flows in window, one held finding: %+v %+v", curl, curl.Findings)
	}
	ssh := findConversation(t, res.Conversations, "sshd", "10.0.0.5")
	if ssh.Direction != "in" || ssh.Port != 22 || ssh.Flows != 2 {
		t.Fatalf("served replies fold into one inbound row on 22: %+v", ssh)
	}
	smb := findConversation(t, res.Conversations, "smbclient", "203.0.113.9")
	if smb.Blocked != 1 || smb.Direction != "out" || smb.Port != 445 {
		t.Fatalf("blocked flow: %+v", smb)
	}
	c := res.Counts
	if c.All != 4 || c.Flagged != 2 || c.Open != 1 || c.New != 3 || c.Blocked != 1 || c.In != 1 || c.Out != 3 {
		// python3, sshd's client and smbclient were all first reached in the window.
		t.Fatalf("counts: %+v", c)
	}

	for _, tc := range []struct {
		q    ConversationQuery
		want int
	}{
		{ConversationQuery{Mark: "flagged"}, 2},
		{ConversationQuery{Mark: "blocked"}, 1},
		{ConversationQuery{Mark: "new", Direction: "out"}, 2},
		{ConversationQuery{Direction: "in"}, 1},
		{ConversationQuery{Search: "web-01"}, 4},
		{ConversationQuery{Search: "445"}, 1},
		{ConversationQuery{Search: "PYTHON"}, 1},
		{ConversationQuery{Limit: 2}, 2},
	} {
		r, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, tc.q)
		if err != nil {
			t.Fatalf("%+v: %v", tc.q, err)
		}
		if len(r.Conversations) != tc.want {
			t.Errorf("%+v: want %d rows, got %d", tc.q, tc.want, len(r.Conversations))
		}
		if tc.q.Limit == 2 && (!r.Truncated || r.Matching != 4) {
			t.Errorf("a capped list says it is truncated: %+v", r)
		}
	}
}

// Agents report this host's end as the source whichever way the packet went.
// A datagram received is usually the answer to this host's own query, so it
// joins the outbound row; one received on a service port is a client reaching
// the service, and the peer is that client, never this host.
func TestTrafficConversationsInboundUsesTheAgentLayout(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	udp := func(at time.Duration, path string, sport int, dst string, dport int, dir string) Event {
		e := convEvent(now.Add(at), path, "10.0.0.10", sport, dst, dport, "PERMIT")
		e.Protocol, e.Direction = 17, dir
		return e
	}
	batch := []Event{
		// systemd-resolved asks 10.0.0.1 and hears back.
		udp(-5*time.Minute, "/usr/lib/resolved", 45000, "10.0.0.1", 53, "OUTBOUND"),
		udp(-5*time.Minute, "/usr/lib/resolved", 45000, "10.0.0.1", 53, "INBOUND"),
		// dnsmasq answers two sockets of one client.
		udp(-4*time.Minute, "/usr/sbin/dnsmasq", 53, "10.0.0.7", 51000, "INBOUND"),
		udp(-3*time.Minute, "/usr/sbin/dnsmasq", 53, "10.0.0.7", 51001, "INBOUND"),
	}
	if err := store.InsertTelemetryBatch(batch, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	if len(res.Conversations) != 2 {
		t.Fatalf("want one row each for resolved and dnsmasq: %+v", res.Conversations)
	}
	resolved := findConversation(t, res.Conversations, "resolved", "10.0.0.1")
	if resolved.Direction != "out" || resolved.Port != 53 || resolved.Flows != 2 {
		t.Fatalf("query and answer are one outbound row on 53: %+v", resolved)
	}
	dnsmasq := findConversation(t, res.Conversations, "dnsmasq", "10.0.0.7")
	if dnsmasq.Direction != "in" || dnsmasq.Port != 53 || dnsmasq.Flows != 2 || dnsmasq.Proto != 17 {
		t.Fatalf("the client reaching the service is one inbound row on 53: %+v", dnsmasq)
	}
}

// A finding's port tells which row it is about: the service port of an outbound
// row, a client port of a served one.
func TestTrafficConversationFindingsMatchThePort(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	batch := []Event{
		convEvent(now.Add(-5*time.Minute), "/usr/sbin/nginx", "10.0.0.10", 443, "10.0.0.5", 50123, "PERMIT"),
		convEvent(now.Add(-5*time.Minute), "/usr/sbin/nginx", "10.0.0.10", 50200, "10.0.0.5", 8080, "PERMIT"),
	}
	if err := store.InsertTelemetryBatch(batch, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	finding := AnomalyAlert{ID: "f-out", TenantID: "default", EndpointID: "ep-1", AnomalyType: "UNUSUAL_PORT", Severity: "HIGH", Title: "Out",
		ProcessPath: "/usr/sbin/nginx", DstIP: "10.0.0.5", DstPort: 8080, Timestamp: now.Add(-4 * time.Minute)}
	if err := store.CreateAnomalyAlert(finding); err != nil {
		t.Fatalf("CreateAnomalyAlert: %v", err)
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	for _, c := range res.Conversations {
		if flagged := c.Findings != nil; flagged != (c.Direction == "out") {
			t.Errorf("only the outbound row to 8080 carries the finding: %+v %+v", c, c.Findings)
		}
	}
	finding.ID, finding.DstPort = "f-in", 50123
	if err := store.CreateAnomalyAlert(finding); err != nil {
		t.Fatalf("CreateAnomalyAlert: %v", err)
	}
	store.trafficConv = conversationCache{}
	if res, err = store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{Direction: "in"}); err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	if len(res.Conversations) != 1 || res.Conversations[0].Findings == nil || res.Conversations[0].Findings.IDs[0] != "f-in" {
		t.Fatalf("a finding on the client's port is about the served row: %+v", res.Conversations)
	}
}

// The order is applied before the cut, and a limit over the cap is the cap.
func TestTrafficConversationsSortAndLimit(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	loud := convEvent(now.Add(-30*time.Minute), "/usr/bin/rsync", "10.0.0.10", 50001, "192.0.2.1", 443, "PERMIT")
	loud.BytesIn = 1 << 30
	recent := convEvent(now.Add(-1*time.Minute), "/usr/bin/curl", "10.0.0.10", 50002, "192.0.2.2", 443, "PERMIT")
	blocked := convEvent(now.Add(-20*time.Minute), "/usr/bin/nc", "10.0.0.10", 50003, "192.0.2.3", 445, "BLOCK")
	if err := store.InsertTelemetryBatch([]Event{loud, recent, blocked}, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	for by, want := range map[string]string{"": "nc", "volume": "rsync", "recent": "curl"} {
		res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{Sort: by, Limit: 1})
		if err != nil {
			t.Fatalf("%q: %v", by, err)
		}
		if len(res.Conversations) != 1 || res.Conversations[0].Process != want || res.Matching != 3 || !res.Truncated {
			t.Errorf("sort %q: want %s first of 3, got %+v", by, want, res)
		}
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{Limit: MaxConversations + 200})
	if err != nil {
		t.Fatalf("over the cap: %v", err)
	}
	if len(res.Conversations) != 3 {
		t.Fatalf("a limit over the cap must not shrink the list: %d rows", len(res.Conversations))
	}
}

// A host enrolled inside the window has no history before it: its peers are
// not new even though the fleet's history reaches back.
func TestTrafficConversationsNewIsPerHost(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	if err := store.InsertTelemetryBatch([]Event{convEvent(now.Add(-48*time.Hour), "/usr/bin/curl", "10.0.0.10", 50001, "192.0.2.1", 443, "PERMIT")}, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	veteran := convEvent(now.Add(-5*time.Minute), "/usr/bin/python3", "10.0.0.10", 50002, "192.0.2.9", 443, "PERMIT")
	newcomer := convEvent(now.Add(-5*time.Minute), "/usr/bin/python3", "10.0.0.20", 50003, "192.0.2.9", 443, "PERMIT")
	newcomer.EndpointID = "ep-2"
	if err := store.InsertTelemetryBatch([]Event{veteran, newcomer}, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	if !res.NewKnown {
		t.Fatalf("the fleet's history reaches back: %+v", res)
	}
	for _, c := range res.Conversations {
		if want := c.EndpointID == "ep-1"; c.New != want {
			t.Errorf("%s: new=%v, want %v", c.EndpointID, c.New, want)
		}
	}
}

// A hub that started recording inside the window cannot call anything new:
// every peer would be "first seen" only because nothing earlier was kept.
func TestTrafficConversationsNewNeedsHistory(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC()
	if err := store.InsertTelemetryBatch([]Event{convEvent(now.Add(-5*time.Minute), "/usr/bin/curl", "10.0.0.10", 50001, "192.0.2.1", 443, "PERMIT")}, "web-01", ""); err != nil {
		t.Fatalf("InsertTelemetryBatch: %v", err)
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{TenantID: "default", Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatalf("QueryTrafficConversations: %v", err)
	}
	if res.NewKnown || res.Counts.New != 0 || len(res.Conversations) != 1 || res.Conversations[0].New {
		t.Fatalf("no history before the window: nothing is new: %+v", res)
	}
	if res.Conversations[0].KnownSince == nil || res.LatestFlow == nil {
		t.Fatalf("known-since and latest flow are reported: %+v", res)
	}
}
