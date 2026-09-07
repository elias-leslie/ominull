package storage

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTopologyLocalAddressesAreNotExternalThreats(t *testing.T) {
	s := newTestStore(t)
	for _, ip := range []string{"fd12:3456::9", "fe80::9", "100.64.0.9", "172.31.0.9"} {
		if err := s.InsertEvent(Event{TenantID: "default", EndpointID: "test-host", Timestamp: time.Now().UTC(), SrcIP: "10.0.4.2", DstIP: ip, Action: "BLOCK", Protocol: 6}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 5 || len(g.Edges) != 4 {
		t.Fatalf("fixture missing: nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}
	for _, n := range g.Nodes {
		if n.Type == "cloud" || n.Type == "threat" || n.Risk == "CRITICAL" || n.Group == "External" {
			t.Errorf("local address classified as external threat: %+v", n)
		}
	}
}

func TestTrafficWindowTotalsRankingsAndDistributionsAgree(t *testing.T) {
	s := newTestStore(t)
	start := time.Date(2025, 1, 2, 10, 30, 0, 0, time.UTC)
	end := start.Add(7 * time.Hour)
	for _, at := range []time.Time{start.Add(-time.Minute), start.Add(time.Hour), end.Add(time.Minute)} {
		if err := s.InsertTelemetryBatch([]Event{{TenantID: "default", EndpointID: "test-host", Timestamp: at, SrcIP: "10.0.4.2", DstIP: "198.51.100.9", Protocol: 6, Action: "PERMIT", Direction: "OUTBOUND", ProcessPath: "/usr/bin/test-client", BytesOut: 20}}, "test-host", "test-site"); err != nil {
			t.Fatal(err)
		}
	}
	o, err := s.QueryTrafficOverview(TrafficFilter{TenantID: "default", From: start, To: end})
	if err != nil {
		t.Fatal(err)
	}
	if o.TotalFlows != 1 || o.Totals.TotalBytes != 20 {
		t.Errorf("wrong totals: %+v", o.Totals)
	}
	if len(o.Rankings.TopProcesses) != 1 || o.Rankings.TopProcesses[0].TotalBytes != 20 || o.Rankings.TopProcesses[0].FlowCount != 1 {
		t.Errorf("ranking uses lifetime history: %+v", o.Rankings.TopProcesses)
	}
	if len(o.Distributions.Protocols) != 1 || o.Distributions.Protocols[0].Count != 1 || o.Distributions.Protocols[0].Percentage != 1 {
		t.Errorf("protocol distribution uses a different window: %+v", o.Distributions.Protocols)
	}
	var count int64
	for _, b := range o.Trends {
		count += b.Flows
	}
	if count != 1 {
		t.Errorf("trend includes %d events, want 1", count)
	}
}

func TestTopologyWindowDoesNotIncludeEarlierDailyTotals(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	dayStart := now.Truncate(24 * time.Hour)
	window := now.Sub(dayStart) / 2
	if window < time.Second {
		t.Skip("midnight boundary has no earlier same-day fixture")
	}
	for _, ev := range []Event{
		{TenantID: "default", EndpointID: "test-host", Timestamp: dayStart, SrcIP: "10.0.4.2", DstIP: "198.51.100.9", Protocol: 6, Action: "PERMIT", BytesOut: 1000},
		{TenantID: "default", EndpointID: "test-host", Timestamp: now, SrcIP: "10.0.4.2", DstIP: "198.51.100.9", Protocol: 6, Action: "PERMIT", BytesOut: 10},
	} {
		if err := s.InsertEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyGraph(window)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("fixture missing: %d edges", len(g.Edges))
	}
	if g.Edges[0].TotalBytes != 10 || g.Edges[0].FlowCount != 1 {
		t.Errorf("daily history leaked into window: %+v", g.Edges[0])
	}
}

func TestTopologyReportsEstateAndAddressScopeSeparately(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetSetting("topology.networks", `[{"cidr":"2001:db8:4::/64","label":"Lab segment"}]`); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAssetFromScan("2001:db8:9::2", "", "", "known-host", "", "", "", 0, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"2001:db8:4::2", "2001:db8:8::2", "fd12::2"} {
		if err := s.InsertEvent(Event{TenantID: "default", EndpointID: "test-host", Timestamp: time.Now().UTC(), SrcIP: "10.0.4.2", DstIP: ip, Action: "PERMIT", Protocol: 6}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(g.Nodes)
	var nodes []map[string]interface{}
	if err := json.Unmarshal(b, &nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 5 {
		t.Fatalf("fixture missing: %d nodes", len(nodes))
	}
	for _, n := range nodes {
		switch n["ip"] {
		case "2001:db8:4::2":
			if n["estate_member"] != true || n["network_label"] != "Lab segment" || n["address_scope"] != "public" {
				t.Errorf("configured global segment lost: %+v", n)
			}
		case "2001:db8:9::2":
			if n["estate_member"] != true {
				t.Errorf("known global asset marked external: %+v", n)
			}
		case "2001:db8:8::2":
			if n["estate_member"] != false || n["network_label"] != "Internet" {
				t.Errorf("unknown global peer not external: %+v", n)
			}
		case "fd12::2":
			if n["address_scope"] != "private" || n["estate_member"] != false || n["network_label"] == "Internet" {
				t.Errorf("local scope was mistaken for membership: %+v", n)
			}
		}
	}
}

func TestRouterTalkersKeepPublicIPv6AndExcludeLocalDestinations(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	var flows []RouterFlow
	for _, ip := range []string{"fd12::9", "fe80::9", "ff02::1", "::1", "100.64.0.9", "2001:db8::9"} {
		flows = append(flows, RouterFlow{SrcIP: "10.0.4.2", DstIP: ip, DstPort: 443, Protocol: "tcp", OrigBytes: 10})
	}
	a, r, err := s.RecordRouterFlows("test-router", flows, now)
	if err != nil {
		t.Fatal(err)
	}
	if a != 6 || r != 0 {
		t.Fatalf("fixture not ingested: %d accepted, %d rejected", a, r)
	}
	talkers, err := s.SummariseRouterTalkers(now.Add(-time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(talkers) != 1 || talkers[0].Conversations != 1 || len(talkers[0].Destinations) != 1 || talkers[0].Destinations[0] != "2001:db8::9" {
		t.Errorf("external summary includes local traffic or loses public IPv6: %+v", talkers)
	}
}

func TestEventWritesCanonicalizeAddressesBeforeProjection(t *testing.T) {
	s := newTestStore(t)
	ev := Event{TenantID: "default", EndpointID: "test-host", Timestamp: time.Now().UTC(), SrcIP: "::ffff:10.0.4.2", DstIP: "2001:0DB8:0:0:0:0:0:9", Action: "PERMIT", Protocol: 6}
	if err := s.InsertEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEventsBatch([]Event{ev}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListEvents("default", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("fixture missing: %d events", len(events))
	}
	for _, got := range events {
		if got.SrcIP != "10.0.4.2" || got.DstIP != "2001:db8::9" {
			t.Errorf("noncanonical observation: %s -> %s", got.SrcIP, got.DstIP)
		}
	}
}

func TestDiscoveryCanonicalAddressesHaveDistinctStableIdentities(t *testing.T) {
	s := newTestStore(t)
	for _, ip := range []string{"2001:0db8::1", "2001:db8::1", "2001:d:b8::1", "fe80::1%eth0", "fe80::1%eth1"} {
		if err := s.UpsertAssetFromScan(ip, "", "", "", "", "", "", 0, nil, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	assets, err := s.ListAssets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 4 {
		t.Fatalf("want 4 assets (equivalent spellings merge; distinct addresses/scopes never merge), got %+v", assets)
	}
	seen := map[string]bool{}
	for _, a := range assets {
		seen[a.IP] = true
	}
	for _, ip := range []string{"2001:db8::1", "2001:d:b8::1", "fe80::1%eth0", "fe80::1%eth1"} {
		if !seen[ip] {
			t.Errorf("canonical address missing: %s", ip)
		}
	}
}

func TestTopologySeparatesBlockingFromThreatAndNamesRealProtocol(t *testing.T) {
	s := newTestStore(t)
	for i, proto := range []uint8{58, 132} {
		if err := s.InsertEvent(Event{TenantID: "default", EndpointID: "test-host", Timestamp: time.Now().UTC(), SrcIP: "10.0.4.2", DstIP: []string{"2001:db8::9", "198.51.100.9"}[i], Action: "BLOCK", Protocol: proto}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("fixture missing: %+v", g)
	}
	if g.Metrics.AnomalousEdgeCount != 0 {
		t.Errorf("policy blocks counted as anomalies: %d", g.Metrics.AnomalousEdgeCount)
	}
	for _, n := range g.Nodes {
		if n.Risk == "CRITICAL" || n.Type == "threat" {
			t.Errorf("block invented a threat: %+v", n)
		}
	}
	for _, e := range g.Edges {
		want := "ICMPv6"
		if e.Target == "198.51.100.9" {
			want = "IP/132"
		}
		if e.Protocol != want || e.Verdict != "blocked" {
			t.Errorf("edge = %+v, want %s blocked", e, want)
		}
	}
}

func TestTopologyDoesNotInferGatewayOrRiskFromAddressAndContainment(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertAssetFromScan("10.0.4.1", "", "", "host-one", "", "workstation", "LOW", 1, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(Endpoint{ID: "isolated-test", TenantID: "default", IP: "10.0.4.2", IsIsolated: true}); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("missing fixture: %d", len(g.Nodes))
	}
	for _, n := range g.Nodes {
		if n.IP == "10.0.4.1" && n.Type == "gateway" {
			t.Error("last octet invented gateway")
		}
		if n.IP == "10.0.4.2" && (!n.IsIsolated || n.Risk == "CRITICAL") {
			t.Errorf("containment confused with threat: %+v", n)
		}
	}
}

func TestTrafficOverviewDoesNotReportFailedAnomalyQueryAsZero(t *testing.T) {
	s := newTestStore(t)
	// Simulate an unavailable projection in an isolated test database.
	if _, err := s.DB().Exec(`ALTER TABLE anomaly_alerts RENAME TO unavailable_anomaly_alerts`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryTrafficOverview(TrafficFilter{}); err == nil {
		t.Fatal("failed anomaly query reported a successful zero")
	}
}

func TestTrafficDomainRankingUsesFilteredFlowEvidence(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	if err := s.InsertEvent(Event{EndpointID: "test-host", Timestamp: now, ProcessPath: "/test/client", SrcIP: "10.0.4.2", DstIP: "2001:db8::9", Domain: "flow.example.test", BytesOut: 20, Protocol: 6}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDNSEvent(DNSEvent{Timestamp: now, Domain: "unrelated.example.test"}); err != nil {
		t.Fatal(err)
	}
	overview, err := s.QueryTrafficOverview(TrafficFilter{Process: "/test/client"})
	if err != nil {
		t.Fatal(err)
	}
	domains := overview.Rankings.TopDomains
	if len(domains) != 1 || domains[0].Key != "flow.example.test" || domains[0].TotalBytes != 20 {
		t.Errorf("unrelated DNS queries replaced flow ranking: %+v", domains)
	}
}

func TestTrafficOverviewRejectsUnavailableDistribution(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.DB().Exec(`ALTER TABLE events RENAME COLUMN protocol TO unavailable_protocol`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryTrafficOverview(TrafficFilter{}); err == nil {
		t.Fatal("failed distribution reported as empty success")
	}
}

func TestTrafficOverviewRejectsUnavailableRanking(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.DB().Exec(`ALTER TABLE events RENAME COLUMN process_path TO unavailable_process_path`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryTrafficOverview(TrafficFilter{}); err == nil {
		t.Fatal("failed ranking reported as empty success")
	}
}

func TestEventTimeZonesDoNotChangeWindowMembership(t *testing.T) {
	for _, path := range []string{"single", "batch", "telemetry"} {
		t.Run(path, func(t *testing.T) {
			s := newTestStore(t)
			now := time.Now().UTC()
			ev := Event{TenantID: "default", EndpointID: "test-host", Timestamp: now.Add(-time.Minute).In(time.FixedZone("test-offset", 2*60*60)), SrcIP: "10.0.4.2", DstIP: "2001:db8::9", Protocol: 6, BytesOut: 20}
			var err error
			switch path {
			case "single":
				err = s.InsertEvent(ev)
			case "batch":
				err = s.InsertEventsBatch([]Event{ev})
			case "telemetry":
				err = s.InsertTelemetryBatch([]Event{ev}, "", "")
			}
			if err != nil {
				t.Fatal(err)
			}
			overview, err := s.QueryTrafficOverview(TrafficFilter{From: now.Add(-time.Hour), To: now})
			if err != nil {
				t.Fatal(err)
			}
			if overview.TotalFlows != 1 || overview.Totals.TotalBytes != 20 {
				t.Errorf("timezone changed membership: flows=%d bytes=%d", overview.TotalFlows, overview.Totals.TotalBytes)
			}
		})
	}
}

func TestDiurnalProfileIncludesPartialBoundaryHour(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	remaining := from.Truncate(time.Hour).Add(time.Hour).Sub(from)
	if remaining < time.Second {
		t.Skip("boundary fixture needs at least a second inside the partial hour")
	}
	at := from.Add(remaining / 2)
	if err := s.InsertEvent(Event{TenantID: "default", EndpointID: "test-host", Timestamp: at, SrcIP: "10.0.4.2", DstIP: "2001:db8::9", Protocol: 6}); err != nil {
		t.Fatal(err)
	}
	_, live, err := s.GetDiurnalProfiles("default")
	if err != nil {
		t.Fatal(err)
	}
	if live[at.Hour()] != 1 {
		t.Errorf("partial hour observation missing: %+v", live)
	}
}

func TestRouterTalkersExcludeConfiguredAndKnownPublicEstateAddresses(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	if err := s.SetTopologyNetworks([]TopologyNetwork{{CIDR: "2001:db8:4::/64", Label: "Lab"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAssetFromScan("2001:db8:5::2", "", "", "known-host", "", "", "", 0, nil, now); err != nil {
		t.Fatal(err)
	}
	var flows []RouterFlow
	for _, ip := range []string{"2001:db8:4::2", "2001:db8:5::2", "2001:db8:6::2"} {
		flows = append(flows, RouterFlow{SrcIP: "10.0.4.2", DstIP: ip, DstPort: 443, Protocol: "tcp", OrigBytes: 10})
	}
	if accepted, _, err := s.RecordRouterFlows("test-gateway", flows, now); err != nil || accepted != 3 {
		t.Fatalf("fixture: accepted=%d err=%v", accepted, err)
	}
	got, err := s.SummariseRouterTalkers(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Destinations) != 1 || got[0].Destinations[0] != "2001:db8:6::2" {
		t.Errorf("estate traffic reported as external: %+v", got)
	}
}

func TestTopologyScopeGroupsRetainAddressFamily(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	for _, ip := range []string{"169.254.1.2", "fe80::2"} {
		if err := s.InsertEvent(Event{Timestamp: now, SrcIP: "10.0.4.2", DstIP: ip, Protocol: 6}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	count := 0
	for _, n := range g.Nodes {
		if n.AddressScope == "link-local" {
			ids[n.NetworkID] = true
			count++
		}
	}
	if count != 2 || len(ids) != 2 {
		t.Errorf("IPv4 and IPv6 share a mislabeled group: %+v", g.Nodes)
	}
}
