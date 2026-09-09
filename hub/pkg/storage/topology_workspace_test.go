package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestTopologyWorkspaceKeepsIdentityDirectionAndEvidence(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	if err := s.UpsertAssetFromScan("10.0.4.2", "00:11:22:33:44:55", "", "client", "", "", "", 0, nil, now); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{TenantID: "default", EndpointID: "fixture", Timestamp: now, SrcIP: "10.0.4.2", DstIP: "2001:db8::9", Protocol: 6, DstPort: 443, ProcessPath: "/usr/bin/client", Domain: "api.example.invalid", BytesOut: 17},
		{TenantID: "default", EndpointID: "fixture", Timestamp: now, SrcIP: "2001:db8::9", DstIP: "10.0.4.2", Protocol: 6, DstPort: 8443, BytesOut: 23},
	} {
		if err := s.InsertEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.GetTopologyWorkspace(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 2 || len(g.Conversations) != 2 {
		t.Fatalf("missing fixture: %+v", g)
	}
	var id string
	for _, n := range g.Nodes {
		if n.IP == "10.0.4.2" {
			id = n.ID
			if id != n.AssetID || id == n.IP {
				t.Fatalf("unstable identity %+v", n)
			}
		}
	}
	if g.Edges[0].Source == g.Edges[1].Source {
		t.Fatal("opposite directions merged")
	}
	found := false
	for _, r := range g.Conversations {
		if r.Domain == "api.example.invalid" {
			found = true
			if r.Source != id || r.Process != "/usr/bin/client" || r.TotalBytes != 17 || r.DomainSource != "reported domain" {
				t.Fatalf("wrong evidence %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("domain lost")
	}
}

func TestTopologyViewsAreOwnedAndRevisionChecked(t *testing.T) {
	s := newTestStore(t)
	v := TopologyView{ID: "view-one", Name: "Investigate", State: json.RawMessage(`{"group":"network"}`)}
	saved, err := s.SaveTopologyView("operator-a", v)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 {
		t.Fatal(saved)
	}
	other, err := s.ListTopologyViews("operator-b")
	if err != nil || len(other) != 0 {
		t.Fatalf("owner leak %v %v", other, err)
	}
	if _, err = s.SaveTopologyView("operator-a", v); !errors.Is(err, ErrTopologyViewConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	v.Revision = 1
	v.Name = "Updated"
	if _, err = s.SaveTopologyView("operator-a", v); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTopologyView("operator-b", v.ID, 2); !errors.Is(err, ErrTopologyViewConflict) {
		t.Fatalf("other owner delete: %v", err)
	}
	got, _ := s.ListTopologyViews("operator-a")
	if len(got) != 1 || got[0].Name != "Updated" {
		t.Fatal(got)
	}
}

func TestTopologyViewRejectsNonObjectState(t *testing.T) {
	s := newTestStore(t)
	for _, raw := range []string{`null`, `[]`, `"text"`, `{"coverage":12}`, `{"activeOnly":"yes"}`, `{"positions":{"one":{"x":"bad","y":0}}}`} {
		if _, err := s.SaveTopologyView("owner", TopologyView{ID: "bad", Name: "Bad", State: json.RawMessage(raw)}); err == nil {
			t.Errorf("accepted invalid state %s", raw)
		}
	}
}

func TestTopologyGatewayRetainsAgentCoverage(t *testing.T) {
	n := assetNode(Asset{IP: "10.0.4.1", Role: "gateway", AgentEndpointID: "gateway-agent"}, map[string]Endpoint{}, map[string]bool{})
	if n.Type != "gateway" || n.EndpointID != "gateway-agent" {
		t.Fatalf("gateway agent evidence lost: %+v", n)
	}
}

func TestTopologyExplicitVirtualNetworkClassification(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetTopologyNetworks([]TopologyNetwork{{CIDR: "172.20.0.0/16", Label: "Container network", Kind: "virtual"}}); err != nil {
		t.Fatal(err)
	}
	nets, err := s.TopologyNetworks()
	if err != nil {
		t.Fatal(err)
	}
	node := TopologyNode{IP: "172.20.0.8"}
	describeTopologyNetwork(&node, nets)
	if node.NetworkKind != "virtual" {
		t.Fatalf("explicit classification lost: %+v", node)
	}
	node = TopologyNode{IP: "172.17.0.8"}
	describeTopologyNetwork(&node, nets)
	if node.NetworkKind != "" {
		t.Fatal("private range fabricated virtual classification")
	}
	if err := s.SetTopologyNetworks([]TopologyNetwork{{CIDR: "10.0.4.0/24", Kind: "guess"}}); err == nil {
		t.Fatal("invalid network kind accepted")
	}
}

func TestTopologyViewRegionValidation(t *testing.T) {
	for _, raw := range []string{`{"regions":"yes"}`, `{"regionOverrides":{"lan":"guess"}}`, `{"collapsedRegions":{"discovery":"yes"}}`} {
		if validTopologyViewState([]byte(raw)) {
			t.Errorf("invalid region state accepted: %s", raw)
		}
	}
}

func TestTopologyViewScopeValidation(t *testing.T) {
	for _, raw := range []string{`{"scope":{"kind":"guess","id":"a"}}`, `{"scope":{"kind":"host"}}`, `{"trail":"bad"}`, `{"trail":[{"trail":[{}]}]}`, `{"scopeLimit":-1}`} {
		if validTopologyViewState([]byte(raw)) {
			t.Errorf("invalid scope state accepted: %s", raw)
		}
	}
	if !validTopologyViewState([]byte(`{"scope":{"kind":"process","id":"a","process":"/bin/client"},"trail":[{"scope":null,"positions":{"a":{"x":12,"y":42}},"viewport":{"zoom":1,"pan":{"x":0,"y":0}}}]}`)) {
		t.Fatal("valid navigation state rejected")
	}
}

func TestWorkspaceGraphMatchesIndependentAggregation(t *testing.T) {
	s := newTestStore(t)
	at := time.Now().UTC().Add(-time.Minute)
	if err := s.UpsertAssetFromScan("10.0.0.2", "02:00:00:00:00:02", "", "fixture", "", "", "CRITICAL", 1, nil, at); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		action := "PERMIT"
		if i%7 == 0 {
			action = "BLOCK"
		}
		source, target := "10.0.0.2", "2001:db8::9"
		if i%3 == 0 {
			source, target = target, source
		}
		measured := int64(0)
		if i%2 == 0 {
			measured = int64(i + 1)
		}
		if err := s.InsertEvent(Event{TenantID: "fixture", EndpointID: "fixture", Timestamp: at.Add(time.Duration(i) * time.Millisecond), SrcIP: source, DstIP: target, Protocol: 6, DstPort: 443, ProcessPath: fmt.Sprintf("fixture-%d", i%5), Domain: fmt.Sprintf("host-%d.example.invalid", i%4), Action: action, BytesOut: measured}); err != nil {
			t.Fatal(err)
		}
	}
	to := time.Now().UTC()
	from := to.Add(-time.Hour)
	independent, err := s.topologyGraphBetween(from, to, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	var conversations []TopologyConversation
	shared, err := s.topologyGraphBetween(from, to, time.Hour, &conversations)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(independent, shared) {
		t.Fatalf("shared grouping changed graph:\nindependent=%+v\nshared=%+v", independent, shared)
	}
	for _, edge := range shared.Edges {
		if edge.Verdict != "blocked" || edge.Ports[0].Verdict != "blocked" {
			t.Fatal("blocked evidence lost", edge)
		}
	}
	var count, total int64
	for _, c := range conversations {
		count += c.FlowCount
		total += c.TotalBytes
	}
	if count != 120 || count != shared.Metrics.TotalFlowCount || total == 0 {
		t.Fatalf("evidence totals %d/%d graph %+v", count, total, shared.Metrics)
	}
}
