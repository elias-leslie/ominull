package storage

import (
	"encoding/json"
	"errors"
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
