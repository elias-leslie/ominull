package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// Hunt leads stay out of every paging surface - the open list, the counts and
// the alert summary - and are one filter away, in their own finding.
func TestHuntLeadsNeverPage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ws", TenantID: "t-01", Hostname: "ws", RoleTag: "workstation", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	for i, a := range []storage.AnomalyAlert{
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", HeldReason: storage.HeldHunt},
		{Severity: "LOW", AnomalyType: "NOVEL_DESTINATION", HeldReason: storage.HeldHunt, Evidence: `{"muted":"agent_heavy","detector_severity":"MEDIUM"}`},
		{Severity: "HIGH", AnomalyType: "OFF_HOURS_ACTIVITY", HeldReason: storage.HeldHunt},
		{Severity: "CRITICAL", AnomalyType: "LATERAL_PORT_SWEEP"},
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", HeldReason: storage.HeldLearning},
	} {
		a.ID = "t" + string(rune('0'+i))
		a.TenantID, a.EndpointID, a.Hostname, a.Title, a.Timestamp = "t-01", "ws", "ws", "t", now.Add(-time.Hour)
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}

	list := func(q string) map[string]any {
		w := feedRequest(srv, http.MethodGet, "/api/v1/anomalies"+q, "mock_admin_token")
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v %s", q, err, w.Body.String())
		}
		return body
	}
	open := list("?limit=50")
	if open["total"].(float64) != 1 || open["unacknowledged_total"].(float64) != 1 || open["hunt_total"].(float64) != 3 || open["held_total"].(float64) != 1 {
		t.Fatalf("open view = total %v unack %v hunt %v held %v; want 1, 1, 3, 1", open["total"], open["unacknowledged_total"], open["hunt_total"], open["held_total"])
	}
	if hunt := list("?held=hunt"); hunt["total"].(float64) != 3 {
		t.Fatalf("hunt view = %v, want the 3 hunt leads", hunt["total"])
	}
	if held := list("?held=true"); held["total"].(float64) != 1 {
		t.Fatalf("held view = %v, want only the learning-held finding", held["total"])
	}

	var doc struct {
		Findings []struct {
			SeverityID  int            `json:"severity_id"`
			StatusID    int            `json:"status_id"`
			Message     string         `json:"message"`
			FindingInfo map[string]any `json:"finding_info"`
			Unmapped    map[string]any `json:"unmapped"`
		} `json:"findings"`
	}
	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("findings = %v", err)
	}
	seen := 0
	for _, f := range doc.Findings {
		switch f.FindingInfo["uid"] {
		case "ominull.anomalies.summary":
			seen++
			if by := f.Unmapped["by_type"].(map[string]any); len(by) != 1 || by["LATERAL_PORT_SWEEP"] != 1.0 {
				t.Fatalf("summary counts hunt leads: %v", by)
			}
		case "ominull.anomalies.hunt":
			seen++
			if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusNew || f.Unmapped["muted_agent_heavy"] != 1.0 ||
				!strings.HasPrefix(f.Message, "3 findings recorded in the last 24 h, kept for the record") {
				t.Fatalf("hunt finding = sev %d status %d %q %v", f.SeverityID, f.StatusID, f.Message, f.Unmapped)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("summary and hunt findings: saw %d", seen)
	}
}

func TestTuningSaveKeepsAgentHeavyLists(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	cfg := store.GetDetectionTuning()
	cfg.AgentHeavyEndpoints = []string{"Linux-WS"}
	cfg.AgentHeavyRoles = []string{"agent-host"}
	cfg.AgentHeavyObserved = false
	if _, err := store.SaveDetectionTuning(cfg, "test"); err != nil {
		t.Fatal(err)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"off_hours_start": 23}`); code != http.StatusOK {
		t.Fatalf("save = %d %v", code, body)
	}
	got := store.GetDetectionTuning()
	if len(got.AgentHeavyEndpoints) != 1 || got.AgentHeavyEndpoints[0] != "linux-ws" || len(got.AgentHeavyRoles) != 1 || got.AgentHeavyObserved {
		t.Fatalf("agent-heavy lists after a partial save = %v %v", got.AgentHeavyEndpoints, got.AgentHeavyRoles)
	}
	if !got.IsAgentHeavy(storage.Endpoint{ID: "linux-ws"}) || !got.IsAgentHeavy(storage.Endpoint{ID: "x", RoleTag: "Agent-Host"}) ||
		got.IsAgentHeavy(storage.Endpoint{ID: "other", RoleTag: "workstation"}) {
		t.Fatal("IsAgentHeavy matches the wrong endpoints")
	}
}
