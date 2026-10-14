package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The storage report is hub-wide: a hub operator reads it, a tenant key does
// not, and the Nightshift feed carries it as one "Data per endpoint" finding
// that is informational within budget and a warning over it.
func TestStorageReportAndFeedFinding(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	// Before the first retention sweep there is nothing to report.
	if w := feedRequest(srv, http.MethodGet, "/api/v1/storage/report", "mock_admin_token"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"pending":true`) {
		t.Fatalf("report before a sweep = %d %s", w.Code, w.Body.String())
	}

	at := time.Now().UTC().Add(-24 * time.Hour)
	var evs []storage.Event
	for i := 0; i < 20; i++ {
		evs = append(evs, storage.Event{TenantID: "t-01", EndpointID: "e1", Timestamp: at.Add(time.Duration(i) * time.Minute),
			Layer: "linux-socket-v1", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.5", DstIP: "203.0.113.9",
			SrcPort: uint16(40000 + i), DstPort: 443, ProcessPath: "/usr/bin/curl", ProcessID: 7})
	}
	if err := store.InsertEventsBatch(evs); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshDataReport(storage.DefaultRetention()); err != nil {
		t.Fatal(err)
	}

	w := feedRequest(srv, http.MethodGet, "/api/v1/storage/report", "mock_admin_token")
	if w.Code != http.StatusOK {
		t.Fatalf("report = %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Report storage.DataReport `json:"report"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Report.FlowIndexes != 3 || len(body.Report.Types) == 0 {
		t.Errorf("report = %+v", body.Report)
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/storage/report", "mock_tenant_token"); w.Code != http.StatusForbidden {
		t.Errorf("a tenant key read the hub-wide report: %d", w.Code)
	}

	w = feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token")
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range doc.Findings {
		if f.FindingInfo.UID != "ominull.storage.data_per_endpoint" {
			continue
		}
		found = true
		// The report measures this process, whose memory under -race can
		// exceed the hub budget, so the expectation follows the report.
		wantSev, wantStatus := ocsfSevInformational, ocsfStatusResolved
		if len(store.DataReport().OverBudget) > 0 {
			wantSev, wantStatus = ocsfSevMedium, ocsfStatusNew
		}
		if f.SeverityID != wantSev || f.StatusID != wantStatus {
			t.Errorf("finding is severity %d status %d (over budget: %v): %s", f.SeverityID, f.StatusID, store.DataReport().OverBudget, f.Message)
		}
		if _, ok := f.Unmapped["hot_busy_mb_per_day"]; !ok {
			t.Errorf("finding carries no numbers: %v", f.Unmapped)
		}
	}
	if !found {
		t.Fatal("no Data per endpoint finding in the feed")
	}
}
