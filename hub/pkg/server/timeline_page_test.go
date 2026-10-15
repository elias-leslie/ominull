package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestTimelinePage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "ep-web", TenantID: "t-01", Hostname: "web-01", IP: "10.0.0.11"},
		{ID: "ep-db", TenantID: "t-01", Hostname: "db-01", IP: "10.0.0.12"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	alerts := []storage.AnomalyAlert{
		{ID: "a-web", TenantID: "t-01", EndpointID: "ep-web", Hostname: "web-01", AnomalyType: "BEACONING", Severity: "HIGH", Title: "Periodic beacon to <b>203.0.113.9</b>", Timestamp: now.Add(-2 * time.Hour)},
		{ID: "a-db", TenantID: "t-01", EndpointID: "ep-db", Hostname: "db-01", AnomalyType: "BEACONING", Severity: "LOW", Title: "db finding", Timestamp: now.Add(-3 * time.Hour)},
		{ID: "a-old", TenantID: "t-01", EndpointID: "ep-web", Hostname: "web-01", AnomalyType: "BEACONING", Severity: "LOW", Title: "eight days ago", Timestamp: now.Add(-8 * 24 * time.Hour)},
		{ID: "a-learn", TenantID: "t-01", EndpointID: "ep-web", Hostname: "web-01", AnomalyType: "NOVEL_DESTINATION", Severity: "LOW", Title: "held for learning", HeldReason: storage.HeldLearning, Timestamp: now.Add(-1 * time.Hour)},
	}
	for _, a := range alerts {
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []storage.AuditEntry{
		{ID: "au-1", TenantID: "t-01", Username: "owner@example.invalid", Action: "ISOLATE_HOST", Resource: "ep-web", Details: "contained", Timestamp: now.Add(-90 * time.Minute)},
		{ID: "au-2", TenantID: "t-01", Username: "owner@example.invalid", Action: "OWNER_APPROVAL_USED", Resource: "ep-db,ep-web", Timestamp: now.Add(-80 * time.Minute)},
		{ID: "au-3", TenantID: "t-01", Username: "owner@example.invalid", Action: "ISOLATE_HOST", Resource: "ep-db", Timestamp: now.Add(-70 * time.Minute)},
	} {
		if err := store.RecordAudit(e); err != nil {
			t.Fatal(err)
		}
	}

	get := func(query string, signedIn bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/console/timeline"+query, nil)
		if signedIn {
			req.AddCookie(sessionFor(t, srv, "admin", "admin"))
		}
		rec := httptest.NewRecorder()
		srv.handleTimelinePage(rec, req)
		return rec
	}

	if rec := get("", false); rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Fatalf("no session: %d %q, want a redirect to the console sign-in", rec.Code, rec.Header().Get("Location"))
	}

	rec := get("?endpoint=ep-web&range=24h", true)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Periodic beacon to &lt;b&gt;203.0.113.9&lt;/b&gt;", "Isolate host", "Owner approval used", `<option value="ep-web" selected>web-01</option>`} {
		if !strings.Contains(body, want) {
			t.Errorf("host timeline lacks %q", want)
		}
	}
	for _, unwanted := range []string{"db finding", "eight days ago", "held for learning", "<b>203"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("host timeline shows %q", unwanted)
		}
	}
	if strings.Count(body, "Isolate host") != 1 {
		t.Errorf("the other host's isolation leaked in: %d", strings.Count(body, "Isolate host"))
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("page CSP %q", csp)
	}

	body = get("?range=7d", true).Body.String()
	if !strings.Contains(body, "db finding") || strings.Contains(body, "eight days ago") || strings.Count(body, "Isolate host") != 2 {
		t.Error("fleet timeline does not hold both hosts' events within seven days")
	}
	if !strings.Contains(get("?range=30d", true).Body.String(), "eight days ago") {
		t.Error("thirty-day window misses an eight-day-old finding")
	}
	if body := get("?endpoint=gone", true).Body.String(); !strings.Contains(body, "not enrolled any more") {
		t.Error("an unknown host is not reported")
	}
}
