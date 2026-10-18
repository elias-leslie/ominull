package server

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
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

// A terminal's audit entries name the session, not the host. The timeline
// puts them under the host, and leaves out the reopen that every page load of
// a terminal writes.
func TestTimelineTerminalEntries(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-web", TenantID: "default", Hostname: "web-01", IP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	grant := &response.EndpointGrant{Version: response.GrantVersion, GrantID: "g1", TenantID: "default", EndpointID: "ep-web",
		ActionKind: response.ActionKindTerminalSession, OperatorID: "admin", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	sess, err := srv.terminalMgr.CreateSession("default", "ep-web", "admin", "/bin/bash", grant)
	if err != nil {
		t.Fatal(err)
	}
	for i, action := range []string{"TERMINAL_SESSION_CREATED", "TERMINAL_SESSION_REATTACHED", "TERMINAL_SESSION_DETACHED", "TERMINAL_SESSION_CLOSED"} {
		if err := store.RecordAudit(storage.AuditEntry{ID: "t-" + action, TenantID: "default", Username: "admin", Action: action, Resource: sess.SessionID,
			Details: "grant g1 session " + sess.SessionID, Timestamp: now.Add(time.Duration(i-10) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	body := srv.buildTimeline("ep-web", "24h", now)
	var titles []string
	for _, d := range body.Days {
		for _, it := range d.Items {
			titles = append(titles, it.Title)
			if it.Host != "web-01" || it.Detail != "" {
				t.Errorf("%q: host %q detail %q", it.Title, it.Host, it.Detail)
			}
		}
	}
	if strings.Join(titles, "|") != "Ended a terminal|Opened a terminal" {
		t.Errorf("terminal entries %q", titles)
	}
}

// Repeats of the same event in a row share one line with a count, and the
// What filter keeps one kind of event, folding its repeats even when other
// kinds sat between them.
func TestTimelineFoldsRepeatsAndFiltersKind(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-web", TenantID: "t-01", Hostname: "web-01", IP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	// Noon yesterday on the hub's clock, so the five events never straddle midnight.
	loc := store.GetDetectionTuning().Location()
	y, mo, d := time.Now().In(loc).AddDate(0, 0, -1).Date()
	now := time.Date(y, mo, d, 12, 0, 0, 0, loc)
	at := func(m int) time.Time { return now.Add(-time.Duration(m) * time.Minute).UTC() }
	for i, e := range []storage.AuditEntry{
		{Action: "CONSOLE_SIGNIN", Details: "admin key", Timestamp: at(10)},
		{Action: "CONSOLE_SIGNIN", Details: "admin key", Timestamp: at(20)},
		{Action: "CONSOLE_SIGNIN", Details: "passkey", Timestamp: at(30)},
		{Action: "ISOLATE_HOST", Resource: "ep-web", Timestamp: at(40)},
		{Action: "CONSOLE_SIGNIN", Details: "admin key", Timestamp: at(50)},
	} {
		e.ID, e.TenantID, e.Username = "au-"+strconv.Itoa(i), "t-01", "owner@example.invalid"
		if err := store.RecordAudit(e); err != nil {
			t.Fatal(err)
		}
	}

	body := srv.buildTimeline("", "24h", now)
	if body.Count != 5 || body.Lines != 3 {
		t.Fatalf("count %d lines %d, want 5 events on 3 lines", body.Count, body.Lines)
	}
	first := body.Days[0].Items[0]
	if first.Title != "Console signin" || first.Count != 3 || strings.Join(first.Details, "|") != "admin key|passkey" {
		t.Errorf("folded line %+v", first)
	}

	body.filterKind("Sign-in")
	if body.Count != 4 || body.Lines != 1 || body.Days[0].Items[0].Count != 4 {
		t.Errorf("sign-in filter: count %d lines %d", body.Count, body.Lines)
	}
	if len(body.Kinds) != 3 || !body.Kinds[2].Selected || body.Kinds[2].Label != "Sign-in (4)" {
		t.Errorf("kinds %+v", body.Kinds)
	}
	body.filterKind("nonsense")
	if !body.Kinds[0].Selected {
		t.Error("an unknown kind does not fall back to everything")
	}

	req := httptest.NewRequest("GET", "/console/timeline?range=7d&kind=Containment", nil)
	req.AddCookie(sessionFor(t, srv, "admin", "admin"))
	rec := httptest.NewRecorder()
	srv.handleTimelinePage(rec, req)
	page := rec.Body.String()
	if !strings.Contains(page, "Isolate host") || strings.Contains(page, "Console signin") || !strings.Contains(page, `<option value="Containment" selected>Containment (1)</option>`) {
		t.Errorf("containment filter page does not hold just the isolation")
	}
}
