package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/storage"
)

func feedRequest(srv *Server, method, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func issueFeedKey(t *testing.T, srv *Server) string {
	t.Helper()
	w := feedRequest(srv, http.MethodPost, "/api/v1/integrations/nightshift/key", "mock_admin_token")
	if w.Code != http.StatusOK {
		t.Fatalf("feed key issue = %d %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !strings.HasPrefix(body["key"], "nsf_") {
		t.Fatalf("feed key response = %v %v", body, err)
	}
	return body["key"]
}

type feedDoc struct {
	Schema      string `json:"schema"`
	Source      string `json:"source"`
	GeneratedAt string `json:"generated_at"`
	Findings    []struct {
		ClassUID    int    `json:"class_uid"`
		CategoryUID int    `json:"category_uid"`
		SeverityID  int    `json:"severity_id"`
		StatusID    int    `json:"status_id"`
		Time        int64  `json:"time"`
		Message     string `json:"message"`
		FindingInfo struct {
			UID string `json:"uid"`
		} `json:"finding_info"`
		Resources []feedResource `json:"resources"`
		Unmapped  map[string]any `json:"unmapped"`
	} `json:"findings"`
}

func TestNightshiftFeedKeyOpensOnlyTheFeed(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	if w := feedRequest(srv, http.MethodPost, "/api/v1/integrations/nightshift/key", "mock_tenant_token"); w.Code != http.StatusForbidden {
		t.Fatalf("tenant key issued the feed key: %d", w.Code)
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_tenant_token"); w.Code != http.StatusForbidden {
		t.Fatalf("tenant key read the feed: %d", w.Code)
	}
	first := issueFeedKey(t, srv)
	if stored, _ := store.GetSetting(nightshiftFeedKeySetting); stored == first || stored != hashFeedKey(first) {
		t.Fatal("the feed key must be stored only as its hash")
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", first); w.Code != http.StatusOK {
		t.Fatalf("feed key refused: %d %s", w.Code, w.Body.String())
	}
	// The key is not a credential anywhere else, and the feed is read-only.
	for _, path := range []string{"/api/v1/anomalies", "/api/v1/endpoints", "/api/v1/router/flows"} {
		if w := feedRequest(srv, http.MethodGet, path, first); w.Code != http.StatusUnauthorized {
			t.Fatalf("feed key opened %s: %d", path, w.Code)
		}
	}
	if w := feedRequest(srv, http.MethodPost, "/api/v1/integrations/nightshift/findings", first); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("feed accepted a POST: %d", w.Code)
	}
	second := issueFeedKey(t, srv)
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", first); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked feed key still accepted: %d", w.Code)
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", second); w.Code != http.StatusOK {
		t.Fatalf("reissued feed key refused: %d", w.Code)
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token"); w.Code != http.StatusOK {
		t.Fatalf("admin cannot read the feed: %d", w.Code)
	}
	token, err := auth.GenerateJWT(auth.Claims{UserID: "u", Username: "tenant-admin", Role: auth.RoleAdmin, TenantID: "t-01"}, "mock_admin_token", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/nightshift/findings", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped administrator read the fleet-wide feed: %d", w.Code)
	}
}

func TestNightshiftFeedFollowsTheContract(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()

	for _, ep := range []storage.Endpoint{
		{ID: "srv-quiet", TenantID: "t-01", Hostname: "lab-server", RoleTag: "server", Status: "online", LastSeenAt: now.Add(-3 * time.Hour)},
		{ID: "srv-up", TenantID: "t-01", Hostname: "hub-server", RoleTag: "server", Status: "online", LastSeenAt: now},
		{ID: "laptop-gone", TenantID: "t-01", Hostname: "kid-laptop", RoleTag: "workstation", Status: "offline", LastSeenAt: now.Add(-10 * 24 * time.Hour)},
		{ID: "laptop-asleep", TenantID: "t-01", Hostname: "work-laptop", RoleTag: "workstation", Status: "offline", LastSeenAt: now.Add(-2 * time.Hour)},
		{ID: "old", TenantID: "t-01", Hostname: "old", RoleTag: "server", Status: "online", LastSeenAt: now.Add(-90 * 24 * time.Hour)},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RetireEndpoint("old"); err != nil {
		t.Fatal(err)
	}
	for i, a := range []storage.AnomalyAlert{
		{Severity: "CRITICAL", AnomalyType: "LATERAL_PORT_SWEEP", Hostname: "lab-server", Timestamp: now.Add(-time.Hour)},
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "lab-server", Timestamp: now.Add(-2 * time.Hour)},
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "lab-server", Timestamp: now.Add(-48 * time.Hour)}, // backlog only
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "lab-server", Timestamp: now.Add(-time.Hour), Acknowledged: true},
		{Severity: "HIGH", AnomalyType: "NOVEL_PROCESS_EGRESS", Hostname: "lab-server", Timestamp: now.Add(-time.Hour), HeldReason: "learning"},
	} {
		a.ID = "a" + string(rune('0'+i))
		a.TenantID, a.EndpointID, a.Title, a.Description = "t-01", "srv-quiet", "t", "d"
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.TouchRouterSource("gw", "living room", "dns 4/4", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRouterIdentity("gw", strings.Repeat("a", 64), now.Add(-pki.ClientCertLifetime+10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", issueFeedKey(t, srv))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("feed = %d %v", w.Code, w.Header())
	}
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "nightshift.findings/v1" || doc.Source != "ominull" {
		t.Fatalf("document header = %q %q", doc.Schema, doc.Source)
	}
	if _, err := time.Parse(time.RFC3339, doc.GeneratedAt); err != nil {
		t.Fatalf("generated_at: %v", err)
	}
	// The same rules Nightshift's validator applies (nightshift.ingest.convert).
	uidRE := regexp.MustCompile(`^ominull\.[a-z0-9_]+(\.[a-z0-9_]+){0,4}$`)
	byUID := map[string]int{}
	for i, f := range doc.Findings {
		if f.ClassUID != 2004 || f.CategoryUID != 2 || !uidRE.MatchString(f.FindingInfo.UID) || f.Message == "" || len(f.Message) > 300 || f.Time <= 0 {
			t.Fatalf("finding %d breaks the contract: %+v", i, f)
		}
		if _, dup := byUID[f.FindingInfo.UID]; dup {
			t.Fatalf("duplicate uid %s", f.FindingInfo.UID)
		}
		byUID[f.FindingInfo.UID] = i
		for _, name := range []string{"lab-server", "kid-laptop", "living room"} {
			if strings.Contains(f.Message, name) {
				t.Fatalf("message names a device, which may reach a push: %q", f.Message)
			}
		}
	}
	get := func(uid string) int {
		i, ok := byUID[uid]
		if !ok {
			t.Fatalf("no %s in %s", uid, w.Body.String())
		}
		return i
	}
	an := doc.Findings[get("ominull.anomalies.summary")]
	if an.SeverityID != ocsfSevHigh || !strings.HasPrefix(an.Message, "2 new open anomalies in the last 24 h (1 critical, 1 high); 3 open") {
		t.Fatalf("anomaly summary = %d %q", an.SeverityID, an.Message)
	}
	ag := doc.Findings[get("ominull.agents.offline")]
	if ag.SeverityID != ocsfSevMedium || ag.Message != "1 server agent offline (longest 3 h); 1 workstation agent quiet beyond its allowance" {
		t.Fatalf("agents = %d %q", ag.SeverityID, ag.Message)
	}
	if len(ag.Resources) != 2 || ag.Resources[0].UID != "laptop-gone" || ag.Resources[1].UID != "srv-quiet" {
		t.Fatalf("agent resources = %+v", ag.Resources)
	}
	rc := doc.Findings[get("ominull.router.collector")]
	if rc.SeverityID != ocsfSevMedium || rc.Message != "1 router collector silent for 60 min" {
		t.Fatalf("router collector = %d %q", rc.SeverityID, rc.Message)
	}
	cert := doc.Findings[get("ominull.router.certificate")]
	if cert.SeverityID != ocsfSevMedium || cert.StatusID != ocsfStatusNew {
		t.Fatalf("router certificate = %+v", cert)
	}
	if hub := doc.Findings[get("ominull.hub")]; hub.StatusID != ocsfStatusResolved {
		t.Fatalf("hub = %+v", hub)
	}
	// The inventory is an observation for Nightshift's asset registry: every
	// enrolled endpoint (retired ones left out), never a tier.
	inv := doc.Findings[get("ominull.inventory.endpoints")]
	rows, _ := inv.Unmapped["endpoints"].([]any)
	if inv.StatusID != ocsfStatusResolved || inv.Message != "4 endpoints enrolled, 1 reporting now" || len(rows) != 4 {
		t.Fatalf("inventory = %q %v", inv.Message, inv.Unmapped)
	}
	if rows[0] != "laptop-asleep|work-laptop|always_on|workstation|0|offline" || inv.Unmapped["fields"] != "id|host|presence|role|isolated|status" {
		t.Fatalf("inventory row = %v (the hub reports observations, never a tier)", rows[0])
	}
}

func TestLegacyLabPresenceIsParked(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "guest", TenantID: "t-01", Hostname: "guest", RoleTag: "server", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointPresence("guest", "lab"); err != nil {
		t.Fatal(err)
	}
	w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", issueFeedKey(t, srv))
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.FindingInfo.UID != "ominull.inventory.endpoints" {
			continue
		}
		rows, _ := f.Unmapped["endpoints"].([]any)
		if len(rows) != 1 || rows[0] != "guest|guest|parked|server|0|online" {
			t.Fatalf("inventory = %v", f.Unmapped)
		}
		return
	}
	t.Fatal("no inventory finding")
}

func TestNightshiftFeedQuietFleetIsResolved(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "s", TenantID: "t-01", Hostname: "s", RoleTag: "server", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchRouterSource("gw", "", "ok", now); err != nil {
		t.Fatal(err)
	}
	w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token")
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.StatusID != ocsfStatusResolved {
			t.Fatalf("%s is not resolved on a quiet fleet: %q", f.FindingInfo.UID, f.Message)
		}
	}
	if len(doc.Findings) != 8 {
		t.Fatalf("findings = %d, want hub, anomalies, hunt leads, agent egress, agents, inventory, router collector, router certificate", len(doc.Findings))
	}
}

func TestNightshiftFeedReportsAgentEgressAtItsWorstSeverity(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	find := func() (status, severity int) {
		t.Helper()
		var doc feedDoc
		w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token")
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.agent_egress" {
				return f.StatusID, f.SeverityID
			}
		}
		t.Fatal("no agent egress finding in the feed")
		return 0, 0
	}
	add := func(id, typ, sev string) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "e", Hostname: "dev",
			AnomalyType: typ, Severity: sev, Title: typ, Timestamp: now.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := find(); st != ocsfStatusResolved {
		t.Fatalf("no agent findings should be resolved, got %d", st)
	}
	add("a1", "AGENT_NEW_DESTINATION", "MEDIUM")
	if st, sev := find(); st != ocsfStatusNew || sev != ocsfSevLow {
		t.Fatalf("an ordinary new destination = status %d severity %d", st, sev)
	}
	add("a2", "AGENT_NEW_DESTINATION", "HIGH")
	if _, sev := find(); sev != ocsfSevHigh {
		t.Fatalf("a HIGH new destination surfaced at severity %d", sev)
	}
}

func TestNightshiftFeedV2CarriesTypedRecordsWithVerifiedOutcomes(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	week := 7 * 24 * time.Hour
	n := 0
	add := func(endpoint, typ string, at time.Time) string {
		n++
		id := fmt.Sprintf("r%d", n)
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: endpoint, Hostname: "secret-host",
			AnomalyType: typ, Severity: "MEDIUM", Title: "reached secret.example.com", Timestamp: at}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	resolve := func(id, verdict, method string) {
		if _, err := store.ResolveAnomalies("", []string{id}, storage.Resolution{Reason: "test", By: "test", Verdict: verdict, Method: method}); err != nil {
			t.Fatal(err)
		}
	}
	audit := func(action, resource string, at time.Time) {
		n++
		if err := store.RecordAudit(storage.AuditEntry{ID: fmt.Sprintf("a%d", n), Action: action, Resource: resource, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	// linux-secret-host: off-hours every week for four weeks, judged benign in
	// the first and still open now - recurrence from a judgement.
	for i := 3; i >= 0; i-- {
		id := add("linux-secret-host", "OFF_HOURS_ACTIVITY", now.Add(-time.Duration(i)*week))
		if i == 3 {
			resolve(id, storage.VerdictBenign, storage.MethodOperator)
		}
	}
	// linux-unjudged: the same shape with nobody ever judging it.
	for i := 3; i >= 0; i-- {
		add("linux-unjudged", "UNUSUAL_PORT", now.Add(-time.Duration(i)*week))
	}
	// linux-beacon: a beacon every week, the first closed benign: repetition
	// of a beacon is never evidence.
	for i := 3; i >= 0; i-- {
		id := add("linux-beacon", "C2_BEACONING", now.Add(-time.Duration(i)*week))
		if i == 3 {
			resolve(id, storage.VerdictBenign, storage.MethodOperator)
		}
	}
	resolve(add("linux-acked", "NOVEL_DESTINATION", now), storage.VerdictBenign, storage.MethodOperator)
	resolve(add("linux-auto", "NOVEL_PROCESS_EGRESS", now), storage.VerdictBenign, storage.MethodTuning)
	resolve(add("linux-bad", "BANDWIDTH_SPIKE", now), storage.VerdictMalicious, storage.MethodOperator)
	// A plain acknowledgement, alone or in a batch, carries no verdict.
	if err := store.AcknowledgeAnomaly(add("linux-plain", "NOVEL_COUNTRY", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeAnomaliesBatch([]string{add("linux-plain", "ENDPOINT_SILENT", now)}); err != nil {
		t.Fatal(err)
	}
	// Acked unread, found malicious later: the verdict still lands.
	late := add("linux-late-verdict", "THREAT_INTEL_MATCH", now)
	if err := store.AcknowledgeAnomaly(late); err != nil {
		t.Fatal(err)
	}
	resolve(late, storage.VerdictMalicious, storage.MethodOperator)
	add("linux-open", "BRAND_NEW_DETECTOR", now)
	add("linux-isolated", "LATERAL_PORT_SWEEP", now)
	audit("ISOLATE_HOST", "linux-isolated", now)
	// Neither a bulk entry nor a pre-attempt guard entry is an isolation.
	add("linux-tried", "AGENT_NEW_DESTINATION", now)
	audit("BULK_ISOLATE", "linux-tried", now)
	audit("ISOLATE_HOST_FORCED", "linux-tried", now)
	audit("ISOLATE_HOST_UNVERIFIED", "linux-tried", now)
	// linux-later: judged benign two weeks ago, isolated this week. The
	// earlier label may have been the start of it, so it is withdrawn.
	resolve(add("linux-later", "ENDPOINT_RETURNED", now.Add(-2*week)), storage.VerdictBenign, storage.MethodOperator)
	audit("AUTO_ISOLATE_HOST", "linux-later", now)

	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v9", "mock_admin_token"); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown contract was served: %d", w.Code)
	}
	v1 := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token")
	if strings.Contains(v1.Body.String(), "anomaly_records") || !strings.Contains(v1.Body.String(), `"nightshift.findings/v1"`) {
		t.Fatal("the default document must stay v1")
	}
	w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v2", "mock_admin_token")
	var doc struct {
		Schema  string `json:"schema"`
		Records []struct {
			DeviceID      string `json:"device_id"`
			Kind          string `json:"kind"`
			Count         int    `json:"count"`
			FirstSeen     int64  `json:"first_seen"`
			LastSeen      int64  `json:"last_seen"`
			Window        string `json:"baseline_window_id"`
			Outcome       string `json:"outcome"`
			Verified      bool   `json:"verified"`
			OutcomeSource string `json:"outcome_source"`
		} `json:"anomaly_records"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Schema != "nightshift.findings/v2" {
		t.Fatalf("v2 = %d %v %q", w.Code, err, doc.Schema)
	}
	// No hostname, endpoint id or finding text leaves in a record.
	var raw struct {
		Records json.RawMessage `json:"anomaly_records"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	for _, leak := range []string{"secret", "linux-", "example.com"} {
		if strings.Contains(string(raw.Records), leak) {
			t.Fatalf("records carry %q: %s", leak, raw.Records)
		}
	}
	thisWeek, twoAgo := mustWeek(now), mustWeek(now.Add(-2*week))
	got := map[string]string{}
	for _, r := range doc.Records {
		if r.Window == thisWeek || r.Window == twoAgo {
			got[r.Window+" "+r.Kind] = fmt.Sprintf("%s/%v/%s", r.Outcome, r.Verified, r.OutcomeSource)
		}
		if !strings.HasPrefix(r.DeviceID, "dev_") || r.Count < 1 || r.FirstSeen > r.LastSeen {
			t.Fatalf("malformed record %+v", r)
		}
	}
	want := map[string]string{
		"off_hours":             "benign/true/recurrence",
		"unusual_port":          "unverified/false/",
		"beaconing":             "unverified/false/",
		"novel_destination":     "benign/true/acknowledged",
		"novel_process_egress":  "benign/true/auto_resolved",
		"bandwidth_spike":       "incident/true/verdict",
		"threat_intel":          "incident/true/verdict",
		"novel_country":         "unverified/false/",
		"endpoint_silent":       "unverified/false/",
		"other":                 "unverified/false/",
		"lateral_sweep":         "incident/true/isolation",
		"agent_new_destination": "unverified/false/",
	}
	for k, v := range want {
		if got[thisWeek+" "+k] != v {
			t.Errorf("%s this week = %q, want %q", k, got[thisWeek+" "+k], v)
		}
	}
	if g := got[twoAgo+" endpoint_returned"]; g != "unverified/false/" {
		t.Errorf("a benign label before an isolation = %q, want it withdrawn", g)
	}
	// The salt is kept: a second request names every device the same way.
	again := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v2", "mock_admin_token")
	var raw2 struct {
		Records json.RawMessage `json:"anomaly_records"`
	}
	_ = json.Unmarshal(again.Body.Bytes(), &raw2)
	if string(raw2.Records) != string(raw.Records) {
		t.Fatal("a second request renamed devices or changed records")
	}
	// The same device keeps one id across windows and requests.
	ids := map[string]bool{}
	for _, r := range doc.Records {
		if r.Kind == "off_hours" {
			ids[r.DeviceID] = true
		}
	}
	if len(ids) != 1 {
		t.Fatalf("one device had %d ids", len(ids))
	}
}

func TestBaselineWindowsAreISOWeeksAcrossTheYearBoundary(t *testing.T) {
	for _, c := range []struct {
		at, week, start string
	}{
		{"2026-01-01T12:00:00Z", "2026-W01", "2025-12-29"},
		{"2027-01-03T23:59:00Z", "2026-W53", "2026-12-28"},
		{"2027-01-04T00:00:00Z", "2027-W01", "2027-01-04"},
		{"2026-10-12T08:00:00+05:00", "2026-W42", "2026-10-12"},
		{"2026-10-12T03:00:00+05:00", "2026-W41", "2026-10-05"},
	} {
		at, _ := time.Parse(time.RFC3339, c.at)
		w, start := isoWeek(at)
		if w != c.week || start.Format("2006-01-02") != c.start {
			t.Errorf("isoWeek(%s) = %s %s, want %s %s", c.at, w, start.Format("2006-01-02"), c.week, c.start)
		}
	}
}

func TestAMalformedDeviceSaltIsNeverReplaced(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.SetSetting(feedDeviceSaltSetting, "not-hex"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.deviceSalt(); err == nil {
		t.Fatal("a malformed salt was accepted")
	}
	if v, _ := store.GetSetting(feedDeviceSaltSetting); v != "not-hex" {
		t.Fatalf("the salt was overwritten with %q", v)
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v2", "mock_admin_token"); w.Code == http.StatusOK {
		t.Fatal("v2 was served with device ids from a bad salt")
	}
}
