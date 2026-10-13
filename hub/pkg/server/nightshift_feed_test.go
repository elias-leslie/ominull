package server

import (
	"encoding/json"
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
	if ag.SeverityID != ocsfSevMedium || ag.Message != "1 server agent offline (longest 3 h); 1 workstation agent quiet over 7 days" {
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
	if len(doc.Findings) != 6 {
		t.Fatalf("findings = %d, want hub, anomalies, agent egress, agents, router collector, router certificate", len(doc.Findings))
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
