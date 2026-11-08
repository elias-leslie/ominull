package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

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

type feedDoc struct {
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

	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("feed = %d %v", w.Code, w.Header())
	}
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, doc.GeneratedAt); err != nil {
		t.Fatalf("generated_at: %v", err)
	}
	// The finding shape the rows are built from.
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
		// The alert summary names the host on purpose: it is the notice's sentence.
		for _, name := range []string{"lab-server", "kid-laptop", "living room"} {
			if f.FindingInfo.UID != "ominull.anomalies.summary" && strings.Contains(f.Message, name) {
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
	if an.SeverityID != ocsfSevCritical || !strings.HasPrefix(an.Message, "A program on lab-server") || !strings.HasSuffix(an.Message, "(+1 more)") {
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
	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
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
	srv.floorDrillDue(now) // as Start does
	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
	var doc feedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.StatusID != ocsfStatusResolved {
			t.Fatalf("%s is not resolved on a quiet fleet: %q", f.FindingInfo.UID, f.Message)
		}
	}
	if len(doc.Findings) != 16 {
		t.Fatalf("findings = %d, want hub, anomalies, hunt leads, digest, agent egress, agents, agent certificates, policy expiry, inventory, router collector, router certificate, maintenance runs, maintenance schedule, detection policy soundness, floor drill and changes", len(doc.Findings))
	}
}

// feedRead is one finding as a test reads it.
type feedRead struct {
	StatusID, SeverityID int
	Message              string
	Unmapped             map[string]any
}

// The digest names the recorded findings, one line per group, and never
// asks; pages stay out of it.
func TestNightshiftFeedDigestIsANote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	find := func() feedRead {
		t.Helper()
		var doc feedDoc
		w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.digest" {
				return feedRead{f.StatusID, f.SeverityID, f.Message, f.Unmapped}
			}
		}
		t.Fatal("no digest finding in the feed")
		return feedRead{}
	}
	add := func(id, typ, sev, class, held string, at time.Time) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "e", Hostname: "dev",
			AnomalyType: typ, Severity: sev, Title: typ, ProcessPath: "/usr/bin/curl", DstIP: "203.0.113.5", DstPort: 443,
			Evidence: `{"class":"` + class + `"}`, HeldReason: held, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	if f := find(); f.StatusID != ocsfStatusResolved || f.Message != "Nothing recorded in the last 24 h" {
		t.Fatalf("quiet digest = %d %q", f.StatusID, f.Message)
	}
	add("r1", "OFF_HOURS_ACTIVITY", "LOW", storage.ClassRecord, storage.HeldHunt, now.Add(-time.Hour))
	add("r2", "OFF_HOURS_ACTIVITY", "LOW", storage.ClassRecord, storage.HeldHunt, now.Add(-2*time.Hour))
	add("d1", "C2_BEACONING", "MEDIUM", storage.ClassDigest, storage.HeldHunt, now.Add(-3*time.Hour))
	add("old", "C2_BEACONING", "MEDIUM", storage.ClassDigest, storage.HeldHunt, now.Add(-30*time.Hour))
	add("p1", "DECOY_TOUCH", "CRITICAL", storage.ClassPage, "", now.Add(-time.Hour))
	f := find()
	if f.StatusID != ocsfStatusNew || f.SeverityID != ocsfSevInformational {
		t.Fatalf("digest = status %d severity %d", f.StatusID, f.SeverityID)
	}
	if !strings.HasPrefix(f.Message, "3 findings recorded in the last 24 h, none asking for you. Most common: ") ||
		!strings.Contains(f.Message, "(2 times)") || strings.Contains(f.Message, "decoy") {
		t.Fatalf("digest message = %q", f.Message)
	}
	byClass, _ := f.Unmapped["by_class"].(map[string]any)
	if byClass["record"] != float64(2) || byClass["digest"] != float64(1) || f.Unmapped["groups"] != float64(2) {
		t.Fatalf("digest unmapped = %v", f.Unmapped)
	}
}
