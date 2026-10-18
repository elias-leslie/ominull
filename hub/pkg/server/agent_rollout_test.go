package server

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestCanaryUpdateDoesNotPublishToOtherEndpoints(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	if err := db.SetSetting("desired_agent_version", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	for _, id := range []string{"canary", "hold"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	poll := func(id string) bool {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id="+id, nil)
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("poll: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		present, _ := body["update_available"].(bool)
		return present
	}
	if poll("hold") {
		t.Error("publishing a bundle offered an unrequested update")
	}
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(`{"endpoint_ids":["canary"],"version":"1.2.0"}`))
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := serveApproved(t, s, s.Handler(), r, `{"endpoint_ids":["canary"],"version":"1.2.0"}`)
	if w.Code != 200 {
		t.Fatalf("queue: %d %s", w.Code, w.Body.String())
	}
	if !poll("canary") {
		t.Error("selected canary has no update")
	}
	if poll("hold") {
		t.Error("canary request published update to unselected endpoint")
	}
}

func TestUpdateStatusUsesPublishedBundleAfterPreviousRollout(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	if err := db.SetSetting("desired_agent_version", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	seedEndpointWithCapability(t, db, "canary", "Linux", "1.1.0", "deb")
	r := httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		Latest   string              `json:"latest_version"`
		Outdated []map[string]string `json:"outdated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Latest != "1.2.0" || len(body.Outdated) != 1 {
		t.Fatalf("previous fleet setting hid an outdated canary: %s", w.Body.String())
	}
}

func TestUpdateStatusDoesNotCallStaleEndpointOnline(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	seedEndpointWithCapability(t, db, "stale-agent", "Linux", "1.1.0", "deb")
	ep, err := db.GetEndpoint("stale-agent")
	if err != nil {
		t.Fatal(err)
	}
	ep.LastSeenAt = time.Now().Add(-time.Hour)
	ep.Status = "online"
	if err := db.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		Endpoints []map[string]string `json:"endpoints"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Endpoints) != 1 || body.Endpoints[0]["status"] != "offline" {
		t.Fatalf("stale endpoint called online: %s", w.Body.String())
	}
}

// One approval covers a staged rollout: the canary is queued at once, the
// rest only after the canary runs the version with clean provenance.
func TestStagedRolloutReleasesAfterHealthyCanary(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	for _, id := range []string{"canary", "fleet-a", "fleet-b"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	body := `{"all":true,"version":"1.2.0","canary":["canary"]}`
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 200 {
		t.Fatalf("staged queue: %d %s", w.Code, w.Body.String())
	}
	queued := func(id string) bool {
		t.Helper()
		job, err := db.GetAgentUpdateJob(id)
		return err == nil && job != nil && job.DesiredVersion == "1.2.0"
	}
	if !queued("canary") || queued("fleet-a") || queued("fleet-b") {
		t.Fatal("staged rollout queued more than the canary")
	}
	// The held endpoints' grants stay pending, even through a reconcile,
	// until the canary is healthy.
	s.reconcilePendingGrantsIssuedBefore(math.MaxInt64, time.Now())
	for _, id := range []string{"fleet-a", "fleet-b"} {
		if g := s.updateGrantFor(id, "1.2.0"); g != nil {
			t.Fatalf("held %s got its update grant before the canary was healthy", id)
		}
	}
	if g := s.updateGrantFor("canary", "1.2.0"); g == nil {
		t.Fatal("canary has no update grant")
	}
	if v, _ := db.GetSetting("desired_agent_version"); v == "1.2.0" {
		t.Fatal("fleet desired version moved before the canary was healthy")
	}

	s.advanceAgentRollouts(time.Now())
	if queued("fleet-a") {
		t.Fatal("released before the canary updated")
	}
	// The new binary's first report races dpkg (stale package answer); the
	// updater's restart a moment later reports clean provenance.
	if err := db.UpsertEndpoint(storage.Endpoint{ID: "canary", TenantID: "default", Hostname: "canary", OS: "Linux", DriverVersion: "1.2.0",
		UpdateCapability: "deb", Status: "online", LastSeenAt: time.Now().UTC(), ProvenanceStatus: "mismatch"}); err != nil {
		t.Fatal(err)
	}
	s.advanceAgentRollouts(time.Now())
	if ros, _ := db.AgentRollouts(false, 5); len(ros) != 1 || ros[0].State == "halted" {
		t.Fatalf("a transient provenance mismatch halted the rollout: %+v", ros)
	}
	healthyCanary(t, s, "canary", "1.2.0")
	s.advanceAgentRollouts(time.Now())
	if !queued("fleet-a") || !queued("fleet-b") {
		t.Fatal("healthy canary did not release the held endpoints")
	}
	for _, id := range []string{"fleet-a", "fleet-b"} {
		if g := s.updateGrantFor(id, "1.2.0"); g == nil {
			t.Fatalf("released %s has no update grant", id)
		}
	}
	if v, _ := db.GetSetting("desired_agent_version"); v != "1.2.0" {
		t.Fatalf("desired version %q after release", v)
	}
	ros, _ := db.AgentRollouts(false, 5)
	if len(ros) != 1 || ros[0].State != "released" {
		t.Fatalf("rollouts %+v", ros)
	}
}

func TestStagedRolloutHaltsOnBadCanary(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	for _, id := range []string{"canary", "fleet-a"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	body := `{"endpoint_ids":["canary","fleet-a"],"version":"1.2.0","canary":["canary"]}`
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 200 {
		t.Fatalf("staged queue: %d %s", w.Code, w.Body.String())
	}
	// The canary runs the version but not from the native package.
	if err := db.UpsertEndpoint(storage.Endpoint{ID: "canary", TenantID: "default", Hostname: "canary", OS: "Linux", DriverVersion: "1.2.0",
		UpdateCapability: "deb", Status: "online", LastSeenAt: time.Now().UTC(), ProvenanceStatus: "unmanaged"}); err != nil {
		t.Fatal(err)
	}
	// A first unclean report is the package's own restart racing dpkg: wait.
	now := time.Now()
	s.advanceAgentRollouts(now)
	if ros, _ := db.AgentRollouts(false, 5); len(ros) != 1 || ros[0].State == "halted" {
		t.Fatalf("one unclean provenance report halted the rollout: %+v", ros)
	}
	// Still unclean after the grace period: halt.
	s.advanceAgentRollouts(now.Add(rolloutProvenanceGrace + time.Second))
	if job, _ := db.GetAgentUpdateJob("fleet-a"); job != nil {
		t.Fatal("a canary failing provenance released the fleet")
	}
	ros, _ := db.AgentRollouts(false, 5)
	if len(ros) != 1 || ros[0].State != "halted" || !strings.Contains(ros[0].Detail, "provenance") {
		t.Fatalf("rollouts %+v", ros)
	}
	// A halted rollout's held grants are gone, not delivered.
	s.reconcilePendingGrantsIssuedBefore(math.MaxInt64, time.Now())
	if g := s.updateGrantFor("fleet-a", "1.2.0"); g != nil {
		t.Fatal("halted rollout delivered the held endpoint's grant")
	}
	if pending, _ := db.PendingGrants(math.MaxInt64); len(pending) != 0 {
		t.Fatalf("halted rollout left %d pending grant(s)", len(pending))
	}

	// A canary that never reports halts at the deadline.
	body = `{"endpoint_ids":["fleet-a","canary"],"version":"1.2.0","canary":["fleet-a"]}`
	r = httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 200 {
		t.Fatalf("second staged queue: %d %s", w.Code, w.Body.String())
	}
	s.advanceAgentRollouts(time.Now().Add(rolloutCanaryDeadline + time.Minute))
	ros, _ = db.AgentRollouts(false, 1)
	if ros[0].State != "halted" || !strings.Contains(ros[0].Detail, "did not all run") {
		t.Fatalf("deadline: %+v", ros[0])
	}
}

// A newer plain update supersedes a staged rollout, which then neither
// steps the fleet back nor delivers its held grants.
func TestPlainUpdateSupersedesStagedRollout(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.3.0_amd64.deb")
	for _, id := range []string{"canary", "fleet-a"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	body := `{"all":true,"version":"1.2.0","canary":["canary"]}`
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 200 {
		t.Fatalf("staged queue: %d %s", w.Code, w.Body.String())
	}
	s.agentVersion = "1.3.0" // the hub was upgraded meanwhile
	body = `{"all":true,"version":"1.3.0"}`
	r = httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 200 {
		t.Fatalf("plain update: %d %s", w.Code, w.Body.String())
	}
	ros, _ := db.AgentRollouts(false, 5)
	if len(ros) != 1 || ros[0].State != "superseded" {
		t.Fatalf("rollouts %+v", ros)
	}
	healthyCanary(t, s, "canary", "1.3.0")
	s.advanceAgentRollouts(time.Now())
	if job, _ := db.GetAgentUpdateJob("fleet-a"); job == nil || job.DesiredVersion != "1.3.0" {
		t.Fatalf("fleet-a job %+v, want 1.3.0", job)
	}
	if g := s.updateGrantFor("fleet-a", "1.2.0"); g != nil {
		t.Fatal("superseded rollout delivered its held grant")
	}
	if pending, _ := db.PendingGrants(math.MaxInt64); len(pending) != 0 {
		t.Fatalf("superseded rollout left %d pending grant(s)", len(pending))
	}
}

// A canary that cannot install refuses the whole request; no canary is queued.
func TestStagedRolloutQueuesNoCanaryWhenOneCannotInstall(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	seedEndpointWithCapability(t, db, "a", "Linux", "1.1.0", "deb")
	seedEndpointWithCapability(t, db, "b", "Linux", "1.1.0", "")
	seedEndpointWithCapability(t, db, "c", "Linux", "1.1.0", "deb")
	body := `{"endpoint_ids":["a","b","c"],"version":"1.2.0","canary":["a","b"]}`
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, s, s.Handler(), r, body); w.Code != 409 {
		t.Fatalf("want 409, got %d %s", w.Code, w.Body.String())
	}
	if job, _ := db.GetAgentUpdateJob("a"); job != nil {
		t.Fatal("a canary was queued although the request was refused")
	}
	if ros, _ := db.AgentRollouts(false, 5); len(ros) != 0 {
		t.Fatalf("refused request recorded rollouts %+v", ros)
	}
}

func TestStagedRolloutRefusesBadCanaries(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	seedEndpointWithCapability(t, db, "a", "Linux", "1.1.0", "deb")
	seedEndpointWithCapability(t, db, "b", "Linux", "1.1.0", "deb")
	for _, body := range []string{
		`{"endpoint_ids":["a"],"version":"1.2.0","canary":["b"]}`,
		`{"endpoint_ids":["a","b"],"version":"1.2.0","canary":["a","b"]}`,
	} {
		if w := adminPost(s, "/api/v1/agents/update", body, ""); w.Code != 400 {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
}

// healthyCanary records an endpoint running version from its native package.
func healthyCanary(t *testing.T, s *Server, id, version string) {
	t.Helper()
	expected, ok := nativePackageForCapability("deb")
	if !ok {
		t.Fatal("no native package for deb")
	}
	if err := s.store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: id, OS: "Linux", DriverVersion: version,
		UpdateCapability: "deb", Status: "online", LastSeenAt: time.Now().UTC(), ProvenanceStatus: "native",
		InstallType: expected.InstallType, PackageIdentifier: expected.Identifier, RegisteredPackageVersion: version}); err != nil {
		t.Fatal(err)
	}
}

// The update status lists the retired agent releases, so the console can name
// them next to the routine release keys.
func TestUpdateStatusListsRetiredReleases(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	get := func() []string {
		r := httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var body struct {
			Retired *[]string `json:"retired_versions"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Retired == nil {
			t.Fatalf("retired_versions missing or null: %s", w.Body.String())
		}
		return *body.Retired
	}
	if got := get(); len(got) != 0 {
		t.Fatalf("fresh hub lists retired releases: %v", got)
	}
	if err := db.SetSetting(retiredAgentVersionsSetting, `["1.8.88"]`); err != nil {
		t.Fatal(err)
	}
	if got := get(); len(got) != 1 || got[0] != "1.8.88" {
		t.Fatalf("retired releases not listed: %v", got)
	}
}
