package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// beat runs one heartbeat of a grant-verifying agent through ingestion and
// returns the hub's answer as JSON.
func trustBeat(t *testing.T, srv *Server, id string, report *response.AgentTrustReport) map[string]json.RawMessage {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	resp, err := srv.ingestTelemetry(req, "default", TelemetryBatchMessage{
		Type: "telemetry", EndpointID: id, TenantID: "default", Hostname: id, OS: "Linux", DriverVersion: "1.8.59", Trust: report,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(resp)
	var out map[string]json.RawMessage
	_ = json.Unmarshal(raw, &out)
	return out
}

func grantsIn(t *testing.T, out map[string]json.RawMessage) []response.EnforcementGrant {
	t.Helper()
	var g []response.EnforcementGrant
	if raw, ok := out["enforcement_grants"]; ok {
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func keyOf(t *testing.T, h string) ed25519.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("key %q", h)
	}
	return b
}

// signTrustBundle stands in for the owner: a test release key replaces the
// pinned one, the hub's statement is signed with it and posted.
func signTrustBundle(t *testing.T, srv *Server, keys *response.TrustKeys) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	srv.trust.mu.Lock()
	srv.trust.releasePub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	srv.trust.mu.Unlock()
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trust/statement?tenant=default", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var st struct {
		Statement string `json:"statement"`
		Signed    bool   `json:"signed"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Signed {
		t.Fatalf("statement: %d %s", w.Code, w.Body.String())
	}
	k := *keys
	k.TenantID = "default"
	k.Epoch = 1
	if st.Statement != response.TrustBundleStatement(&k) {
		t.Fatalf("statement %q", st.Statement)
	}
	post := func(sig string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"tenant_id":"default","epoch":1,"signature":%q}`, sig)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/trust/bundle", strings.NewReader(body))
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	sign := func(msg string) string {
		sum := sha256.Sum256([]byte(msg))
		der, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}
	other := k
	other.ResponseKey = strings.Repeat("ab", 32)
	if w := post(sign(response.TrustBundleStatement(&other))); w.Code != http.StatusBadRequest {
		t.Fatalf("a signature over other keys: %d %s", w.Code, w.Body.String())
	}
	later := k
	later.Epoch = 2
	if w := post(sign(response.TrustBundleStatement(&later))); w.Code != http.StatusBadRequest {
		t.Fatalf("a signature over another epoch: %d %s", w.Code, w.Body.String())
	}
	sig := sign(st.Statement)
	if w := post(sig); w.Code != http.StatusOK {
		t.Fatalf("bundle: %d %s", w.Code, w.Body.String())
	}
	return sig
}

func TestAgentTrustDelivery(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-a", ResponseCapabilities: `{"isolate":true,"collect":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-b", ResponseCapabilities: `{"isolate":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-pve", ResponseCapabilities: `{"isolate":true}`})
	monitorOnly(t, srv, "ep-pve")
	auth := ownerOf(t, srv).auth
	keys, _ := auth.TrustKeys("default")

	// A legacy agent (no trust report) gets none of it.
	legacy := trustBeat(t, srv, "ep-b", nil)
	for _, k := range []string{"trust", "capability_manifest", "enforcement_grants"} {
		if _, ok := legacy[k]; ok {
			t.Fatalf("legacy agent got %s", k)
		}
	}

	// Keys are offered only with the release key's signature over them.
	fresh := &response.AgentTrustReport{V: 1, Keys: "missing"}
	if _, ok := trustBeat(t, srv, "ep-a", fresh)["trust"]; ok {
		t.Fatal("unsigned keys offered")
	}
	sig := signTrustBundle(t, srv, keys)
	out := trustBeat(t, srv, "ep-a", fresh)
	var got response.TrustKeys
	_ = json.Unmarshal(out["trust"], &got)
	want := *keys
	want.Epoch = 1
	want.BundleSig = sig
	if got != want {
		t.Fatalf("offered keys %+v, want %+v", got, want)
	}
	der, _ := base64.StdEncoding.DecodeString(got.BundleSig)
	if response.VerifyReleaseSignature(srv.releasePublicKey(), []byte(response.TrustBundleStatement(&got)), der) != nil {
		t.Fatal("offered bundle does not verify")
	}
	var m response.CapabilityManifest
	if err := json.Unmarshal(out["capability_manifest"], &m); err != nil || m.Profile != "respond" || m.Verify(keyOf(t, keys.PolicyKey)) != nil {
		t.Fatalf("manifest %+v %v", m, err)
	}
	if _, ok := out["enforcement_marks"]; ok {
		t.Fatal("the hub still tells agents which grants to skip")
	}
	pve := trustBeat(t, srv, "ep-pve", fresh)
	_ = json.Unmarshal(pve["capability_manifest"], &m)
	if m.Profile != "monitor" {
		t.Fatalf("monitor-only manifest %q, want monitor", m.Profile)
	}

	// The owner isolates ep-a: the grant reaches ep-a, verifiable by the agent.
	h := srv.Handler()
	body := `{"endpoint_id":"ep-a","allow_ips":["10.0.0.9"],"force":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/isolate", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, srv, h, req, body); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	pinned := &response.AgentTrustReport{V: 1, Keys: "pinned", ResponseKey: true, AutoIsolateKey: true, PolicyKey: true, ManifestSeq: m.Seq, Profile: "respond", IsoSeen: 1, MeshSeen: 1}
	out = trustBeat(t, srv, "ep-a", pinned)
	if _, ok := out["trust"]; ok {
		t.Fatal("keys re-offered to an agent that has them pinned")
	}
	g := grantsIn(t, out)
	if len(g) != 1 || g[0].Grant.ActionKind != response.ActionKindIsolationChange || g[0].Grant.EndpointID != "ep-a" {
		t.Fatalf("grants %+v", g)
	}
	if err := g[0].Grant.Verify(keyOf(t, keys.ResponseKey), time.Now()); err != nil {
		t.Fatalf("delivered grant does not verify: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(g[0].PayloadB64)
	if !strings.Contains(string(payload), `"route":"/api/v1/endpoints/isolate"`) || !strings.Contains(string(payload), `"10.0.0.9"`) {
		t.Fatalf("payload %s", payload)
	}
	if other := grantsIn(t, trustBeat(t, srv, "ep-b", pinned)); len(other) != 0 {
		t.Fatalf("ep-b received ep-a's grant: %+v", other)
	}
	pinned.IsoSeen = g[0].Grant.IssuedAt
	if again := grantsIn(t, trustBeat(t, srv, "ep-a", pinned)); len(again) != 0 {
		t.Fatal("a processed grant was sent again")
	}

	// A mesh quarantine reaches every agent.
	mbody := `{"target_ip":"10.0.0.66","reason":"beaconing"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mesh/quarantine", strings.NewReader(mbody))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, srv, h, req, mbody); w.Code >= 300 {
		t.Fatalf("mesh: %d %s", w.Code, w.Body.String())
	}
	mg := grantsIn(t, trustBeat(t, srv, "ep-b", &response.AgentTrustReport{V: 1, Keys: "pinned", ResponseKey: true, AutoIsolateKey: true, PolicyKey: true, IsoSeen: 1, MeshSeen: 1}))
	if len(mg) != 1 || mg[0].Grant.EndpointID != "mesh:10.0.0.66" {
		t.Fatalf("mesh grants %+v", mg)
	}

	// The detector's isolation is signed with the narrow key.
	srv.signDetectorIsolation("ep-b", "lateral sweep")
	ag := grantsIn(t, trustBeat(t, srv, "ep-b", &response.AgentTrustReport{V: 1, Keys: "pinned", IsoSeen: 1, MeshSeen: mg[0].Grant.IssuedAt}))
	if len(ag) != 1 || ag[0].Grant.ActionKind != response.ActionKindAutoIsolate || ag[0].Grant.Verify(keyOf(t, keys.AutoIsolateKey), time.Now()) != nil {
		t.Fatalf("auto grants %+v", ag)
	}

	// An agent update the owner approved carries its grant.
	ubody := `{"endpoint_ids":["ep-a"],"version":"9.9.9"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agents/update", strings.NewReader(ubody))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, srv, h, req, ubody); w.Code >= 300 {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	ug := srv.updateGrantFor("ep-a", "9.9.9")
	if ug == nil || ug.Grant.ActionKind != response.ActionKindAgentUpdate || ug.Grant.Verify(keyOf(t, keys.ResponseKey), time.Now()) != nil {
		t.Fatalf("update grant %+v", ug)
	}
	if srv.updateGrantFor("ep-a", "9.9.8") != nil || srv.updateGrantFor("ep-b", "9.9.9") != nil {
		t.Fatal("update grant for another version or endpoint")
	}

	// Fleet trust view.
	freq := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/trust", nil)
	freq.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, freq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"verification":"agent"`) || !strings.Contains(w.Body.String(), `"trust_bundle":"signed"`) {
		t.Fatalf("fleet trust %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), keys.ResponseKey) {
		t.Fatal("fleet trust view carries key material")
	}
}

func TestFleetTrustShowsPinnedRoutineKeys(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-r"})
	trustBeat(t, srv, "ep-r", &response.AgentTrustReport{V: 1, Keys: "pinned", RoutineEpoch: 4, RoutineKeys: 2})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/trust", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"routine_epoch":4,"routine_keys":2`) {
		t.Fatalf("fleet trust %d %s", w.Code, w.Body.String())
	}
}

func TestMonitorOnlyNarrowsManifest(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-h", ResponseCapabilities: `{"isolate":true}`})
	out := trustBeat(t, srv, "ep-h", &response.AgentTrustReport{V: 1, Keys: "missing"})
	var m response.CapabilityManifest
	_ = json.Unmarshal(out["capability_manifest"], &m)
	if m.Profile != "respond" {
		t.Fatalf("initial %q", m.Profile)
	}
	monitorOnly(t, srv, "ep-h")
	out = trustBeat(t, srv, "ep-h", &response.AgentTrustReport{V: 1, Keys: "pinned", ManifestSeq: m.Seq, Profile: "respond"})
	var n response.CapabilityManifest
	if err := json.Unmarshal(out["capability_manifest"], &n); err != nil || n.Profile != "monitor" || n.Seq != m.Seq+1 {
		t.Fatalf("after monitor-only: %+v %v", n, err)
	}
	// Lifting it is the owner's raise back to respond.
	cur, _ := store.GetEndpoint("ep-h")
	body := fmt.Sprintf(`{"endpoint_id":"ep-h","reason":"not a hypervisor","revision":%d}`, cur.ResponseProfileRev)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/allow-isolation", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, srv, srv.Handler(), req, body); w.Code != http.StatusOK {
		t.Fatalf("allow-isolation: %d %s", w.Code, w.Body.String())
	}
	out = trustBeat(t, srv, "ep-h", &response.AgentTrustReport{V: 1, Keys: "pinned", ManifestSeq: n.Seq, Profile: "monitor"})
	var r response.CapabilityManifest
	if err := json.Unmarshal(out["capability_manifest"], &r); err != nil || r.Profile != "respond" || r.Seq != n.Seq+1 {
		t.Fatalf("after allow-isolation: %+v %v", r, err)
	}
	// The allow-isolation grant is not an isolation the agent should act on.
	if g := grantsIn(t, out); len(g) != 0 {
		t.Fatalf("allow-isolation produced an enforcement grant: %+v", g)
	}
}

func TestCapabilityChangeNeedsOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-c", ResponseCapabilities: `{"isolate":true}`})
	trustBeat(t, srv, "ep-c", &response.AgentTrustReport{V: 1, Keys: "missing"})
	body := `{"endpoint_id":"ep-c","profile":"engagement","reason":"lab exercise"}`
	if w := adminPost(srv, "/api/v1/endpoints/capabilities", body, ""); w.Code != http.StatusAccepted {
		t.Fatalf("want 202 approval, got %d %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/capabilities", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := serveApproved(t, srv, srv.Handler(), req, body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"script"`) {
		t.Fatalf("capability change: %d %s", w.Code, w.Body.String())
	}
	out := trustBeat(t, srv, "ep-c", &response.AgentTrustReport{V: 1, Keys: "pinned", ManifestSeq: 1, Profile: "respond"})
	var m response.CapabilityManifest
	if err := json.Unmarshal(out["capability_manifest"], &m); err != nil || m.Profile != "engagement" || m.Seq != 2 {
		t.Fatalf("manifest %+v %v", m, err)
	}
}

// A capability raise never outranks the hub's monitor-only setting: the
// manifest is narrowed straight back until allow-isolation lifts it.
func TestCapabilityRaiseKeepsMonitorOnly(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-m", ResponseCapabilities: `{"isolate":true}`})
	monitorOnly(t, srv, "ep-m")
	trustBeat(t, srv, "ep-m", &response.AgentTrustReport{V: 1, Keys: "missing"})
	body := `{"endpoint_id":"ep-m","profile":"engagement","reason":"lab exercise"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/capabilities", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := serveApproved(t, srv, srv.Handler(), req, body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "still_monitor_only") {
		t.Fatalf("capability change: %d %s", w.Code, w.Body.String())
	}
	out := trustBeat(t, srv, "ep-m", &response.AgentTrustReport{V: 1, Keys: "pinned", ManifestSeq: 1, Profile: "monitor"})
	var m response.CapabilityManifest
	if err := json.Unmarshal(out["capability_manifest"], &m); err != nil || m.Profile != "monitor" || m.Seq != 3 {
		t.Fatalf("manifest %+v %v", m, err)
	}
}

func TestIsolationGrantCarriesItsExceptions(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-x", ResponseCapabilities: `{"isolate":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-y", ResponseCapabilities: `{"isolate":true}`})
	reportReady(t, store, "ep-x", "10.0.0.53")
	reportReady(t, store, "ep-y", "10.0.0.53")
	savePolicy(t, store, "resolver", storage.BaselineRule{Service: "dns", Destination: "10.0.0.53"})

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-x"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	pinned := &response.AgentTrustReport{V: 1, Keys: "pinned", ResponseKey: true, AutoIsolateKey: true, PolicyKey: true, IsoSeen: 1, MeshSeen: 1}
	g := grantsIn(t, trustBeat(t, srv, "ep-x", pinned))
	if len(g) != 1 {
		t.Fatalf("grants %+v", g)
	}
	payload, _ := base64.StdEncoding.DecodeString(g[0].PayloadB64)
	if !strings.Contains(string(payload), `"baselines":[{"endpoints":["ep-x"],"rules":[{"destination":"10.0.0.53","port":53,"protocol":"udp","service":"dns"}]}]`) {
		t.Fatalf("payload %s", payload)
	}

	// A failed action withdraws the grants kept for it.
	failing := srv.ownerApproved(srv.resolveIsolate, func(w http.ResponseWriter, r *http.Request) {
		if len(grantedTargets(r)) == 0 {
			t.Error("handler ran without its grants")
		}
		if during := grantsIn(t, trustBeat(t, srv, "ep-y", pinned)); len(during) != 0 {
			t.Error("a grant was delivered before its action succeeded")
		}
		writeJSONError(w, http.StatusInternalServerError, "simulated failure")
	})
	body := `{"endpoint_id":"ep-y"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/isolate", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	req.Header.Set("X-Role", "admin")
	if w := serveApproved(t, srv, srv.authMiddleware(failing), req, body); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing isolate: %d %s", w.Code, w.Body.String())
	}
	if left := grantsIn(t, trustBeat(t, srv, "ep-y", pinned)); len(left) != 0 {
		t.Fatalf("a failed isolation left %d grant(s) for delivery", len(left))
	}
}

func TestPendingGrantsAreReconciled(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-r", ResponseCapabilities: `{"isolate":true}`})
	issued := time.Now().Add(-10 * time.Minute).Unix()
	iso := []byte(`{"body":{"endpoint_id":"ep-r"},"route":"/api/v1/endpoints/isolate","targets":["ep-r"]}`)
	rel := []byte(`{"body":{"endpoint_id":"ep-r"},"route":"/api/v1/endpoints/unisolate","targets":["ep-r"]}`)
	g := func(id string, payload []byte, at int64) storage.StoredGrant {
		return storage.StoredGrant{GrantID: id, TenantID: "default", Target: "ep-r", Kind: "isolation_change", GrantJSON: "{}",
			Payload: payload, IssuedAt: at, ExpiresAt: at + 86400, Pending: true}
	}
	if err := store.SaveEnforcementGrants([]storage.StoredGrant{g("took-effect", iso, issued), g("never-ran", rel, issued+1), g("young", rel, time.Now().Unix())}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointIsolation("ep-r", true, nil); err != nil {
		t.Fatal(err)
	}
	srv.reconcilePendingGrants(time.Now())
	got, err := store.LatestIsolationGrant("ep-r", 0, time.Now().Unix())
	if err != nil || got == nil || got.GrantID != "took-effect" {
		t.Fatalf("delivered %+v %v, want the isolation whose action was recorded", got, err)
	}
	left, _ := store.PendingGrants(time.Now().Unix())
	if len(left) != 1 || left[0].GrantID != "young" {
		t.Fatalf("pending after reconcile %+v, want only the young grant", left)
	}
	// An isolation whose own exceptions were never recorded is withdrawn,
	// even though the host is isolated (with other exceptions).
	wide := []byte(`{"body":{"allow_ips":["10.0.0.9"],"endpoint_id":"ep-r"},"route":"/api/v1/endpoints/isolate","targets":["ep-r"]}`)
	if err := store.SaveEnforcementGrants([]storage.StoredGrant{g("other-holes", wide, issued+2)}); err != nil {
		t.Fatal(err)
	}
	// An expired pending grant is never released, even when the hub's state matches.
	old := time.Now().Add(-48 * time.Hour).Unix()
	exp := g("expired", iso, old)
	exp.ExpiresAt = old + 86400
	if err := store.SaveEnforcementGrants([]storage.StoredGrant{exp}); err != nil {
		t.Fatal(err)
	}
	// At start every pending grant is settled, young ones included.
	srv.reconcilePendingGrantsIssuedBefore(math.MaxInt64, time.Now())
	if left, _ := store.PendingGrants(math.MaxInt64); len(left) != 0 {
		t.Fatalf("pending after the start reconcile %+v", left)
	}
	if got, _ := store.LatestIsolationGrant("ep-r", 0, time.Now().Unix()); got == nil || got.GrantID != "took-effect" {
		t.Fatalf("delivered %+v, want the recorded isolation, not the one with other exceptions", got)
	}
}

func TestApprovedAddressesAreNormalizedBeforeSigning(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	nb, allow, ok := normalizedAllowIPs(rec, []byte(`{"allow_ips":[" 10.0.0.9 ","::ffff:10.0.0.8"],"endpoint_id":"ep-1"}`), []string{" 10.0.0.9 ", "::ffff:10.0.0.8"}, true)
	if !ok || strings.Join(allow, ",") != "10.0.0.9,10.0.0.8" || string(nb) != `{"allow_ips":["10.0.0.9","10.0.0.8"],"endpoint_id":"ep-1"}` {
		t.Fatalf("normalized %s %v %v", nb, allow, ok)
	}
	rec = httptest.NewRecorder()
	if _, _, ok := normalizedAllowIPs(rec, []byte(`{"allow_ips":["host.example"]}`), []string{"host.example"}, true); ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("a non-address allow entry was accepted (%d)", rec.Code)
	}
}

// monitor-scripts (collect, script, update) stands on a monitor-only host:
// it adds no isolation. A hub restart (empty manifest cache) and later beats
// keep it; a raise to engagement is still narrowed back to monitor; and moving
// a respond host to it is a raise, never a silent narrowing.
func TestMonitorScriptsProfile(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-h", ResponseCapabilities: `{"isolate":true}`})
	monitorOnly(t, srv, "ep-h")
	trustBeat(t, srv, "ep-h", &response.AgentTrustReport{V: 1, Keys: "missing"})
	change := func(profile string) string {
		body := `{"endpoint_id":"ep-h","profile":"` + profile + `","reason":"signed upkeep"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/capabilities", strings.NewReader(body))
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := serveApproved(t, srv, srv.Handler(), req, body)
		if w.Code != http.StatusOK {
			t.Fatalf("capability change %s: %d %s", profile, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if b := change("monitor-scripts"); strings.Contains(b, "still_monitor_only") || !strings.Contains(b, `"profile":"monitor-scripts"`) ||
		!strings.Contains(b, `"caps":["collect","script","update"]`) {
		t.Fatalf("monitor-scripts on a monitor-only host: %s", b)
	}
	beat := func(seq int64, profile string) response.CapabilityManifest {
		out := trustBeat(t, srv, "ep-h", &response.AgentTrustReport{V: 1, Keys: "pinned", ManifestSeq: seq, Profile: profile})
		var m response.CapabilityManifest
		if raw, ok := out["capability_manifest"]; ok {
			_ = json.Unmarshal(raw, &m)
		}
		return m
	}
	m := beat(1, "monitor")
	if m.Profile != "monitor-scripts" {
		t.Fatalf("heartbeat narrowed it: %+v", m)
	}
	srv.trust.mu.Lock()
	srv.trust.manifests = map[string]*response.CapabilityManifest{}
	srv.trust.mu.Unlock()
	if again := beat(m.Seq, "monitor-scripts"); again.Profile != "" && again.Profile != "monitor-scripts" {
		t.Fatalf("after a hub restart: %+v", again)
	}
	srv.afterProfileChange(context.Background(), "ep-h")
	if again := beat(m.Seq, "monitor-scripts"); again.Profile != "" && again.Profile != "monitor-scripts" {
		t.Fatalf("after a profile refresh: %+v", again)
	}
	if b := change("engagement"); !strings.Contains(b, "still_monitor_only") || !strings.Contains(b, `"profile":"monitor"`) {
		t.Fatalf("engagement on a monitor-only host: %s", b)
	}

	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-r", ResponseCapabilities: `{"isolate":true}`})
	trustBeat(t, srv, "ep-r", &response.AgentTrustReport{V: 1, Keys: "missing"})
	got, err := srv.responseAuth.EndpointManifest(context.Background(), &responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-r", Profile: "monitor-scripts"})
	if err != nil || got.Profile != "respond" {
		t.Fatalf("respond -> monitor-scripts was signed without approval: %+v %v", got, err)
	}
}
