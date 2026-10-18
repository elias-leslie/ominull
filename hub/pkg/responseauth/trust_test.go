package responseauth_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/responseauth/approvaltest"
)

func pub(t *testing.T, h string) ed25519.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("bad key %q", h)
	}
	return b
}

// approveAndConsume runs one owner approval end to end.
func approveAndConsume(t *testing.T, auth *responseauth.Authority, ap *approvaltest.Approver, in *responseauth.ApprovalRequestInput) []*response.EndpointGrant {
	t.Helper()
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	grants, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: in.TenantID, Requester: in.Requester, Kind: in.Kind, Digest: digestOf(in.Payload), Targets: in.Targets})
	if err != nil {
		t.Fatal(err)
	}
	return grants
}

func routedPayload(route string, body map[string]interface{}, targets []string) []byte {
	b, _ := json.Marshal(body)
	raw, _ := json.Marshal(map[string]interface{}{"route": route, "body": json.RawMessage(b), "targets": targets})
	return raw
}

func TestTrustKeysAreThreeDistinctStableKeys(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	k1, err := auth.TrustKeys("default")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := auth.TrustKeys("default")
	if *k1 != *k2 {
		t.Fatal("trust keys changed between calls")
	}
	if k1.ResponseKey == k1.AutoIsolateKey || k1.ResponseKey == k1.PolicyKey || k1.AutoIsolateKey == k1.PolicyKey {
		t.Fatal("trust keys are not distinct")
	}
	resp, _, _ := auth.GetOrCreateTenantKey("default")
	if hex.EncodeToString(resp) != k1.ResponseKey {
		t.Fatal("response key is not the tenant key")
	}
	for _, bad := range []string{"default#policy", "a/b", ""} {
		if _, err := auth.TrustKeys(bad); err == nil {
			t.Fatalf("tenant %q accepted", bad)
		}
	}
	if _, _, err := auth.GetOrCreateTenantKey("default#auto-isolate"); err == nil {
		t.Fatal("a slot key was reachable as a tenant")
	}
}

func TestAutoIsolationIsNarrowAndRationed(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	keys, _ := auth.TrustKeys("default")
	g, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1", Reason: "port sweep"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Grant.ActionKind != response.ActionKindAutoIsolate || g.Grant.ExpiresAt-g.Grant.IssuedAt != 600 {
		t.Fatalf("auto grant %+v", g.Grant)
	}
	if err := g.Grant.Verify(pub(t, keys.AutoIsolateKey), time.Now()); err != nil {
		t.Fatalf("auto grant does not verify under the auto key: %v", err)
	}
	if err := g.Grant.Verify(pub(t, keys.ResponseKey), time.Now()); err == nil {
		t.Fatal("auto grant verifies under the owner key")
	}
	payload, _ := base64.StdEncoding.DecodeString(g.PayloadB64)
	var p struct {
		Route   string   `json:"route"`
		Targets []string `json:"targets"`
	}
	if json.Unmarshal(payload, &p) != nil || p.Route != response.AutoIsolateRoute || len(p.Targets) != 1 || p.Targets[0] != "ep-1" {
		t.Fatalf("auto payload %s", payload)
	}
	if _, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1"}); !errors.Is(err, responseauth.ErrAutoIsolateRateLimit) {
		t.Fatalf("second isolation of the same endpoint within 10 min: %v", err)
	}
	last := g.Grant.IssuedAt
	for i := 2; i <= 6; i++ {
		g, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-" + string(rune('0'+i))})
		if err != nil {
			t.Fatalf("isolation %d: %v", i, err)
		}
		if g.Grant.IssuedAt <= last {
			t.Fatal("auto grants are not strictly ordered")
		}
		last = g.Grant.IssuedAt
	}
	if _, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-7"}); !errors.Is(err, responseauth.ErrAutoIsolateRateLimit) {
		t.Fatalf("seventh isolation in an hour: %v", err)
	}
	if _, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "mesh:10.0.0.1"}); err == nil {
		t.Fatal("auto isolation of a mesh target accepted")
	}
}

func TestEnforcementGrantsAreStrictlyOrdered(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	a := approveAndConsume(t, auth, ap, isolateRequest())
	in := isolateRequest()
	in.Payload = routedPayload("/api/v1/endpoints/unisolate", map[string]interface{}{"endpoint_id": "ep-1"}, []string{"ep-1"})
	b := approveAndConsume(t, auth, ap, in)
	if b[0].IssuedAt <= a[0].IssuedAt {
		t.Fatalf("release issued at %d, isolation at %d", b[0].IssuedAt, a[0].IssuedAt)
	}
	if a[0].ExpiresAt-a[0].IssuedAt != 86400 {
		t.Fatalf("isolation grant lives %d s, want 24 h", a[0].ExpiresAt-a[0].IssuedAt)
	}
}

func TestNonCanonicalPayloadRefused(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	for name, raw := range map[string]string{
		"spaces":      `{"body": {"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`,
		"case keys":   `{"Route":"/api/v1/endpoints/unisolate","body":{"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`,
		"escaped key": `{"body":{"endpoint_id":"ep-1"},"rout\u0065":"/api/v1/endpoints/isolate","targets":["ep-1"]}`,
		"dup key":     `{"body":{"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`,
	} {
		in := isolateRequest()
		in.Payload = []byte(raw)
		if _, err := auth.RequestApproval(in); err == nil {
			t.Fatalf("%s payload accepted", name)
		}
	}
	in := isolateRequest()
	in.TenantID = "default#policy"
	if _, err := auth.RequestApproval(in); err == nil {
		t.Fatal("slot tenant accepted")
	}
}

func TestManifestLifecycle(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	keys, _ := auth.TrustKeys("default")
	polKey := pub(t, keys.PolicyKey)
	m, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1"})
	if err != nil || m.Profile != "respond" || m.Seq != 1 {
		t.Fatalf("initial manifest %+v %v", m, err)
	}
	if err := m.Verify(polKey); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-2", Profile: "engagement"}); !errors.Is(err, responseauth.ErrManifestNeedsApproval) {
		t.Fatalf("initial engagement without approval: %v", err)
	}
	same, _ := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1", Profile: "engagement"})
	if same.Seq != 1 || same.Profile != "respond" {
		t.Fatalf("a raise without approval changed the manifest: %+v", same)
	}
	narrow, _ := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1", Profile: "monitor"})
	if narrow.Seq != 2 || narrow.Profile != "monitor" || narrow.Verify(polKey) != nil {
		t.Fatalf("narrowing: %+v", narrow)
	}

	// Lifting monitor-only raises to respond when the owner's approval is used.
	allow := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindIsolation, Targets: []string{"ep-1"},
		Payload: routedPayload("/api/v1/endpoints/allow-isolation", map[string]interface{}{"endpoint_id": "ep-1", "reason": "lab", "revision": 1}, []string{"ep-1"})}
	approveAndConsume(t, auth, ap, allow)
	raised, _ := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1"})
	if raised.Seq != 3 || raised.Profile != "respond" {
		t.Fatalf("after allow-isolation: %+v", raised)
	}

	// Engagement only through a capability_change approval.
	change := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindCapability, Targets: []string{"ep-1"},
		Payload: routedPayload("/api/v1/endpoints/capabilities", map[string]interface{}{"endpoint_id": "ep-1", "profile": "engagement", "reason": "pentest"}, []string{"ep-1"})}
	v, err := auth.RequestApproval(change)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Summary, "engagement") {
		t.Fatalf("summary %q does not name the profile", v.Summary)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin", Kind: change.Kind, Digest: digestOf(change.Payload), Targets: change.Targets}); err != nil {
		t.Fatal(err)
	}
	eng, _ := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1"})
	if eng.Seq != 4 || eng.Profile != "engagement" || !eng.Has(response.CapScript) || eng.Verify(polKey) != nil {
		t.Fatalf("after capability approval: %+v", eng)
	}
}

func TestIsolationExceptionsAreApprovedWithTheIsolation(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	mk := func(baselines interface{}, route string, targets []string) *responseauth.ApprovalRequestInput {
		body := map[string]interface{}{"endpoint_id": targets[0]}
		if route == "/api/v1/endpoints/isolate-bulk" {
			body = map[string]interface{}{"scope": "ids", "ids": targets}
		}
		fields := map[string]interface{}{"route": route, "body": body, "targets": targets}
		if baselines != nil {
			fields["baselines"] = baselines
		}
		raw, _ := json.Marshal(fields)
		return &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindIsolation, Targets: targets, Payload: raw}
	}
	dns := []response.IsolationBaseline{{Endpoints: []string{"ep-1"}, Rules: []response.IsolationRule{{Destination: "10.0.0.53", Port: 53, Protocol: "udp", Service: "dns"}}}}
	v, err := auth.RequestApproval(mk(dns, "/api/v1/endpoints/isolate", []string{"ep-1"}))
	if err != nil || !strings.Contains(v.Summary, "exceptions: dns udp/53 10.0.0.53") {
		t.Fatalf("summary %+v %v", v, err)
	}
	bad := map[string]interface{}{
		"endpoint not a target": []response.IsolationBaseline{{Endpoints: []string{"ep-2"}, Rules: dns[0].Rules}},
		"endpoint twice":        []response.IsolationBaseline{dns[0], dns[0]},
		"name destination":      []response.IsolationBaseline{{Endpoints: []string{"ep-1"}, Rules: []response.IsolationRule{{Destination: "example", Port: 53, Protocol: "udp", Service: "dns"}}}},
		"cidr destination":      []response.IsolationBaseline{{Endpoints: []string{"ep-1"}, Rules: []response.IsolationRule{{Destination: "0.0.0.0/0", Port: 53, Protocol: "udp", Service: "dns"}}}},
		"port 0":                []response.IsolationBaseline{{Endpoints: []string{"ep-1"}, Rules: []response.IsolationRule{{Destination: "10.0.0.53", Port: 0, Protocol: "udp", Service: "dns"}}}},
		"protocol any":          []response.IsolationBaseline{{Endpoints: []string{"ep-1"}, Rules: []response.IsolationRule{{Destination: "10.0.0.53", Port: 53, Protocol: "any", Service: "dns"}}}},
	}
	for name, b := range bad {
		if _, err := auth.RequestApproval(mk(b, "/api/v1/endpoints/isolate", []string{"ep-1"})); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A release cannot carry exceptions, and no other top-level member passes.
	rel := mk(dns, "/api/v1/endpoints/isolate", []string{"ep-1"})
	rel.Payload = []byte(strings.Replace(string(rel.Payload), "/api/v1/endpoints/isolate", "/api/v1/endpoints/unisolate", 1))
	if _, err := auth.RequestApproval(rel); err == nil {
		t.Fatal("a release with exceptions accepted")
	}
	extra := isolateRequest()
	extra.Payload = []byte(`{"body":{"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"],"zzz":1}`)
	if _, err := auth.RequestApproval(extra); err == nil {
		t.Fatal("an unknown payload member accepted")
	}
	upper := isolateRequest()
	upper.Payload = []byte(`{"body":{"Endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`)
	if _, err := auth.RequestApproval(upper); err == nil {
		t.Fatal("an upper-case key accepted")
	}
	// The detector's narrow grant carries the host's own exceptions only.
	g, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1", Baselines: dns})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(g.PayloadB64)
	if !strings.Contains(string(payload), `"baselines":[{"endpoints":["ep-1"],"rules":[{"destination":"10.0.0.53","port":53,"protocol":"udp","service":"dns"}]}]`) {
		t.Fatalf("auto payload %s", payload)
	}
	if _, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-9", Baselines: dns}); err == nil {
		t.Fatal("auto isolation with another host's exceptions accepted")
	}
}

func TestCorruptEnforcementClockRefusesToSign(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	if err := os.WriteFile(filepath.Join(dir, "enforcement_clock.json"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1"}); err == nil {
		t.Fatal("signed with a corrupt enforcement clock")
	}
	// A good clock is persisted before a time is handed out.
	dir2 := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir2, "keys"), 0o700)
	auth2, _ := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir2}, responseauth.NewMemoryStore())
	if _, err := auth2.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1"}); err == nil {
		t.Fatal("the detector brought a tenant into being")
	}
	_, _ = auth2.TrustKeys("default")
	g, err := auth2.SignAutoIsolation(&responseauth.AutoIsolateRequest{TenantID: "default", EndpointID: "ep-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir2, "enforcement_clock.json"))
	if string(raw) != fmt.Sprintf(`{"default":%d}`, g.Grant.IssuedAt) {
		t.Fatalf("clock file %q, grant issued %d", raw, g.Grant.IssuedAt)
	}
}

func TestTrustEpochIsTheAuthoritysAndManifestsFollowThePolicyKey(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	store := responseauth.NewMemoryStore()
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, store)
	if err != nil {
		t.Fatal(err)
	}
	k, err := auth.TrustKeys("default")
	if err != nil || k.Epoch != 1 {
		t.Fatalf("first epoch %+v %v", k, err)
	}
	if k2, _ := auth.TrustKeys("default"); k2.Epoch != 1 {
		t.Fatalf("epoch moved without a key change: %d", k2.Epoch)
	}
	m, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1"})
	if err != nil {
		t.Fatal(err)
	}
	// A floor set by root on the authority host raises the epoch.
	auth2, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir, TrustEpochFloor: 7}, store)
	if err != nil {
		t.Fatal(err)
	}
	if k3, _ := auth2.TrustKeys("default"); k3.Epoch != 7 || k3.ResponseKey != k.ResponseKey {
		t.Fatalf("after the floor: %+v", k3)
	}
	// A manifest signed under a retired policy key is re-signed at the next seq.
	raw, _ := os.ReadFile(filepath.Join(dir, "manifests.json"))
	_ = os.WriteFile(filepath.Join(dir, "manifests.json"), []byte(strings.Replace(string(raw), m.SignerKeyID, strings.Repeat("0", 64), 1)), 0o600)
	auth3, _ := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, store)
	n, err := auth3.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-1"})
	if err != nil || n.Seq != m.Seq+1 || n.SignerKeyID != m.SignerKeyID || n.Profile != m.Profile {
		t.Fatalf("re-signed manifest %+v %v (was %+v)", n, err, m)
	}
}

// A manifest signed before a release added a capability to its profile (screen
// joined respond in 1.8.80) is re-signed with the profile's current list, same
// profile, next seq; one that already matches is left alone.
func TestManifestFollowsItsProfileAcrossReleases(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	open := func() *responseauth.Authority {
		a, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	auth := open()
	req := &responseauth.ManifestRequest{TenantID: "default", EndpointID: "ep-old"}
	m, err := auth.EndpointManifest(req)
	if err != nil || m.Seq != 1 || !m.Has(response.CapScreen) {
		t.Fatalf("initial manifest %+v %v", m, err)
	}
	again, _ := auth.EndpointManifest(req)
	if again.Seq != 1 {
		t.Fatalf("a manifest that matches its profile was re-signed: %+v", again)
	}

	// Rewrite the stored manifest as an older release signed it: respond
	// without screen.
	path := filepath.Join(dir, "manifests.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 {
		t.Fatalf("manifests.json: %v %d", err, len(list))
	}
	list[0]["caps"] = []string{"collect", "isolate", "mesh", "terminal", "update"}
	raw, _ = json.Marshal(list)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	auth = open()
	keys, _ := auth.TrustKeys("default")
	n, err := auth.EndpointManifest(req)
	if err != nil {
		t.Fatal(err)
	}
	if n.Seq != 2 || n.Profile != "respond" || !n.Has(response.CapScreen) || !n.MatchesProfile() || n.Verify(pub(t, keys.PolicyKey)) != nil {
		t.Fatalf("stale manifest not refreshed: %+v", n)
	}
	if still, _ := auth.EndpointManifest(req); still.Seq != 2 {
		t.Fatalf("refreshed manifest re-signed again: %+v", still)
	}
}
