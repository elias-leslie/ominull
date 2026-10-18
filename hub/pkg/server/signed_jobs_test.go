package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

type signedFixture struct {
	srv   *Server
	priv  ed25519.PrivateKey
	keyID string
}

func newSignedFixture(t *testing.T, role string) *signedFixture {
	t.Helper()
	srv := playbookTestServer(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(pub)
	f := &signedFixture{srv: srv, priv: priv, keyID: hex.EncodeToString(fp[:])}
	f.report(true, role)
	return f
}

// report records the endpoint's trust report as its agent would send it.
func (f *signedFixture) report(hostAuthority bool, role string) {
	rep := response.AgentTrustReport{V: 1, HostAuthority: hostAuthority}
	if hostAuthority {
		rep.HostKeys = []response.HostKeyReport{{ID: f.keyID, Role: role}}
	}
	f.srv.trust.mu.Lock()
	f.srv.trust.init()
	f.srv.trust.reports["ep-lap"] = trustReportSeen{report: rep, at: time.Now()}
	f.srv.trust.mu.Unlock()
}

const signedPayload = `{"script_id":"nightshift-scrub","script_version":1,"script_digest":"%s","interpreter":"/bin/sh",` +
	`"source":"echo <scrub> & done\n","parameters":{"mode":"audit"},"timeout_seconds":600,"max_output_bytes":65536}`

func signedPayloadJSON() string {
	sum := sha256.Sum256([]byte("echo <scrub> & done\n"))
	return strings.Replace(signedPayload, "%s", hex.EncodeToString(sum[:]), 1)
}

type reserveAnswer struct {
	JobID        string `json:"job_id"`
	PayloadJSON  string `json:"payload_json"`
	ActionDigest string `json:"action_digest"`
	TenantID     string `json:"tenant_id"`
	EndpointID   string `json:"endpoint_id"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (f *signedFixture) reserve(t *testing.T, payload string) reserveAnswer {
	t.Helper()
	w := adminDo(f.srv, http.MethodPost, "/api/v1/endpoints/ep-lap/jobs/signed/reserve", `{"payload":`+payload+`}`)
	var r reserveAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &r) != nil {
		t.Fatalf("reserve: %d %s", w.Code, w.Body.String())
	}
	return r
}

func (f *signedFixture) grant(r reserveAnswer, operator string) *response.EndpointGrant {
	now := time.Now().Unix()
	g := &response.EndpointGrant{Version: response.GrantVersionJob, GrantID: "ns-" + r.JobID[:8], TenantID: r.TenantID,
		EndpointID: r.EndpointID, ActionKind: response.ActionKindScriptExec, ActionDigest: r.ActionDigest, OperatorID: operator,
		IssuedAt: now, ExpiresAt: now + 600, Nonce: "00112233445566778899aabbccddeeff", JobID: r.JobID, SignerKeyID: f.keyID}
	g.Signature = hex.EncodeToString(ed25519.Sign(f.priv, g.CanonicalBytes()))
	return g
}

func (f *signedFixture) submit(payload string, g *response.EndpointGrant) (int, string) {
	gj, _ := json.Marshal(g)
	w := adminDo(f.srv, http.MethodPost, "/api/v1/endpoints/ep-lap/jobs/signed", `{"payload":`+payload+`,"grant":`+string(gj)+`}`)
	return w.Code, w.Body.String()
}

// The courier queues a Nightshift-signed script job under the reserved id,
// with the canonical payload the grant's digest covers, and the offer carries
// the V3 grant unchanged. It never signs anything itself.
func TestSignedJobCourier(t *testing.T) {
	t.Parallel()
	f := newSignedFixture(t, "tap")
	payload := signedPayloadJSON()
	r := f.reserve(t, payload)
	sum := sha256.Sum256([]byte(r.PayloadJSON))
	if r.ActionDigest != hex.EncodeToString(sum[:]) || r.EndpointID != "ep-lap" || r.TenantID != "default" {
		t.Fatalf("reserve answer: %+v", r)
	}
	// Go's encoding: HTML characters escaped, so the signer signs these bytes, not its own.
	if !strings.Contains(r.PayloadJSON, `\u003cscrub\u003e \u0026 done`) {
		t.Fatalf("payload_json is not the canonical encoding: %s", r.PayloadJSON)
	}
	g := f.grant(r, response.OperatorNightshiftTap)
	if code, body := f.submit(payload, g); code != http.StatusOK || !strings.Contains(body, r.JobID) {
		t.Fatalf("submit: %d %s", code, body)
	}
	offers := offerAndAck(t, f.srv, "ep-lap")
	if len(offers) != 1 || offers[0].JobID != r.JobID || offers[0].PayloadJSON != r.PayloadJSON {
		t.Fatalf("offer: %+v", offers)
	}
	og := offers[0].Grant
	if og.Version != 3 || og.JobID != r.JobID || og.Signature != g.Signature {
		t.Fatalf("offered grant: %+v", og)
	}
	pub := f.priv.Public().(ed25519.PublicKey)
	if err := og.Verify(pub, time.Now()); err != nil {
		t.Fatalf("offered grant does not verify: %v", err)
	}
	job, err := f.srv.responseStore.GetJob("default", r.JobID)
	if err != nil || job.RequestedBy != response.OperatorNightshiftTap {
		t.Fatalf("job: %+v %v", job, err)
	}
	if got := requesterLabel(job.RequestedBy); !strings.Contains(got, "signed by Nightshift") {
		t.Fatalf("label %q", got)
	}

	// The same reservation cannot carry a second grant.
	if code, _ := f.submit(payload, g); code != http.StatusConflict {
		t.Fatalf("replayed submit: %d", code)
	}
}

func TestSignedJobRefusals(t *testing.T) {
	t.Parallel()
	f := newSignedFixture(t, "tap")
	payload := signedPayloadJSON()

	cases := []struct {
		name   string
		mutate func(g *response.EndpointGrant)
		resign bool
		want   string
	}{
		{"auto operator on a tap key", func(g *response.EndpointGrant) { g.OperatorID = response.OperatorNightshiftAuto }, true, "role"},
		{"other operator", func(g *response.EndpointGrant) { g.OperatorID = "alice" }, true, "operator"},
		{"v2", func(g *response.EndpointGrant) { g.Version = 2; g.JobID = ""; g.ResponseSessionID = "s" }, true, "V3"},
		{"other digest", func(g *response.EndpointGrant) { g.ActionDigest = strings.Repeat("ab", 32) }, true, "digest"},
		{"unknown signer", func(g *response.EndpointGrant) { g.SignerKeyID = strings.Repeat("cd", 32) }, true, "signer"},
		{"too long", func(g *response.EndpointGrant) { g.ExpiresAt = g.IssuedAt + 7200 }, true, "hour"},
		{"session id", func(g *response.EndpointGrant) { g.ResponseSessionID = "sess" }, true, "response_session_id"},
	}
	for _, c := range cases {
		r := f.reserve(t, payload)
		g := f.grant(r, response.OperatorNightshiftTap)
		c.mutate(g)
		if c.resign {
			g.Signature = hex.EncodeToString(ed25519.Sign(f.priv, g.CanonicalBytes()))
		}
		code, body := f.submit(payload, g)
		if code == http.StatusOK || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", c.name, code, body)
		}
	}

	// A grant for a job id that was never reserved.
	r := f.reserve(t, payload)
	g := f.grant(r, response.OperatorNightshiftTap)
	g.JobID = "6f1c2a8e-0000-4000-8000-000000000000"
	g.Signature = hex.EncodeToString(ed25519.Sign(f.priv, g.CanonicalBytes()))
	if code, body := f.submit(payload, g); code != http.StatusConflict {
		t.Errorf("unreserved job id: %d %s", code, body)
	}

	// An edited payload no longer matches the grant.
	r = f.reserve(t, payload)
	g = f.grant(r, response.OperatorNightshiftTap)
	edited := strings.Replace(payload, `"timeout_seconds":600`, `"timeout_seconds":900`, 1)
	if code, body := f.submit(edited, g); code != http.StatusBadRequest || !strings.Contains(body, "digest") {
		t.Errorf("edited payload: %d %s", code, body)
	}

	// Payload checks at reserve time.
	for _, bad := range []string{
		strings.Replace(payload, `"interpreter"`, `"extra":1,"interpreter"`, 1),
		strings.Replace(payload, `echo <scrub>`, `echo <other>`, 1), // digest no longer the source's
		strings.Replace(payload, `"timeout_seconds":600`, `"timeout_seconds":7200`, 1),
	} {
		w := adminDo(f.srv, http.MethodPost, "/api/v1/endpoints/ep-lap/jobs/signed/reserve", `{"payload":`+bad+`}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("bad payload reserved: %d %s", w.Code, w.Body.String())
		}
	}

	// Only endpoints whose agent reports a host authority.
	f.report(false, "")
	w := adminDo(f.srv, http.MethodPost, "/api/v1/endpoints/ep-lap/jobs/signed/reserve", `{"payload":`+payload+`}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("no host authority: %d %s", w.Code, w.Body.String())
	}
	if w := adminDo(f.srv, http.MethodPost, "/api/v1/endpoints/ep-gone/jobs/signed/reserve", `{"payload":`+payload+`}`); w.Code != http.StatusNotFound {
		t.Errorf("unknown endpoint: %d", w.Code)
	}
}

// V3 canonical bytes: V2's fields with the V3 tag, job_id after the nonce.
// The hex is pinned so the agent's encoder (test_response_canonical.c)
// checks against the same bytes.
func TestGrantV3Canonical(t *testing.T) {
	g := response.EndpointGrant{Version: 3, GrantID: "g-1", TenantID: "default", EndpointID: "ep-1", ActionKind: "script_exec",
		ActionDigest: strings.Repeat("AB", 32), OperatorID: "nightshift:tap", ResponseSessionID: "", IssuedAt: 1760000000,
		ExpiresAt: 1760000600, Nonce: "00FF", JobID: "job-1", SignerKeyID: strings.Repeat("cd", 32)}
	got := hex.EncodeToString(g.CanonicalBytes())
	if got != grantV3Golden {
		t.Fatalf("V3 canonical bytes changed:\n%s", got)
	}
	v2 := g
	v2.Version = 2
	if strings.Contains(string(v2.CanonicalBytes()), "job-1") || !strings.Contains(string(v2.CanonicalBytes()), "GRANT-V2") {
		t.Fatal("V2 bytes must not carry the job id")
	}
}

const grantV3Golden = "000000194f4d494e554c4c2d454e44504f494e542d4752414e542d56330000000300000003672d310000000764656661756c740000000465702d310000000b7363726970745f6578656300000040616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620000000e6e6967687473686966743a746170000000000000000068e778000000000068e77a580000000430306666000000056a6f622d310000004063646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364"
