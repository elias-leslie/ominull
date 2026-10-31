package server

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// fakeAgentLeaf stands for the certificate a TLS handshake verified. The
// handler only reads VerifiedChains, so the leaf need not be signed here.
func fakeAgentLeaf(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, SerialNumber: big.NewInt(notAfter.Unix()),
		NotBefore: notBefore, NotAfter: notAfter}
}

func agentHeartbeat(t *testing.T, srv *Server, credential, endpoint string, leaf *x509.Certificate, capable bool) map[string]any {
	t.Helper()
	body := `{"type":"telemetry","endpoint_id":"` + endpoint + `","ip":"10.0.4.7","events":[]`
	if capable {
		body += `,"cert_renewal":true`
	}
	body += `}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(body))
	r.Header.Set(deviceCredentialHeader, credential)
	r.TLS = &tls.ConnectionState{}
	if leaf != nil {
		r.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	var reply map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func renewalOffer(t *testing.T, reply map[string]any) map[string]any {
	t.Helper()
	offer, _ := reply["client_certificate"].(map[string]any)
	return offer
}

func setupCertEndpoint(t *testing.T, id string) (*Server, *storage.Store, string) {
	t.Helper()
	srv, store := setupTestServer(t)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", IP: "10.0.4.7", Status: "online"}); err != nil {
		t.Fatal(err)
	}
	cred, _, err := store.IssueDeviceCredential(id)
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, cred
}

func TestAgentCertRenewedOverHeartbeatBeforeExpiry(t *testing.T) {
	t.Parallel()
	const ep = "linux-cert-test"
	srv, store, cred := setupCertEndpoint(t, ep)
	defer store.Close()
	now := time.Now().UTC()
	expiring := fakeAgentLeaf(ep, now.Add(-330*24*time.Hour), now.Add(30*24*time.Hour))

	// An agent that cannot install a certificate is never offered one (it
	// would be issued a fresh key on every beat for two months), but its
	// certificate's expiry is still recorded for the feed.
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, expiring, false)); offer != nil {
		t.Fatalf("renewal offered to an agent that did not ask: %v", offer)
	}
	st, err := store.GetAgentCertState(ep)
	if err != nil || !st.NotAfter.Equal(expiring.NotAfter.UTC()) {
		t.Fatalf("expiry not recorded: %+v %v", st, err)
	}

	offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, expiring, true))
	if offer == nil {
		t.Fatal("no renewal for a certificate 30 days from expiry")
	}
	certPEM, _ := base64.StdEncoding.DecodeString(offer["cert_pem_b64"].(string))
	keyPEM, _ := base64.StdEncoding.DecodeString(offer["key_pem_b64"].(string))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("renewed certificate and key do not pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != ep || leaf.NotAfter.Sub(now) < 360*24*time.Hour {
		t.Fatalf("renewed certificate: CN %q, expires %s", leaf.Subject.CommonName, leaf.NotAfter)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: srv.pki.ClientCAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("renewed certificate does not chain to the hub CA: %v", err)
	}
	if pfx, _ := offer["pfx_b64"].(string); pfx == "" {
		t.Fatal("no PKCS#12 form for Windows agents")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate is not PEM")
	}

	// The reply was delivered; the next beat still presents the old
	// certificate (the agent is installing it). No second key within the hour.
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, expiring, true)); offer != nil {
		t.Fatal("renewal offered again on the next beat")
	}
	// Once the agent presents the new one, nothing more is offered.
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, leaf, true)); offer != nil {
		t.Fatal("renewal offered for a fresh certificate")
	}
	st, _ = store.GetAgentCertState(ep)
	if !st.NotAfter.Equal(leaf.NotAfter.UTC()) {
		t.Fatalf("new certificate not recorded: %+v", st)
	}
	logs, _ := store.ListAuditLogs("", 50)
	found := false
	for _, l := range logs {
		found = found || l.Action == "AGENT_CERT_RENEWAL_OFFERED"
	}
	if !found {
		t.Fatal("renewal not audited")
	}
}

func TestAgentCertRenewalOnRequestAndAfterLapse(t *testing.T) {
	t.Parallel()
	const ep = "windows-cert-test"
	srv, store, cred := setupCertEndpoint(t, ep)
	defer store.Close()
	now := time.Now().UTC()
	healthy := fakeAgentLeaf(ep, now.Add(-100*24*time.Hour), now.Add(265*24*time.Hour))
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, healthy, true)); offer != nil {
		t.Fatal("renewal offered for a certificate with 265 days left")
	}

	// An operator asks; the next beat with the old certificate gets one.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/cert-renewal", strings.NewReader(`{"endpoint_id":"`+ep+`"}`))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant key requested a renewal: %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/cert-renewal", strings.NewReader(`{"endpoint_id":"`+ep+`"}`))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("renewal request: %d %s", w.Code, w.Body.String())
	}
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, healthy, true)); offer == nil {
		t.Fatal("requested renewal not offered")
	}
	issuedAfter := fakeAgentLeaf(ep, time.Now().UTC().Add(-10*time.Minute), now.Add(365*24*time.Hour))
	if err := store.MarkAgentCertOffered(ep, now.Add(-2*time.Hour)); err != nil { // past the cooldown
		t.Fatal(err)
	}
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, issuedAfter, true)); offer != nil {
		t.Fatal("request satisfied by a certificate issued after it, but offered again")
	}

	// A Windows agent drops a certificate that has expired and reports under
	// its device credential alone. The hub heals it.
	if err := store.RecordAgentCertSeen(ep, now.Add(-24*time.Hour), "01", now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if offer := renewalOffer(t, agentHeartbeat(t, srv, cred, ep, nil, true)); offer == nil {
		t.Fatal("lapsed certificate not reissued to its credential-authenticated endpoint")
	}
}

func TestAgentCertRenewalReasonTable(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	window := 60 * 24 * time.Hour
	leaf := func(daysLeft int) *x509.Certificate {
		return fakeAgentLeaf("ep", now.Add(-200*24*time.Hour), now.Add(time.Duration(daysLeft)*24*time.Hour))
	}
	for _, tc := range []struct {
		name string
		st   storage.AgentCertState
		leaf *x509.Certificate
		cred bool
		want string
	}{
		{"healthy", storage.AgentCertState{}, leaf(200), true, ""},
		{"inside window", storage.AgentCertState{}, leaf(59), true, "expiring"},
		{"cooldown", storage.AgentCertState{OfferedAt: now.Add(-10 * time.Minute)}, leaf(10), true, ""},
		{"cooldown over", storage.AgentCertState{OfferedAt: now.Add(-2 * time.Hour)}, leaf(10), true, "expiring"},
		{"no cert, never had one", storage.AgentCertState{}, nil, true, ""},
		{"no cert, lapsed", storage.AgentCertState{NotAfter: now.Add(-time.Hour)}, nil, true, "lapsed"},
		{"no cert, lapsed, shared key", storage.AgentCertState{NotAfter: now.Add(-time.Hour)}, nil, false, ""},
		{"no cert, still valid", storage.AgentCertState{NotAfter: now.Add(time.Hour)}, nil, true, ""},
	} {
		if got := agentCertRenewalReason(tc.st, tc.leaf, tc.cred, now, window, time.Hour); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAgentCertFeedWarnsWhenRenewalStalls(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, ep := range []string{"linux-fresh", "windows-stale", "windows-off", "linux-failing"} {
		seen := now
		if ep == "windows-off" {
			seen = now.Add(-30 * 24 * time.Hour)
		}
		if err := store.UpsertEndpoint(storage.Endpoint{ID: ep, Hostname: ep, TenantID: "default", Status: "online", LastSeenAt: seen}); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.RecordAgentCertSeen("linux-fresh", now.Add(300*24*time.Hour), "a", now)
	f, err := srv.agentCertFinding(now)
	if err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved || !strings.Contains(f.Message, "next expires in 300 days") {
		t.Fatalf("healthy fleet: %+v", f)
	}
	if unknown, _ := f.Unmapped["unknown"].([]string); len(unknown) != 3 {
		t.Fatalf("hosts never seen presenting a certificate must be unknown, not fine: %v", f.Unmapped["unknown"])
	}
	_ = store.RecordAgentCertSeen("windows-stale", now.Add(20*24*time.Hour), "b", now)
	f, err = srv.agentCertFinding(now)
	if err != nil {
		t.Fatal(err)
	}
	// The due machine comes first, then the ones with no expiry known, each once.
	if f.SeverityID != ocsfSevMedium || f.StatusID != ocsfStatusNew || len(f.Resources) != 3 || f.Resources[0].UID != "windows-stale" ||
		f.Message != "1 agent certificate not renewed: 1 on an agent too old to renew (update it); 2 endpoints have not shown a certificate yet" {
		t.Fatalf("stalled renewal: %q %+v", f.Message, f.Resources)
	}
	// Each due machine is counted once, by what it needs.
	_ = store.RecordAgentCertSeen("windows-off", now.Add(-24*time.Hour), "c", now.Add(-30*24*time.Hour))
	_ = store.RecordAgentCertSeen("linux-failing", now.Add(10*24*time.Hour), "d", now)
	_ = store.MarkAgentCertOffered("linux-failing", now.Add(-time.Hour))
	f, _ = srv.agentCertFinding(now)
	want := "3 agent certificates not renewed, 1 already expired: 1 machine offline (renews when back; re-enrol it if it cannot reconnect); " +
		"1 on an agent too old to renew (update it); 1 sent a new one that did not install (see its agent log)"
	if f.Message != want || strings.Contains(f.Message, "windows-") || len(f.Resources) != 3 || f.Resources[0].UID != "windows-off" {
		t.Fatalf("got %q\nwant %q", f.Message, want)
	}
	// An hour past expiry is a day ago, not "0 days left"; a renewal in
	// progress is said.
	if got := daysLeft(now.Add(-time.Hour), now); got != -1 {
		t.Fatalf("daysLeft an hour past expiry = %d", got)
	}

	// The finding is in the Nightshift document.
	w := httptest.NewRecorder()
	srv.handleNightshiftFeed(w, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v4", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"uid":"ominull.agents.certificate"`) {
		t.Fatalf("feed lacks the certificate finding: %d", w.Code)
	}
}

func TestAgentCertFeedNamesUnknownAndRenewingHosts(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, ep := range []string{"desk", "laptop", "server"} {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: ep, Hostname: ep, TenantID: "default", Status: "online"}); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := srv.agentCertFinding(now)
	if f.StatusID != ocsfStatusResolved || f.Message != "No expiry known yet: agents report their certificate when they next connect, nothing to do (3 endpoints)" || len(f.Resources) != 3 {
		t.Fatalf("nothing recorded yet: %q", f.Message)
	}
	_ = store.RecordAgentCertSeen("desk", now.Add(300*24*time.Hour), "a", now)
	_ = store.RecordAgentCertSeen("server", now.Add(50*24*time.Hour), "b", now)
	_ = store.MarkAgentCertOffered("server", now.Add(-10*time.Minute))
	f, _ = srv.agentCertFinding(now)
	// server is both the next to expire and the one renewing: listed once.
	want := "Agent certificates renew by themselves 60 days before expiry; the next expires in 50 days; renewal sent to 1 endpoint; 1 endpoint has not shown a certificate yet"
	if f.StatusID != ocsfStatusResolved || f.Message != want || len(f.Resources) != 2 || f.Resources[1].UID != "laptop" {
		t.Fatalf("got %q\nwant %q", f.Message, want)
	}
}

func TestAgentCertRenewalRequestErrors(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	_ = store.UpsertEndpoint(storage.Endpoint{ID: "old", Hostname: "old", TenantID: "default", Status: "retired"})
	for body, want := range map[string]int{`{}`: 400, `{"endpoint":"old"}`: 400, `{"endpoint_id":"nope"}`: 404, `{"endpoint_id":"old"}`: 409} {
		w := httptest.NewRecorder()
		srv.handleAgentCertRenewal(w, httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/cert-renewal", strings.NewReader(body)))
		if w.Code != want {
			t.Errorf("%s: %d %s, want %d", body, w.Code, w.Body.String(), want)
		}
	}
}

func TestAgentCertNeverOfferedWithoutTLS(t *testing.T) {
	t.Parallel()
	srv, store, cred := setupCertEndpoint(t, "plain-ep")
	defer store.Close()
	_ = store.RequestAgentCertRenewal("plain-ep", time.Now().UTC().Add(-time.Minute))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(`{"type":"telemetry","endpoint_id":"plain-ep","ip":"10.0.4.7","events":[],"cert_renewal":true}`))
	r.Header.Set(deviceCredentialHeader, cred)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "client_certificate") {
		t.Fatal("a private key went out over a connection without TLS")
	}
}
