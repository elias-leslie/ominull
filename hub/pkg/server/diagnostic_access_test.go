package server

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/configuration"
	"ominull/hub/pkg/diagnostics"
	"ominull/hub/pkg/storage"
)

// Cloudflare Access authenticates every console sign-in on a hub that runs in
// LAN mode with its agents reaching it directly, and until these tests the only
// Cloudflare row in the diagnostic list was the Tunnel adapter's - which reports
// not_configured on exactly that deployment, and used to say so in words that
// claimed Cloudflare was doing nothing at all.

// jwksHost rewrites every outbound request to a local test server, so the
// verifier's real URL construction is exercised without the production code
// carrying a test hook for it.
type jwksHost struct{ host string }

func (j jwksHost) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = j.host
	return http.DefaultTransport.RoundTrip(clone)
}

func jwksServing(t *testing.T, keys ...*rsa.PublicKey) *httptest.Server {
	t.Helper()
	entries := make([]map[string]string, 0, len(keys))
	for i, key := range keys {
		entries = append(entries, map[string]string{
			"kid": "kid-" + string(rune('1'+i)),
			"kty": "RSA",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cdn-cgi/access/certs") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": entries})
	}))
	t.Cleanup(server.Close)
	return server
}

func saveAccessConfiguration(t *testing.T, store *storage.Store, team, aud string) {
	t.Helper()
	encoded, err := json.Marshal(configuration.Config{
		NetworkMode: "lan", ConsoleURL: "http://10.0.0.58:9999", AgentURL: "https://10.0.0.58:9443",
		TLSMode: "self-issued", ClientCerts: "required",
		AccessTeam: team, AccessAudience: aud, Cloudflare: false,
	}.Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("setup.configuration", string(encoded)); err != nil {
		t.Fatal(err)
	}
}

func resultFor(t *testing.T, srv *Server, id string) diagnostics.Result {
	t.Helper()
	for _, result := range srv.runDiagnostics(context.Background()) {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("no diagnostic with id %q; the check list does not cover it", id)
	return diagnostics.Result{}
}

// A hub with no Access in front of it must say so plainly rather than reporting
// a gap.
func TestAccessCheckIsNotConfiguredWithoutAnAccessApplication(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	got := resultFor(t, srv, "access")
	if got.State != diagnostics.NotConfigured {
		t.Fatalf("state %q, want not_configured: %+v", got.State, got)
	}
}

// Saved but not loaded is a restart away from working and invisible from the
// operator's side: Access says they signed in, the hub shows them the key prompt.
func TestAccessCheckFailsWhenConfigurationIsSavedButNoVerifierIsLive(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	saveAccessConfiguration(t, store, "testteam", "aud-for-this-application")

	got := resultFor(t, srv, "access")
	if got.State != diagnostics.Fail {
		t.Fatalf("state %q, want fail: %+v", got.State, got)
	}
}

// The distinction the OIDC check already draws: reachable and configured is not
// the same as ever actually having verified anybody.
func TestAccessCheckWarnsUntilAnAssertionHasVerified(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	saveAccessConfiguration(t, store, "testteam", "aud-for-this-application")

	verifier, key := testVerifier(t, oneAdmin())
	fake := jwksServing(t, &key.PublicKey)
	verifier.client = &http.Client{Transport: jwksHost{host: strings.TrimPrefix(fake.URL, "http://")}, Timeout: 5 * time.Second}
	srv.access = verifier

	got := resultFor(t, srv, "access")
	if got.State != diagnostics.Warn {
		t.Fatalf("state %q, want warn: %+v", got.State, got)
	}
	if !strings.Contains(got.Evidence, "signing key(s) published at https://testteam.cloudflareaccess.com/cdn-cgi/access/certs") {
		t.Errorf("evidence does not name the key set it reached: %q", got.Evidence)
	}

	if err := store.SetSetting(accessLastSuccessSetting, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	got = resultFor(t, srv, "access")
	if got.State != diagnostics.Pass {
		t.Fatalf("state %q, want pass once an assertion has verified: %+v", got.State, got)
	}
	if !strings.Contains(got.Evidence, "last verified assertion") {
		t.Errorf("a passing Access check must say when an assertion last verified: %q", got.Evidence)
	}
}

// Unreachable keys with none cached means nobody can sign in, and the check has
// to say that rather than report the configuration back.
func TestAccessCheckFailsWhenTheSigningKeysAreUnreachable(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	saveAccessConfiguration(t, store, "testteam", "aud-for-this-application")

	verifier, _ := testVerifier(t, oneAdmin())
	verifier.keys = map[string]*rsa.PublicKey{}
	dead := jwksServing(t)
	host := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	verifier.client = &http.Client{Transport: jwksHost{host: host}, Timeout: time.Second}
	srv.access = verifier

	got := resultFor(t, srv, "access")
	if got.State != diagnostics.Fail {
		t.Fatalf("state %q, want fail: %+v", got.State, got)
	}
}

// A cached key set outlives a failed refetch on purpose, so an unreachable
// Cloudflare is a warning about the next rotation, not a broken console.
func TestAccessCheckWarnsWhenKeysAreCachedButCloudflareIsUnreachable(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	saveAccessConfiguration(t, store, "testteam", "aud-for-this-application")
	if err := store.SetSetting(accessLastSuccessSetting, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	verifier, _ := testVerifier(t, oneAdmin())
	dead := jwksServing(t)
	host := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	verifier.client = &http.Client{Transport: jwksHost{host: host}, Timeout: time.Second}
	srv.access = verifier

	got := resultFor(t, srv, "access")
	if got.State != diagnostics.Warn {
		t.Fatalf("state %q, want warn: %+v", got.State, got)
	}
}

// The marker is what survives a restart, so the check can answer "has Cloudflare
// ever actually verified anybody" rather than only "is it configured".
func TestAVerifiedAssertionRecordsTheLastSuccessMarker(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertOperator("operator@example.com", "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if err := srv.SetAccess(AccessOptions{Team: "testteam", AUD: "aud-for-this-application"}); err != nil {
		t.Fatal(err)
	}
	if srv.access == nil {
		t.Fatal("SetAccess did not install a verifier")
	}
	record := srv.access.record
	verifier, key := testVerifier(t, oneAdmin())
	verifier.record = record
	srv.access = verifier

	if _, ok := verifier.Verify(requestWith(signToken(t, key, "RS256", "kid-1", validClaims()))); !ok {
		t.Fatal("a valid assertion was refused")
	}
	marker, err := store.GetSetting(accessLastSuccessSetting)
	if err != nil || strings.TrimSpace(marker) == "" {
		t.Fatalf("a verified assertion recorded no marker: %q %v", marker, err)
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(marker)); err != nil {
		t.Fatalf("marker %q is not an RFC3339 timestamp: %v", marker, err)
	}
}

// The marker says the Cloudflare side works. Whether the person it names may use
// the console is the operator list's separate answer, and an unlisted signer must
// not make the Access check read as broken.
func TestAnAssertionFromAnUnlistedSignerStillRecordsThatAccessWorks(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := srv.SetAccess(AccessOptions{Team: "testteam", AUD: "aud-for-this-application"}); err != nil {
		t.Fatal(err)
	}
	record := srv.access.record
	verifier, key := testVerifier(t, map[string]string{})
	verifier.record = record

	if _, ok := verifier.Verify(requestWith(signToken(t, key, "RS256", "kid-1", validClaims()))); ok {
		t.Fatal("an unlisted signer was let into the console")
	}
	marker, err := store.GetSetting(accessLastSuccessSetting)
	if err != nil || strings.TrimSpace(marker) == "" {
		t.Fatalf("the assertion verified but nothing recorded it: %q %v", marker, err)
	}
}

// Recording on every request would be a database write per page load.
func TestTheLastSuccessMarkerIsRateLimited(t *testing.T) {
	verifier, key := testVerifier(t, oneAdmin())
	writes := 0
	verifier.record = func(time.Time) { writes++ }

	for i := 0; i < 5; i++ {
		if _, ok := verifier.Verify(requestWith(signToken(t, key, "RS256", "kid-1", validClaims()))); !ok {
			t.Fatal("a valid assertion was refused")
		}
	}
	if writes != 1 {
		t.Errorf("five sign-ins wrote the marker %d times, want 1", writes)
	}
}

// The row this whole change exists for. On a LAN-mode hub the Tunnel adapter is
// genuinely not in use, and the row said "direct native access is active;
// Cloudflare remains optional" on a hub authenticating every console sign-in
// through Cloudflare Access.
func TestTheTunnelAdapterRowDoesNotDenyThatAccessIsRunning(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	saveAccessConfiguration(t, store, "testteam", "aud-for-this-application")
	verifier, _ := testVerifier(t, oneAdmin())
	srv.access = verifier

	got := resultFor(t, srv, "cloudflare")
	if got.State != diagnostics.NotConfigured {
		t.Fatalf("state %q, want not_configured; agents reach this hub directly: %+v", got.State, got)
	}
	if !strings.Contains(strings.ToLower(got.Summary), "access") {
		t.Errorf("the adapter row must not imply Cloudflare is unused while Access verifies sign-in: %q", got.Summary)
	}
	if !strings.Contains(strings.ToLower(got.Summary), "tunnel") {
		t.Errorf("the adapter row must name what is actually not in use: %q", got.Summary)
	}

	// Without Access, the same row is about the Tunnel and only the Tunnel.
	srv.access = nil
	got = resultFor(t, srv, "cloudflare")
	if strings.Contains(strings.ToLower(got.Summary), "access still verifies") {
		t.Errorf("no Access verifier is live, so the row must not claim one is: %q", got.Summary)
	}
}
