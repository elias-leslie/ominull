package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// adminPost sends one POST with the static admin key. The approval argument is
// kept for old call sites; authorization is a single call, so it is ignored
// and callers pass "".
func adminPost(srv *Server, path, body string, _ string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func isolated(t *testing.T, store *storage.Store, id string) bool {
	t.Helper()
	ep, err := store.GetEndpoint(id)
	if err != nil || ep == nil {
		t.Fatalf("endpoint %s: %v", id, err)
	}
	return ep.IsIsolated
}

func seedPlain(t *testing.T, store *storage.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: "host-" + id, OS: "test", Status: "online"}); err != nil {
			t.Fatal(err)
		}
	}
}

// seedOwnerSignedRelease publishes both agent packages of version with
// release statements signed by key (as scripts/sign-release.sh does).
func seedOwnerSignedRelease(t *testing.T, dir, version string, key *ecdsa.PrivateKey) {
	t.Helper()
	for _, name := range []string{agentPackageName(version, "deb"), agentPackageName(version, "windows-native")} {
		seedSignedRelease(t, dir, name)
		sum := sha256.Sum256([]byte("package-bytes-for-" + name))
		digest := sha256.Sum256([]byte(responseauth.ReleaseStatement(name, version, hex.EncodeToString(sum[:]))))
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".release.sig"), sig, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// authorizedAudit returns the ACTION_AUTHORIZED audit rows, newest first.
func authorizedAudit(t *testing.T, store *storage.Store) []storage.AuditEntry {
	t.Helper()
	page, err := store.AuditHistory("", 200, "", storage.AuditFilter{Action: "ACTION_AUTHORIZED"})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

// authorizedAuditHas reports whether an ACTION_AUTHORIZED row mentions every part.
func authorizedAuditHas(t *testing.T, store *storage.Store, parts ...string) bool {
	t.Helper()
	for _, e := range authorizedAudit(t, store) {
		all := true
		for _, p := range parts {
			if !strings.Contains(e.Details, p) && !strings.Contains(e.Resource, p) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}
