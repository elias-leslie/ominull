package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

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

func TestRolloutRuleHubRollsOwnerSignedReleaseWithoutAsking(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	owner := ownerOf(t, s)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	owner.auth.SetReleaseKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, id := range []string{"canary", "rest"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	post := func(body, approval string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(body))
		r.Header.Set("X-API-Key", "mock_admin_token")
		if approval != "" {
			r.Header.Set(approvalHeader, approval)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	// 1.2.0: the owner answers the ask with "Approve all like this".
	seedOwnerSignedRelease(t, s.binaryDir, "1.2.0", key)
	first := `{"endpoint_ids":["canary"],"version":"1.2.0"}`
	w := post(first, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("first rollout should ask the owner: %d %s", w.Code, w.Body.String())
	}
	var pending struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &pending)
	v, _ := owner.auth.GetApproval(pending.ApprovalID, "")
	if v.Offer != "rollouts" {
		t.Fatalf("owner-signed rollout ask does not offer the rule: %+v", v)
	}
	if _, err := owner.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: owner.approver.Assert(v.Challenge, "rule")}); err != nil {
		t.Fatal(err)
	}
	if w = post(first, pending.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved rollout: %d %s", w.Code, w.Body.String())
	}

	// 1.3.0, staged: runs at once, canary first, with an audit row.
	seedOwnerSignedRelease(t, s.binaryDir, "1.3.0", key)
	s.agentVersion = "1.3.0"
	w = post(`{"endpoint_ids":["canary","rest"],"version":"1.3.0","canary":["canary"]}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rollout under the rule should run without asking: %d %s", w.Code, w.Body.String())
	}
	if job, err := db.GetAgentUpdateJob("canary"); err != nil || job == nil || job.DesiredVersion != "1.3.0" {
		t.Fatalf("canary not queued: %+v %v", job, err)
	}
	if job, _ := db.GetAgentUpdateJob("rest"); job != nil && job.DesiredVersion == "1.3.0" {
		t.Fatal("the held endpoint was queued before its canary ran the release")
	}
	page, err := db.AuditHistory("", 10, "", storage.AuditFilter{Action: autoApprovedAudit})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("want one audit row for the auto-approved rollout: %v %+v", err, page)
	}

	// The detection-policy note names the rule and the rollout it ran.
	notes, err := s.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range notes {
		if b, _ := json.Marshal(f); strings.Contains(string(b), "approve-all rule") && strings.Contains(string(b), "1 agent rollout approved without asking") {
			found = true
		}
	}
	if !found {
		t.Fatal("the feed's detection-policy note does not show the rule and its rollout")
	}

	// An unsigned release still asks; removing the rule makes signed ones ask.
	seedSignedRelease(t, s.binaryDir, agentPackageName("1.3.1", "deb"))
	seedSignedRelease(t, s.binaryDir, agentPackageName("1.3.1", "windows-native"))
	s.agentVersion = "1.3.1"
	if w = post(`{"endpoint_ids":["canary"],"version":"1.3.1"}`, ""); w.Code != http.StatusAccepted {
		t.Fatalf("a release without release signatures must ask: %d %s", w.Code, w.Body.String())
	}
	del := httptest.NewRequest("DELETE", "/api/v1/approvals/rules", nil)
	del.Header.Set("X-API-Key", "mock_admin_token")
	dw := httptest.NewRecorder()
	s.Handler().ServeHTTP(dw, del)
	if dw.Code != http.StatusOK || !strings.Contains(dw.Body.String(), `"removed":true`) {
		t.Fatalf("remove rule: %d %s", dw.Code, dw.Body.String())
	}
	seedOwnerSignedRelease(t, s.binaryDir, "1.3.2", key)
	s.agentVersion = "1.3.2"
	if w = post(`{"endpoint_ids":["canary"],"version":"1.3.2"}`, ""); w.Code != http.StatusAccepted {
		t.Fatalf("after removing the rule a rollout must ask: %d %s", w.Code, w.Body.String())
	}
}
