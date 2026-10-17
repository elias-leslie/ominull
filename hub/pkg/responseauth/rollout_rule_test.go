package responseauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/responseauth/approvaltest"
)

type releaseKey struct {
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newReleaseKey(t *testing.T) *releaseKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &releaseKey{priv: k, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// evidence signs the release statements of both agent packages of version.
func (k *releaseKey) evidence(t *testing.T, version string) []responseauth.ReleaseEvidence {
	t.Helper()
	var out []responseauth.ReleaseEvidence
	for _, name := range []string{"ominull-agent_" + version + "_amd64.deb", "ominull-agent-windows-" + version + ".msi"} {
		pkg := sha256.Sum256([]byte("package " + name))
		sha := hex.EncodeToString(pkg[:])
		sum := sha256.Sum256([]byte(responseauth.ReleaseStatement(name, version, sha)))
		sig, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, responseauth.ReleaseEvidence{Package: name, SHA256: sha, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return out
}

func rolloutRequest(version string, targets, canary []string, ev []responseauth.ReleaseEvidence) *responseauth.ApprovalRequestInput {
	body := map[string]interface{}{"endpoint_ids": targets, "version": version}
	if len(canary) > 0 {
		body["canary"] = canary
	}
	payload, _ := json.Marshal(map[string]interface{}{"route": "/api/v1/agents/update", "body": body, "targets": targets})
	return &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindAgentUpdate,
		Action: "Update agents", Summary: "Install agent " + version, Targets: targets, Payload: payload, Release: ev}
}

func statementOffer(t *testing.T, v *responseauth.ApprovalView) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v.Statement)
	if err != nil {
		t.Fatal(err)
	}
	var st responseauth.ApprovalStatement
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.Offer
}

// makeRule answers one owner-signed rollout ask with "Approve all like this".
func makeRule(t *testing.T, auth *responseauth.Authority, ap *approvaltest.Approver, key *releaseKey) {
	t.Helper()
	v, err := auth.RequestApproval(rolloutRequest("1.8.72", []string{"ep-1"}, nil, key.evidence(t, "1.8.72")))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalPending || statementOffer(t, v) != "rollouts" {
		t.Fatalf("an owner-signed rollout with no rule should ask and offer the rule: %s offer %q", v.State, statementOffer(t, v))
	}
	got, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")})
	if err != nil || got.State != responseauth.ApprovalApproved || got.Method != "passkey" {
		t.Fatalf("rule answer: %v %+v", err, got)
	}
}

func newRuleAuthority(t *testing.T) (*responseauth.Authority, *approvaltest.Approver, *releaseKey, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ap := approvaltest.New("owner-phone", testRP, testOrigin)
	path := filepath.Join(dir, "approvers.json")
	if err := approvaltest.WriteFile(path, ap); err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(path)
	key := newReleaseKey(t)
	auth.SetReleaseKey(key.pem)
	return auth, ap, key, dir
}

func TestRolloutRuleApprovesOwnerSignedRolloutsWithoutAsking(t *testing.T) {
	auth, ap, key, dir := newRuleAuthority(t)
	makeRule(t, auth, ap, key)
	rules, err := auth.RolloutRules("default")
	if err != nil || len(rules) != 1 || rules[0].ApproverID != "owner-phone" {
		t.Fatalf("rule not listed: %v %+v", err, rules)
	}

	targets := []string{"ep-1", "ep-2", "ep-3"}
	in := rolloutRequest("1.8.73", targets, []string{"ep-1"}, key.evidence(t, "1.8.73"))
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalApproved || v.Method != "rule" || statementOffer(t, v) != "" {
		t.Fatalf("staged owner-signed rollout under a rule should be approved without asking: %+v", v)
	}
	for _, p := range auth.PendingApprovals() {
		if p.ID == v.ID {
			t.Fatal("an auto-approved rollout must not reach the owner's phone")
		}
	}
	sum := sha256.Sum256(in.Payload)
	grants, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin",
		Kind: responseauth.ActionKindAgentUpdate, Digest: hex.EncodeToString(sum[:]), Targets: targets})
	if err != nil || len(grants) != 3 {
		t.Fatalf("auto-approved rollout should sign one grant per endpoint: %v %d", err, len(grants))
	}
	rows, _ := auth.GetAuditLog("default", 100)
	auto := 0
	for _, r := range rows {
		if r.EventType == "approval_auto_approved" {
			auto++
			if !strings.Contains(r.Details, "release 1.8.73 owner-signed") {
				t.Errorf("audit row does not name the verified release: %s", r.Details)
			}
		}
	}
	if auto != 1 {
		t.Fatalf("want one audit row per auto-approved rollout, got %d", auto)
	}

	// The rule survives a restart of the authority.
	again, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if rules, _ := again.RolloutRules("default"); len(rules) != 1 || rules[0].Week != 1 {
		t.Fatalf("rule lost or use not counted after restart: %+v", rules)
	}
}

func TestRolloutRuleRefusesWhatItDoesNotCover(t *testing.T) {
	auth, ap, key, _ := newRuleAuthority(t)
	makeRule(t, auth, ap, key)
	other := newReleaseKey(t)
	tampered := key.evidence(t, "1.8.74")
	tampered[0].SHA256 = strings.Repeat("0", 64)
	cases := map[string]*responseauth.ApprovalRequestInput{
		"unsigned release":              rolloutRequest("1.8.74", []string{"ep-1"}, nil, nil),
		"signed with another key":       rolloutRequest("1.8.74", []string{"ep-1"}, nil, other.evidence(t, "1.8.74")),
		"signature for another version": rolloutRequest("1.8.74", []string{"ep-1"}, nil, key.evidence(t, "1.8.73")),
		"digest not the signed one":     rolloutRequest("1.8.74", []string{"ep-1"}, nil, tampered),
		"only one package signed":       rolloutRequest("1.8.74", []string{"ep-1"}, nil, key.evidence(t, "1.8.74")[:1]),
		"fleet rollout not staged":      rolloutRequest("1.8.74", []string{"ep-1", "ep-2"}, nil, key.evidence(t, "1.8.74")),
		"not a rollout (isolation)":     isolateRequest(),
	}
	for name, in := range cases {
		if name == "not a rollout (isolation)" {
			in.Release = key.evidence(t, "1.8.74") // evidence never turns another kind into a rollout
		}
		v, err := auth.RequestApproval(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v.State != responseauth.ApprovalPending || v.Method == "rule" || statementOffer(t, v) != "" {
			t.Errorf("%s: approved or offered under the rule: %+v", name, v)
		}
		// No approve-all answer is accepted on an ask that does not offer it.
		if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")}); err == nil {
			t.Errorf("%s: a rule answer was accepted on an ask that offers none", name)
		}
		if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "deny"}); err != nil {
			t.Fatalf("%s: deny: %v", name, err) // keep under the pending cap
		}
	}
}

func TestRolloutRuleAnswerNeedsTheRuleSignature(t *testing.T) {
	auth, ap, key, _ := newRuleAuthority(t)
	v, err := auth.RequestApproval(rolloutRequest("1.8.72", []string{"ep-1"}, nil, key.evidence(t, "1.8.72")))
	if err != nil {
		t.Fatal(err)
	}
	// A passkey assertion for a plain approve is not an approve-all.
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "approve")}); err == nil {
		t.Fatal("an approve assertion created a rule")
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule"}); err == nil {
		t.Fatal("a rule answer without an assertion was accepted")
	}
	if rules, _ := auth.RolloutRules(""); len(rules) != 0 {
		t.Fatalf("rule created without the owner's rule signature: %+v", rules)
	}
	// A plain approve approves this rollout and creates no rule.
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	if rules, _ := auth.RolloutRules(""); len(rules) != 0 {
		t.Fatalf("a plain approve created a rule: %+v", rules)
	}
}

func TestRolloutRuleForgetEndsIt(t *testing.T) {
	auth, ap, key, _ := newRuleAuthority(t)
	makeRule(t, auth, ap, key)
	if had, err := auth.ForgetRolloutRule("default", "admin"); err != nil || !had {
		t.Fatalf("forget: %v %v", had, err)
	}
	v, err := auth.RequestApproval(rolloutRequest("1.8.73", []string{"ep-1"}, nil, key.evidence(t, "1.8.73")))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalPending || statementOffer(t, v) != "rollouts" {
		t.Fatalf("after forgetting, a rollout should ask (and offer again): %+v", v)
	}
}
