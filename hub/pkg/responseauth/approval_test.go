package responseauth_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/responseauth/approvaltest"
)

const testRP = "approve.example.invalid"
const testOrigin = "https://approve.example.invalid"

func newApprovalAuthority(t *testing.T) (*responseauth.Authority, *approvaltest.Approver) {
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
	return auth, ap
}

func isolateRequest() *responseauth.ApprovalRequestInput {
	return &responseauth.ApprovalRequestInput{
		TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindIsolation,
		Action: "Isolate host", Summary: "Isolate lab-vm", Targets: []string{"ep-1"},
		Payload: json.RawMessage(`{"route":"/api/v1/endpoints/isolate","body":{"endpoint_id":"ep-1"}}`),
	}
}

func TestApprovalRefusedWithoutPinnedApprover(t *testing.T) {
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(filepath.Join(t.TempDir(), "missing.json"))
	if _, err := auth.RequestApproval(isolateRequest()); !errors.Is(err, responseauth.ErrNoApprovers) {
		t.Fatalf("want ErrNoApprovers, got %v", err)
	}
}

func TestApprovalStatementIsSignedAndChallengeDerived(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	v, err := auth.RequestApproval(isolateRequest())
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := auth.GetOrCreateTenantKey("default")
	if err != nil {
		t.Fatal(err)
	}
	stmt, _ := base64.StdEncoding.DecodeString(v.Statement)
	signed := append([]byte("OMINULL-OWNER-APPROVAL-V1\n"), stmt...)
	sig, _ := hex.DecodeString(v.Signature)
	if !ed25519.Verify(pub, signed, sig) {
		t.Fatal("statement signature does not verify with the tenant key")
	}
	ch := sha256.Sum256(signed)
	if hex.EncodeToString(ch[:]) != v.Challenge {
		t.Fatal("challenge is not sha256(prefix || statement)")
	}
	var parsed responseauth.ApprovalStatement
	if err := json.Unmarshal(stmt, &parsed); err != nil || parsed.ID != v.ID || parsed.Summary != "Isolate lab-vm" {
		t.Fatalf("statement does not carry the shown fields: %+v %v", parsed, err)
	}
}

func TestApprovalApproveConsumeOnce(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	in := isolateRequest()
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	consume := &responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Kind: in.Kind, Digest: digestOf(in.Payload), Targets: []string{"ep-1"}}
	if _, err := auth.ConsumeApproval(consume); !errors.Is(err, responseauth.ErrApprovalNotUsable) {
		t.Fatalf("pending approval consumed: %v", err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	grants, err := auth.ConsumeApproval(consume)
	if err != nil || len(grants) != 1 {
		t.Fatalf("consume: %v %d", err, len(grants))
	}
	pub, _, _ := auth.GetOrCreateTenantKey("default")
	g := grants[0]
	if g.EndpointID != "ep-1" || g.ActionKind != responseauth.ActionKindIsolation || g.ResponseSessionID != "approval:"+v.ID {
		t.Fatalf("grant fields: %+v", g)
	}
	sig, _ := hex.DecodeString(g.Signature)
	if !ed25519.Verify(pub, g.CanonicalBytes(), sig) {
		t.Fatal("grant signature invalid")
	}
	if _, err := auth.ConsumeApproval(consume); !errors.Is(err, responseauth.ErrApprovalNotUsable) {
		t.Fatalf("second consume allowed: %v", err)
	}
}

func digestOf(p []byte) string {
	h := sha256.Sum256(p)
	return hex.EncodeToString(h[:])
}

func TestApprovalAssertionChecks(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	other := approvaltest.New("other", testRP, testOrigin)
	cases := map[string]func(ch string) *responseauth.ApprovalAssertion{
		"deny-signed used to approve": func(ch string) *responseauth.ApprovalAssertion { return ap.Assert(ch, "deny") },
		"wrong origin": func(ch string) *responseauth.ApprovalAssertion {
			return ap.AssertWith(ch, "approve", "https://evil.example.invalid", testRP, 0x05)
		},
		"wrong rp id": func(ch string) *responseauth.ApprovalAssertion {
			return ap.AssertWith(ch, "approve", testOrigin, "evil.example.invalid", 0x05)
		},
		"no user verification": func(ch string) *responseauth.ApprovalAssertion {
			return ap.AssertWith(ch, "approve", testOrigin, testRP, 0x01)
		},
		"unpinned key":               func(ch string) *responseauth.ApprovalAssertion { return other.Assert(ch, "approve") },
		"other approval's challenge": func(ch string) *responseauth.ApprovalAssertion { return ap.Assert(sha256hex("x"), "approve") },
		"pinned id, foreign key": func(ch string) *responseauth.ApprovalAssertion {
			a := other.Assert(ch, "approve")
			a.CredentialID = ap.CredentialID
			return a
		},
		"missing assertion": func(ch string) *responseauth.ApprovalAssertion { return nil },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			in := isolateRequest()
			in.Targets = []string{"ep-" + name}
			v, err := auth.RequestApproval(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: mk(v.Challenge)}); err == nil {
				t.Fatal("bad assertion accepted")
			}
			got, _ := auth.GetApproval(v.ID, "default")
			if got.State != responseauth.ApprovalPending {
				t.Fatalf("state after rejected assertion: %s", got.State)
			}
			// Clean up so the pending cap does not trip later cases.
			_, _ = auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "deny"})
		})
	}
}

func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestApprovalConsumeMustMatch(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	in := isolateRequest()
	in.Targets = []string{"ep-1", "ep-2"}
	v, _ := auth.RequestApproval(in)
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	good := responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Kind: in.Kind, Digest: digestOf(in.Payload), Targets: []string{"ep-2", "ep-1"}}
	bad := []responseauth.ApprovalConsumeRequest{good, good, good, good}
	bad[0].Kind = response.ActionKindTerminalSession
	bad[1].Digest = sha256hex("other")
	bad[2].Targets = []string{"ep-1"}
	bad[3].TenantID = "other"
	for i := range bad {
		if _, err := auth.ConsumeApproval(&bad[i]); err == nil {
			t.Fatalf("mismatch %d consumed", i)
		}
	}
	grants, err := auth.ConsumeApproval(&good)
	if err != nil || len(grants) != 2 {
		t.Fatalf("matching consume after refusals: %v", err)
	}
}

func TestApprovalDenyAndRateLimit(t *testing.T) {
	auth, ap := newApprovalAuthority(t)
	var ids []string
	for i := 0; i < 3; i++ {
		in := isolateRequest()
		in.Targets = []string{"ep-" + string(rune('a'+i))}
		v, err := auth.RequestApproval(in)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.ID)
	}
	if _, err := auth.RequestApproval(isolateRequest()); !errors.Is(err, responseauth.ErrApprovalRateLimit) {
		t.Fatalf("fourth pending allowed: %v", err)
	}
	v, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ids[0], Decision: "deny", Assertion: ap.Assert(mustChallenge(t, auth, ids[0]), "deny")})
	if err != nil || v.State != responseauth.ApprovalDenied || v.Method != "passkey" {
		t.Fatalf("verified deny: %+v %v", v, err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ids[0], Decision: "approve", Assertion: ap.Assert(mustChallenge(t, auth, ids[0]), "approve")}); err == nil {
		t.Fatal("denied approval was approved afterwards")
	}
}

func mustChallenge(t *testing.T, auth *responseauth.Authority, id string) string {
	v, err := auth.GetApproval(id, "default")
	if err != nil {
		t.Fatal(err)
	}
	return v.Challenge
}

func TestTerminalGrantNeedsOwnerApproval(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	_, err := auth.SignGrant(&responseauth.SignGrantRequest{TenantID: "default", ActionKind: response.ActionKindTerminalSession, Proof: &responseauth.ActionProof{}})
	if err == nil {
		t.Fatal("terminal grant signed without an owner approval")
	}
}
