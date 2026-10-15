package responseauth_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	return isolateRequestFor("ep-1")
}

// isolateRequestFor builds the payload the hub sends: route, body, targets.
func isolateRequestFor(targets ...string) *responseauth.ApprovalRequestInput {
	route, body := "/api/v1/endpoints/isolate-bulk", map[string]interface{}{"scope": "ids", "ids": targets}
	if len(targets) == 1 {
		route, body = "/api/v1/endpoints/isolate", map[string]interface{}{"endpoint_id": targets[0]}
	}
	payload, _ := json.Marshal(map[string]interface{}{"route": route, "body": body, "targets": targets})
	return &responseauth.ApprovalRequestInput{
		TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindIsolation,
		Action: "Isolate host", Summary: "Isolate lab-vm", Targets: targets,
		Payload: payload,
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
	if err := json.Unmarshal(stmt, &parsed); err != nil || parsed.ID != v.ID || parsed.Summary != "Cut 1 host(s) off the network: ep-1 (no exceptions: hub and loopback only)" || parsed.Action != "Isolate host" {
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
	consume := &responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin", Kind: in.Kind, Digest: digestOf(in.Payload), Targets: []string{"ep-1"}}
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
			in := isolateRequestFor("ep-" + name)
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
	in := isolateRequestFor("ep-1", "ep-2")
	v, _ := auth.RequestApproval(in)
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	good := responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin", Kind: in.Kind, Digest: digestOf(in.Payload), Targets: []string{"ep-2", "ep-1"}}
	bad := []responseauth.ApprovalConsumeRequest{good, good, good, good, good}
	bad[4].Requester = "someone-else"
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
		in := isolateRequestFor("ep-" + string(rune('a'+i)))
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

func TestApproverFileMustNotBeWritableByOthers(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "approvers.json")
	if err := approvaltest.WriteFile(path, approvaltest.New("x", testRP, testOrigin)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(path)
	if _, err := auth.RequestApproval(isolateRequest()); err == nil || !strings.Contains(err.Error(), "not group or world writable") {
		t.Fatalf("a group-writable approver file was trusted: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	_ = os.Chmod(path, 0o644)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(link)
	if _, err := auth.RequestApproval(isolateRequest()); err == nil {
		t.Fatal("a symlinked approver file was trusted")
	}
}

// The owner sees the authority's words, derived from the digested payload:
// hub prose is ignored, and a route that does not match the kind is refused.
func TestApprovalWordsComeFromThePayload(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	in := isolateRequestFor("ep-1")
	in.Action, in.Summary = "Release isolation", "harmless"
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != "Isolate host" || strings.Contains(v.Summary, "harmless") {
		t.Fatalf("hub prose reached the owner: %q / %q", v.Action, v.Summary)
	}

	refused := map[string]*responseauth.ApprovalRequestInput{}
	r := isolateRequestFor("ep-1")
	r.Kind = responseauth.ActionKindMesh
	refused["kind differs from route"] = r
	r = isolateRequestFor("ep-1")
	r.Payload = json.RawMessage(`{"route":"/api/v1/endpoints/delete","body":{},"targets":["ep-1"]}`)
	refused["unknown route"] = r
	r = isolateRequestFor("ep-1")
	r.Payload = json.RawMessage(`{"route":"/api/v1/endpoints/isolate","body":{"endpoint_id":"ep-9"},"targets":["ep-1"]}`)
	refused["body names another endpoint"] = r
	r = isolateRequestFor("ep-1")
	r.Targets = []string{"ep-2"}
	refused["payload targets differ"] = r
	r = isolateRequestFor("ep-1")
	r.Kind = responseauth.ActionKindAgentUpdate
	r.Payload = json.RawMessage(`{"route":"/api/v1/agents/update","body":{"all":true},"targets":["ep-1"]}`)
	refused["update without version"] = r
	for name, in := range refused {
		if _, err := auth.RequestApproval(in); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}

	term := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindTerminalSession,
		Targets: []string{"ep-1"}, Payload: json.RawMessage(`{"program":"/bin/bash"}`)}
	v, err = auth.RequestApproval(term)
	if err != nil || v.Action != "Open terminal" || !strings.Contains(v.Summary, "/bin/bash on ep-1") {
		t.Fatalf("terminal words: %+v %v", v, err)
	}
}

// Concurrent requests must not all pass the caps on the same stale counts.
func TestApprovalCapsHoldUnderConcurrency(t *testing.T) {
	auth, _ := newApprovalAuthority(t)
	const n = 40
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := auth.RequestApproval(isolateRequestFor(fmt.Sprintf("ep-%d", i))); err == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := ok.Load(); got != 3 {
		t.Fatalf("%d concurrent requests passed the pending cap of 3", got)
	}
}
