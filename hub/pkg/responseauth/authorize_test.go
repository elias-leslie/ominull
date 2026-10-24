package responseauth_test

import (
	"crypto/ed25519"
	"crypto/sha256"
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
)

func newTestAuthority(t *testing.T) *responseauth.Authority {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func isolateRequest() *responseauth.AuthorizeInput { return isolateRequestFor("ep-1") }

// isolateRequestFor builds the payload the hub sends: route, body, targets.
func isolateRequestFor(targets ...string) *responseauth.AuthorizeInput {
	route, body := "/api/v1/endpoints/isolate-bulk", map[string]interface{}{"scope": "ids", "ids": targets}
	if len(targets) == 1 {
		route, body = "/api/v1/endpoints/isolate", map[string]interface{}{"endpoint_id": targets[0]}
	}
	payload, _ := json.Marshal(map[string]interface{}{"route": route, "body": body, "targets": targets})
	return &responseauth.AuthorizeInput{
		TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindIsolation,
		Targets: targets, Payload: payload,
	}
}

// An authorization signs the grants at once: one per target, with the tenant
// key, bound to the payload digest and the requester.
func TestAuthorizeSignsGrantsAtOnce(t *testing.T) {
	auth := newTestAuthority(t)
	pub, _, err := auth.GetOrCreateTenantKey("default")
	if err != nil {
		t.Fatal(err)
	}
	in := isolateRequestFor("ep-1", "ep-2")
	au, err := auth.Authorize(in)
	if err != nil {
		t.Fatal(err)
	}
	if au.Action != "Isolate hosts" && au.Action != "Isolate host" {
		t.Fatalf("action %q", au.Action)
	}
	if len(au.Grants) != 2 {
		t.Fatalf("want a grant per target, got %d", len(au.Grants))
	}
	for _, g := range au.Grants {
		if g.ActionKind != responseauth.ActionKindIsolation || g.OperatorID != "admin" || g.ActionDigest != digestOf(in.Payload) {
			t.Fatalf("grant not bound to the request: %+v", g)
		}
		if g.ResponseSessionID != "approval:"+au.ID {
			t.Fatalf("grant session %q", g.ResponseSessionID)
		}
		sig, _ := hex.DecodeString(g.Signature)
		if !ed25519.Verify(pub, g.CanonicalBytes(), sig) {
			t.Fatalf("grant signature does not verify with the tenant key: %+v", g)
		}
	}
}

// The authority words the action from the payload; what the hub says about it
// is ignored.
func TestAuthorizeWordsComeFromThePayload(t *testing.T) {
	auth := newTestAuthority(t)
	au, err := auth.Authorize(isolateRequestFor("ep-1"))
	if err != nil {
		t.Fatal(err)
	}
	if au.Action != "Isolate host" || !strings.Contains(au.Summary, "ep-1") {
		t.Fatalf("words: %q / %q", au.Action, au.Summary)
	}
	term := &responseauth.AuthorizeInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindTerminalSession,
		Targets: []string{"ep-1"}, Payload: json.RawMessage(`{"program":"/bin/bash"}`)}
	au, err = auth.Authorize(term)
	if err != nil || au.Action != "Open terminal" || !strings.Contains(au.Summary, "/bin/bash on ep-1") || len(au.Grants) != 1 {
		t.Fatalf("terminal: %+v %v", au, err)
	}
}

// An action the authority cannot read is refused with the reason, and nothing
// is signed.
func TestAuthorizeRefusesWhatItCannotRead(t *testing.T) {
	auth := newTestAuthority(t)
	refused := map[string]*responseauth.AuthorizeInput{}
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
	r = isolateRequestFor("ep-1")
	r.Targets = nil
	refused["no targets"] = r
	r = isolateRequestFor("ep-1")
	r.Payload = json.RawMessage(`not json`)
	refused["payload is not json"] = r
	r = isolateRequestFor("ep-1")
	r.Kind = response.ActionKind("format_disk")
	refused["unknown kind"] = r
	many := make([]string, 0, 51)
	for i := 0; i < 51; i++ {
		many = append(many, fmt.Sprintf("ep-%d", i))
	}
	refused["too many targets"] = isolateRequestFor(many...)
	for name, in := range refused {
		au, err := auth.Authorize(in)
		if err == nil || au != nil {
			t.Fatalf("%s: signed", name)
		}
	}
	if _, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindTerminalSession,
		Targets: []string{"ep-1"}, Payload: json.RawMessage(`{"program":"/bin/bash"}`), SessionSeconds: 0}); err != nil {
		t.Fatalf("a plain terminal is signed: %v", err)
	}
	if _, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindTerminalSession,
		Targets: []string{"ep-1", "ep-2"}, Payload: json.RawMessage(`{"program":"/bin/bash"}`)}); !errors.Is(err, responseauth.ErrNotAuthorized) {
		t.Fatalf("a terminal on two endpoints: %v", err)
	}
}

// The direct sign-grant route stays closed for kinds that go through Authorize.
func TestTerminalGrantNeedsAnAuthorization(t *testing.T) {
	auth := newTestAuthority(t)
	_, err := auth.SignGrant(&responseauth.SignGrantRequest{TenantID: "default", ActionKind: response.ActionKindTerminalSession, Proof: &responseauth.ActionProof{}})
	if err == nil {
		t.Fatal("terminal grant signed without an authorization")
	}
}

// Concurrent authorizations each get their own grants and ids; the
// enforcement clock never repeats.
func TestAuthorizeUnderConcurrency(t *testing.T) {
	auth := newTestAuthority(t)
	const n = 40
	var wg sync.WaitGroup
	var ok atomic.Int32
	issued := sync.Map{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			au, err := auth.Authorize(isolateRequestFor(fmt.Sprintf("ep-%d", i)))
			if err != nil {
				return
			}
			ok.Add(1)
			for _, g := range au.Grants {
				if _, dup := issued.LoadOrStore(g.IssuedAt, true); dup {
					t.Errorf("issued-at %d reused", g.IssuedAt)
				}
			}
		}(i)
	}
	wg.Wait()
	if got := ok.Load(); got != n {
		t.Fatalf("%d of %d concurrent authorizations signed", got, n)
	}
}

// A detection-policy authorization signs no grant: the hub applies the change
// itself.
func TestDetectionPolicyAuthorizationSignsNoGrants(t *testing.T) {
	auth := newTestAuthority(t)
	payload := []byte(`{"after":{"beacon_enabled":false},"before":{"beacon_enabled":true},"op":"save","policy":"detection_tuning"}`)
	au, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "admin (api-key)", Kind: responseauth.ActionKindDetection,
		Targets: []string{"detection:tuning"}, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if au.Summary != "beacon_enabled true -> false" || len(au.Grants) != 0 {
		t.Fatalf("summary %q grants %d", au.Summary, len(au.Grants))
	}
}

// An agent's self-declared label is accepted only from an admin-key requester,
// and only in the plain form; session length and ask-first reach the words.
func TestAuthorizeAgentLabelSessionAndAskFirst(t *testing.T) {
	auth := newTestAuthority(t)
	if _, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "alice (console)",
		Kind: response.ActionKindTerminalSession, Targets: []string{"ep-1"}, Payload: []byte(`{"program":"/bin/bash"}`), AgentLabel: "claude-ops"}); err == nil {
		t.Fatal("an agent label without the admin key was accepted")
	}
	if _, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "admin (api-key)",
		Kind: response.ActionKindTerminalSession, Targets: []string{"ep-1"}, Payload: []byte(`{"program":"/bin/bash"}`), AgentLabel: `a"b`}); err == nil {
		t.Fatal("an agent label with a quote was accepted")
	}
	for _, tc := range []struct {
		name    string
		kind    response.ActionKind
		payload string
		askF    bool
	}{
		{"terminal", response.ActionKindTerminalSession, `{"program":"/bin/bash"}`, false},
		{"screen", response.ActionKindScreenSession, `{"mode":"control","ask_first":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			au, err := auth.Authorize(&responseauth.AuthorizeInput{TenantID: "default", Requester: "admin (api-key)", Kind: tc.kind,
				Targets: []string{"ep-1"}, Payload: []byte(tc.payload), SessionSeconds: 1800, AskFirst: tc.askF, AgentLabel: "claude-ops"})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(au.Summary, `calling itself "claude-ops"`) || !strings.Contains(au.Summary, "30 minutes") || len(au.Grants) != 1 {
				t.Fatalf("summary %q grants %d", au.Summary, len(au.Grants))
			}
		})
	}
}

// Only the steward's screen request names a maintenance run.
func TestAuthorizeStewardRunOnlyForTheSteward(t *testing.T) {
	auth := newTestAuthority(t)
	screen := func(requester, run string) *responseauth.AuthorizeInput {
		return &responseauth.AuthorizeInput{TenantID: "default", Requester: requester, Kind: response.ActionKindScreenSession,
			Targets: []string{"ep-1"}, Payload: []byte(`{"mode":"control","ask_first":true}`), SessionSeconds: 1800, AskFirst: true, StewardRun: run}
	}
	if _, err := auth.Authorize(screen("admin (api-key)", "run-1")); err == nil {
		t.Fatal("a steward run on an ordinary screen request was signed")
	}
	au, err := auth.Authorize(screen("steward (steward-key)", "run-1"))
	if err != nil || !strings.Contains(au.Summary, "maintenance run run-1") {
		t.Fatalf("steward screen: %+v %v", au, err)
	}
	if _, err := auth.Authorize(screen("steward (steward-key)", "bad run\n")); err == nil {
		t.Fatal("an unprintable run id was signed")
	}
}

func digestOf(p []byte) string {
	h := sha256.Sum256(p)
	return hex.EncodeToString(h[:])
}
