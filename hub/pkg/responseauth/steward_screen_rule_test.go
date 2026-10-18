package responseauth_test

import (
	"errors"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

const stewardReq = "steward (steward-key)"

func stewardSession(endpoint, payload string, seconds int64, run string) *responseauth.ApprovalRequestInput {
	return &responseauth.ApprovalRequestInput{TenantID: "default", Requester: stewardReq, Kind: response.ActionKindScreenSession,
		Targets: []string{endpoint}, Payload: []byte(payload), SessionSeconds: seconds, AskFirst: strings.Contains(payload, "ask_first"), StewardRun: run}
}

// raiseSteward makes the owner's steward screen rule for ep-1 with one tap.
func raiseSteward(t *testing.T, auth *responseauth.Authority, tap func(id, challenge string), payload string, ask responseauth.StewardScreenAsk) *responseauth.ApprovalView {
	t.Helper()
	in := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "owner@example.invalid (console)", Kind: response.ActionKindScreenSession,
		Targets: []string{"windows-ep-1"}, Payload: []byte(payload), AskFirst: strings.Contains(payload, "ask_first"), StewardRule: &ask}
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalPending || v.Action != "Let the steward use the screen" ||
		!strings.Contains(v.Summary, "Nightshift's steward may see and control the screen on windows-ep-1 without asking you") ||
		!strings.Contains(v.Summary, "up to 30 minutes each time") || !strings.Contains(v.Summary, "inside the machine's maintenance window") ||
		!strings.Contains(v.Summary, "person at the keyboard is asked") {
		t.Fatalf("the owner should read exactly what the rule allows: %s %q %q", v.State, v.Action, v.Summary)
	}
	tap(v.ID, v.Challenge)
	return v
}

func TestStewardScreenRule(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	if m, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "windows-ep-1", Profile: "respond"}); err != nil || m.Profile != "respond" {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	if m, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "windows-ep-2", Profile: "monitor"}); err != nil || m.Profile != "monitor" {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	if m, err := auth.EndpointManifest(&responseauth.ManifestRequest{TenantID: "default", EndpointID: "linux-host-1", Profile: "respond"}); err != nil || m.Profile != "respond" {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	tap := func(id, ch string) {
		if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: id, Decision: "approve", Assertion: ap.Assert(ch, "approve")}); err != nil {
			t.Fatal(err)
		}
	}
	control := `{"mode":"control","ask_first":true}`
	view := `{"mode":"view","ask_first":true}`

	// Without a rule the steward asks like anyone, named by its key.
	v, err := auth.RequestApproval(stewardSession("windows-ep-1", control, 1800, "job-1"))
	if err != nil || v.State != responseauth.ApprovalPending || !strings.Contains(v.Summary, "Nightshift's steward (steward key) will see and control the screen on windows-ep-1") ||
		!strings.Contains(v.Summary, "to unstick maintenance run job-1") {
		t.Fatalf("an uncovered steward session should ask and say who and why: %v %+v", err, v)
	}
	_, _ = auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "deny"})

	// A machine without the screen, or the owner's Linux infrastructure,
	// never takes a rule.
	monitorAsk := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "owner@example.invalid (console)", Kind: response.ActionKindScreenSession,
		Targets: []string{"windows-ep-2"}, Payload: []byte(control), AskFirst: true, StewardRule: &responseauth.StewardScreenAsk{MaxSeconds: 1800}}
	if _, err := auth.RequestApproval(monitorAsk); err == nil || !strings.Contains(err.Error(), "does not include the remote screen") {
		t.Fatalf("a machine without the screen in its profile must be refused a steward rule: %v", err)
	}
	linuxAsk := *monitorAsk
	linuxAsk.Targets = []string{"linux-host-1"}
	if _, err := auth.RequestApproval(&linuxAsk); err == nil || !strings.Contains(err.Error(), "only on Windows machines") {
		t.Fatalf("a Linux machine (the owner's infrastructure) must be refused a steward rule: %v", err)
	}

	ask := raiseSteward(t, auth, tap, control, responseauth.StewardScreenAsk{MaxSeconds: 1800, OnlyInWindow: true})
	got, err := auth.GetApproval(ask.ID, "default")
	if err != nil || got.StewardRule == "" {
		t.Fatalf("the approved ask should carry the rule token: %v %+v", err, got)
	}
	token := got.StewardRule
	rule, err := responseauth.ReadStewardRuleToken(token)
	if err != nil || rule.EndpointID != "windows-ep-1" || rule.Mode != "control" || rule.MaxSeconds != 1800 || !rule.AskFirst || !rule.OnlyInWindow || rule.ApproverID != "owner-phone" {
		t.Fatalf("token should state what the owner approved: %v %+v", err, rule)
	}
	// The tap signs no grant.
	if g, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: ask.ID, TenantID: "default", Requester: "owner@example.invalid (console)",
		Kind: response.ActionKindScreenSession, Digest: digestOf([]byte(control)), Targets: []string{"windows-ep-1"}, AskFirst: true}); err != nil || len(g) != 0 {
		t.Fatalf("raising the setting signs no grant: %v %d", err, len(g))
	}

	withToken := func(in *responseauth.ApprovalRequestInput, narrow *responseauth.StewardScreenNarrow) *responseauth.ApprovalRequestInput {
		in.StewardRuleToken, in.StewardNarrow = token, narrow
		return in
	}
	// Covered: the steward, a named run, that machine, within mode and length.
	for i, in := range []*responseauth.ApprovalRequestInput{
		withToken(stewardSession("windows-ep-1", control, 1800, "job-2"), nil),
		withToken(stewardSession("windows-ep-1", view, 600, "job-3"), nil),
	} {
		got, err := auth.RequestApproval(in)
		if err != nil || got.State != responseauth.ApprovalApproved || got.Method != "rule" || got.ApproverID != "owner-phone" {
			t.Fatalf("covered steward session %d: %v %+v", i, err, got)
		}
		grants, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: got.ID, TenantID: "default", Requester: stewardReq,
			Kind: response.ActionKindScreenSession, Digest: digestOf(in.Payload), Targets: in.Targets,
			SessionSeconds: in.SessionSeconds, AskFirst: in.AskFirst, StewardRun: in.StewardRun})
		if err != nil || len(grants) != 1 {
			t.Fatalf("covered session %d should sign its grant: %v", i, err)
		}
	}

	// Not covered: each asks the owner as before.
	forged := token[:len(token)-4] + "0000"
	if strings.HasSuffix(token, "0000") {
		forged = token[:len(token)-4] + "1111"
	}
	uncovered := map[string]*responseauth.ApprovalRequestInput{
		"no token": stewardSession("windows-ep-1", control, 1800, "job-4"),
		"forged token": func() *responseauth.ApprovalRequestInput {
			in := stewardSession("windows-ep-1", control, 1800, "job-4")
			in.StewardRuleToken = forged
			return in
		}(),
		"no run":           withToken(stewardSession("windows-ep-1", control, 1800, ""), nil),
		"other machine":    withToken(stewardSession("windows-ep-2", control, 1800, "job-4"), nil),
		"longer":           withToken(stewardSession("windows-ep-1", control, 3600, "job-4"), nil),
		"no length":        withToken(stewardSession("windows-ep-1", control, 0, "job-4"), nil),
		"no ask":           withToken(stewardSession("windows-ep-1", `{"mode":"control"}`, 1800, "job-4"), nil),
		"unattended":       withToken(stewardSession("windows-ep-1", `{"mode":"control","unattended":true,"ask_first":true}`, 1800, "job-4"), nil),
		"narrowed to view": withToken(stewardSession("windows-ep-1", control, 900, "job-4"), &responseauth.StewardScreenNarrow{Mode: "view"}),
		"narrowed shorter": withToken(stewardSession("windows-ep-1", view, 1200, "job-4"), &responseauth.StewardScreenNarrow{MaxSeconds: 900}),
		"admin-key bot":    {TenantID: "default", Requester: "admin (api-key)", Kind: response.ActionKindScreenSession, Targets: []string{"windows-ep-1"}, Payload: []byte(control), SessionSeconds: 1800, AskFirst: true, AgentLabel: "steward", StewardRuleToken: token},
	}
	for name, in := range uncovered {
		got, err := auth.RequestApproval(in)
		if err == nil && got.State == responseauth.ApprovalApproved {
			t.Fatalf("%s: approved without asking: %+v", name, got)
		}
		if err == nil {
			_, _ = auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: got.ID, Decision: "deny"})
		}
	}
	// Narrowing can never widen: a longer narrow is ignored.
	wide := withToken(stewardSession("windows-ep-1", control, 3600, "job-5"), &responseauth.StewardScreenNarrow{MaxSeconds: 7200})
	if got, _ := auth.RequestApproval(wide); got != nil && got.State == responseauth.ApprovalApproved {
		t.Fatal("a narrowing must not widen the rule")
	} else if got != nil {
		_, _ = auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: got.ID, Decision: "deny"})
	}
	if got, _ := auth.RequestApproval(withToken(stewardSession("windows-ep-1", view, 900, "job-6"), &responseauth.StewardScreenNarrow{Mode: "view", MaxSeconds: 900})); got == nil || got.State != responseauth.ApprovalApproved {
		t.Fatalf("a session within the narrowed rule: %+v", got)
	}

	// A run id is the steward's alone.
	in := &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin (api-key)", Kind: response.ActionKindScreenSession,
		Targets: []string{"windows-ep-1"}, Payload: []byte(control), SessionSeconds: 1800, AskFirst: true, StewardRun: "job-7"}
	if _, err := auth.RequestApproval(in); err == nil {
		t.Fatal("an admin-key request must not name a steward run")
	}
	// The steward cannot raise its own rule.
	self := stewardSession("windows-ep-1", control, 0, "")
	self.StewardRule = &responseauth.StewardScreenAsk{MaxSeconds: 1800}
	if _, err := auth.RequestApproval(self); err == nil {
		t.Fatal("the steward must not ask for its own screen rule")
	}
	// The consume must carry the run the rule approved.
	got, _ = auth.RequestApproval(withToken(stewardSession("windows-ep-1", control, 1800, "job-8"), nil))
	if _, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: got.ID, TenantID: "default", Requester: stewardReq,
		Kind: response.ActionKindScreenSession, Digest: digestOf([]byte(control)), Targets: []string{"windows-ep-1"}, SessionSeconds: 1800, AskFirst: true, StewardRun: "job-9"}); !errors.Is(err, responseauth.ErrApprovalMismatch) {
		t.Fatalf("another run under the same approval: %v", err)
	}
}
