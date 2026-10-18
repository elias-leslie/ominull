package responseauth_test

import (
	"testing"
	"time"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/responseauth/approvaltest"
)

func blastOf(t *testing.T, v *responseauth.ApprovalView) map[string]any {
	t.Helper()
	b, _ := statementOf(t, v)["blast"].(map[string]any)
	if b == nil || v.Blast == nil || b["verdict"] != v.Blast.Verdict || b["class"] != v.Blast.Class {
		t.Fatalf("blast missing or differs between statement and view: %v %+v", b, v.Blast)
	}
	return b
}

// openSession saves the defaults plus an open work session: a loosening, so
// it takes the owner's tap on the approval_rules ask.
func openSession(t *testing.T, auth *responseauth.Authority, ap *approvaltest.Approver) {
	t.Helper()
	in := &responseauth.ApprovalRowsInput{Rows: map[string]string{}, Session: &responseauth.RowSession{Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Hour)}}
	ask, err := auth.AskApprovalRows(in)
	if err != nil || ask.Approval == nil {
		t.Fatalf("session ask: %v %+v", err, ask)
	}
	if b := blastOf(t, ask.Approval); b["verdict"] != "core" {
		t.Fatalf("a rules loosening is core: %v", b)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ask.Approval.ID, Decision: "approve", Assertion: ap.Assert(ask.Approval.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	in.ApprovalID = ask.Approval.ID
	if _, err := auth.SetApprovalRows(in); err != nil {
		t.Fatal(err)
	}
}

// Every ask is classed by blast radius, signed into its statement: audit
// runs are safe, released safe packages and a restart undoable, careful
// packages dangerous, isolating a host-locked machine core.
func TestBlastClassesEveryAsk(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	for _, tc := range []struct {
		name           string
		in             *responseauth.ApprovalRequestInput
		class, verdict string
	}{
		{"audit", packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "audit", 3600)), "package", "safe"},
		{"cleanup", packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay)), "package", "undoable"},
		{"restart", packageRequest([]string{"ep-a"}, packageItem(t, "windows-reboot", "careful", "enforce", 3600, "window", allDay)), "reboot", "undoable"},
		{"debloat", packageRequest([]string{"ep-a"}, packageItem(t, "windows-debloat", "careful", "enforce", 900)), "package", "dangerous"},
		{"gpu step", packageRequest([]string{"ep-a"}, packageItem(t, "windows-performance", "safe", "enforce", 900, "gpu_scheduling", "true")), "package", "dangerous"},
		{"isolate", isolateRequestFor("ep-1"), "isolation", "undoable"},
	} {
		v, err := auth.RequestApproval(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if b := blastOf(t, v); b["class"] != tc.class || b["verdict"] != tc.verdict || b["why"] == "" {
			t.Errorf("%s: blast %v, want %s/%s", tc.name, b, tc.class, tc.verdict)
		}
		if v.State == responseauth.ApprovalPending {
			_, _ = auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "deny"})
		}
	}
	locked := isolateRequestFor("ep-1")
	locked.Facts = &responseauth.ApprovalFacts{Locked: []string{"ep-1"}}
	v, err := auth.RequestApproval(locked)
	if err != nil {
		t.Fatal(err)
	}
	if b := blastOf(t, v); b["verdict"] != "core" {
		t.Fatalf("isolating a host-locked machine is core: %v", b)
	}
}

// While the owner's work session is open everything but core goes through
// without asking (method session), whatever its row says; core still asks.
func TestSessionApprovesAllButCore(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	debloat := func() *responseauth.ApprovalRequestInput {
		return packageRequest([]string{"ep-a"}, packageItem(t, "windows-debloat", "careful", "enforce", 900))
	}
	if v, err := auth.RequestApproval(debloat()); err != nil || v.State != responseauth.ApprovalPending {
		t.Fatalf("a careful package asks outside a session: %v %+v", err, v)
	}
	openSession(t, auth, ap)
	if v, err := auth.RequestApproval(debloat()); err != nil || v.State != responseauth.ApprovalApproved || v.Method != "session" {
		t.Fatalf("a careful package in the session: %v %+v", err, v)
	}
	if v, err := auth.RequestApproval(isolateRequestFor("ep-1")); err != nil || v.Method != "session" {
		t.Fatalf("isolating an unlocked machine (row ask) in the session: %v %+v", err, v)
	}
	locked := isolateRequestFor("ep-1")
	locked.Facts = &responseauth.ApprovalFacts{Locked: []string{"ep-1"}}
	if v, err := auth.RequestApproval(locked); err != nil || v.State != responseauth.ApprovalPending {
		t.Fatalf("core asks even in the session: %v %+v", err, v)
	}
}

// Three passkey approvals of the same non-core job shape with no denial make
// it automatic (method learned); a denial resets the count, and the owner's
// undo (forget in a rows save) makes it ask again.
func TestLearnedShapeAfterThreeApprovals(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	debloat := func() *responseauth.ApprovalRequestInput {
		return packageRequest([]string{"ep-a"}, packageItem(t, "windows-debloat", "careful", "enforce", 900))
	}
	answer := func(decision string) {
		t.Helper()
		v, err := auth.RequestApproval(debloat())
		if err != nil || v.State != responseauth.ApprovalPending {
			t.Fatalf("expected an ask before %s: %v %+v", decision, err, v)
		}
		if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: decision, Assertion: ap.Assert(v.Challenge, decision)}); err != nil {
			t.Fatal(err)
		}
	}
	answer("approve")
	answer("approve")
	answer("deny") // resets
	answer("approve")
	answer("approve")
	answer("approve") // third in a row: learned
	v, err := auth.RequestApproval(debloat())
	if err != nil || v.State != responseauth.ApprovalApproved || v.Method != "learned" || v.ApproverID != "owner-phone" {
		t.Fatalf("learned shape: %v %+v", err, v)
	}
	// A different machine is a different shape.
	other := packageRequest([]string{"ep-b"}, packageItem(t, "windows-debloat", "careful", "enforce", 900))
	if v, err := auth.RequestApproval(other); err != nil || v.State != responseauth.ApprovalPending {
		t.Fatalf("another machine must ask: %v %+v", err, v)
	}
	learned := auth.ApprovalRowsView("default").Learned
	if len(learned) == 0 || !learned[0].Auto || learned[0].Approvals != 3 {
		t.Fatalf("learned view: %+v", learned)
	}
	// Core never learns.
	locked := isolateRequestFor("ep-1")
	locked.Facts = &responseauth.ApprovalFacts{Locked: []string{"ep-1"}}
	for i := 0; i < 3; i++ {
		lv, _ := auth.RequestApproval(locked)
		if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: lv.ID, Decision: "approve", Assertion: ap.Assert(lv.Challenge, "approve")}); err != nil {
			t.Fatal(err)
		}
	}
	if lv, _ := auth.RequestApproval(locked); lv.State != responseauth.ApprovalPending {
		t.Fatalf("core learned: %+v", lv)
	}
	if _, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: map[string]string{}, Forget: []string{learned[0].Shape}}); err != nil {
		t.Fatal(err)
	}
	if v, err := auth.RequestApproval(debloat()); err != nil || v.State != responseauth.ApprovalPending {
		t.Fatalf("after the owner's undo it asks again: %v %+v", err, v)
	}
	if _, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: map[string]string{}, Forget: []string{"nope"}}); err == nil {
		t.Fatal("a malformed shape was accepted")
	}
}
