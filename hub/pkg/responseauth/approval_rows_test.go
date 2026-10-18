package responseauth_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/responseauth"
)

const allDay = "00:00-12:00,12:00-00:00Z"

func statementOf(t *testing.T, v *responseauth.ApprovalView) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v.Statement)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// machineWindow is a two-hour machine-time window around now on a machine
// offset minutes east of UTC.
func machineWindow(offset int) string {
	h := time.Now().UTC().Add(time.Duration(offset) * time.Minute).Hour()
	return fmt.Sprintf("%02d:00-%02d:00", (h+23)%24, (h+1)%24)
}

// Before any save the defaults decide: a maintenance run inside every
// target's window runs without asking (method row, the row and its inputs
// signed into the statement); outside it the session row asks while no
// session is open. The machine's clock offset comes from the hub's facts;
// without it a machine-time window counts as closed.
func TestApprovalRowsDefaultsDecideByWindow(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	in := packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay))
	v, err := auth.RequestApproval(in)
	if err != nil || v.State != responseauth.ApprovalApproved || v.Method != "row" || v.Row != "ominull.maintenance.in" || v.ApproverID != "defaults" {
		t.Fatalf("in-window run: %v %+v", err, v)
	}
	st := statementOf(t, v)
	ri, _ := st["row_inputs"].(map[string]any)
	if st["row"] != "ominull.maintenance.in" || ri["in_window"] != true || ri["category"] != "maintenance" || ri["reboot"] != false || ri["lab"] != false {
		t.Fatalf("statement row fields: %v", st)
	}

	w := machineWindow(300)
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", w))
	if v, err = auth.RequestApproval(in); err != nil || v.State != responseauth.ApprovalPending || statementOf(t, v)["row"] != "ominull.maintenance.out" {
		t.Fatalf("machine-time window without the offset must count as closed: %v %+v", err, v)
	}
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", w))
	in.Facts = &responseauth.ApprovalFacts{UTCOffsets: map[string]int{"ep-a": 300}}
	if v, err = auth.RequestApproval(in); err != nil || v.State != responseauth.ApprovalApproved || v.Row != "ominull.maintenance.in" {
		t.Fatalf("machine-time window with the offset: %v %+v", err, v)
	}
	// A restart step makes it a reboot run; careful packages always ask.
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-reboot", "careful", "enforce", 3600, "window", allDay))
	if v, err = auth.RequestApproval(in); err != nil || v.Row != "ominull.reboot.in" || v.State != responseauth.ApprovalApproved {
		t.Fatalf("restart in window: %v %+v", err, v)
	}
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-debloat", "careful", "enforce", 900, "window", allDay))
	if v, err = auth.RequestApproval(in); err != nil || v.State != responseauth.ApprovalPending || statementOf(t, v)["ask_reason"] == nil {
		t.Fatalf("careful package must ask: %v %+v", err, v)
	}
	// A host-locked target always asks, whatever the row.
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay))
	in.Facts = &responseauth.ApprovalFacts{Locked: []string{"ep-a"}}
	if v, err = auth.RequestApproval(in); err != nil || v.State != responseauth.ApprovalPending || !strings.Contains(fmt.Sprint(statementOf(t, v)["ask_reason"]), "host-locked") {
		t.Fatalf("locked target: %v %+v", err, v)
	}
	// A schedule's rule-only ask is covered by the row.
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay))
	in.RuleOnly = true
	if v, err = auth.RequestApproval(in); err != nil || v.Method != "row" {
		t.Fatalf("rule-only in window: %v %+v", err, v)
	}
}

// Tightening saves at once; loosening needs the owner's tap on a signed
// approval_rules ask that binds exactly the rows, session and lab list, spent
// once. A re-push of what is held is never looser.
func TestApprovalRowsSaveNeedsTheOwnerToLoosen(t *testing.T) {
	auth, ap, _, dir := newRuleAuthority(t)
	strict := map[string]string{"ominull.maintenance.in": "ask"}
	res, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: strict, SavedAt: "t1"})
	if err != nil || !res.Accepted || len(res.Looser) != 0 || !res.Rows.Stored || res.Rows.Rows["ominull.maintenance.in"] != "ask" {
		t.Fatalf("tightening: %v %+v", err, res)
	}
	in := packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay))
	if v, err := auth.RequestApproval(in); err != nil || v.State != responseauth.ApprovalPending || v.Offer != "" {
		t.Fatalf("after tightening the run asks, offering no approve-all rule: %v %+v", err, v)
	}
	if _, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: strict}); err != nil {
		t.Fatalf("re-push: %v", err)
	}

	session := &responseauth.RowSession{Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Hour)}
	loose := &responseauth.ApprovalRowsInput{Rows: map[string]string{"ominull.remote.people": "auto"}, Session: session, Lab: []string{"lab-1"}}
	if _, err := auth.SetApprovalRows(loose); !errors.Is(err, responseauth.ErrRowsNeedApproval) {
		t.Fatalf("loosening without the owner: %v", err)
	}
	ask, err := auth.AskApprovalRows(loose)
	if err != nil || ask.Approval == nil || ask.Approval.Kind != responseauth.ApprovalKindRules || ask.Approval.State != responseauth.ApprovalPending {
		t.Fatalf("ask: %v %+v", err, ask)
	}
	want := map[string]bool{"ominull.maintenance.in": true, "ominull.remote.people": true, "session": true}
	for _, id := range ask.Looser {
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("looser %v misses %v", ask.Looser, want)
	}
	st := statementOf(t, ask.Approval)
	rows, _ := st["rows"].(map[string]any)
	if st["kind"] != "approval_rules" || rows["ominull.remote.people"] != "auto" || st["session"] == nil || fmt.Sprint(st["lab"]) != "[lab-1]" {
		t.Fatalf("the signed statement must carry the rows, session and lab: %v", st)
	}
	found := false
	for _, p := range auth.PendingApprovals() {
		found = found || p.ID == ask.Approval.ID
	}
	if !found {
		t.Fatal("the rules ask is not relayed with the other approvals")
	}
	loose.ApprovalID = ask.Approval.ID
	if _, err := auth.SetApprovalRows(loose); !errors.Is(err, responseauth.ErrRowsNeedApproval) {
		t.Fatalf("pending ask must not save: %v", err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: ask.Approval.ID, Decision: "approve", Assertion: ap.Assert(ask.Approval.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	// The approved ask binds exactly its rows: a different save cannot spend it.
	other := *loose
	other.Rows = map[string]string{"ominull.remote.people": "auto", "ominull.isolation": "auto"}
	if _, err := auth.SetApprovalRows(&other); !errors.Is(err, responseauth.ErrRowsNeedApproval) {
		t.Fatalf("a different save spent the approval: %v", err)
	}
	if _, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: ask.Approval.ID, TenantID: "default", Requester: ask.Approval.Requester,
		Kind: responseauth.ApprovalKindRules, Digest: statementOf(t, ask.Approval)["digest"].(string), Targets: []string{"approval-rules"}}); err == nil {
		t.Fatal("a rules approval must never sign grants")
	}
	res, err = auth.SetApprovalRows(loose)
	if err != nil || !res.Accepted || res.Rows.ApproverID != "owner-phone" || !res.Rows.SessionOpen || res.Rows.Rows["ominull.maintenance.in"] != "auto" {
		t.Fatalf("approved save: %v %+v", err, res)
	}
	// Spent: loosening again with the same approval fails; re-pushing is fine.
	again := *loose
	again.Rows = map[string]string{"ominull.remote.people": "auto", "ominull.isolation": "auto"}
	if _, err := auth.SetApprovalRows(&again); !errors.Is(err, responseauth.ErrRowsNeedApproval) {
		t.Fatalf("spent approval reused: %v", err)
	}
	loose.ApprovalID = ""
	if _, err := auth.SetApprovalRows(loose); err != nil {
		t.Fatalf("re-push of held rows: %v", err)
	}
	// The session row now runs out-of-window maintenance, and the lab list
	// picks remote.lab.
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600))
	if v, err := auth.RequestApproval(in); err != nil || v.Row != "ominull.maintenance.out" || v.State != responseauth.ApprovalApproved {
		t.Fatalf("out of window during the session: %v %+v", err, v)
	}
	// Kept across a restart.
	auth2, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if v := auth2.ApprovalRowsView("default"); !v.Stored || v.Rows["ominull.remote.people"] != "auto" || len(v.Lab) != 1 {
		t.Fatalf("after restart: %+v", v)
	}
	// An unreadable file approves nothing until Nightshift saves again.
	if err := os.WriteFile(filepath.Join(dir, "approval_rows.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth3, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: dir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	auth3.SetApproversPath(filepath.Join(dir, "approvers.json"))
	if v := auth3.ApprovalRowsView("default"); v.Error == "" || v.Rows["ominull.maintenance.in"] != "ask" {
		t.Fatalf("corrupt rows: %+v", v)
	}
	in = packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "enforce", 3600, "window", allDay))
	if v, err := auth3.RequestApproval(in); err != nil || v.State != responseauth.ApprovalPending {
		t.Fatalf("corrupt rows must ask: %v %+v", err, v)
	}
	if _, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: map[string]string{"ominull.nope": "auto"}}); err == nil {
		t.Fatal("unknown row accepted")
	}
	if _, err := auth.SetApprovalRows(&responseauth.ApprovalRowsInput{Rows: map[string]string{"ominull.other": "always"}}); err == nil {
		t.Fatal("unknown choice accepted")
	}
}
