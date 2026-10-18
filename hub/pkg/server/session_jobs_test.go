package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

// Terminal and screen jobs end when their session does: the agent never posts
// a result for them, so without this they stay acknowledged forever.
func TestSessionJobsEndWithTheirSession(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if srv.terminalMgr == nil {
		srv.terminalMgr = terminal.NewManager(srv.store.DB(), nil, 30*time.Minute, 10*time.Minute)
		t.Cleanup(func() { _ = srv.terminalMgr.Close() })
	}
	newJob := func(kind response.ActionKind) (string, string) {
		t.Helper()
		g := &response.EndpointGrant{Version: response.GrantVersion, GrantID: fmt.Sprintf("g-%d", time.Now().UnixNano()), TenantID: "default",
			EndpointID: "ep-lap", ActionKind: kind, ActionDigest: strings.Repeat("0", 64), OperatorID: "owner",
			ResponseSessionID: "rs", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
		sess, err := srv.terminalMgr.CreateSession("default", "ep-lap", "owner", "/bin/sh", g)
		if err != nil {
			t.Fatal(err)
		}
		job, err := srv.responseStore.CreateJob("default", "ep-lap", kind, "owner", g,
			fmt.Sprintf(`{"session_id":%q,"mode":"view","connect_token":"x"}`, sess.SessionID), "")
		if err != nil {
			t.Fatal(err)
		}
		return job.ID, sess.SessionID
	}

	ran, ranSess := newJob(response.ActionKindTerminalSession)
	never, neverSess := newJob(response.ActionKindScreenSession)
	live, _ := newJob(response.ActionKindScreenSession)
	if n := len(offerAndAck(t, srv, "ep-lap")); n != 3 {
		t.Fatalf("offered %d", n)
	}
	if s, _ := srv.terminalMgr.GetSession(ranSess); s != nil {
		now := time.Now().UTC()
		s.StartedAt = &now
	}
	closeSession := func(id string) {
		if err := srv.terminalMgr.CloseSession(id, "operator closed"); err != nil {
			t.Fatal(err)
		}
	}
	closeSession(ranSess)
	closeSession(neverSess)
	untaken, untakenSess := newJob(response.ActionKindTerminalSession)
	closeSession(untakenSess)
	if n := srv.reconcileSessionJobs(time.Now().UTC()); n != 3 {
		t.Fatalf("ended %d jobs, want 3", n)
	}
	for id, want := range map[string]response.JobState{ran: response.StateSucceeded, never: response.StateFailed,
		untaken: response.StateCancelled, live: response.StateAcknowledged} {
		j, err := srv.responseStore.GetJob("default", id)
		if err != nil || j.State != want {
			t.Errorf("job %s: %v %v, want %s", id, j.State, err, want)
		}
	}
	if j, _ := srv.responseStore.GetJob("default", never); j.ErrorCode != "session_never_started" {
		t.Errorf("never-started code %q", j.ErrorCode)
	}
	if n := srv.reconcileSessionJobs(time.Now().UTC()); n != 0 {
		t.Fatalf("second pass ended %d", n)
	}
	// The screen session the hub ended leaves its reason in the audit log;
	// terminal sessions do not get a screen row.
	logs, err := srv.store.ListAuditLogs("", 500)
	if err != nil {
		t.Fatal(err)
	}
	ended := map[string]string{}
	for _, e := range logs {
		if e.Action == "SCREEN_SESSION_ENDED" {
			ended[e.Resource] = e.Details
		}
	}
	if len(ended) != 1 || !strings.Contains(ended[neverSess], "ep-lap") || !strings.Contains(ended[neverSess], "operator closed") {
		t.Fatalf("SCREEN_SESSION_ENDED rows: %v", ended)
	}

	// A session the hub has lost ends its job after a day, not before.
	lost := response.OpenSessionJob{JobID: "x", SessionID: "gone", RequestedAt: time.Now().Add(-time.Hour)}
	if _, _, end := sessionJobOutcome(srv.terminalMgr, lost, time.Now()); end {
		t.Fatal("ended a recent job with an unknown session")
	}
	if code, _, end := sessionJobOutcome(srv.terminalMgr, lost, time.Now().Add(sessionJobOrphanAfter)); !end || code != "session_unknown" {
		t.Fatalf("lost session: %q %v", code, end)
	}
}
