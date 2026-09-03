package terminal

import (
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func TestTerminalManager_SessionLifecycle(t *testing.T) {
	mgr := NewManager(30*time.Minute, 10*time.Minute)

	tenantID := "tenant-test"
	endpointID := "linux-node-1"
	opID := "admin-1"
	program := "/bin/bash"

	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-shell-01",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        opID,
		ResponseSessionID: "resp-sess-01",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}

	// 1. Create Session
	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sess.State != StateWaiting || sess.ConnectToken == "" {
		t.Fatalf("unexpected initial session state: %+v", sess)
	}

	// 2. Reject duplicate concurrent session on same endpoint
	_, err = mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err == nil {
		t.Fatalf("expected duplicate session creation to fail")
	}

	// 3. Record Stdin/Stdout frames
	err = mgr.RecordFrame(sess.SessionID, TerminalFrame{
		Type: FrameStdin,
		Data: []byte("whoami\n"),
	})
	if err != nil {
		t.Fatalf("RecordFrame stdin failed: %v", err)
	}

	err = mgr.RecordFrame(sess.SessionID, TerminalFrame{
		Type: FrameStdout,
		Data: []byte("root\n"),
	})
	if err != nil {
		t.Fatalf("RecordFrame stdout failed: %v", err)
	}

	// 4. Inspect Summary
	summary := sess.Summary()
	if summary["frame_count"].(int) != 2 {
		t.Fatalf("expected 2 recorded frames, got %v", summary["frame_count"])
	}

	// 5. Close Session
	if err := mgr.CloseSession(sess.SessionID, "operator_exit"); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}
	if sess.State != StateClosed {
		t.Fatalf("expected state closed, got %s", sess.State)
	}

	// 6. After close, new session can be created on same endpoint
	sess2, err := mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err != nil {
		t.Fatalf("CreateSession after close failed: %v", err)
	}
	if sess2.SessionID == sess.SessionID {
		t.Fatalf("expected distinct session ID")
	}
}
