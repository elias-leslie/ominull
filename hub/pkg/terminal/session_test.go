package terminal

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	"ominull/hub/pkg/evidence"
	"ominull/hub/pkg/response"
)

func TestTerminalManager_SessionLifecycle(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

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

func TestTerminalManager_EvidenceStoreRecording(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer db.Close()

	masterKey, err := evidence.LoadOrCreateMasterKey(filepath.Join(tmpDir, "evidence.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey failed: %v", err)
	}

	evidStore, err := evidence.NewStore(db, filepath.Join(tmpDir, "evidence_objects"), masterKey)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	mgr := NewManager(db, evidStore, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	tenantID := "tenant-forensics-1"
	endpointID := "srv-db-01"
	opID := "sec-analyst"
	program := "/bin/sh"

	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-evidence-shell-01",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
		OperatorID:        opID,
		ResponseSessionID: "resp-sess-evid-01",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(15 * time.Minute).Unix(),
	}

	// 1. Create session with Evidence Store attached
	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sess.BundleID == "" {
		t.Fatalf("expected bundle_id to be populated from evidence store")
	}
	if sess.RecordingState != "recording" {
		t.Fatalf("expected recording_state recording, got %s", sess.RecordingState)
	}

	// 2. Record interactive frames (stdin, resize, stdout)
	framesToRecord := []TerminalFrame{
		{Type: FrameStdin, Data: []byte("uname -a\n")},
		{Type: FrameResize, Rows: 30, Cols: 100},
		{Type: FrameStdout, Data: []byte("Linux srv-db-01 6.1.0 #1 SMP\n")},
		{Type: FrameClose},
	}

	for _, f := range framesToRecord {
		if err := mgr.RecordFrame(sess.SessionID, f); err != nil {
			t.Fatalf("RecordFrame %s failed: %v", f.Type, err)
		}
	}

	// 3. Verify reading live recording from memory
	liveFrames, liveMeta, err := mgr.GetSessionRecording(tenantID, sess.SessionID)
	if err != nil {
		t.Fatalf("GetSessionRecording live failed: %v", err)
	}
	if len(liveFrames) != len(framesToRecord) {
		t.Fatalf("expected %d live frames, got %d", len(framesToRecord), len(liveFrames))
	}
	if liveMeta.RecordingState != "recording" {
		t.Fatalf("expected live state recording, got %s", liveMeta.RecordingState)
	}
	if liveMeta.Encryption != "AES-256-GCM (Evidence Store)" {
		t.Fatalf("unexpected encryption metadata: %s", liveMeta.Encryption)
	}

	// 4. Close session -> triggers automatic sealing into Evidence Store
	if err := mgr.CloseSession(sess.SessionID, "analyst_exit"); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	// In-memory frames should be nil (RAM released)
	sess.mu.RLock()
	inMemFrames := sess.Frames
	recState := sess.RecordingState
	evidItemID := sess.EvidenceItemID
	sess.mu.RUnlock()

	if inMemFrames != nil {
		t.Fatalf("expected in-memory frames to be cleared after sealing, got %d frames", len(inMemFrames))
	}
	if recState != "sealed" {
		t.Fatalf("expected recording_state sealed, got %s", recState)
	}
	if evidItemID == "" {
		t.Fatalf("expected evidence_item_id to be populated")
	}

	// 5. Read sealed recording -> must decrypt from Evidence Store
	sealedFrames, sealedMeta, err := mgr.GetSessionRecording(tenantID, sess.SessionID)
	if err != nil {
		t.Fatalf("GetSessionRecording sealed failed: %v", err)
	}
	if len(sealedFrames) != len(framesToRecord) {
		t.Fatalf("expected %d sealed frames, got %d", len(framesToRecord), len(sealedFrames))
	}
	if sealedMeta.RecordingState != "sealed" {
		t.Fatalf("expected sealed state, got %s", sealedMeta.RecordingState)
	}
	if string(sealedFrames[0].Data) != "uname -a\n" {
		t.Fatalf("expected frame 0 data 'uname -a\\n', got %q", string(sealedFrames[0].Data))
	}
	if sealedFrames[1].Rows != 30 || sealedFrames[1].Cols != 100 {
		t.Fatalf("expected resize frame rows=30 cols=100, got %+v", sealedFrames[1])
	}
	if string(sealedFrames[2].Data) != "Linux srv-db-01 6.1.0 #1 SMP\n" {
		t.Fatalf("expected frame 2 data 'Linux srv-db-01 6.1.0 #1 SMP\\n', got %q", string(sealedFrames[2].Data))
	}

	// 6. Tenant isolation on recording read
	_, _, err = mgr.GetSessionRecording("other-tenant", sess.SessionID)
	if err == nil || !strings.Contains(err.Error(), "tenant mismatch") {
		t.Fatalf("expected tenant mismatch error, got: %v", err)
	}

	// 7. Verify evidence bundle and receipt in Evidence Store
	bundle, err := evidStore.GetBundle(tenantID, sess.BundleID)
	if err != nil {
		t.Fatalf("GetBundle failed: %v", err)
	}
	if bundle.Status != evidence.BundleStatusCompleted {
		t.Fatalf("expected bundle status completed, got %s", bundle.Status)
	}
	if bundle.ReceiptSHA256 == "" {
		t.Fatalf("expected non-empty receipt_sha256 on evidence bundle")
	}
}

func TestTerminalManager_BoundedRecordingCap(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	// Set low recording byte cap: 250 bytes
	mgr.SetMaxRecordingBytes(250)

	tenantID := "tenant-cap-test"
	endpointID := "srv-cap-01"
	opID := "admin"
	program := "/bin/bash"

	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-cap-01",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        opID,
		ResponseSessionID: "resp-sess-cap-01",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}

	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, grant)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Frame 1: 50 bytes (under cap)
	err = mgr.RecordFrame(sess.SessionID, TerminalFrame{
		Type: FrameStdout,
		Data: []byte("first frame output\n"),
	})
	if err != nil {
		t.Fatalf("RecordFrame 1 failed: %v", err)
	}
	if sess.RecordingState != "recording" {
		t.Fatalf("expected state recording, got %s", sess.RecordingState)
	}

	// Frame 2: 300 bytes (exceeds cap)
	largeData := make([]byte, 300)
	for i := range largeData {
		largeData[i] = 'A'
	}
	err = mgr.RecordFrame(sess.SessionID, TerminalFrame{
		Type: FrameStdout,
		Data: largeData,
	})
	if err != nil {
		t.Fatalf("RecordFrame 2 failed: %v", err)
	}

	// Recording should now be marked "bounded"
	sess.mu.RLock()
	st := sess.RecordingState
	frameCount := len(sess.Frames)
	lastFrame := sess.Frames[frameCount-1]
	sess.mu.RUnlock()

	if st != "bounded" {
		t.Fatalf("expected recording state bounded, got %s", st)
	}
	if !strings.Contains(string(lastFrame.Data), "Recording limit reached") {
		t.Fatalf("expected bounded marker frame, got: %s", string(lastFrame.Data))
	}

	// Frame 3: further attempts to record should be dropped without error
	err = mgr.RecordFrame(sess.SessionID, TerminalFrame{
		Type: FrameStdout,
		Data: []byte("dropped frame\n"),
	})
	if err != nil {
		t.Fatalf("expected RecordFrame to succeed (drop frame), got: %v", err)
	}

	sess.mu.RLock()
	newCount := len(sess.Frames)
	sess.mu.RUnlock()

	if newCount != frameCount {
		t.Fatalf("expected frame count to remain %d, got %d", frameCount, newCount)
	}
}
