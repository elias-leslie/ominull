package terminal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

func newTestGrant(tenantID, endpointID, opID string) *response.EndpointGrant {
	return &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           fmt.Sprintf("grant-%s", endpointID),
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        opID,
		ResponseSessionID: fmt.Sprintf("resp-%s", endpointID),
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}
}

func TestStore_CapsEnforcement(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	tenantID := "tenant-caps-test"
	opID := "admin-caps"
	program := "/bin/bash"
	create := func(ep string) (*TerminalSession, error) {
		return mgr.CreateSession(tenantID, ep, opID, program, newTestGrant(tenantID, ep, opID))
	}

	// 1. Endpoint cap: several shells on one endpoint, up to MaxSessionsPerEndpoint.
	var first *TerminalSession
	for i := 0; i < MaxSessionsPerEndpoint; i++ {
		s, err := create("ep-1")
		if err != nil {
			t.Fatalf("session %d on ep-1: %v", i+1, err)
		}
		if first == nil {
			first = s
		}
	}
	if _, err := create("ep-1"); err == nil || !strings.Contains(err.Error(), "per endpoint") {
		t.Fatalf("expected endpoint cap rejection, got: %v", err)
	}

	// 2. Tenant cap across endpoints.
	n := MaxSessionsPerEndpoint
	for i := 2; n < MaxSessionsPerTenant; i++ {
		if _, err := create(fmt.Sprintf("ep-%d", i)); err != nil {
			t.Fatalf("session %d: %v", n+1, err)
		}
		n++
	}
	if _, err := create("ep-extra"); err == nil || !strings.Contains(err.Error(), "per tenant") {
		t.Fatalf("expected tenant cap rejection, got: %v", err)
	}

	// Closing one frees a slot.
	if err := mgr.CloseSession(first.SessionID, "test_close"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if _, err := create("ep-extra"); err != nil {
		t.Fatalf("expected a session after one closed, got: %v", err)
	}
}

func TestStore_DurablePersistenceAndTokenPrivacy(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	tenantID := "tenant-persist"
	endpointID := "ep-persist-1"
	opID := "admin-persist"
	program := "/bin/bash"

	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, newTestGrant(tenantID, endpointID, opID))
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 1. Verify row exists in SQLite
	loaded, err := mgr.loadDurableSession(sess.SessionID)
	if err != nil {
		t.Fatalf("loadDurableSession failed: %v", err)
	}
	if loaded.SessionID != sess.SessionID {
		t.Fatalf("expected session ID %s, got %s", sess.SessionID, loaded.SessionID)
	}
	if loaded.State != StateWaiting {
		t.Fatalf("expected state %s, got %s", StateWaiting, loaded.State)
	}
	if loaded.TokenHash != sess.TokenHash {
		t.Fatalf("expected token hash %s, got %s", sess.TokenHash, loaded.TokenHash)
	}
	if loaded.Grant == nil || loaded.Grant.GrantID != fmt.Sprintf("grant-%s", endpointID) {
		t.Fatalf("expected grant restored from grant_json")
	}

	// 2. Token privacy: verify plaintext token is never in DB
	db := mgr.DB()
	var rawTokenHash, rawState string
	err = db.QueryRow("SELECT token_hash, state FROM terminal_sessions WHERE session_id = ?", sess.SessionID).Scan(&rawTokenHash, &rawState)
	if err != nil {
		t.Fatalf("direct query failed: %v", err)
	}
	if rawTokenHash != sess.TokenHash {
		t.Fatalf("mismatched token hash in DB")
	}
	if strings.Contains(rawTokenHash, sess.ConnectToken) {
		t.Fatalf("SECURITY VIOLATION: plaintext token found in DB column token_hash")
	}

	// Scan all text columns for plaintext token
	var colVals []string
	rows, err := db.Query("SELECT session_id || ' ' || tenant_id || ' ' || endpoint_id || ' ' || operator_id || ' ' || program || ' ' || state || ' ' || token_hash || ' ' || COALESCE(close_reason, '') || ' ' || COALESCE(grant_json, '') FROM terminal_sessions WHERE session_id = ?", sess.SessionID)
	if err != nil {
		t.Fatalf("query all columns failed: %v", err)
	}
	for rows.Next() {
		var rowText string
		_ = rows.Scan(&rowText)
		colVals = append(colVals, rowText)
	}
	rows.Close()

	for _, text := range colVals {
		if strings.Contains(text, sess.ConnectToken) {
			t.Fatalf("SECURITY VIOLATION: plaintext token found in DB dump: %s", text)
		}
	}

	// 3. Token privacy in JSON and Summary
	jsonBytes, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session failed: %v", err)
	}
	if strings.Contains(string(jsonBytes), sess.ConnectToken) || strings.Contains(string(jsonBytes), sess.TokenHash) {
		t.Fatalf("SECURITY VIOLATION: token or token_hash leaked in JSON: %s", string(jsonBytes))
	}

	summary := sess.Summary()
	for k, v := range summary {
		vStr := fmt.Sprintf("%v", v)
		if strings.Contains(k, "token") || strings.Contains(vStr, sess.ConnectToken) || strings.Contains(vStr, sess.TokenHash) {
			t.Fatalf("SECURITY VIOLATION: token leaked in Summary: %s=%v", k, v)
		}
	}
}

func TestStore_SweeperConnectTimeout(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	// Shorten connect timeout for test
	mgr.SetConnectTimeout(50 * time.Millisecond)

	tenantID := "tenant-sweep"
	endpointID := "ep-sweep-timeout"
	opID := "admin-sweep"
	program := "/bin/bash"

	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, newTestGrant(tenantID, endpointID, opID))
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Wait for connect timeout to pass and trigger sweep
	time.Sleep(100 * time.Millisecond)
	mgr.Sweep()

	// Verify session transitioned to StateFailed with connect_timeout
	loaded, err := mgr.loadDurableSession(sess.SessionID)
	if err != nil {
		t.Fatalf("loadDurableSession failed: %v", err)
	}
	if loaded.State != StateFailed {
		t.Fatalf("expected state %s, got %s", StateFailed, loaded.State)
	}
	if loaded.CloseReason != "connect_timeout" {
		t.Fatalf("expected close_reason 'connect_timeout', got '%s'", loaded.CloseReason)
	}

	// Check in-memory session reflects it too
	sess.mu.RLock()
	st := sess.State
	cr := sess.CloseReason
	sess.mu.RUnlock()
	if st != StateFailed {
		t.Fatalf("expected in-memory state %s, got %s", StateFailed, st)
	}
	if cr != "connect_timeout" {
		t.Fatalf("expected in-memory close_reason 'connect_timeout', got '%s'", cr)
	}
}

func TestStore_SweeperIdleTimeout(t *testing.T) {
	mgr := NewManager(nil, nil, 30*time.Minute, 50*time.Millisecond)
	defer mgr.Close()

	tenantID := "tenant-sweep-idle"
	endpointID := "ep-sweep-idle"
	opID := "admin-sweep"
	program := "/bin/bash"

	sess, err := mgr.CreateSession(tenantID, endpointID, opID, program, newTestGrant(tenantID, endpointID, opID))
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Transition to active
	now := time.Now().UTC()
	err = mgr.updateDurableState(sess.SessionID, StateActive, &now, nil, "", true, true)
	if err != nil {
		t.Fatalf("updateDurableState failed: %v", err)
	}
	sess.mu.Lock()
	sess.State = StateActive
	sess.IdleExpiresAt = now.Add(50 * time.Millisecond)
	sess.mu.Unlock()

	// Update idle_expires_at in DB to be in past
	past := now.Add(-10 * time.Millisecond)
	_, err = mgr.DB().Exec("UPDATE terminal_sessions SET idle_expires_at = ? WHERE session_id = ?", past, sess.SessionID)
	if err != nil {
		t.Fatalf("update idle_expires_at failed: %v", err)
	}

	mgr.Sweep()

	loaded, err := mgr.loadDurableSession(sess.SessionID)
	if err != nil {
		t.Fatalf("loadDurableSession failed: %v", err)
	}
	if loaded.State != StateExpired {
		t.Fatalf("expected state %s, got %s", StateExpired, loaded.State)
	}
	if loaded.CloseReason != "idle_timeout" {
		t.Fatalf("expected close_reason 'idle_timeout', got '%s'", loaded.CloseReason)
	}
}

func TestStore_StartupDaemonRestartRecovery(t *testing.T) {
	// 1. Create a shared SQLite DB
	db, err := sql.Open("sqlite", "file:test_recovery?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer db.Close()

	// 2. Initialize schema manually and insert sessions in dangling states
	_, err = db.Exec(`
	CREATE TABLE terminal_sessions (
		session_id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		program TEXT NOT NULL,
		state TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		idle_expires_at TIMESTAMP NOT NULL,
		started_at TIMESTAMP,
		closed_at TIMESTAMP,
		close_reason TEXT,
		operator_connected BOOLEAN NOT NULL DEFAULT 0,
		agent_connected BOOLEAN NOT NULL DEFAULT 0,
		grant_json TEXT
	);
	INSERT INTO terminal_sessions (session_id, tenant_id, endpoint_id, operator_id, program, state, token_hash, created_at, expires_at, idle_expires_at)
	VALUES
		('sess-waiting', 't1', 'e1', 'op1', '/bin/sh', 'waiting', 'hash1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('sess-connecting', 't1', 'e2', 'op1', '/bin/sh', 'connecting', 'hash2', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('sess-active', 't1', 'e3', 'op1', '/bin/sh', 'active', 'hash3', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('sess-closed', 't1', 'e4', 'op1', '/bin/sh', 'closed', 'hash4', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("insert fixture failed: %v", err)
	}

	// 3. Spin up NewManager with this DB -> runs initStore() and recovery
	mgr := NewManager(db, nil, 30*time.Minute, 10*time.Minute)
	defer mgr.Close()

	// 4. Verify all dangling sessions transitioned to failed with daemon_restarted
	for _, id := range []string{"sess-waiting", "sess-connecting", "sess-active"} {
		var state, closeReason string
		var closedAt sql.NullTime
		err := db.QueryRow("SELECT state, close_reason, closed_at FROM terminal_sessions WHERE session_id = ?", id).Scan(&state, &closeReason, &closedAt)
		if err != nil {
			t.Fatalf("query session %s failed: %v", id, err)
		}
		if state != string(StateFailed) {
			t.Errorf("session %s: expected state failed, got %s", id, state)
		}
		if closeReason != "daemon_restarted" {
			t.Errorf("session %s: expected close_reason daemon_restarted, got %s", id, closeReason)
		}
		if !closedAt.Valid {
			t.Errorf("session %s: expected closed_at timestamp", id)
		}
	}

	// 5. Verify sess-closed remained closed and was not modified
	var state, closeReason sql.NullString
	err = db.QueryRow("SELECT state, close_reason FROM terminal_sessions WHERE session_id = 'sess-closed'").Scan(&state, &closeReason)
	if err != nil {
		t.Fatalf("query sess-closed failed: %v", err)
	}
	if state.String != string(StateClosed) {
		t.Errorf("sess-closed state altered to %s", state.String)
	}
	if closeReason.Valid && closeReason.String == "daemon_restarted" {
		t.Errorf("sess-closed close_reason altered to daemon_restarted")
	}
}
