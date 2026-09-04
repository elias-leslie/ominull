package terminal

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
	"ominull/hub/pkg/response"
)

// initStore initializes the SQLite schema and runs startup recovery.
func (m *Manager) initStore() error {
	if m.db == nil {
		db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=busy_timeout(5000)")
		if err != nil {
			return fmt.Errorf("open in-memory sqlite failed: %w", err)
		}
		m.db = db
	}

	schema := `
	CREATE TABLE IF NOT EXISTS terminal_sessions (
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
		grant_json TEXT,
		bundle_id TEXT DEFAULT '',
		evidence_item_id TEXT DEFAULT '',
		recording_state TEXT DEFAULT 'recording',
		recording_bytes INTEGER DEFAULT 0,
		frame_count INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_terminal_sessions_tenant ON terminal_sessions(tenant_id, state);
	CREATE INDEX IF NOT EXISTS idx_terminal_sessions_endpoint ON terminal_sessions(endpoint_id, state);
	`
	if _, err := m.db.Exec(schema); err != nil {
		return fmt.Errorf("init terminal_sessions schema: %w", err)
	}

	// Schema migrations for backward compatibility
	_, _ = m.db.Exec("ALTER TABLE terminal_sessions ADD COLUMN bundle_id TEXT DEFAULT ''")
	_, _ = m.db.Exec("ALTER TABLE terminal_sessions ADD COLUMN evidence_item_id TEXT DEFAULT ''")
	_, _ = m.db.Exec("ALTER TABLE terminal_sessions ADD COLUMN recording_state TEXT DEFAULT 'recording'")
	_, _ = m.db.Exec("ALTER TABLE terminal_sessions ADD COLUMN recording_bytes INTEGER DEFAULT 0")
	_, _ = m.db.Exec("ALTER TABLE terminal_sessions ADD COLUMN frame_count INTEGER DEFAULT 0")

	// Startup Recovery: Any sessions left in active/connecting/waiting states are marked failed
	recoveryQuery := `
	UPDATE terminal_sessions
	SET state = 'failed', closed_at = CURRENT_TIMESTAMP, close_reason = 'daemon_restarted'
	WHERE state IN ('waiting', 'connecting', 'active');
	`
	if _, err := m.db.Exec(recoveryQuery); err != nil {
		return fmt.Errorf("terminal startup recovery failed: %w", err)
	}

	return nil
}

// insertDurableSession persists a newly created session to SQLite.
func (m *Manager) insertDurableSession(s *TerminalSession) error {
	var grantJSON []byte
	if s.Grant != nil {
		var err error
		grantJSON, err = json.Marshal(s.Grant)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}
	}

	query := `
	INSERT INTO terminal_sessions (
		session_id, tenant_id, endpoint_id, operator_id, program,
		state, token_hash, created_at, expires_at, idle_expires_at,
		grant_json, bundle_id, evidence_item_id, recording_state, recording_bytes, frame_count
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := m.db.Exec(
		query,
		s.SessionID, s.TenantID, s.EndpointID, s.OperatorID, s.Program,
		string(s.State), s.TokenHash, s.CreatedAt, s.ExpiresAt, s.IdleExpiresAt,
		string(grantJSON), s.BundleID, s.EvidenceItemID, s.RecordingState, s.RecordingBytes, s.FrameCount,
	)
	return err
}

// updateRecordingMetadata persists updated recording state, bytes, and frame count to SQLite.
func (m *Manager) updateRecordingMetadata(sessionID, bundleID, evidenceItemID, recordingState string, recordingBytes int64, frameCount int) error {
	query := `
	UPDATE terminal_sessions
	SET bundle_id = ?, evidence_item_id = ?, recording_state = ?, recording_bytes = ?, frame_count = ?
	WHERE session_id = ?;
	`
	_, err := m.db.Exec(query, bundleID, evidenceItemID, recordingState, recordingBytes, frameCount, sessionID)
	return err
}

// updateDurableState updates state and closure reasons in SQLite.
func (m *Manager) updateDurableState(sessionID string, state SessionState, startedAt, closedAt *time.Time, closeReason string, opConn, agConn bool) error {
	query := `
	UPDATE terminal_sessions
	SET state = ?, started_at = COALESCE(?, started_at), closed_at = ?, close_reason = ?,
	    operator_connected = ?, agent_connected = ?
	WHERE session_id = ?;
	`
	_, err := m.db.Exec(query, string(state), startedAt, closedAt, closeReason, opConn, agConn, sessionID)
	return err
}

// countActiveSessions queries the database for active sessions.
func (m *Manager) countActiveSessions(tenantID, endpointID string, now time.Time) (activeTenant int, activeEndpoint int, err error) {
	// Tenant count
	row := m.db.QueryRow(`
		SELECT COUNT(*) FROM terminal_sessions
		WHERE tenant_id = ? AND state IN ('waiting', 'connecting', 'active') AND expires_at > ?;
	`, tenantID, now)
	if err := row.Scan(&activeTenant); err != nil {
		return 0, 0, err
	}

	// Endpoint count
	row = m.db.QueryRow(`
		SELECT COUNT(*) FROM terminal_sessions
		WHERE endpoint_id = ? AND state IN ('waiting', 'connecting', 'active') AND expires_at > ?;
	`, endpointID, now)
	if err := row.Scan(&activeEndpoint); err != nil {
		return 0, 0, err
	}

	return activeTenant, activeEndpoint, nil
}

// expiredSessionInfo records a swept session ID and reason for relay teardown.
type expiredSessionInfo struct {
	SessionID string
	Reason    string
	NewState  SessionState
}

// sweepExpiredSessions identifies and expires stale sessions in SQLite.
func (m *Manager) sweepExpiredSessions(now time.Time, connectTimeout time.Duration) ([]expiredSessionInfo, error) {
	// 1. Waiting / connecting sessions exceeding connect timeout (30s from created_at)
	connectCutoff := now.Add(-connectTimeout)
	rows, err := m.db.Query(`
		SELECT session_id FROM terminal_sessions
		WHERE state IN ('waiting', 'connecting') AND created_at < ?;
	`, connectCutoff)
	if err != nil {
		return nil, err
	}

	var expired []expiredSessionInfo
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			expired = append(expired, expiredSessionInfo{
				SessionID: id,
				Reason:    "connect_timeout",
				NewState:  StateFailed,
			})
		}
	}
	rows.Close()

	// 2. Active sessions exceeding idle timeout
	rows, err = m.db.Query(`
		SELECT session_id FROM terminal_sessions
		WHERE state = 'active' AND idle_expires_at < ?;
	`, now)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			expired = append(expired, expiredSessionInfo{
				SessionID: id,
				Reason:    "idle_timeout",
				NewState:  StateExpired,
			})
		}
	}
	rows.Close()

	// 3. Any active/connecting/waiting session exceeding max duration (expires_at)
	rows, err = m.db.Query(`
		SELECT session_id FROM terminal_sessions
		WHERE state IN ('waiting', 'connecting', 'active') AND expires_at < ?;
	`, now)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			expired = append(expired, expiredSessionInfo{
				SessionID: id,
				Reason:    "max_duration_exceeded",
				NewState:  StateExpired,
			})
		}
	}
	rows.Close()

	// Update DB rows for all expired sessions
	for _, item := range expired {
		_, _ = m.db.Exec(`
			UPDATE terminal_sessions
			SET state = ?, closed_at = ?, close_reason = ?
			WHERE session_id = ? AND state IN ('waiting', 'connecting', 'active');
		`, string(item.NewState), now, item.Reason, item.SessionID)
	}

	return expired, nil
}

// loadDurableSession retrieves a session record from SQLite.
func (m *Manager) loadDurableSession(sessionID string) (*TerminalSession, error) {
	query := `
	SELECT session_id, tenant_id, endpoint_id, operator_id, program,
	       state, token_hash, created_at, expires_at, idle_expires_at,
	       started_at, closed_at, close_reason, operator_connected, agent_connected,
	       grant_json, bundle_id, evidence_item_id, recording_state, recording_bytes, frame_count
	FROM terminal_sessions
	WHERE session_id = ?;
	`
	row := m.db.QueryRow(query, sessionID)

	var s TerminalSession
	var stateStr, grantJSON string
	var startedAt, closedAt sql.NullTime
	var closeReason sql.NullString
	var bundleID, evidenceItemID, recordingState sql.NullString
	var recordingBytes, frameCount sql.NullInt64

	err := row.Scan(
		&s.SessionID, &s.TenantID, &s.EndpointID, &s.OperatorID, &s.Program,
		&stateStr, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.IdleExpiresAt,
		&startedAt, &closedAt, &closeReason, &s.OperatorConnected, &s.AgentConnected,
		&grantJSON, &bundleID, &evidenceItemID, &recordingState, &recordingBytes, &frameCount,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("terminal session not found")
		}
		return nil, err
	}

	s.BundleID = bundleID.String
	s.EvidenceItemID = evidenceItemID.String
	s.RecordingState = recordingState.String
	if s.RecordingState == "" {
		s.RecordingState = "recording"
	}
	s.RecordingBytes = recordingBytes.Int64
	s.FrameCount = int(frameCount.Int64)

	s.State = SessionState(stateStr)
	if startedAt.Valid {
		s.StartedAt = &startedAt.Time
	}
	if closedAt.Valid {
		s.ClosedAt = &closedAt.Time
	}
	if closeReason.Valid {
		s.CloseReason = closeReason.String
	}
	if grantJSON != "" {
		var g response.EndpointGrant
		if err := json.Unmarshal([]byte(grantJSON), &g); err == nil {
			s.Grant = &g
		}
	}

	return &s, nil
}
