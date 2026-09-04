package terminal

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// SessionState represents the terminal connection state.
type SessionState string

const (
	StateClosed     SessionState = "closed"
	StateWaiting    SessionState = "waiting"
	StateConnecting SessionState = "connecting"
	StateActive     SessionState = "active"
	StateClosing    SessionState = "closing"
	StateFailed     SessionState = "failed"
	StateExpired    SessionState = "expired"
)

// FrameType specifies the type of data frame exchanged over terminal relay.
type FrameType string

const (
	FrameStdin  FrameType = "stdin"
	FrameStdout FrameType = "stdout"
	FrameResize FrameType = "resize"
	FrameClose  FrameType = "close"
)

// TerminalFrame represents an auditable input/output/resize frame.
type TerminalFrame struct {
	Type      FrameType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data,omitempty"`
	Rows      uint16    `json:"rows,omitempty"`
	Cols      uint16    `json:"cols,omitempty"`
}

// TerminalSession tracks an interactive remote pseudoterminal session.
type TerminalSession struct {
	mu                sync.RWMutex
	SessionID         string                  `json:"session_id"`
	TenantID          string                  `json:"tenant_id"`
	EndpointID        string                  `json:"endpoint_id"`
	OperatorID        string                  `json:"operator_id"`
	Program           string                  `json:"program"` // /bin/sh, /bin/bash, powershell.exe, cmd.exe
	State             SessionState            `json:"state"`
	ConnectToken      string                  `json:"-"`
	TokenHash         string                  `json:"-"`
	CreatedAt         time.Time               `json:"created_at"`
	ExpiresAt         time.Time               `json:"expires_at"`
	IdleExpiresAt     time.Time               `json:"idle_expires_at"`
	StartedAt         *time.Time              `json:"started_at,omitempty"`
	ClosedAt          *time.Time              `json:"closed_at,omitempty"`
	CloseReason       string                  `json:"close_reason,omitempty"`
	OperatorConnected bool                    `json:"operator_connected"`
	AgentConnected    bool                    `json:"agent_connected"`
	Grant             *response.EndpointGrant `json:"grant,omitempty"`
	Frames            []TerminalFrame         `json:"-"`
	relay             *PairedRelay            `json:"-"`
}

// Manager manages active terminal sessions, persistence, and pairing.
type Manager struct {
	mu              sync.RWMutex
	db              *sql.DB
	sessions        map[string]*TerminalSession
	maxDuration     time.Duration
	idleTimeout     time.Duration
	connectTimeout  time.Duration
	stopSweeper     chan struct{}
	sweeperDone     chan struct{}
	stopSweeperOnce sync.Once
}

// NewManager creates a new Terminal Session Manager backed by SQLite.
func NewManager(db *sql.DB, maxDuration, idleTimeout time.Duration) *Manager {
	if maxDuration <= 0 {
		maxDuration = 60 * time.Minute
	}
	if idleTimeout <= 0 {
		idleTimeout = 15 * time.Minute
	}
	m := &Manager{
		db:             db,
		sessions:       make(map[string]*TerminalSession),
		maxDuration:    maxDuration,
		idleTimeout:    idleTimeout,
		connectTimeout: 30 * time.Second,
		stopSweeper:    make(chan struct{}),
		sweeperDone:    make(chan struct{}),
	}
	_ = m.initStore()
	m.startSweeper(5 * time.Second)
	return m
}

// Close gracefully terminates the sweeper and cleans up active sessions.
func (m *Manager) Close() error {
	m.stopSweeperOnce.Do(func() {
		close(m.stopSweeper)
		<-m.sweeperDone
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		sess.mu.Lock()
		relay := sess.relay
		sess.mu.Unlock()
		if relay != nil {
			relay.Close("manager_closed")
		}
	}
	return nil
}

// DB returns the underlying database handle.
func (m *Manager) DB() *sql.DB {
	return m.db
}

// SetConnectTimeout overrides the default 30-second connect timeout for testing.
func (m *Manager) SetConnectTimeout(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectTimeout = d
}

// startSweeper runs background sweeping for expired sessions.
func (m *Manager) startSweeper(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer func() {
			ticker.Stop()
			close(m.sweeperDone)
		}()

		for {
			select {
			case <-m.stopSweeper:
				return
			case <-ticker.C:
				m.Sweep()
			}
		}
	}()
}

// Sweep checks for and expires sessions exceeding timeouts.
func (m *Manager) Sweep() {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()

	expired, err := m.sweepExpiredSessions(now, m.connectTimeout)
	if err != nil {
		return
	}

	for _, item := range expired {
		if sess, exists := m.sessions[item.SessionID]; exists {
			sess.mu.Lock()
			sess.State = item.NewState
			sess.ClosedAt = &now
			if sess.CloseReason == "" {
				sess.CloseReason = item.Reason
			}
			relay := sess.relay
			sess.mu.Unlock()

			if relay != nil {
				relay.Close(item.Reason)
			}
		}
	}
}

// CreateSession initializes a new waiting terminal session with a signed grant.
func (m *Manager) CreateSession(tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant) (*TerminalSession, error) {
	return m.CreateSessionWithID("", "", tenantID, endpointID, operatorID, program, grant)
}

// CreateSessionWithID initializes a new waiting terminal session with explicit IDs and limits enforcement.
func (m *Manager) CreateSessionWithID(sessionID, token, tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant) (*TerminalSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()

	// 1. Enforce caps via SQLite store:
	// - 1 active session per endpoint
	// - 4 active sessions per tenant
	activeTenant, activeEndpoint, err := m.countActiveSessions(tenantID, endpointID, now)
	if err == nil {
		if activeTenant >= 4 {
			return nil, fmt.Errorf("active terminal session limit reached: max 4 active terminal sessions allowed per tenant (%s)", tenantID)
		}
		if activeEndpoint >= 1 {
			return nil, fmt.Errorf("active terminal session already exists: max 1 active terminal session allowed per endpoint (%s)", endpointID)
		}
	}

	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	if token == "" {
		token = uuid.New().String()
	}

	sess := &TerminalSession{
		SessionID:     sessionID,
		TenantID:      tenantID,
		EndpointID:    endpointID,
		OperatorID:    operatorID,
		Program:       program,
		State:         StateWaiting,
		ConnectToken:  token,
		TokenHash:     HashToken(token),
		CreatedAt:     now,
		ExpiresAt:     now.Add(m.maxDuration),
		IdleExpiresAt: now.Add(m.idleTimeout),
		Grant:         grant,
		Frames:        make([]TerminalFrame, 0, 128),
	}

	// Persist to SQLite
	if err := m.insertDurableSession(sess); err != nil {
		return nil, fmt.Errorf("persist terminal session: %w", err)
	}

	m.sessions[sessionID] = sess
	return sess, nil
}

// GetSession returns a session by ID, loading from DB if not in memory.
func (m *Manager) GetSession(sessionID string) (*TerminalSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[sessionID]
	if exists {
		return sess, nil
	}

	// Load from database
	loaded, err := m.loadDurableSession(sessionID)
	if err != nil {
		return nil, err
	}
	loaded.Frames = make([]TerminalFrame, 0, 128)
	m.sessions[sessionID] = loaded
	return loaded, nil
}

// ListSessions returns terminal sessions for a tenant.
func (m *Manager) ListSessions(tenantID string) []*TerminalSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*TerminalSession
	for _, s := range m.sessions {
		if s.TenantID == tenantID {
			result = append(result, s)
		}
	}
	return result
}

// RecordFrame appends an input/output frame to the session audit log.
func (m *Manager) RecordFrame(sessionID string, frame TerminalFrame) error {
	switch frame.Type {
	case FrameStdin, FrameStdout, FrameResize, FrameClose:
	default:
		return fmt.Errorf("unknown or invalid frame type: %q", frame.Type)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("terminal session not found")
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	now := time.Now().UTC()
	frame.Timestamp = now
	sess.Frames = append(sess.Frames, frame)
	sess.IdleExpiresAt = now.Add(m.idleTimeout)

	// Update idle expiration in database
	_ = m.updateDurableState(sessionID, sess.State, sess.StartedAt, sess.ClosedAt, sess.CloseReason, sess.OperatorConnected, sess.AgentConnected)
	return nil
}

// CloseSession transitions a session to closed, persists to DB, and closes paired relays.
func (m *Manager) CloseSession(sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	sess.mu.Lock()
	relay := sess.relay
	now := time.Now().UTC()
	sess.State = StateClosed
	sess.ClosedAt = &now
	sess.CloseReason = reason
	sess.mu.Unlock()

	_ = m.updateDurableState(sessionID, StateClosed, sess.StartedAt, &now, reason, sess.OperatorConnected, sess.AgentConnected)

	if relay != nil {
		relay.Close(reason)
	}
	return nil
}

// SessionSummary returns a serializable snapshot of the session.
func (s *TerminalSession) Summary() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, _ := json.Marshal(s)
	var res map[string]interface{}
	_ = json.Unmarshal(b, &res)
	res["frame_count"] = len(s.Frames)
	return res
}
