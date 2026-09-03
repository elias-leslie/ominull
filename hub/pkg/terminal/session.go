package terminal

import (
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
	ConnectToken      string                  `json:"connect_token"`
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
}

// Manager manages active terminal sessions and pairing.
type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*TerminalSession
	maxDuration time.Duration
	idleTimeout time.Duration
}

// NewManager creates a new Terminal Session Manager.
func NewManager(maxDuration, idleTimeout time.Duration) *Manager {
	if maxDuration <= 0 {
		maxDuration = 60 * time.Minute
	}
	if idleTimeout <= 0 {
		idleTimeout = 15 * time.Minute
	}
	return &Manager{
		sessions:    make(map[string]*TerminalSession),
		maxDuration: maxDuration,
		idleTimeout: idleTimeout,
	}
}

// CreateSession initializes a new waiting terminal session with a signed grant.
func (m *Manager) CreateSession(tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant) (*TerminalSession, error) {
	return m.CreateSessionWithID("", "", tenantID, endpointID, operatorID, program, grant)
}

// CreateSessionWithID initializes a new waiting terminal session with explicit IDs.
func (m *Manager) CreateSessionWithID(sessionID, token, tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant) (*TerminalSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check per-endpoint concurrency limit (1 active per endpoint)
	now := time.Now().UTC()
	for _, s := range m.sessions {
		if s.EndpointID == endpointID && (s.State == StateWaiting || s.State == StateConnecting || s.State == StateActive) {
			if now.Before(s.ExpiresAt) {
				return nil, fmt.Errorf("active terminal session %s already exists for endpoint %s", s.SessionID, endpointID)
			}
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
		CreatedAt:     now,
		ExpiresAt:     now.Add(m.maxDuration),
		IdleExpiresAt: now.Add(m.idleTimeout),
		Grant:         grant,
		Frames:        make([]TerminalFrame, 0, 128),
	}

	m.sessions[sessionID] = sess
	return sess, nil
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(sessionID string) (*TerminalSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, exists := m.sessions[sessionID]
	if !exists {
		return nil, errors.New("terminal session not found")
	}
	return sess, nil
}

// ListSessions returns active terminal sessions for a tenant.
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
	return nil
}

// CloseSession transitions a session to closed.
func (m *Manager) CloseSession(sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	now := time.Now().UTC()
	sess.State = StateClosed
	sess.ClosedAt = &now
	sess.CloseReason = reason
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
