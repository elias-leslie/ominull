package terminal

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/evidence"
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

// DefaultMaxSessionRecordingBytes is the maximum recorded byte cap per terminal session (10 MiB).
const DefaultMaxSessionRecordingBytes int64 = 10 * 1024 * 1024

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
	BundleID          string                  `json:"bundle_id,omitempty"`
	EvidenceItemID    string                  `json:"evidence_item_id,omitempty"`
	RecordingState    string                  `json:"recording_state,omitempty"` // "recording", "sealed", "bounded"
	RecordingBytes    int64                   `json:"recording_bytes"`
	MaxRecordingBytes int64                   `json:"max_recording_bytes,omitempty"`
	FrameCount        int                     `json:"frame_count"`
	relay             *PairedRelay            `json:"-"`
}

// Manager manages active terminal sessions, persistence, and pairing.
type Manager struct {
	mu                sync.RWMutex
	db                *sql.DB
	evidenceStore     *evidence.Store
	sessions          map[string]*TerminalSession
	maxDuration       time.Duration
	idleTimeout       time.Duration
	connectTimeout    time.Duration
	maxRecordingBytes int64
	stopSweeper       chan struct{}
	sweeperDone       chan struct{}
	stopSweeperOnce   sync.Once
}

// NewManager creates a new Terminal Session Manager backed by SQLite.
func NewManager(db *sql.DB, evidStore *evidence.Store, maxDuration, idleTimeout time.Duration) *Manager {
	if maxDuration <= 0 {
		maxDuration = 60 * time.Minute
	}
	if idleTimeout <= 0 {
		idleTimeout = 15 * time.Minute
	}
	m := &Manager{
		db:                db,
		evidenceStore:     evidStore,
		sessions:          make(map[string]*TerminalSession),
		maxDuration:       maxDuration,
		idleTimeout:       idleTimeout,
		connectTimeout:    30 * time.Second,
		maxRecordingBytes: DefaultMaxSessionRecordingBytes,
		stopSweeper:       make(chan struct{}),
		sweeperDone:       make(chan struct{}),
	}
	_ = m.initStore()
	m.startSweeper(5 * time.Second)
	return m
}

// SetEvidenceStore configures the evidence store backend for frame encryption.
func (m *Manager) SetEvidenceStore(store *evidence.Store) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evidenceStore = store
}

// SetMaxRecordingBytes sets a custom per-session recording byte limit.
func (m *Manager) SetMaxRecordingBytes(b int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxRecordingBytes = b
}

// Close gracefully terminates the sweeper and cleans up active sessions.
func (m *Manager) Close() error {
	m.stopSweeperOnce.Do(func() {
		close(m.stopSweeper)
		<-m.sweeperDone
	})

	m.mu.Lock()
	var relaysToClose []*PairedRelay
	for _, sess := range m.sessions {
		sess.mu.Lock()
		if sess.relay != nil {
			relaysToClose = append(relaysToClose, sess.relay)
		}
		sess.mu.Unlock()
	}
	m.mu.Unlock()

	for _, relay := range relaysToClose {
		relay.Close("manager_closed")
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
	expired, err := m.sweepExpiredSessions(now, m.connectTimeout)
	if err != nil {
		m.mu.Unlock()
		return
	}

	var toCloseRelays []*PairedRelay
	var toSealIDs []string
	for _, item := range expired {
		toSealIDs = append(toSealIDs, item.SessionID)
		if sess, exists := m.sessions[item.SessionID]; exists {
			sess.mu.Lock()
			sess.State = item.NewState
			sess.ClosedAt = &now
			if sess.CloseReason == "" {
				sess.CloseReason = item.Reason
			}
			if sess.relay != nil {
				toCloseRelays = append(toCloseRelays, sess.relay)
			}
			sess.mu.Unlock()
		}
	}
	m.mu.Unlock()

	for _, relay := range toCloseRelays {
		relay.Close("timeout")
	}
	for _, id := range toSealIDs {
		_ = m.SealSessionRecording(id)
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

	maxRec := m.maxRecordingBytes
	if maxRec <= 0 {
		maxRec = DefaultMaxSessionRecordingBytes
	}

	sess := &TerminalSession{
		SessionID:         sessionID,
		TenantID:          tenantID,
		EndpointID:        endpointID,
		OperatorID:        operatorID,
		Program:           program,
		State:             StateWaiting,
		ConnectToken:      token,
		TokenHash:         HashToken(token),
		CreatedAt:         now,
		ExpiresAt:         now.Add(m.maxDuration),
		IdleExpiresAt:     now.Add(m.idleTimeout),
		Grant:             grant,
		Frames:            make([]TerminalFrame, 0, 128),
		RecordingState:    "recording",
		MaxRecordingBytes: maxRec,
	}

	// Create an evidence bundle for this terminal session if evidence store is attached
	if m.evidenceStore != nil {
		bundle, err := m.evidenceStore.CreateBundle(tenantID, endpointID, sessionID, "terminal_session", 30*24*time.Hour)
		if err == nil && bundle != nil {
			sess.BundleID = bundle.ID
		}
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

// RecordFrame appends an input/output frame to the session audit log, enforcing byte limits.
func (m *Manager) RecordFrame(sessionID string, frame TerminalFrame) error {
	switch frame.Type {
	case FrameStdin, FrameStdout, FrameResize, FrameClose:
	default:
		return fmt.Errorf("unknown or invalid frame type: %q", frame.Type)
	}

	m.mu.Lock()
	sess, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		var err error
		sess, err = m.loadDurableSession(sessionID)
		if err != nil {
			return errors.New("terminal session not found")
		}
		m.mu.Lock()
		m.sessions[sessionID] = sess
	}
	m.mu.Unlock()

	sess.mu.Lock()
	defer sess.mu.Unlock()

	now := time.Now().UTC()
	frame.Timestamp = now

	if sess.RecordingState == "bounded" {
		return nil
	}

	// Estimate frame byte size: payload data length + overhead
	frameBytes := int64(len(frame.Data) + 64)
	if sess.MaxRecordingBytes > 0 && sess.RecordingBytes+frameBytes > sess.MaxRecordingBytes {
		sess.RecordingState = "bounded"
		marker := TerminalFrame{
			Type:      FrameStdout,
			Timestamp: now,
			Data:      []byte("\r\n[Recording limit reached (10 MiB cap). Further stream frames bounded.]\r\n"),
		}
		sess.Frames = append(sess.Frames, marker)
		sess.FrameCount = len(sess.Frames)
		_ = m.updateRecordingMetadata(sessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, sess.FrameCount)
		return nil
	}

	sess.Frames = append(sess.Frames, frame)
	sess.RecordingBytes += frameBytes
	sess.FrameCount = len(sess.Frames)
	sess.IdleExpiresAt = now.Add(m.idleTimeout)

	// Update idle expiration and recording metadata in database
	_ = m.updateDurableState(sessionID, sess.State, sess.StartedAt, sess.ClosedAt, sess.CloseReason, sess.OperatorConnected, sess.AgentConnected)
	_ = m.updateRecordingMetadata(sessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, sess.FrameCount)
	return nil
}

// SealSessionRecording finalizes and encrypts recorded frames into the evidence store.
func (m *Manager) SealSessionRecording(sessionID string) error {
	m.mu.Lock()
	sess, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		var err error
		sess, err = m.loadDurableSession(sessionID)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.sessions[sessionID] = sess
	}
	m.mu.Unlock()

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.RecordingState == "sealed" {
		return nil // Already sealed
	}

	if m.evidenceStore == nil || sess.BundleID == "" {
		if sess.RecordingState != "bounded" {
			sess.RecordingState = "closed"
		}
		sess.FrameCount = len(sess.Frames)
		_ = m.updateRecordingMetadata(sess.SessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, sess.FrameCount)
		return nil
	}

	now := time.Now().UTC()
	var buf bytes.Buffer
	for _, f := range sess.Frames {
		b, err := json.Marshal(f)
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	payloadBytes := buf.Bytes()

	status := "recorded"
	if len(sess.Frames) == 0 {
		status = "empty"
	} else if sess.RecordingState == "bounded" {
		status = "truncated"
	}

	item, err := m.evidenceStore.StoreItem(sess.TenantID, sess.BundleID, "session_frames.ndjson", "application/x-ndjson", status, payloadBytes)
	if err != nil {
		sess.RecordingState = "seal_failed"
		_ = m.updateRecordingMetadata(sess.SessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, len(sess.Frames))
		log.Printf("[-] SealSessionRecording StoreItem failed for session %s: %v", sessionID, err)
		return fmt.Errorf("seal recording to evidence store: %w", err)
	}

	manifest := &evidence.Manifest{
		BundleID:    sess.BundleID,
		EndpointID:  sess.EndpointID,
		TenantID:    sess.TenantID,
		JobID:       sess.SessionID,
		Profile:     "terminal_session",
		CollectedAt: now,
		Items: []evidence.ManifestItem{
			{
				Name:            "session_frames.ndjson",
				SizeBytes:       item.SizeBytes,
				SHA256:          item.SHA256,
				CollectorStatus: status,
			},
		},
	}

	_, err = m.evidenceStore.FinalizeBundle(sess.TenantID, sess.BundleID, manifest, "")
	if err != nil {
		sess.RecordingState = "seal_failed"
		_ = m.updateRecordingMetadata(sess.SessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, len(sess.Frames))
		log.Printf("[-] SealSessionRecording FinalizeBundle failed for session %s: %v", sessionID, err)
		return fmt.Errorf("finalize evidence bundle: %w", err)
	}

	sess.EvidenceItemID = item.ID
	sess.RecordingState = "sealed"
	sess.FrameCount = len(sess.Frames)
	sess.RecordingBytes = item.SizeBytes
	sess.Frames = nil // Free in-memory buffer after encrypted persistence

	_ = m.updateRecordingMetadata(sess.SessionID, sess.BundleID, sess.EvidenceItemID, sess.RecordingState, sess.RecordingBytes, sess.FrameCount)
	return nil
}

// SessionRecordingMetadata provides audit metadata for a session's recorded frames.
type SessionRecordingMetadata struct {
	SessionID      string `json:"session_id"`
	TenantID       string `json:"tenant_id"`
	EndpointID     string `json:"endpoint_id"`
	BundleID       string `json:"bundle_id,omitempty"`
	EvidenceItemID string `json:"evidence_item_id,omitempty"`
	RecordingState string `json:"recording_state"`
	RecordingBytes int64  `json:"recording_bytes"`
	FrameCount     int    `json:"frame_count"`
	Encryption     string `json:"encryption"`
}

// GetSessionRecording returns all recorded frames for a session, decrypting from evidence store if sealed.
func (m *Manager) GetSessionRecording(tenantID, sessionID string) ([]TerminalFrame, *SessionRecordingMetadata, error) {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.TenantID != tenantID {
		return nil, nil, errors.New("tenant mismatch")
	}

	meta := &SessionRecordingMetadata{
		SessionID:      sess.SessionID,
		TenantID:       sess.TenantID,
		EndpointID:     sess.EndpointID,
		BundleID:       sess.BundleID,
		EvidenceItemID: sess.EvidenceItemID,
		RecordingState: sess.RecordingState,
		RecordingBytes: sess.RecordingBytes,
		FrameCount:     sess.FrameCount,
		Encryption:     "AES-256-GCM (Evidence Store)",
	}
	if meta.BundleID == "" {
		meta.Encryption = "none"
	}

	// Live / in-memory frames
	if len(sess.Frames) > 0 {
		meta.FrameCount = len(sess.Frames)
		framesCopy := make([]TerminalFrame, len(sess.Frames))
		copy(framesCopy, sess.Frames)
		return framesCopy, meta, nil
	}

	// Sealed encrypted frames from evidence store
	if m.evidenceStore != nil && sess.EvidenceItemID != "" {
		plaintext, err := m.evidenceStore.ReadItemData(sess.TenantID, sess.EvidenceItemID)
		if err != nil {
			return nil, meta, fmt.Errorf("read encrypted frames from evidence store: %w", err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(plaintext))
		var frames []TerminalFrame
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var f TerminalFrame
			if err := json.Unmarshal(line, &f); err == nil {
				frames = append(frames, f)
			}
		}
		meta.FrameCount = len(frames)
		return frames, meta, nil
	}

	return []TerminalFrame{}, meta, nil
}

// CloseSession transitions a session to closed, persists to DB, closes paired relays, and seals recording.
func (m *Manager) CloseSession(sessionID, reason string) error {
	m.mu.Lock()
	sess, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		var err error
		sess, err = m.loadDurableSession(sessionID)
		if err != nil {
			return errors.New("session not found")
		}
		m.mu.Lock()
		m.sessions[sessionID] = sess
	}
	m.mu.Unlock()

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

	// Seal session recording into evidence store
	_ = m.SealSessionRecording(sessionID)
	return nil
}

// SessionSummary returns a serializable snapshot of the session.
func (s *TerminalSession) Summary() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, _ := json.Marshal(s)
	var res map[string]interface{}
	_ = json.Unmarshal(b, &res)
	if s.FrameCount > 0 {
		res["frame_count"] = s.FrameCount
	} else {
		res["frame_count"] = len(s.Frames)
	}
	if s.RecordingState == "" {
		if s.ClosedAt != nil {
			res["recording_state"] = "closed"
		} else {
			res["recording_state"] = "recording"
		}
	} else {
		res["recording_state"] = s.RecordingState
	}
	res["recording_bytes"] = s.RecordingBytes
	if s.BundleID != "" {
		res["encryption"] = "AES-256-GCM (Evidence Store)"
		res["bundle_id"] = s.BundleID
	}
	if s.EvidenceItemID != "" {
		res["evidence_item_id"] = s.EvidenceItemID
	}
	return res
}
