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
	"sync/atomic"
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

	// StateDetached is a live session with a live agent and no operator
	// watching it: the shell and its process tree are still running, the
	// recording is still open, and an operator can attach to it again.
	//
	// Before this state existed a detached session was not merely
	// unsupported, it was impossible - the operator's socket closing tore
	// the relay down, which sent a close frame to the agent, which killed
	// the remote process group. "Detach Viewer", the scrim, the header
	// close and Escape inside vim all did that.
	//
	// It counts as active everywhere a live session counts: it holds the
	// per-endpoint (1) and per-tenant (4) caps, so reattach has a slot to
	// come back to, and it is swept for idle and max-duration like any
	// other live session. Only `closed` seals the recording.
	StateDetached SessionState = "detached"
)

// LiveStates are the states in which a session holds a slot and its relay may
// still be running. Kept in one place so a new state cannot be added to the
// caps and forgotten in the sweeper.
func LiveStates() []SessionState {
	return []SessionState{StateWaiting, StateConnecting, StateActive, StateDetached}
}

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
	mu           sync.RWMutex
	SessionID    string       `json:"session_id"`
	TenantID     string       `json:"tenant_id"`
	EndpointID   string       `json:"endpoint_id"`
	OperatorID   string       `json:"operator_id"`
	Program      string       `json:"program"` // /bin/sh, /bin/bash, powershell.exe, cmd.exe
	State        SessionState `json:"state"`
	ConnectToken string       `json:"-"`
	TokenHash    string       `json:"-"`
	// OperatorTokenHash is the operator's own connect credential, minted at
	// creation apart from the agent's token, consumed by the attach it opens
	// and rotated by /sessions/attach for the next one. The agent validates
	// against TokenHash only. Empty means "no operator token outstanding":
	// the agent's token never answers for the operator side.
	OperatorTokenHash string                  `json:"-"`
	OperatorToken     string                  `json:"-"`
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
	// dirty marks recording counters and the idle deadline as changed since
	// they were last written. RecordFrame runs on every keystroke and every
	// output chunk, so it only marks; the sweeper writes them in one UPDATE.
	dirty             bool
	BundleID          string       `json:"bundle_id,omitempty"`
	EvidenceItemID    string       `json:"evidence_item_id,omitempty"`
	RecordingState    string       `json:"recording_state,omitempty"` // "recording", "sealed", "bounded"
	RecordingBytes    int64        `json:"recording_bytes"`
	MaxRecordingBytes int64        `json:"max_recording_bytes,omitempty"`
	FrameCount        int          `json:"frame_count"`
	relay             *PairedRelay `json:"-"`
}

// Manager manages active terminal sessions, persistence, and pairing.
type Manager struct {
	mu                sync.RWMutex
	db                *sql.DB
	evidenceStore     *evidence.Store
	sessions          map[string]*TerminalSession
	maxDuration       time.Duration
	idleTimeout       atomic.Int64 // nanoseconds; read on the frame path without m.mu
	perEndpoint       int
	perTenant         int
	connectTimeout    time.Duration
	maxRecordingBytes int64
	stopSweeper       chan struct{}
	sweeperDone       chan struct{}
	stopSweeperOnce   sync.Once
}

// Default session limits, used until the hub applies its own (SetLimits:
// startup flags, then the limits saved from the console). Several shells on
// one endpoint (an editor, a log tail, a build) are normal use; the tenant cap
// bounds the hub's relay load. Long maintenance work (updates, laptop
// cleanup) routinely runs past an hour.
const (
	MaxSessionsPerEndpoint = 3
	MaxSessionsPerTenant   = 8
	DefaultMaxDuration     = 4 * time.Hour
	DefaultIdleTimeout     = 15 * time.Minute
)

// Limits are the hub's terminal session limits. Zero fields keep the current
// value in SetLimits.
type Limits struct {
	MaxDuration time.Duration
	IdleTimeout time.Duration
	PerEndpoint int
	PerTenant   int
}

// DefaultLimits are the limits a hub runs with when nothing is configured.
func DefaultLimits() Limits {
	return Limits{MaxDuration: DefaultMaxDuration, IdleTimeout: DefaultIdleTimeout, PerEndpoint: MaxSessionsPerEndpoint, PerTenant: MaxSessionsPerTenant}
}

// LimitBounds are the safety bounds every configured limit must sit inside,
// whoever sets it. The idle timeout may not exceed the session's maximum.
var LimitBounds = struct {
	MinDuration, MaxDuration time.Duration
	MinIdle                  time.Duration
	MinPerEndpoint           int
	MaxPerEndpoint           int
	MinPerTenant             int
	MaxPerTenant             int
}{
	MinDuration: 5 * time.Minute, MaxDuration: 24 * time.Hour,
	MinIdle:        time.Minute,
	MinPerEndpoint: 1, MaxPerEndpoint: 10,
	MinPerTenant: 1, MaxPerTenant: 50,
}

// Validate checks a complete set of limits against LimitBounds.
func (l Limits) Validate() error {
	b := LimitBounds
	switch {
	case l.MaxDuration < b.MinDuration || l.MaxDuration > b.MaxDuration:
		return fmt.Errorf("session length must be between %s and %s", b.MinDuration, b.MaxDuration)
	case l.MaxDuration%time.Minute != 0:
		return errors.New("session length must be whole minutes")
	case l.IdleTimeout < b.MinIdle || l.IdleTimeout > l.MaxDuration:
		return fmt.Errorf("idle timeout must be between %s and the session length", b.MinIdle)
	case l.IdleTimeout%time.Minute != 0:
		return errors.New("idle timeout must be whole minutes")
	case l.PerEndpoint < b.MinPerEndpoint || l.PerEndpoint > b.MaxPerEndpoint:
		return fmt.Errorf("sessions per endpoint must be between %d and %d", b.MinPerEndpoint, b.MaxPerEndpoint)
	case l.PerTenant < b.MinPerTenant || l.PerTenant > b.MaxPerTenant:
		return fmt.Errorf("sessions per tenant must be between %d and %d", b.MinPerTenant, b.MaxPerTenant)
	case l.PerTenant < l.PerEndpoint:
		return errors.New("sessions per tenant may not be fewer than sessions per endpoint")
	}
	return nil
}

// NewManager creates a new Terminal Session Manager backed by SQLite.
func NewManager(db *sql.DB, evidStore *evidence.Store, maxDuration, idleTimeout time.Duration) *Manager {
	if maxDuration <= 0 {
		maxDuration = DefaultMaxDuration
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	m := &Manager{
		db:                db,
		evidenceStore:     evidStore,
		sessions:          make(map[string]*TerminalSession),
		maxDuration:       maxDuration,
		perEndpoint:       MaxSessionsPerEndpoint,
		perTenant:         MaxSessionsPerTenant,
		connectTimeout:    30 * time.Second,
		maxRecordingBytes: DefaultMaxSessionRecordingBytes,
		stopSweeper:       make(chan struct{}),
		sweeperDone:       make(chan struct{}),
	}
	m.idleTimeout.Store(int64(idleTimeout))
	_ = m.initStore()
	m.startSweeper(5 * time.Second)
	return m
}

// SetLimits applies the hub's configured session limits to new sessions.
func (m *Manager) SetLimits(l Limits) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.MaxDuration > 0 {
		m.maxDuration = l.MaxDuration
	}
	if l.IdleTimeout > 0 {
		m.idleTimeout.Store(int64(l.IdleTimeout))
	}
	if l.PerEndpoint > 0 {
		m.perEndpoint = l.PerEndpoint
	}
	if l.PerTenant > 0 {
		m.perTenant = l.PerTenant
	}
}

// Limits are the limits new sessions get now.
func (m *Manager) Limits() Limits {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Limits{MaxDuration: m.maxDuration, IdleTimeout: m.idle(), PerEndpoint: m.perEndpoint, PerTenant: m.perTenant}
}

// idle is the current idle timeout.
func (m *Manager) idle() time.Duration { return time.Duration(m.idleTimeout.Load()) }

// MaxDuration is the longest a new session may run.
func (m *Manager) MaxDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxDuration
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
	// Persist any progress the sweeper had not written yet.
	m.flushDirty()
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
	m.flushDirty()
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

// CreateSessionFor is CreateSession for a session that ends after d (at most
// the hub's maximum; zero or less means the maximum).
func (m *Manager) CreateSessionFor(tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant, d time.Duration) (*TerminalSession, error) {
	return m.createSession("", "", tenantID, endpointID, operatorID, program, grant, d)
}

// CreateSessionWithID initializes a new waiting terminal session with explicit IDs and limits enforcement.
func (m *Manager) CreateSessionWithID(sessionID, token, tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant) (*TerminalSession, error) {
	return m.createSession(sessionID, token, tenantID, endpointID, operatorID, program, grant, 0)
}

func (m *Manager) createSession(sessionID, token, tenantID, endpointID, operatorID, program string, grant *response.EndpointGrant, d time.Duration) (*TerminalSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()

	// 1. Enforce caps via SQLite store. Detached sessions hold their slot.
	// A failed count refuses: a cap that cannot be checked is not a cap.
	activeTenant, activeEndpoint, err := m.countActiveSessions(tenantID, endpointID, now)
	if err != nil {
		return nil, fmt.Errorf("terminal session caps could not be checked: %w", err)
	}
	if activeTenant >= m.perTenant {
		return nil, fmt.Errorf("active terminal session limit reached: max %d active terminal sessions allowed per tenant (%s)", m.perTenant, tenantID)
	}
	if activeEndpoint >= m.perEndpoint {
		return nil, fmt.Errorf("active terminal session limit reached: max %d active terminal sessions allowed per endpoint (%s)", m.perEndpoint, endpointID)
	}
	if d <= 0 || d > m.maxDuration {
		d = m.maxDuration
	}

	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	if token == "" {
		token = uuid.New().String()
	}
	// The operator gets its own one-use token. The agent's token travels to
	// the endpoint (and in the agent's WebSocket URL); it never opens the
	// operator side.
	opToken := uuid.New().String()

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
		OperatorToken:     opToken,
		OperatorTokenHash: HashToken(opToken),
		CreatedAt:         now,
		ExpiresAt:         now.Add(d),
		IdleExpiresAt:     now.Add(m.idle()),
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

	/* Idle means "the operator has done nothing", not "the wire is quiet".
	   This bumped the deadline on every frame including agent stdout, which
	   was harmless while a dropped operator socket killed the session and is
	   not harmless now: a detached `tail -f` or `yes` produces stdout for
	   ever and would hold a root shell open on a live endpoint until the
	   session's max duration, with nobody watching it. Only frames the
	   operator originates - keystrokes and window resizes - and attaching
	   count as activity. */
	if frame.Type == FrameStdin || frame.Type == FrameResize {
		sess.IdleExpiresAt = now.Add(m.idle())
	}

	// Counters and the idle deadline reach SQLite on the next sweep (5 s)
	// or at close, not here: this is the per-frame hot path.
	sess.dirty = true
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

// RotateOperatorToken mints a fresh operator connect token for a live session
// and returns the plaintext exactly once.
//
// Reattach goes through here rather than reusing the creation token for two
// reasons. The creation cookie has a 300-second MaxAge, so a session detached
// for six minutes could not be reattached at all; and a token that stays valid
// for the life of a 60-minute session is a credential to a root shell sitting
// in whatever captured it. Rotating on every attach makes a captured one
// useless the moment the real operator comes back.
//
// The agent's token is untouched: see OperatorTokenHash.
func (m *Manager) RotateOperatorToken(sessionID string) (string, error) {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return "", err
	}

	token := uuid.New().String()
	hash := HashToken(token)

	sess.mu.Lock()
	switch sess.State {
	case StateClosed, StateFailed, StateExpired:
		st := sess.State
		sess.mu.Unlock()
		return "", fmt.Errorf("session is in terminal state: %s", st)
	}
	// A connected operator does not block rotation: the new token is how a
	// viewer whose old socket is half-open (phone asleep, network switch)
	// takes the session back. AttachOperator then supersedes the old socket.
	// Who may rotate is the caller's check (the session's own operator).
	sess.OperatorToken = token
	sess.OperatorTokenHash = hash
	sess.mu.Unlock()

	if err := m.updateDurableOperatorToken(sessionID, hash); err != nil {
		return "", fmt.Errorf("persist rotated operator token: %w", err)
	}
	return token, nil
}

// DetachSession drops the operator side of a live session without touching the
// remote process tree. The console reaches this by closing its WebSocket; this
// is the explicit path, for a caller that has no socket to close.
func (m *Manager) DetachSession(sessionID, reason string) error {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}
	sess.mu.RLock()
	relay := sess.relay
	sess.mu.RUnlock()
	if relay == nil {
		return errors.New("session has no active relay")
	}
	if reason == "" {
		reason = "operator_detached"
	}
	relay.DetachOperator(reason)
	return nil
}

// IsLive reports whether a session still holds a slot and can be attached to.
func (s *TerminalSession) IsLive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch s.State {
	case StateWaiting, StateConnecting, StateActive, StateDetached:
		return true
	}
	return false
}

// flushDirty writes the recording counters and idle deadline of every session
// RecordFrame touched since the last flush. One UPDATE per active session per
// sweep replaces two per frame.
func (m *Manager) flushDirty() {
	type row struct {
		id, state string
		bytes     int64
		frames    int
		idle      time.Time
	}
	var rows []row
	m.mu.Lock()
	for id, sess := range m.sessions {
		sess.mu.Lock()
		if sess.dirty {
			sess.dirty = false
			rows = append(rows, row{id, sess.RecordingState, sess.RecordingBytes, sess.FrameCount, sess.IdleExpiresAt})
		}
		sess.mu.Unlock()
	}
	m.mu.Unlock()
	for _, r := range rows {
		_ = m.updateRecordingProgress(r.id, r.state, r.bytes, r.frames, r.idle)
	}
}
