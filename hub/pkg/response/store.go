package response

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	ErrJobNotFound          = errors.New("response job not found")
	ErrTenantMismatch       = errors.New("tenant id mismatch")
	ErrEndpointMismatch     = errors.New("endpoint id mismatch")
	ErrLeaseMismatch        = errors.New("lease id mismatch")
	ErrLeaseExpired         = errors.New("lease has expired")
	ErrInvalidJobTransition = errors.New("invalid job state transition")
)

// IsValidTransition returns true if the transition from currentState to targetState is allowed.
func IsValidTransition(from, to JobState) bool {
	if from == to {
		return true // idempotent
	}
	switch from {
	case StateQueued:
		return to == StateOffered || to == StateCancelled
	case StateOffered:
		return to == StateAcknowledged || to == StateFailed || to == StateQueued || to == StateCancelled
	case StateAcknowledged:
		return to == StateRunning || to == StateSucceeded || to == StateFailed || to == StateCancelRequested || to == StateCancelled
	case StateRunning:
		return to == StateSucceeded || to == StateFailed || to == StateCancelRequested || to == StateCancelled
	case StateCancelRequested:
		return to == StateCancelled || to == StateSucceeded || to == StateFailed
	case StateSucceeded, StateFailed, StateCancelled:
		return false // terminal states are immutable
	default:
		return false
	}
}

// JobRecord represents a durable response job in the store.
type JobRecord struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	EndpointID           string     `json:"endpoint_id"`
	Kind                 ActionKind `json:"kind"`
	RequestedBy          string     `json:"requested_by"`
	RequestedAt          time.Time  `json:"requested_at"`
	State                JobState   `json:"state"`
	LeaseID              string     `json:"lease_id,omitempty"`
	LeaseExpiresAt       *time.Time `json:"lease_expires_at,omitempty"`
	StartedAt            *time.Time `json:"started_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	CancelRequestedAt    *time.Time `json:"cancel_requested_at,omitempty"`
	Attempt              int        `json:"attempt"`
	IdempotencyKey       string     `json:"idempotency_key,omitempty"`
	AuthorizationGrantID string     `json:"authorization_grant_id"`
	RequestJSON          string     `json:"request_json"`
	ResultJSON           string     `json:"result_json,omitempty"`
	ErrorCode            string     `json:"error_code,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// JobAuditEntry represents an audit log entry for job state transitions.
type JobAuditEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	TenantID   string    `json:"tenant_id"`
	EndpointID string    `json:"endpoint_id"`
	JobID      string    `json:"job_id"`
	GrantID    string    `json:"grant_id,omitempty"`
	FromState  string    `json:"from_state"`
	ToState    string    `json:"to_state"`
	Actor      string    `json:"actor"`
	Details    string    `json:"details,omitempty"`
}

// Store manages persistence and state transitions for response jobs.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// NewStore initializes a SQLite-backed response job store.
func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("response store migration failed: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS response_jobs (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		kind TEXT NOT NULL,
		requested_by TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		state TEXT NOT NULL,
		lease_id TEXT,
		lease_expires_at TIMESTAMP,
		started_at TIMESTAMP,
		completed_at TIMESTAMP,
		cancel_requested_at TIMESTAMP,
		attempt INTEGER DEFAULT 0,
		idempotency_key TEXT,
		authorization_grant_id TEXT,
		request_json TEXT NOT NULL,
		result_json TEXT,
		error_code TEXT,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_response_jobs_tenant ON response_jobs(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_response_jobs_endpoint_state ON response_jobs(endpoint_id, state);
	CREATE INDEX IF NOT EXISTS idx_response_jobs_idempotency ON response_jobs(tenant_id, idempotency_key);

	CREATE TABLE IF NOT EXISTS response_job_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP NOT NULL,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		job_id TEXT NOT NULL,
		grant_id TEXT,
		from_state TEXT NOT NULL,
		to_state TEXT NOT NULL,
		actor TEXT NOT NULL,
		details TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_response_job_audit_job ON response_job_audit(job_id);
	CREATE INDEX IF NOT EXISTS idx_response_job_audit_tenant ON response_job_audit(tenant_id);
	`
	_, err := s.db.Exec(query)
	return err
}

func (s *Store) recordAudit(tenantID, endpointID, jobID, grantID string, fromState, toState JobState, actor, details string) error {
	_, err := s.db.Exec(`
		INSERT INTO response_job_audit (timestamp, tenant_id, endpoint_id, job_id, grant_id, from_state, to_state, actor, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, time.Now().UTC(), tenantID, endpointID, jobID, grantID, string(fromState), string(toState), actor, details)
	return err
}

// CreateJob creates a new queued response job. If an idempotency key is given and exists, returns the existing job.
func (s *Store) CreateJob(tenantID, endpointID string, kind ActionKind, requestedBy string, grant *EndpointGrant, payloadJSON, idempotencyKey string) (*JobRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tenantID == "" || endpointID == "" || grant == nil {
		return nil, errors.New("missing required job fields")
	}

	now := time.Now().UTC()

	// Check idempotency
	if idempotencyKey != "" {
		var existing JobRecord
		var leaseExp, started, completed, cancelReq sql.NullTime
		var leaseID, idemp, grantID, resJSON, errCode sql.NullString

		err := s.db.QueryRow(`
			SELECT id, tenant_id, endpoint_id, kind, requested_by, requested_at, state,
			       lease_id, lease_expires_at, started_at, completed_at, cancel_requested_at,
			       attempt, idempotency_key, authorization_grant_id, request_json, result_json, error_code,
			       created_at, updated_at
			FROM response_jobs
			WHERE tenant_id = ? AND idempotency_key = ?
		`, tenantID, idempotencyKey).Scan(
			&existing.ID, &existing.TenantID, &existing.EndpointID, &existing.Kind, &existing.RequestedBy, &existing.RequestedAt, &existing.State,
			&leaseID, &leaseExp, &started, &completed, &cancelReq,
			&existing.Attempt, &idemp, &grantID, &existing.RequestJSON, &resJSON, &errCode,
			&existing.CreatedAt, &existing.UpdatedAt,
		)
		if err == nil {
			if leaseID.Valid { existing.LeaseID = leaseID.String }
			if leaseExp.Valid { existing.LeaseExpiresAt = &leaseExp.Time }
			if started.Valid { existing.StartedAt = &started.Time }
			if completed.Valid { existing.CompletedAt = &completed.Time }
			if cancelReq.Valid { existing.CancelRequestedAt = &cancelReq.Time }
			if idemp.Valid { existing.IdempotencyKey = idemp.String }
			if grantID.Valid { existing.AuthorizationGrantID = grantID.String }
			if resJSON.Valid { existing.ResultJSON = resJSON.String }
			if errCode.Valid { existing.ErrorCode = errCode.String }
			return &existing, nil
		}
	}

	jobID := uuid.New().String()
	job := &JobRecord{
		ID:                   jobID,
		TenantID:             tenantID,
		EndpointID:           endpointID,
		Kind:                 kind,
		RequestedBy:          requestedBy,
		RequestedAt:          now,
		State:                StateQueued,
		Attempt:              0,
		IdempotencyKey:       idempotencyKey,
		AuthorizationGrantID: grant.GrantID,
		RequestJSON:          payloadJSON,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}

	// Stash grant inside request JSON wrapper
	wrappedReq := map[string]interface{}{
		"grant":   grant,
		"payload": payloadJSON,
	}
	wrappedBytes, _ := json.Marshal(wrappedReq)
	job.RequestJSON = string(wrappedBytes)

	_, err = s.db.Exec(`
		INSERT INTO response_jobs (
			id, tenant_id, endpoint_id, kind, requested_by, requested_at, state,
			attempt, idempotency_key, authorization_grant_id, request_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, job.ID, job.TenantID, job.EndpointID, string(job.Kind), job.RequestedBy, job.RequestedAt, string(job.State),
		job.Attempt, job.IdempotencyKey, job.AuthorizationGrantID, job.RequestJSON, job.CreatedAt, job.UpdatedAt)
	if err != nil {
		return nil, err
	}

	_ = s.recordAudit(tenantID, endpointID, job.ID, grant.GrantID, "", StateQueued, requestedBy, "job created")
	_ = grantJSON
	return job, nil
}

// OfferPendingJobs finds queued or lease-expired jobs for an endpoint and assigns fresh leases.
func (s *Store) OfferPendingJobs(tenantID, endpointID string, maxOffers int, leaseDuration time.Duration) ([]*JobOffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if maxOffers <= 0 || maxOffers > 10 {
		maxOffers = 4
	}
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Minute
	}

	rows, err := s.db.Query(`
		SELECT id, kind, state, attempt, authorization_grant_id, request_json
		FROM response_jobs
		WHERE tenant_id = ? AND endpoint_id = ? AND (
			state = ? OR (state = ? AND lease_expires_at < ?)
		)
		ORDER BY requested_at ASC
		LIMIT ?
	`, tenantID, endpointID, string(StateQueued), string(StateOffered), now, maxOffers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var offers []*JobOffer
	type item struct {
		id      string
		kind    ActionKind
		state   JobState
		attempt int
		grantID string
		reqJSON string
	}
	var items []item

	for rows.Next() {
		var it item
		var stateStr string
		if err := rows.Scan(&it.id, &it.kind, &stateStr, &it.attempt, &it.grantID, &it.reqJSON); err != nil {
			return nil, err
		}
		it.state = JobState(stateStr)
		items = append(items, it)
	}

	for _, it := range items {
		leaseID := uuid.New().String()
		leaseExpiresAt := now.Add(leaseDuration)

		var wrapped struct {
			Grant   EndpointGrant `json:"grant"`
			Payload string        `json:"payload"`
		}
		if err := json.Unmarshal([]byte(it.reqJSON), &wrapped); err != nil {
			continue
		}

		newAttempt := it.attempt + 1
		_, err := s.db.Exec(`
			UPDATE response_jobs
			SET state = ?, lease_id = ?, lease_expires_at = ?, attempt = ?, updated_at = ?
			WHERE id = ?
		`, string(StateOffered), leaseID, leaseExpiresAt, newAttempt, now, it.id)
		if err != nil {
			continue
		}

		_ = s.recordAudit(tenantID, endpointID, it.id, it.grantID, it.state, StateOffered, "scheduler", fmt.Sprintf("leased to %s attempt %d", leaseID, newAttempt))

		offers = append(offers, &JobOffer{
			JobID:          it.id,
			Kind:           it.kind,
			LeaseID:        leaseID,
			LeaseExpiresAt: leaseExpiresAt.Unix(),
			Grant:          &wrapped.Grant,
			PayloadJSON:    wrapped.Payload,
		})
	}

	return offers, nil
}

// AcknowledgeJob records an endpoint's ACK or rejection of an offered job with tenant and endpoint binding.
func (s *Store) AcknowledgeJob(tenantID, endpointID, jobID, leaseID string, accepted bool, rejectionReason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var curTenant, curEndpoint, currentState, currentLease, grantID string
	var leaseExp sql.NullTime
	err := s.db.QueryRow(`
		SELECT tenant_id, endpoint_id, state, lease_id, lease_expires_at, authorization_grant_id
		FROM response_jobs
		WHERE id = ?
	`, jobID).Scan(&curTenant, &curEndpoint, &currentState, &currentLease, &leaseExp, &grantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobNotFound
		}
		return err
	}

	if tenantID != "" && curTenant != tenantID {
		return ErrTenantMismatch
	}
	if endpointID != "" && curEndpoint != endpointID {
		return ErrEndpointMismatch
	}
	if currentLease != leaseID {
		return ErrLeaseMismatch
	}
	if leaseExp.Valid && now.After(leaseExp.Time) {
		return ErrLeaseExpired
	}

	targetState := StateAcknowledged
	if !accepted {
		targetState = StateFailed
	}

	if !IsValidTransition(JobState(currentState), targetState) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidJobTransition, currentState, targetState)
	}

	if accepted {
		_, err = s.db.Exec(`
			UPDATE response_jobs
			SET state = ?, started_at = ?, updated_at = ?
			WHERE id = ?
		`, string(StateAcknowledged), now, now, jobID)
	} else {
		_, err = s.db.Exec(`
			UPDATE response_jobs
			SET state = ?, error_code = ?, completed_at = ?, updated_at = ?
			WHERE id = ?
		`, string(StateFailed), rejectionReason, now, now, jobID)
	}
	if err != nil {
		return err
	}

	actor := fmt.Sprintf("endpoint:%s", curEndpoint)
	details := "job accepted by endpoint"
	if !accepted {
		details = fmt.Sprintf("job rejected: %s", rejectionReason)
	}
	_ = s.recordAudit(curTenant, curEndpoint, jobID, grantID, JobState(currentState), targetState, actor, details)
	return nil
}

// RecordProgress records incremental progress reported by an endpoint.
func (s *Store) RecordProgress(tenantID, endpointID, jobID, leaseID string, progress *JobProgress) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if progress == nil {
		return errors.New("nil progress")
	}

	now := time.Now().UTC()
	var curTenant, curEndpoint, currentState, currentLease, grantID string
	var leaseExp sql.NullTime
	err := s.db.QueryRow(`
		SELECT tenant_id, endpoint_id, state, lease_id, lease_expires_at, authorization_grant_id
		FROM response_jobs
		WHERE id = ?
	`, jobID).Scan(&curTenant, &curEndpoint, &currentState, &currentLease, &leaseExp, &grantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobNotFound
		}
		return err
	}

	if tenantID != "" && curTenant != tenantID {
		return ErrTenantMismatch
	}
	if endpointID != "" && curEndpoint != endpointID {
		return ErrEndpointMismatch
	}
	if currentLease != leaseID {
		return ErrLeaseMismatch
	}
	if leaseExp.Valid && now.After(leaseExp.Time) {
		return ErrLeaseExpired
	}

	// Progress transitions an acknowledged job to running
	fromState := JobState(currentState)
	toState := fromState
	if fromState == StateAcknowledged {
		toState = StateRunning
		_, err = s.db.Exec(`
			UPDATE response_jobs
			SET state = ?, updated_at = ?
			WHERE id = ?
		`, string(StateRunning), now, jobID)
		if err != nil {
			return err
		}
	} else {
		_, err = s.db.Exec(`UPDATE response_jobs SET updated_at = ? WHERE id = ?`, now, jobID)
		if err != nil {
			return err
		}
	}

	actor := fmt.Sprintf("endpoint:%s", curEndpoint)
	details := fmt.Sprintf("progress %d%%: %s", progress.ProgressPct, progress.Message)
	_ = s.recordAudit(curTenant, curEndpoint, jobID, grantID, fromState, toState, actor, details)
	return nil
}

// CompleteJob transitions a job to a terminal outcome (succeeded, failed, or cancelled) with tenant and endpoint binding.
func (s *Store) CompleteJob(tenantID, endpointID, jobID, leaseID string, result *JobResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if result == nil {
		return errors.New("nil job result")
	}

	now := time.Now().UTC()
	var curTenant, curEndpoint, currentState, currentLease, grantID string
	err := s.db.QueryRow(`
		SELECT tenant_id, endpoint_id, state, lease_id, authorization_grant_id
		FROM response_jobs
		WHERE id = ?
	`, jobID).Scan(&curTenant, &curEndpoint, &currentState, &currentLease, &grantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobNotFound
		}
		return err
	}

	if tenantID != "" && curTenant != tenantID {
		return ErrTenantMismatch
	}
	if endpointID != "" && curEndpoint != endpointID {
		return ErrEndpointMismatch
	}

	// Replay protection: if terminal state already reached, idempotent success
	if currentState == string(StateSucceeded) || currentState == string(StateFailed) || currentState == string(StateCancelled) {
		return nil
	}

	if currentLease != leaseID {
		return ErrLeaseMismatch
	}

	state := result.State
	if state != StateSucceeded && state != StateFailed && state != StateCancelled {
		state = StateSucceeded
		if result.ExitCode != 0 || result.ErrorCode != "" {
			state = StateFailed
		}
	}

	if !IsValidTransition(JobState(currentState), state) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidJobTransition, currentState, state)
	}

	resultBytes, _ := json.Marshal(result)

	_, err = s.db.Exec(`
		UPDATE response_jobs
		SET state = ?, result_json = ?, error_code = ?, completed_at = ?, updated_at = ?
		WHERE id = ?
	`, string(state), string(resultBytes), result.ErrorCode, now, now, jobID)
	if err != nil {
		return err
	}

	actor := fmt.Sprintf("endpoint:%s", curEndpoint)
	details := fmt.Sprintf("completed state=%s exit_code=%d", state, result.ExitCode)
	_ = s.recordAudit(curTenant, curEndpoint, jobID, grantID, JobState(currentState), state, actor, details)
	return nil
}

// CancelJob requests cooperative cancellation of a job.
func (s *Store) CancelJob(tenantID, jobID, requestedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var curTenant, curEndpoint, currentState, grantID string
	err := s.db.QueryRow(`
		SELECT tenant_id, endpoint_id, state, authorization_grant_id
		FROM response_jobs
		WHERE id = ?
	`, jobID).Scan(&curTenant, &curEndpoint, &currentState, &grantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobNotFound
		}
		return err
	}

	if tenantID != "" && curTenant != tenantID {
		return ErrTenantMismatch
	}

	if currentState == string(StateSucceeded) || currentState == string(StateFailed) || currentState == string(StateCancelled) {
		return nil // already terminal
	}

	targetState := StateCancelRequested
	if currentState == string(StateQueued) {
		targetState = StateCancelled
	}

	if !IsValidTransition(JobState(currentState), targetState) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidJobTransition, currentState, targetState)
	}

	_, err = s.db.Exec(`
		UPDATE response_jobs
		SET state = ?, cancel_requested_at = ?, updated_at = ?
		WHERE id = ?
	`, string(targetState), now, now, jobID)
	if err != nil {
		return err
	}

	_ = s.recordAudit(curTenant, curEndpoint, jobID, grantID, JobState(currentState), targetState, requestedBy, "cancellation requested")
	return nil
}

// ListJobs returns jobs matching tenant, optional endpoint filter, and pagination.
func (s *Store) ListJobs(tenantID, endpointID string, limit int) ([]*JobRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	var rows *sql.Rows
	var err error
	if endpointID != "" {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, kind, requested_by, requested_at, state,
			       lease_id, lease_expires_at, started_at, completed_at, cancel_requested_at,
			       attempt, idempotency_key, authorization_grant_id, request_json, result_json, error_code,
			       created_at, updated_at
			FROM response_jobs
			WHERE tenant_id = ? AND endpoint_id = ?
			ORDER BY requested_at DESC
			LIMIT ?
		`, tenantID, endpointID, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, kind, requested_by, requested_at, state,
			       lease_id, lease_expires_at, started_at, completed_at, cancel_requested_at,
			       attempt, idempotency_key, authorization_grant_id, request_json, result_json, error_code,
			       created_at, updated_at
			FROM response_jobs
			WHERE tenant_id = ?
			ORDER BY requested_at DESC
			LIMIT ?
		`, tenantID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*JobRecord
	for rows.Next() {
		var j JobRecord
		var leaseExp, started, completed, cancelReq sql.NullTime
		var leaseID, idemp, grantID, resJSON, errCode sql.NullString

		if err := rows.Scan(
			&j.ID, &j.TenantID, &j.EndpointID, &j.Kind, &j.RequestedBy, &j.RequestedAt, &j.State,
			&leaseID, &leaseExp, &started, &completed, &cancelReq,
			&j.Attempt, &idemp, &grantID, &j.RequestJSON, &resJSON, &errCode,
			&j.CreatedAt, &j.UpdatedAt,
		); err != nil {
			return nil, err
		}

		if leaseID.Valid { j.LeaseID = leaseID.String }
		if leaseExp.Valid { j.LeaseExpiresAt = &leaseExp.Time }
		if started.Valid { j.StartedAt = &started.Time }
		if completed.Valid { j.CompletedAt = &completed.Time }
		if cancelReq.Valid { j.CancelRequestedAt = &cancelReq.Time }
		if idemp.Valid { j.IdempotencyKey = idemp.String }
		if grantID.Valid { j.AuthorizationGrantID = grantID.String }
		if resJSON.Valid { j.ResultJSON = resJSON.String }
		if errCode.Valid { j.ErrorCode = errCode.String }

		jobs = append(jobs, &j)
	}
	return jobs, nil
}

// GetJobAuditLog retrieves the transition audit log for a job.
func (s *Store) GetJobAuditLog(tenantID, jobID string, limit int) ([]*JobAuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT id, timestamp, tenant_id, endpoint_id, job_id, grant_id, from_state, to_state, actor, details
		FROM response_job_audit
		WHERE tenant_id = ? AND job_id = ?
		ORDER BY id ASC
		LIMIT ?
	`, tenantID, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*JobAuditEntry
	for rows.Next() {
		var e JobAuditEntry
		var grantID, details sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.TenantID, &e.EndpointID, &e.JobID, &grantID, &e.FromState, &e.ToState, &e.Actor, &details); err != nil {
			return nil, err
		}
		if grantID.Valid { e.GrantID = grantID.String }
		if details.Valid { e.Details = details.String }
		entries = append(entries, &e)
	}
	return entries, nil
}
