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
	`
	_, err := s.db.Exec(query)
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
		SELECT id, kind, request_json
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
		reqJSON string
	}
	var items []item

	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.kind, &it.reqJSON); err != nil {
			return nil, err
		}
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

		_, err := s.db.Exec(`
			UPDATE response_jobs
			SET state = ?, lease_id = ?, lease_expires_at = ?, attempt = attempt + 1, updated_at = ?
			WHERE id = ?
		`, string(StateOffered), leaseID, leaseExpiresAt, now, it.id)
		if err != nil {
			continue
		}

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

// AcknowledgeJob records an endpoint's ACK or rejection of an offered job.
func (s *Store) AcknowledgeJob(jobID, leaseID string, accepted bool, rejectionReason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var currentState, currentLease string
	err := s.db.QueryRow(`SELECT state, lease_id FROM response_jobs WHERE id = ?`, jobID).Scan(&currentState, &currentLease)
	if err != nil {
		return err
	}
	if currentLease != leaseID {
		return errors.New("lease id mismatch")
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
	return err
}

// CompleteJob transitions a job to a terminal outcome (succeeded, failed, or cancelled).
func (s *Store) CompleteJob(jobID, leaseID string, result *JobResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if result == nil {
		return errors.New("nil job result")
	}

	now := time.Now().UTC()
	var currentState, currentLease string
	err := s.db.QueryRow(`SELECT state, lease_id FROM response_jobs WHERE id = ?`, jobID).Scan(&currentState, &currentLease)
	if err != nil {
		return err
	}

	// Check terminal idempotency
	if currentState == string(StateSucceeded) || currentState == string(StateFailed) || currentState == string(StateCancelled) {
		return nil // terminal already reached
	}
	if currentLease != leaseID {
		return errors.New("lease id mismatch")
	}

	state := result.State
	if state != StateSucceeded && state != StateFailed && state != StateCancelled {
		state = StateSucceeded
		if result.ExitCode != 0 || result.ErrorCode != "" {
			state = StateFailed
		}
	}

	resultBytes, _ := json.Marshal(result)

	_, err = s.db.Exec(`
		UPDATE response_jobs
		SET state = ?, result_json = ?, error_code = ?, completed_at = ?, updated_at = ?
		WHERE id = ?
	`, string(state), string(resultBytes), result.ErrorCode, now, now, jobID)
	return err
}

// CancelJob requests cooperative cancellation of a job.
func (s *Store) CancelJob(jobID, requestedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var state string
	err := s.db.QueryRow(`SELECT state FROM response_jobs WHERE id = ?`, jobID).Scan(&state)
	if err != nil {
		return err
	}
	if state == string(StateSucceeded) || state == string(StateFailed) || state == string(StateCancelled) {
		return nil // already terminal
	}

	_, err = s.db.Exec(`
		UPDATE response_jobs
		SET state = ?, cancel_requested_at = ?, updated_at = ?
		WHERE id = ?
	`, string(StateCancelRequested), now, now, jobID)
	return err
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
