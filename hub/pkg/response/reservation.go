package response

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Job reservations serve the host-authority courier route
// (docs/HOST_AUTHORITY.md). A V3 grant binds the job it is for, so the signer
// needs the job id before it signs: the hub reserves one for an endpoint and a
// payload digest, the signer signs a grant naming it, and the hub queues the
// job under exactly that id. A reservation is used once and lapses after
// ReservationTTL.

// ReservationTTL is how long a reserved job id waits for its signed grant.
const ReservationTTL = 15 * time.Minute

// JobReservation is one reserved job id.
type JobReservation struct {
	JobID        string    `json:"job_id"`
	TenantID     string    `json:"tenant_id"`
	EndpointID   string    `json:"endpoint_id"`
	ActionDigest string    `json:"action_digest"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Reservation errors.
var (
	ErrReservationUnknown  = errors.New("no such reserved job id (it was used, lapsed, or never reserved)")
	ErrReservationMismatch = errors.New("the reserved job id is for another endpoint or payload")
)

func (s *Store) migrateReservations() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS response_job_reservations (
		job_id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		action_digest TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL
	);
	`)
	return err
}

// ReserveJob reserves a fresh job id for one endpoint and payload digest.
func (s *Store) ReserveJob(tenantID, endpointID, actionDigest string, now time.Time) (*JobReservation, error) {
	if tenantID == "" || endpointID == "" || len(actionDigest) != 64 {
		return nil, errors.New("missing reservation fields")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM response_job_reservations WHERE expires_at < ?`, now.UTC()); err != nil {
		return nil, err
	}
	r := &JobReservation{JobID: uuid.New().String(), TenantID: tenantID, EndpointID: endpointID,
		ActionDigest: strings.ToLower(actionDigest), ExpiresAt: now.UTC().Add(ReservationTTL).Truncate(time.Second)}
	_, err := s.db.Exec(`INSERT INTO response_job_reservations (job_id, tenant_id, endpoint_id, action_digest, expires_at) VALUES (?, ?, ?, ?, ?)`,
		r.JobID, r.TenantID, r.EndpointID, r.ActionDigest, r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// TakeReservation uses a reservation up: it must be live and match the
// endpoint and digest. It is removed whatever the outcome of a match, so a
// reserved id is offered to one grant only.
func (s *Store) TakeReservation(jobID, tenantID, endpointID, actionDigest string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r JobReservation
	err := s.db.QueryRow(`SELECT job_id, tenant_id, endpoint_id, action_digest, expires_at FROM response_job_reservations WHERE job_id = ?`, jobID).
		Scan(&r.JobID, &r.TenantID, &r.EndpointID, &r.ActionDigest, &r.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrReservationUnknown
	}
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM response_job_reservations WHERE job_id = ?`, jobID); err != nil {
		return err
	}
	if now.UTC().After(r.ExpiresAt) {
		return ErrReservationUnknown
	}
	if r.TenantID != tenantID || r.EndpointID != endpointID || !strings.EqualFold(r.ActionDigest, actionDigest) {
		return ErrReservationMismatch
	}
	return nil
}
