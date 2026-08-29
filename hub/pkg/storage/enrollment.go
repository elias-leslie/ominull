package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// EnrollmentTokenTTL is how long a bootstrap script's certificate credential
// stays usable. Enrolment happens minutes after the script is generated; an
// hour is generous and still bounds how long a leaked installer is worth
// anything.
const EnrollmentTokenTTL = time.Hour

// CreateEnrollmentToken mints a single-use credential that authorises exactly
// one client-certificate issuance.
//
// It exists because the enrolment route had no notion of who was allowed to be
// issued what: any caller the hub authenticated could ask for a certificate in
// any endpoint's name, and the tenant key that authenticates them is on every
// endpoint in the fleet. A certificate is the thing the hub tells endpoints
// apart by, so that made the identity it proves worth nothing.
//
// endpointID may be empty, for an installer that derives its own id from the
// hostname at run time. The token is still single-use and still expires; it
// just names one endpoint of the installer's choosing rather than one the
// operator picked in advance.
func (s *Store) CreateEnrollmentToken(endpointID string, ttl time.Duration) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating an enrolment token: %w", err)
	}
	token := hex.EncodeToString(raw[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = EnrollmentTokenTTL
	}
	if _, err := s.db.Exec(
		`INSERT INTO enrollment_tokens (token_hash, endpoint_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashEnrollmentToken(token), strings.TrimSpace(endpointID), now, now.Add(ttl),
	); err != nil {
		return "", err
	}

	// Expired and spent rows are of no further use; clearing them here keeps
	// the table from growing without a separate sweep.
	_, _ = s.db.Exec(`DELETE FROM enrollment_tokens WHERE expires_at < ? OR used_at IS NOT NULL`, now.Add(-24*time.Hour))

	return token, nil
}

// ConsumeEnrollmentToken redeems a token for one endpoint id, or reports why it
// cannot be. Redemption is a conditional UPDATE rather than a read followed by
// a write, so two installers racing on the same token cannot both win it.
func (s *Store) ConsumeEnrollmentToken(token, endpointID string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("no enrolment token presented")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	res, err := s.db.Exec(
		`UPDATE enrollment_tokens SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		   AND (endpoint_id = '' OR endpoint_id = ?)`,
		now, hashEnrollmentToken(token), now, strings.TrimSpace(endpointID),
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 1 {
		return nil
	}

	// Nothing was updated. Say which of the reasons it was, because "expired"
	// and "already used" send an operator to different places, and neither
	// discloses anything to a caller who did not hold the token to begin with.
	var (
		boundTo string
		expires time.Time
		usedAt  sql.NullTime
	)
	err = s.db.QueryRow(
		`SELECT endpoint_id, expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?`,
		hashEnrollmentToken(token),
	).Scan(&boundTo, &expires, &usedAt)
	switch {
	case err == sql.ErrNoRows:
		return fmt.Errorf("the enrolment token is not one this hub issued")
	case err != nil:
		return err
	case usedAt.Valid:
		return fmt.Errorf("the enrolment token has already been redeemed")
	case !expires.After(now):
		return fmt.Errorf("the enrolment token expired at %s", expires.Format(time.RFC3339))
	default:
		return fmt.Errorf("the enrolment token was issued for endpoint %q, not %q", boundTo, endpointID)
	}
}

// hashEnrollmentToken is the form the table holds.
func hashEnrollmentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
