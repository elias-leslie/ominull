package storage

// This file keeps the old install_tickets table and its data-access methods so
// an upgrade can open databases created by older releases. Current installers
// use enrollment profiles and never call this compatibility surface.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// An install ticket is what makes a one-line agent install safe to paste.
//
// The three bootstrap routes authenticate with the hub's admin key in the query
// string. That is the fleet's most privileged credential, and putting it in a
// URL puts it in shell history, in every proxy and access log on the path, and
// on the screen of whoever is watching the operator type. The console cannot
// offer "copy this command and run it on the host" while that is the only way
// in.
//
// A ticket is the credential that command should carry instead: it authorises
// fetching one enrolment script and nothing else, it works once, and it expires
// in half an hour. It also carries the enrolment parameters, so the URL says
// nothing about the tenant, the location or the endpoint either - the ticket is
// opaque and the hub remembers what it was for.
const InstallTicketTTL = 30 * time.Minute

// InstallTicket is what one redeemed ticket describes.
type InstallTicket struct {
	Platform   string
	TenantID   string
	LocationID string
	Role       string
	EndpointID string
}

// CreateInstallTicket mints a single-use ticket for one enrolment script.
func (s *Store) CreateInstallTicket(t InstallTicket, ttl time.Duration) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating an install ticket: %w", err)
	}
	token := hex.EncodeToString(raw[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = InstallTicketTTL
	}
	if _, err := s.db.Exec(
		`INSERT INTO install_tickets
		 (token_hash, platform, tenant_id, location_id, role, endpoint_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hashEnrollmentToken(token),
		strings.TrimSpace(t.Platform), strings.TrimSpace(t.TenantID), strings.TrimSpace(t.LocationID),
		strings.TrimSpace(t.Role), strings.TrimSpace(t.EndpointID),
		now, now.Add(ttl),
	); err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM install_tickets WHERE expires_at < ? OR used_at IS NOT NULL`, now.Add(-24*time.Hour)); err != nil {
		return "", fmt.Errorf("pruning install tickets: %w", err)
	}
	return token, nil
}

// ConsumeInstallTicket redeems a ticket once and returns what it was minted for.
//
// The UPDATE is the check: claiming the row and reading it back in one statement
// is what stops two simultaneous fetches from both being served. A separate
// SELECT then UPDATE would let both through, which for a single-use credential
// is the whole failure.
func (s *Store) ConsumeInstallTicket(token string) (InstallTicket, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return InstallTicket{}, fmt.Errorf("no install ticket was presented")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	res, err := s.db.Exec(
		`UPDATE install_tickets SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now, hashEnrollmentToken(token), now,
	)
	if err != nil {
		return InstallTicket{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return InstallTicket{}, fmt.Errorf("checking install ticket claim: %w", err)
	}
	if n == 0 {
		// Say which of the three it was, because "spent" and "expired" mean
		// different things to whoever is standing at the endpoint.
		var expires time.Time
		var used sql.NullTime
		err := s.db.QueryRow(
			`SELECT expires_at, used_at FROM install_tickets WHERE token_hash = ?`,
			hashEnrollmentToken(token)).Scan(&expires, &used)
		switch {
		case err == sql.ErrNoRows:
			return InstallTicket{}, fmt.Errorf("this install link is not one this hub issued")
		case err != nil:
			return InstallTicket{}, err
		case used.Valid:
			return InstallTicket{}, fmt.Errorf("this install link has already been used; generate another")
		default:
			return InstallTicket{}, fmt.Errorf("this install link expired at %s; generate another", expires.Format(time.RFC3339))
		}
	}

	var t InstallTicket
	if err := s.db.QueryRow(
		`SELECT platform, tenant_id, location_id, role, endpoint_id
		 FROM install_tickets WHERE token_hash = ?`,
		hashEnrollmentToken(token),
	).Scan(&t.Platform, &t.TenantID, &t.LocationID, &t.Role, &t.EndpointID); err != nil {
		return InstallTicket{}, err
	}
	return t, nil
}

func (s *Store) initInstallTicketSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS install_tickets (
		token_hash TEXT PRIMARY KEY,
		platform TEXT NOT NULL DEFAULT '',
		tenant_id TEXT NOT NULL DEFAULT '',
		location_id TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL DEFAULT '',
		endpoint_id TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_install_tickets_expiry ON install_tickets(expires_at);
	`)
	return err
}
