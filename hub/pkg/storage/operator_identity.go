package storage

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

type OperatorIdentity struct {
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// ResolveOperatorIdentity maps a verified issuer/subject to a current role.
// Email is only a bootstrap lookup for an identity seen for the first time;
// subsequent logins use the stable subject pair.
func (s *Store) ResolveOperatorIdentity(issuer, subject, email string) (OperatorIdentity, bool, error) {
	issuer, subject, email = strings.TrimSpace(issuer), strings.TrimSpace(subject), normaliseEmail(email)
	if issuer == "" || subject == "" {
		return OperatorIdentity{}, false, errors.New("OIDC issuer and subject are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var identity OperatorIdentity
	err := s.db.QueryRow(`SELECT issuer, subject, email, role, created_at
		FROM operator_identities WHERE issuer = ? AND subject = ?`, issuer, subject).
		Scan(&identity.Issuer, &identity.Subject, &identity.Email, &identity.Role, &identity.CreatedAt)
	if err == nil {
		return identity, true, nil
	}
	if err != sql.ErrNoRows {
		return OperatorIdentity{}, false, err
	}
	var role string
	if err := s.db.QueryRow(`SELECT role FROM operators WHERE email = ?`, email).Scan(&role); err != nil {
		if err == sql.ErrNoRows {
			return OperatorIdentity{}, false, nil
		}
		return OperatorIdentity{}, false, err
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`INSERT INTO operator_identities
		(issuer, subject, email, role, created_at) VALUES (?, ?, ?, ?, ?)`,
		issuer, subject, email, role, now); err != nil {
		return OperatorIdentity{}, false, err
	}
	return OperatorIdentity{Issuer: issuer, Subject: subject, Email: email, Role: role, CreatedAt: now}, true, nil
}

func (s *Store) ListOperatorIdentities() ([]OperatorIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT issuer, subject, email, role, created_at
		FROM operator_identities ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperatorIdentity
	for rows.Next() {
		var identity OperatorIdentity
		if err := rows.Scan(&identity.Issuer, &identity.Subject, &identity.Email, &identity.Role, &identity.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, identity)
	}
	return out, rows.Err()
}

func (s *Store) initOperatorIdentitySchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS operator_identities (
		issuer TEXT NOT NULL,
		subject TEXT NOT NULL,
		email TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		PRIMARY KEY (issuer, subject)
	);
	CREATE INDEX IF NOT EXISTS idx_operator_identities_email ON operator_identities(email);
	`)
	return err
}
