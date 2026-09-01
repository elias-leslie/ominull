package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type EnrollmentProfile struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"` // invitation, campaign, deployment
	Platform   string     `json:"platform"`
	TenantID   string     `json:"tenant_id"`
	LocationID string     `json:"location_id"`
	Role       string     `json:"role"`
	EndpointID string     `json:"endpoint_id,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	MaxUses    int        `json:"max_uses"` // zero means unlimited
	Used       int        `json:"used"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

const EnrollmentProfileTTL = 30 * time.Minute

func (p EnrollmentProfile) state(now time.Time) string {
	if p.RevokedAt != nil {
		return "revoked"
	}
	if !p.ExpiresAt.After(now) {
		return "expired"
	}
	if p.MaxUses > 0 && p.Used >= p.MaxUses {
		return "spent"
	}
	return "open"
}

func (s *Store) CreateEnrollmentProfile(p EnrollmentProfile, ttl time.Duration) (EnrollmentProfile, string, error) {
	if p.Kind == "" {
		p.Kind = "invitation"
	}
	p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))
	if p.Kind != "invitation" && p.Kind != "campaign" && p.Kind != "deployment" {
		return EnrollmentProfile{}, "", errors.New("enrollment profile kind must be invitation, campaign, or deployment")
	}
	p.Platform = strings.ToLower(strings.TrimSpace(p.Platform))
	if p.Platform != "linux" && p.Platform != "windows" && p.Platform != "" {
		return EnrollmentProfile{}, "", errors.New("enrollment profile platform must be linux, windows, or empty")
	}
	if p.TenantID == "" {
		p.TenantID = "default"
	}
	if p.MaxUses < 0 {
		return EnrollmentProfile{}, "", errors.New("max uses cannot be negative")
	}
	if p.Kind == "invitation" {
		// An invitation is the one-use primitive. Campaigns deliberately use
		// zero for unlimited and deployment profiles remain persistent until
		// revoked, so an invitation can never be widened by a caller.
		p.MaxUses = 1
	}
	if p.Kind != "invitation" && strings.TrimSpace(p.EndpointID) != "" {
		return EnrollmentProfile{}, "", errors.New("a reusable enrollment profile cannot pin every install to one endpoint id")
	}
	if ttl <= 0 && p.Kind != "deployment" {
		ttl = EnrollmentProfileTTL
	}
	if ttl > 7*24*time.Hour {
		return EnrollmentProfile{}, "", errors.New("enrollment profile may not live longer than seven days")
	}
	var idRaw [16]byte
	var tokenRaw [32]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		return EnrollmentProfile{}, "", err
	}
	if _, err := rand.Read(tokenRaw[:]); err != nil {
		return EnrollmentProfile{}, "", err
	}
	p.ID = "enr_" + hex.EncodeToString(idRaw[:])
	code := "one_" + hex.EncodeToString(tokenRaw[:])
	p.CreatedAt = time.Now().UTC()
	if p.ExpiresAt.IsZero() {
		if p.Kind == "deployment" && ttl <= 0 {
			// SQLite keeps an expiry column for every profile. A persistent
			// deployment key uses the largest representable application time and
			// remains revocable by id; it is never treated as an expiring campaign.
			p.ExpiresAt = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
		} else {
			p.ExpiresAt = p.CreatedAt.Add(ttl)
		}
	}
	if !p.ExpiresAt.After(p.CreatedAt) {
		return EnrollmentProfile{}, "", errors.New("enrollment profile expiry must be in the future")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO enrollment_profiles
		(id, kind, platform, tenant_id, location_id, role, endpoint_id, code_hash,
		 created_by, created_at, expires_at, max_uses, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		p.ID, p.Kind, p.Platform, p.TenantID, strings.TrimSpace(p.LocationID),
		strings.TrimSpace(p.Role), strings.TrimSpace(p.EndpointID), hashEnrollmentToken(code),
		strings.TrimSpace(p.CreatedBy), p.CreatedAt, p.ExpiresAt, p.MaxUses)
	if err != nil {
		return EnrollmentProfile{}, "", err
	}
	return p, code, nil
}

// RedeemEnrollmentProfile atomically spends one use and returns the profile.
// The code is accepted only in a request body by the HTTP layer; it never
// belongs in a URL, command line, service definition, or package metadata.
func (s *Store) RedeemEnrollmentProfile(code, platform string) (EnrollmentProfile, error) {
	code = strings.TrimSpace(code)
	platform = strings.ToLower(strings.TrimSpace(platform))
	if code == "" {
		return EnrollmentProfile{}, errors.New("enrollment code is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	wherePlatform := "(platform = '' OR platform = ?)"
	res, err := s.db.Exec(`UPDATE enrollment_profiles SET used = used + 1
		WHERE code_hash = ? AND revoked_at IS NULL AND expires_at > ?
		AND (max_uses = 0 OR used < max_uses) AND `+wherePlatform,
		hashEnrollmentToken(code), now, platform)
	if err != nil {
		return EnrollmentProfile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return EnrollmentProfile{}, err
	}
	if n == 0 {
		var p EnrollmentProfile
		var revoked sql.NullTime
		var used int
		err := s.db.QueryRow(`SELECT id, kind, platform, tenant_id, location_id, role,
			endpoint_id, created_by, created_at, expires_at, max_uses, used, revoked_at
			FROM enrollment_profiles WHERE code_hash = ?`, hashEnrollmentToken(code)).Scan(
			&p.ID, &p.Kind, &p.Platform, &p.TenantID, &p.LocationID, &p.Role,
			&p.EndpointID, &p.CreatedBy, &p.CreatedAt, &p.ExpiresAt, &p.MaxUses, &used, &revoked)
		if err == sql.ErrNoRows {
			return EnrollmentProfile{}, errors.New("enrollment code is invalid")
		}
		if err != nil {
			return EnrollmentProfile{}, err
		}
		p.Used = used
		if revoked.Valid {
			p.RevokedAt = &revoked.Time
		}
		switch p.state(now) {
		case "expired":
			return EnrollmentProfile{}, errors.New("enrollment code has expired")
		case "spent":
			return EnrollmentProfile{}, errors.New("enrollment code has already been used")
		case "revoked":
			return EnrollmentProfile{}, errors.New("enrollment code has been revoked")
		default:
			return EnrollmentProfile{}, fmt.Errorf("enrollment code is not valid for platform %q", platform)
		}
	}
	var p EnrollmentProfile
	if err := s.db.QueryRow(`SELECT id, kind, platform, tenant_id, location_id, role,
		endpoint_id, created_by, created_at, expires_at, max_uses, used
		FROM enrollment_profiles WHERE code_hash = ?`, hashEnrollmentToken(code)).Scan(
		&p.ID, &p.Kind, &p.Platform, &p.TenantID, &p.LocationID, &p.Role,
		&p.EndpointID, &p.CreatedBy, &p.CreatedAt, &p.ExpiresAt, &p.MaxUses, &p.Used); err != nil {
		return EnrollmentProfile{}, err
	}
	return p, nil
}

func (s *Store) RevokeEnrollmentProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE enrollment_profiles SET revoked_at = ?
		WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC(), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListEnrollmentProfiles() ([]EnrollmentProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, kind, platform, tenant_id, location_id, role,
		endpoint_id, created_by, created_at, expires_at, max_uses, used, revoked_at
		FROM enrollment_profiles ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentProfile
	for rows.Next() {
		var p EnrollmentProfile
		var revoked sql.NullTime
		if err := rows.Scan(&p.ID, &p.Kind, &p.Platform, &p.TenantID, &p.LocationID,
			&p.Role, &p.EndpointID, &p.CreatedBy, &p.CreatedAt, &p.ExpiresAt,
			&p.MaxUses, &p.Used, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			p.RevokedAt = &revoked.Time
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) initEnrollmentProfileSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS enrollment_profiles (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		platform TEXT NOT NULL DEFAULT '',
		tenant_id TEXT NOT NULL,
		location_id TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL DEFAULT '',
		endpoint_id TEXT NOT NULL DEFAULT '',
		code_hash TEXT NOT NULL UNIQUE,
		created_by TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		max_uses INTEGER NOT NULL DEFAULT 1,
		used INTEGER NOT NULL DEFAULT 0,
		revoked_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_enrollment_profiles_expiry ON enrollment_profiles(expires_at);
	`)
	return err
}
