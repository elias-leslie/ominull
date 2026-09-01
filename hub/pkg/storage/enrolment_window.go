package storage

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Self-service enrolment: pre-authorising a network instead of a host.
//
// The old per-host install link solved "paste one line on the host" but not "get the agent
// onto forty hosts". Every ticket is minted by an administrator, for one host,
// and dies in thirty minutes - so enrolling a fleet means an operator sitting in
// the console minting links one at a time while someone else walks the building.
//
// An enrolment window is the standing authorisation that replaces that: for the
// next few hours, a machine on this network may ask the hub for its own install
// command. It does not hand out a standing machine credential. The portal mints
// an ordinary single-use enrollment profile per request. What the window
// changes is who may cause one to be minted: an administrator ahead of time, by
// network, instead of by hand, one host at a time.
//
// Four things bound it, and all four are visible and revocable in the console:
// the source networks it accepts, an expiry, a budget of enrolments, and an
// optional passcode for the case where "on the network" is not by itself a
// claim worth trusting - a flat LAN with guest wifi on it, say.
type EnrolmentWindow struct {
	ID          string     `json:"id"`
	Label       string     `json:"label"`
	CIDRs       []string   `json:"cidrs"`
	TenantID    string     `json:"tenant_id"`
	LocationID  string     `json:"location_id"`
	Role        string     `json:"role"`
	MaxUses     int        `json:"max_uses"` // 0 = no limit
	Used        int        `json:"used"`
	HasPasscode bool       `json:"has_passcode"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedBy   string     `json:"created_by"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// Active reports whether this window would still authorise an enrolment.
func (w EnrolmentWindow) Active() bool {
	if w.RevokedAt != nil {
		return false
	}
	if time.Now().UTC().After(w.ExpiresAt) {
		return false
	}
	return w.MaxUses <= 0 || w.Used < w.MaxUses
}

// State is why a window is not usable, for the console to print.
func (w EnrolmentWindow) State() string {
	switch {
	case w.RevokedAt != nil:
		return "revoked"
	case time.Now().UTC().After(w.ExpiresAt):
		return "expired"
	case w.MaxUses > 0 && w.Used >= w.MaxUses:
		return "spent"
	default:
		return "open"
	}
}

// ParseCIDRs validates the networks a window will accept and returns them in a
// canonical form. A bare address is accepted and read as a single host, which is
// what an operator authorising one machine will type.
func ParseCIDRs(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("%q is not an address or a network in CIDR form", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not a network in CIDR form: %w", entry, err)
		}
		out = append(out, network.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one network is required; a window open to nothing authorises nothing")
	}
	return out, nil
}

// cidrsAllow reports whether addr falls inside any of these networks.
func cidrsAllow(cidrs []string, addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	for _, entry := range cidrs {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// CreateEnrolmentWindow opens one. The passcode, if there is one, is stored as a
// hash: the console shows it once at creation and the hub cannot show it again,
// for the same reason it cannot show an admin key twice.
func (s *Store) CreateEnrolmentWindow(w EnrolmentWindow, passcode string) (EnrolmentWindow, error) {
	cidrs, err := ParseCIDRs(w.CIDRs)
	if err != nil {
		return EnrolmentWindow{}, err
	}
	if w.ExpiresAt.IsZero() {
		return EnrolmentWindow{}, fmt.Errorf("an enrolment window must expire; a standing authorisation with no end is not one anybody will remember to close")
	}
	if w.MaxUses < 0 {
		w.MaxUses = 0
	}

	var raw [9]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return EnrolmentWindow{}, fmt.Errorf("generating a window id: %w", err)
	}
	w.ID = "win-" + hex.EncodeToString(raw[:])
	w.CIDRs = cidrs
	w.CreatedAt = time.Now().UTC()
	w.ExpiresAt = w.ExpiresAt.UTC()
	w.Used = 0
	w.HasPasscode = strings.TrimSpace(passcode) != ""

	hash := ""
	if w.HasPasscode {
		hash = hashEnrollmentToken(strings.TrimSpace(passcode))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(
		`INSERT INTO enrolment_windows
		 (id, label, cidrs, passcode_hash, tenant_id, location_id, role, max_uses, used, created_at, expires_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		w.ID, strings.TrimSpace(w.Label), strings.Join(cidrs, ","), hash,
		strings.TrimSpace(w.TenantID), strings.TrimSpace(w.LocationID), strings.TrimSpace(w.Role),
		w.MaxUses, w.CreatedAt, w.ExpiresAt, strings.TrimSpace(w.CreatedBy),
	); err != nil {
		return EnrolmentWindow{}, err
	}
	return w, nil
}

// ListEnrolmentWindows returns every window, newest first. Expired and revoked
// ones stay listed so the console can show what was open and when.
func (s *Store) ListEnrolmentWindows() ([]EnrolmentWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, label, cidrs, passcode_hash, tenant_id, location_id, role,
		        max_uses, used, created_at, expires_at, created_by, revoked_at, last_used_at
		 FROM enrolment_windows ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []EnrolmentWindow{}
	for rows.Next() {
		var w EnrolmentWindow
		var cidrs, hash string
		var revoked, lastUsed sql.NullTime
		if err := rows.Scan(&w.ID, &w.Label, &cidrs, &hash, &w.TenantID, &w.LocationID, &w.Role,
			&w.MaxUses, &w.Used, &w.CreatedAt, &w.ExpiresAt, &w.CreatedBy, &revoked, &lastUsed); err != nil {
			return nil, err
		}
		w.CIDRs = strings.Split(cidrs, ",")
		w.HasPasscode = hash != ""
		if revoked.Valid {
			t := revoked.Time.UTC()
			w.RevokedAt = &t
		}
		if lastUsed.Valid {
			t := lastUsed.Time.UTC()
			w.LastUsedAt = &t
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// RevokeEnrolmentWindow closes one immediately.
func (s *Store) RevokeEnrolmentWindow(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE enrolment_windows SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no open enrolment window with id %q", id)
	}
	return nil
}

// EnrolmentWindowUnavailable is why a self-service request was refused. The
// portal shows the reason to whoever is standing at the endpoint, so it has to
// be true without being a map of what else exists: "no window covers you" is the
// same answer whether none is open at all or three are open for other networks.
type EnrolmentWindowUnavailable struct {
	Reason string
	// NeedsPasscode distinguishes "you are covered but did not say the word"
	// from "you are not covered", because the first one has a form to fill in
	// and the second has nothing the visitor can do.
	NeedsPasscode bool
	// Closed is the state of a window that names this network but has stopped
	// authorising - "expired", "spent", "revoked". Someone walking a building
	// installing agents hits this the moment a budget runs out, and "you are not
	// authorised" would send them looking for the wrong problem. It tells them
	// only about a network they are demonstrably already on.
	Closed string
}

func (e *EnrolmentWindowUnavailable) Error() string { return e.Reason }

// ClaimEnrolment spends one enrolment against whichever open window covers this
// address, and returns the enrolment parameters it authorises.
//
// The UPDATE carries the whole precondition, for the same reason
// ConsumeInstallTicket does: two machines asking at once must not both be served
// by a window with one use left.
func (s *Store) ClaimEnrolment(addr, passcode string) (EnrolmentWindow, error) {
	windows, err := s.ListEnrolmentWindows()
	if err != nil {
		return EnrolmentWindow{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	// Covered but locked is a different answer from not covered, and the visitor
	// can act on the first one. Track it while scanning rather than re-deriving.
	sawCoveredNeedingPasscode := false
	closed := ""

	for _, w := range windows {
		if !cidrsAllow(w.CIDRs, addr) {
			continue
		}
		if !w.Active() {
			// Windows are listed newest first, so the first closed one that
			// names this network is the one whoever is standing there was most
			// likely told to use.
			if closed == "" {
				closed = w.State()
			}
			continue
		}

		var hash string
		if err := s.db.QueryRow(`SELECT passcode_hash FROM enrolment_windows WHERE id = ?`, w.ID).Scan(&hash); err != nil {
			continue
		}
		if hash != "" {
			given := strings.TrimSpace(passcode)
			if given == "" {
				sawCoveredNeedingPasscode = true
				continue
			}
			if subtle.ConstantTimeCompare([]byte(hashEnrollmentToken(given)), []byte(hash)) != 1 {
				sawCoveredNeedingPasscode = true
				continue
			}
		}

		res, err := s.db.Exec(
			`UPDATE enrolment_windows SET used = used + 1, last_used_at = ?
			 WHERE id = ? AND revoked_at IS NULL AND expires_at > ?
			   AND (max_uses <= 0 OR used < max_uses)`,
			now, w.ID, now)
		if err != nil {
			return EnrolmentWindow{}, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Something else spent the last use between the list and here.
			continue
		}
		w.Used++
		w.LastUsedAt = &now
		return w, nil
	}

	if sawCoveredNeedingPasscode {
		return EnrolmentWindow{}, &EnrolmentWindowUnavailable{
			Reason:        "this network needs the enrolment passcode",
			NeedsPasscode: true,
		}
	}
	if closed != "" {
		return EnrolmentWindow{}, &EnrolmentWindowUnavailable{
			Reason: "the enrolment window for this network is " + closed,
			Closed: closed,
		}
	}
	return EnrolmentWindow{}, &EnrolmentWindowUnavailable{
		Reason: "no open enrolment window covers " + addr,
	}
}

// CoveringWindow reports whether any open window covers this address, without
// spending anything. The portal uses it to decide what to put on the page before
// the visitor has asked for a command.
func (s *Store) CoveringWindow(addr string) (EnrolmentWindow, bool) {
	windows, err := s.ListEnrolmentWindows()
	if err != nil {
		return EnrolmentWindow{}, false
	}
	for _, w := range windows {
		if w.Active() && cidrsAllow(w.CIDRs, addr) {
			return w, true
		}
	}
	return EnrolmentWindow{}, false
}

func (s *Store) initEnrolmentWindowSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS enrolment_windows (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL DEFAULT '',
		cidrs TEXT NOT NULL,
		passcode_hash TEXT NOT NULL DEFAULT '',
		tenant_id TEXT NOT NULL DEFAULT '',
		location_id TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL DEFAULT '',
		max_uses INTEGER NOT NULL DEFAULT 0,
		used INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		created_by TEXT NOT NULL DEFAULT '',
		revoked_at DATETIME,
		last_used_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_enrolment_windows_expiry ON enrolment_windows(expires_at);
	`)
	return err
}
