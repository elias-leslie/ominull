package storage

import (
	"database/sql"
	"errors"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"
)

// ExclusionMaxLifetime is the longest term an exclusion can be written with.
// Keeping one longer is a renewal, made on purpose, not a default nobody sees.
const ExclusionMaxLifetime = 90 * 24 * time.Hour

// ErrExclusionNotFound is returned for an id no row carries.
var ErrExclusionNotFound = errors.New("exclusion not found")

var windowsDrivePath = regexp.MustCompile(`^[A-Za-z]:/`)

// Problem says why an exclusion may not be saved or applied, or "" when it is
// sound. An exclusion silences detection, so the write and every read use the
// same rules: a row that predates them, or was written behind the API, never
// matches more than it says.
//
//   - It names at least one selector: an exact process path, an address or
//     CIDR, or a port. A row with none used to match all traffic.
//   - A process path is one exact absolute path. Globs and substrings are
//     refused: "python" used to exempt every path containing it.
//   - An address range that does not parse is refused; it used to match every
//     destination.
//   - A scoped exclusion names what it is scoped to.
//   - It has a reason, and it has not expired.
func (ex Exclusion) Problem(now time.Time) string {
	switch ex.Scope {
	case "global":
	case "client", "location", "endpoint":
		if strings.TrimSpace(ex.ScopeValue) == "" {
			return "a " + ex.Scope + " exclusion needs scope_value"
		}
	default:
		return "scope must be global, client, location or endpoint"
	}
	proc := exclusionAny(ex.ProcessPath)
	if proc != "" && !exactProcessPath(proc) {
		return "process_path must be one exact absolute path, without wildcards"
	}
	dst := exclusionAny(ex.DstIPRange)
	if dst != "" {
		if _, ok := exclusionRange(dst); !ok {
			return "dst_ip_range must be an IP address or a CIDR range"
		}
	}
	switch strings.ToLower(strings.TrimSpace(ex.Protocol)) {
	case "", "any", "tcp", "udp", "icmp":
	default:
		return "protocol must be tcp, udp, icmp or any"
	}
	if proc == "" && dst == "" && ex.Port == 0 {
		return "an exclusion needs a process_path, a dst_ip_range or a port"
	}
	if strings.TrimSpace(ex.Reason) == "" {
		return "reason is required"
	}
	if ex.ExpiresAt.IsZero() || !ex.ExpiresAt.After(now) {
		return "expires_at must be in the future"
	}
	return ""
}

// exclusionAny maps the stored "match anything" spellings to "".
func exclusionAny(v string) string {
	v = strings.TrimSpace(v)
	if v == "*" {
		return ""
	}
	return v
}

func normalizeProcessPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// exactProcessPath accepts one absolute path in canonical form: a Unix path,
// or a Windows drive path. Nothing in it is a pattern.
func exactProcessPath(p string) bool {
	if strings.ContainsAny(p, "*?[]") {
		return false
	}
	p = normalizeProcessPath(p)
	switch {
	case strings.HasPrefix(p, "/"):
		return path.Clean(p) == p
	case windowsDrivePath.MatchString(p):
		return path.Clean(p[2:]) == p[2:]
	}
	return false
}

func exclusionRange(v string) (netip.Prefix, bool) {
	if strings.Contains(v, "/") {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// sameProcess compares exact paths. Windows paths compare without case, as
// the filesystem does; Unix paths compare byte for byte.
func sameProcess(want, got string) bool {
	want, got = normalizeProcessPath(want), normalizeProcessPath(got)
	if windowsDrivePath.MatchString(want) {
		return strings.EqualFold(want, got)
	}
	return want == got
}

// MatchesExclusion applies a previously loaded exclusion snapshot. Loading
// the snapshot is the caller's responsibility; this function has no database
// side effect and can be used for every event in one batch. Rows that fail
// Problem - expired, unexplained, or broader than they read - never match.
func MatchesExclusion(ev Event, locationID string, exclusions []Exclusion) bool {
	now := time.Now().UTC()
	for _, ex := range exclusions {
		if !ex.Active || ex.Problem(now) != "" {
			continue
		}
		switch ex.Scope {
		case "client":
			if ex.ScopeValue != ev.TenantID {
				continue
			}
		case "location":
			if ex.ScopeValue != locationID {
				continue
			}
		case "endpoint":
			if ex.ScopeValue != ev.EndpointID {
				continue
			}
		}
		if ex.Scope != "global" && ex.TenantID != ev.TenantID {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(ex.Protocol)) {
		case "tcp":
			if ev.Protocol != 6 {
				continue
			}
		case "udp":
			if ev.Protocol != 17 {
				continue
			}
		case "icmp":
			if ev.Protocol != 1 {
				continue
			}
		}

		if dst := exclusionAny(ex.DstIPRange); dst != "" {
			prefix, _ := exclusionRange(dst)
			addr, err := netip.ParseAddr(ev.DstIP)
			if err != nil || !prefix.Contains(addr.Unmap()) {
				continue
			}
		}

		if ex.Port != 0 && ex.Port != ev.DstPort {
			continue
		}

		if proc := exclusionAny(ex.ProcessPath); proc != "" && !sameProcess(proc, ev.ProcessPath) {
			continue
		}

		return true
	}
	return false
}

func (s *Store) IsExclusionMatch(ev Event, locationID string) bool {
	exclusions, err := s.ListExclusions(ev.TenantID)
	if err != nil {
		return false
	}
	return MatchesExclusion(ev, locationID, exclusions)
}

func (s *Store) CreateExclusion(ex Exclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if ex.Active {
		actInt = 1
	}

	query := `
	INSERT INTO exclusions (id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		scope=excluded.scope,
		scope_value=excluded.scope_value,
		name=excluded.name,
		process_path=excluded.process_path,
		dst_ip_range=excluded.dst_ip_range,
		port=excluded.port,
		protocol=excluded.protocol,
		reason=excluded.reason,
		active=excluded.active,
		expires_at=excluded.expires_at
	`
	_, err := s.db.Exec(
		query,
		ex.ID, ex.TenantID, ex.Scope, ex.ScopeValue, ex.Name,
		ex.ProcessPath, ex.DstIPRange, ex.Port, ex.Protocol, ex.Reason, actInt, ex.CreatedAt, ex.ExpiresAt.UTC(),
	)
	return err
}

const exclusionColumns = "id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at, expires_at"

func scanExclusion(row interface{ Scan(...any) error }) (Exclusion, error) {
	var ex Exclusion
	var actInt int
	var expires sql.NullTime
	err := row.Scan(&ex.ID, &ex.TenantID, &ex.Scope, &ex.ScopeValue, &ex.Name,
		&ex.ProcessPath, &ex.DstIPRange, &ex.Port, &ex.Protocol, &ex.Reason, &actInt, &ex.CreatedAt, &expires)
	ex.Active = actInt != 0
	if expires.Valid {
		ex.ExpiresAt = expires.Time.UTC()
	}
	return ex, err
}

func (s *Store) ListExclusions(tenantID string) ([]Exclusion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" && tenantID != "default" {
		rows, err = s.db.Query("SELECT "+exclusionColumns+" FROM exclusions WHERE tenant_id = ? OR scope = 'global' ORDER BY created_at DESC", tenantID)
	} else {
		rows, err = s.db.Query("SELECT " + exclusionColumns + " FROM exclusions ORDER BY created_at DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]Exclusion, 0)
	for rows.Next() {
		ex, err := scanExclusion(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, ex)
	}
	return list, rows.Err()
}

// GetExclusion reads one row, or ErrExclusionNotFound.
func (s *Store) GetExclusion(id string) (Exclusion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ex, err := scanExclusion(s.db.QueryRow("SELECT "+exclusionColumns+" FROM exclusions WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Exclusion{}, ErrExclusionNotFound
	}
	return ex, err
}

func (s *Store) DeleteExclusion(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM exclusions WHERE id = ?", id)
	return err
}

func (s *Store) ToggleExclusion(id string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if active {
		actInt = 1
	}
	_, err := s.db.Exec("UPDATE exclusions SET active = ? WHERE id = ?", actInt, id)
	return err
}
