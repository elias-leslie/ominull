package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Monitor-only endpoints.
//
// Host isolation on Linux closes INPUT and OUTPUT. A hypervisor forwards its
// guests' traffic through FORWARD, so isolating it cuts its management while
// every guest keeps talking: the opposite of containment. Such a host is
// monitor-only; its guests are contained one by one on the hypervisor's own
// per-guest firewall (or with their links down), not through the host.
//
// What makes an endpoint monitor-only is never its OS name:
//   - an operator set its response profile to monitor (the hub's half of the
//     capability manifest; the signed manifest pinned at enrollment replaces
//     this setting as its source once agents enforce it),
//   - its role is hypervisor, or
//   - its agent reports it cannot isolate (response capabilities isolate:false).
//
// The hub refuses to record an isolation for such an endpoint at every entry
// point (operator, bulk, detector) and never tells its agent to isolate.

// ResponseProfileMonitor is the operator setting that makes an endpoint
// monitor-only. The empty profile keeps the endpoint's reported capabilities.
const ResponseProfileMonitor = "monitor"

// RoleHypervisor is the role tag that is always monitor-only.
const RoleHypervisor = "hypervisor"

// ErrMonitorOnly is returned when an isolation is asked of a monitor-only endpoint.
var ErrMonitorOnly = errors.New("endpoint is monitor-only: host isolation is refused")

// monitorOnlySQL is 1 for a monitor-only endpoints row and 0 otherwise, never
// NULL (NOT NULL would silently drop rows from an isolation). Every path that
// decides isolation uses this one expression, so they cannot drift apart.
const monitorOnlySQL = "(COALESCE(response_profile, '') = 'monitor'" +
	" OR LOWER(COALESCE(role_tag, '')) = 'hypervisor'" +
	" OR COALESCE(CASE WHEN json_valid(COALESCE(response_capabilities, '')) THEN json_type(response_capabilities, '$.isolate') END, '') = 'false')"

// endpointProfileColumns are appended to every endpoint SELECT (scanned into
// ResponseProfile and MonitorOnly).
const endpointProfileColumns = "COALESCE(response_profile, ''), " + monitorOnlySQL

// MonitorOnlyReason explains why an endpoint is monitor-only ("" when it is
// not). It reads the same three facts monitorOnlySQL does.
func (ep Endpoint) MonitorOnlyReason() string {
	switch {
	case ep.ResponseProfile == ResponseProfileMonitor:
		return "an operator set it monitor-only"
	case strings.EqualFold(strings.TrimSpace(ep.RoleTag), RoleHypervisor):
		return "its role is hypervisor"
	case ep.MonitorOnly:
		return "its agent reports it cannot isolate"
	}
	return ""
}

// SetEndpointResponseProfile records the operator's response profile for an
// endpoint: "monitor" or "" (back to what the agent reports).
func (s *Store) SetEndpointResponseProfile(id, profile string) error {
	if profile != "" && profile != ResponseProfileMonitor {
		return fmt.Errorf("response profile is %q or empty", ResponseProfileMonitor)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE endpoints SET response_profile = ? WHERE id = ?", profile, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrEndpointNotFound
	}
	return nil
}

// SplitMonitorOnly separates ids into endpoints that may be isolated and the
// monitor-only ones. Unknown ids stay in allowed (the caller's scope check
// owns them). Order is kept.
func (s *Store) SplitMonitorOnly(ids []string) (allowed, monitor []string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT id FROM endpoints WHERE " + monitorOnlySQL)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	mon := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, nil, err
		}
		mon[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, id := range ids {
		if mon[id] {
			monitor = append(monitor, id)
		} else {
			allowed = append(allowed, id)
		}
	}
	return allowed, monitor, nil
}

// isolateOneLocked sets is_isolated for one endpoint unless it is monitor-only.
// Caller holds s.mu.
func (s *Store) isolateOneLocked(id, allow string) error {
	res, err := s.db.Exec("UPDATE endpoints SET is_isolated = 1, isolation_allow_ips = ? WHERE id = ? AND NOT "+monitorOnlySQL, allow, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	switch err := s.db.QueryRow("SELECT 1 FROM endpoints WHERE id = ?", id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return nil // unknown id: unchanged behaviour (nothing to isolate)
	case err != nil:
		return err
	}
	return ErrMonitorOnly
}
