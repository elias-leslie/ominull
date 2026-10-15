package storage

import (
	"database/sql"
	"errors"
)

// Monitor-only endpoints.
//
// Host isolation on Linux closes INPUT and OUTPUT. A hypervisor forwards its
// guests' traffic through FORWARD, so isolating it cuts its management while
// every guest keeps talking: the opposite of containment. Such a host is
// monitor-only; its guests are contained one by one on the hypervisor's own
// per-guest firewall (or with their links down), not through the host.
//
// What makes an endpoint monitor-only is never its OS name, and never what the
// endpoint says about itself: its role tag and response capabilities arrive
// with every heartbeat, so an agent could label itself out of isolation. An
// operator sets the response profile to monitor (the hub's half of the
// capability manifest; the signed manifest pinned at enrollment replaces this
// setting as its source once agents enforce it). The setting is refused while
// the endpoint is isolated (releasing an isolation takes the owner), and every
// change bumps a revision, so an owner approval to lift it covers exactly the
// setting the owner saw.
//
// The hub refuses to record an isolation for such an endpoint at every entry
// point (operator, bulk, detector).

// ResponseProfileMonitor is the operator setting that makes an endpoint
// monitor-only. The empty profile keeps the endpoint's reported capabilities.
const ResponseProfileMonitor = "monitor"

// ErrMonitorOnly is returned when an isolation is asked of a monitor-only endpoint.
var ErrMonitorOnly = errors.New("endpoint is monitor-only: host isolation is refused")

// ErrIsolated refuses making an isolated endpoint monitor-only: that would lift
// the isolation without the owner.
var ErrIsolated = errors.New("endpoint is isolated: release the isolation first (owner-approved), then make it monitor-only")

// ErrProfileChanged refuses lifting a monitor-only setting that changed since
// the revision the caller (and the owner's approval) named.
var ErrProfileChanged = errors.New("the monitor-only setting changed since that revision")

// monitorOnlySQL is 1 for a monitor-only endpoints row and 0 otherwise, never
// NULL (NOT NULL would silently drop rows from an isolation). Every path that
// decides isolation uses this one expression, so they cannot drift apart.
const monitorOnlySQL = "(COALESCE(response_profile, '') = 'monitor')"

// endpointProfileColumns are appended to every endpoint SELECT (scanned into
// ResponseProfile, MonitorOnly and ResponseProfileRev).
const endpointProfileColumns = "COALESCE(response_profile, ''), " + monitorOnlySQL + ", COALESCE(response_profile_rev, 0)"

// MonitorOnlyReason explains why an endpoint is monitor-only ("" when it is not).
func (ep Endpoint) MonitorOnlyReason() string {
	if ep.MonitorOnly {
		return "an operator set it monitor-only"
	}
	return ""
}

// SetEndpointMonitorOnly makes an endpoint monitor-only and returns the new
// revision. Refused while the endpoint is isolated.
func (s *Store) SetEndpointMonitorOnly(id string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE endpoints SET response_profile = ?, response_profile_rev = COALESCE(response_profile_rev, 0) + 1"+
		" WHERE id = ? AND COALESCE(is_isolated, 0) = 0", ResponseProfileMonitor, id)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, s.whyNotUpdatedLocked(id, ErrIsolated)
	}
	return s.profileRevLocked(id)
}

// LiftMonitorOnly clears the operator's setting only if it is still at rev,
// and returns the new revision.
func (s *Store) LiftMonitorOnly(id string, rev int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE endpoints SET response_profile = '', response_profile_rev = COALESCE(response_profile_rev, 0) + 1"+
		" WHERE id = ? AND COALESCE(response_profile_rev, 0) = ? AND "+monitorOnlySQL, id, rev)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, s.whyNotUpdatedLocked(id, ErrProfileChanged)
	}
	return s.profileRevLocked(id)
}

func (s *Store) whyNotUpdatedLocked(id string, otherwise error) error {
	var one int
	switch err := s.db.QueryRow("SELECT 1 FROM endpoints WHERE id = ?", id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrEndpointNotFound
	case err != nil:
		return err
	}
	return otherwise
}

func (s *Store) profileRevLocked(id string) (int64, error) {
	var rev int64
	err := s.db.QueryRow("SELECT COALESCE(response_profile_rev, 0) FROM endpoints WHERE id = ?", id).Scan(&rev)
	return rev, err
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
	res, err := s.db.Exec("UPDATE endpoints SET "+isolationStartSQL+", is_isolated = 1, isolation_allow_ips = ? WHERE id = ? AND NOT "+monitorOnlySQL, allow, id)
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
