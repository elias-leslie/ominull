package storage

import (
	"errors"
	"fmt"
	"time"
)

// ErrEndpointNotFound is returned when no endpoint has the given id.
var ErrEndpointNotFound = errors.New("endpoint not registered")

// Presence is how often an endpoint is expected to be reporting.
//
// Silence on an always-on server is the first sign of a stopped agent or a
// dead host, and is reported within minutes. A laptop that is in use but
// often shut, or a test guest that is powered off between experiments, goes
// quiet as a matter of course: reporting every one of those absences buried
// the server outages the silence alert exists for. The operator says which
// kind of host each endpoint is, and the quiet allowance follows.
const (
	PresenceAlwaysOn     = "always_on"
	PresenceIntermittent = "intermittent"
	PresenceLab          = "lab"
)

// IntermittentQuiet is how long an intermittent host may stay quiet before
// its silence is worth a look: long enough for a holiday, short enough that
// a laptop that has quietly lost its agent is noticed within the month.
const IntermittentQuiet = 30 * 24 * time.Hour

// ValidPresence reports a presence value the hub understands.
func ValidPresence(p string) bool {
	switch p {
	case PresenceAlwaysOn, PresenceIntermittent, PresenceLab:
		return true
	}
	return false
}

// QuietAllowance is how long this endpoint may stay quiet before it is
// reported, given the allowance an always-on host of its kind gets. A lab
// endpoint is never reported: it is off unless somebody is testing on it.
func (ep Endpoint) QuietAllowance(alwaysOn time.Duration) (time.Duration, bool) {
	switch ep.Presence {
	case PresenceLab:
		return 0, false
	case PresenceIntermittent:
		return max(alwaysOn, IntermittentQuiet), true
	}
	return alwaysOn, true
}

// SetEndpointPresence records how often an endpoint is expected to report.
func (s *Store) SetEndpointPresence(id, presence string) error {
	if !ValidPresence(presence) {
		return fmt.Errorf("presence is %s, %s or %s", PresenceAlwaysOn, PresenceIntermittent, PresenceLab)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE endpoints SET presence = ? WHERE id = ?", presence, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrEndpointNotFound
	}
	return nil
}
