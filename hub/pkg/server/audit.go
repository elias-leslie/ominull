package server

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/storage"
)

// audit records one privileged action against the identity the hub established
// for the caller, not against anything the caller asserted: authMiddleware
// clears X-Role, X-Tenant-ID, X-Username and X-User-ID on the way in and sets
// them itself, so these are the hub's own findings.
//
// It exists because the audit log covered five actions and none of them were
// the ones that reach the whole fleet. On the live hub the table held three
// rows, while the same day carried three fleet-wide agent roll-outs, several
// certificate issuances and a stream of admin API calls - so the record of who
// did what did not contain the events anyone would go looking for. The list of
// call sites is the list of operations that change more than one endpoint,
// hand out a credential, or reach off the hub.
//
// A failure to write the log is not allowed to fail the operation: the action
// has usually already happened by the time this is called, and refusing to
// report a completed change would be worse than an incomplete log. The write
// error is dropped for the same reason every other RecordAudit call drops it.
func (s *Server) audit(r *http.Request, action, resource, details string) {
	username := r.Header.Get("X-Username")
	if username == "" {
		username = "unknown"
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  username,
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: clientIP(r),
		Timestamp: time.Now().UTC(),
	})
}
