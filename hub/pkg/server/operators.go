package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/storage"
)

// Who runs the fleet, managed from the console rather than from a file on the
// hub.
//
// Cloudflare Access decides who reaches this origin. This list decides what they
// are once they arrive, and the two are deliberately separate: widening an
// Access policy, or pointing a second Access application at this hostname, must
// not by itself hand anyone the fleet.
//
// The list lives in the database because the alternative was a file only someone
// with a shell on the hub could edit. An administrator adding a colleague should
// not need one, and the change should be visible in the audit trail like every
// other change to the fleet.
//
// Two rules hold this together:
//
//   - Only an administrator may read or change the list. An analyst who could
//     read it learns which addresses are worth phishing; an analyst who could
//     change it is an administrator.
//   - The last administrator cannot be demoted or removed. The failure is not
//     "the list is empty" but "the console can no longer be opened by anyone who
//     could repair the list", which needs a shell on the hub to undo.
func (s *Server) handleOperators(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListOperators()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []storage.Operator{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"operators": list,
			"roles":     storage.OperatorRoles,
			// So the console can say "this is you" rather than letting an
			// administrator remove their own access without noticing.
			"you": r.Header.Get("X-Username"),
		})

	case http.MethodPost:
		var req struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable request body")
			return
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		role := strings.ToLower(strings.TrimSpace(req.Role))
		if err := s.store.UpsertOperator(email, role, r.Header.Get("X-Username")); err != nil {
			if errors.Is(err, storage.ErrLastAdmin) {
				writeJSONError(w, http.StatusConflict, err.Error())
				return
			}
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(r, "OPERATOR_GRANT", email, "Granted "+email+" the "+role+" role on this console")
		writeJSON(w, http.StatusOK, map[string]string{"email": email, "role": role})

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleOperatorRemove takes the address in a POST body rather than a query
// string, because a URL is written down in more places than a body is: browser
// history, the access log of every proxy on the path, and whatever the CDN in
// front records.
func (s *Server) handleOperatorRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := s.store.DeleteOperator(email); err != nil {
		if errors.Is(err, storage.ErrLastAdmin) {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "OPERATOR_REVOKE", email, "Removed "+email+" from the console operator list")
	writeJSON(w, http.StatusOK, map[string]string{"email": email})
}

// roleAllows is the one place a read-only role is actually read-only.
//
// requireAdmin already guards the routes that were obviously dangerous when the
// only way to hold a non-admin role was a local account nobody had created. Once
// a Google sign-in can carry a role, that is no longer enough: isolating a host
// and releasing it were never behind requireAdmin, and an auditor reaching them
// would be able to cut the fleet off the network. Rather than audit every route
// individually and hope the next one added remembers, an auditor is refused any
// request that is not a read.
func roleAllows(role, method string) bool {
	if role != auth.RoleAuditor {
		return true
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
