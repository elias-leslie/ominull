package server

import (
	"encoding/json"
	"io"
	"net/http"

	"ominull/hub/pkg/responseauth"
)

// Nightshift's Approvals rows for OmniNull (responseauth/approval_rows.go).
// The hub only couriers them: the authority checks, keeps and decides.
//
//	GET  /api/v1/integrations/nightshift/approval-rules           what the authority holds
//	POST /api/v1/integrations/nightshift/approval-rules           a save (approval_id when it loosens)
//	POST /api/v1/integrations/nightshift/approval-rules/challenge the owner's tap a loosening save needs
func (s *Server) handleRelayApprovalRules(w http.ResponseWriter, r *http.Request) {
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, err := s.responseAuth.ApprovalRows(r.Context(), "default")
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, v)
	case http.MethodPost:
		in, ok := decodeRowsInput(w, r)
		if !ok {
			return
		}
		res, err := s.responseAuth.SetApprovalRows(r.Context(), in)
		if err != nil {
			s.audit(r, "APPROVAL_RULES_REFUSED", "approval-rules", err.Error())
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		if len(res.Looser) > 0 {
			s.audit(r, "APPROVAL_RULES_LOOSENED", "approval-rules", "owner-approved rules save (approval "+in.ApprovalID+")")
		}
		writeJSON(w, http.StatusOK, res)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleRelayApprovalRulesChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	in, ok := decodeRowsInput(w, r)
	if !ok {
		return
	}
	in.ApprovalID = ""
	ask, err := s.responseAuth.AskApprovalRows(r.Context(), in)
	if err != nil {
		writeJSONError(w, approvalStatus(err), err.Error())
		return
	}
	if ask.Approval != nil {
		s.approvalWake.notify()
		s.audit(r, "OWNER_APPROVAL_REQUESTED", "approval-rules", ask.Approval.Action+" (approval "+ask.Approval.ID+"): "+ask.Approval.Summary)
		// The full view, statement and signature included, as the approvals
		// relay sends it: Nightshift's root checks the signed rows.
		writeJSON(w, http.StatusOK, map[string]interface{}{"approval": ask.Approval, "looser": ask.Looser})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"looser": ask.Looser})
}

func decodeRowsInput(w http.ResponseWriter, r *http.Request) (*responseauth.ApprovalRowsInput, bool) {
	var in responseauth.ApprovalRowsInput
	dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rules: "+err.Error())
		return nil, false
	}
	in.TenantID = "default"
	return &in, true
}

// approvalFacts reads the targets' latest trust reports for the authority's
// row choice: each one's clock offset and whether a lock is set on the host
// (a host authority, or a lock level below respond).
func (s *Server) approvalFacts(targets []string) *responseauth.ApprovalFacts {
	f := &responseauth.ApprovalFacts{UTCOffsets: map[string]int{}}
	s.trust.mu.Lock()
	s.trust.init()
	for _, id := range targets {
		seen, ok := s.trust.reports[id]
		if !ok {
			continue
		}
		if seen.report.UTCOffset != nil {
			f.UTCOffsets[id] = *seen.report.UTCOffset
		}
		switch {
		case seen.report.HostAuthority:
			f.Locked = append(f.Locked, id)
		case seen.report.Ceiling != "" && seen.report.Ceiling != "respond" && seen.report.Ceiling != "engagement":
			f.Locked = append(f.Locked, id)
		}
	}
	s.trust.mu.Unlock()
	return f
}
