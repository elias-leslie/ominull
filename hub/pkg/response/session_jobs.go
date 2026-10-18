package response

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Terminal and screen session jobs carry an offer: the agent starts the
// session worker and posts no result, because the session itself (the relay)
// is the work. The hub ends the job when the session ends.

// OpenSessionJob is a session job that has not ended, with its session id.
type OpenSessionJob struct {
	JobID       string
	TenantID    string
	EndpointID  string
	Kind        ActionKind
	State       JobState
	SessionID   string
	RequestedAt time.Time
}

// OpenSessionJobs lists terminal and screen session jobs that have not ended.
func (s *Store) OpenSessionJobs() ([]OpenSessionJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT id, tenant_id, endpoint_id, kind, state, request_json, requested_at
		FROM response_jobs
		WHERE kind IN (?, ?) AND state NOT IN (?, ?, ?)
		ORDER BY requested_at`,
		string(ActionKindTerminalSession), string(ActionKindScreenSession),
		string(StateSucceeded), string(StateFailed), string(StateCancelled))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenSessionJob
	for rows.Next() {
		var j OpenSessionJob
		var kind, state, req string
		if err := rows.Scan(&j.JobID, &j.TenantID, &j.EndpointID, &kind, &state, &req, &j.RequestedAt); err != nil {
			return nil, err
		}
		j.Kind, j.State = ActionKind(kind), JobState(state)
		var wrapped struct {
			Payload string `json:"payload"`
		}
		var payload struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal([]byte(req), &wrapped) == nil && json.Unmarshal([]byte(wrapped.Payload), &payload) == nil {
			j.SessionID = payload.SessionID
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// EndSessionJob ends a session job because its session ended: one no agent
// took is cancelled (its offer is withdrawn); a taken one succeeds, or fails
// with errorCode when the session did not end cleanly. detail is kept as the
// job's result and in its history.
func (s *Store) EndSessionJob(jobID string, errorCode, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tenant, endpoint, state, grantID, kind string
	err := s.db.QueryRow(`SELECT tenant_id, endpoint_id, state, authorization_grant_id, kind FROM response_jobs WHERE id = ?`, jobID).
		Scan(&tenant, &endpoint, &state, &grantID, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobNotFound
	}
	if err != nil {
		return err
	}
	if kind != string(ActionKindTerminalSession) && kind != string(ActionKindScreenSession) {
		return errors.New("not a session job")
	}
	from := JobState(state)
	to := StateSucceeded
	switch {
	case from == StateQueued || from == StateOffered:
		to = StateCancelled
	case errorCode != "":
		to = StateFailed
	}
	if from == to || !IsValidTransition(from, to) {
		return nil
	}
	now := time.Now().UTC()
	result, _ := json.Marshal(map[string]string{"session": detail})
	if _, err := s.db.Exec(`UPDATE response_jobs SET state = ?, completed_at = ?, updated_at = ?, result_json = ?, error_code = ? WHERE id = ?`,
		string(to), now, now, string(result), errorCode, jobID); err != nil {
		return err
	}
	_ = s.recordAudit(tenant, endpoint, jobID, grantID, from, to, "hub", detail)
	return nil
}
