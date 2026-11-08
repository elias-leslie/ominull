package response

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// LatestScriptJobs returns, for one endpoint, the newest script_exec job of
// each script, keyed by script ID. The script ID lives in the signed payload
// kept in request_json ({"grant":...,"payload":"<json>"}).
func (s *Store) LatestScriptJobs(tenantID, endpointID string) (map[string]*JobRecord, error) {
	s.mu.Lock()
	rows, err := s.db.Query(`
		SELECT sid, id FROM (
			SELECT json_extract(json_extract(request_json, '$.payload'), '$.script_id') AS sid, id,
			       ROW_NUMBER() OVER (PARTITION BY json_extract(json_extract(request_json, '$.payload'), '$.script_id')
			                          ORDER BY requested_at DESC) AS rn
			FROM response_jobs
			WHERE tenant_id = ? AND endpoint_id = ? AND kind = ? AND json_valid(request_json)
		) WHERE rn = 1 AND sid IS NOT NULL
	`, tenantID, endpointID, string(ActionKindScriptExec))
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	ids := map[string]string{}
	for rows.Next() {
		var sid, id string
		if err := rows.Scan(&sid, &id); err != nil {
			rows.Close()
			s.mu.Unlock()
			return nil, err
		}
		ids[sid] = id
	}
	err = rows.Err()
	rows.Close()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	out := make(map[string]*JobRecord, len(ids))
	for sid, id := range ids {
		job, err := s.GetJob(tenantID, id)
		if err != nil {
			return nil, err
		}
		out[sid] = job
	}
	return out, nil
}

// ScriptJobs returns one endpoint's newest script_exec jobs of one script,
// newest first.
func (s *Store) ScriptJobs(tenantID, endpointID, scriptID string, limit int) ([]*JobRecord, error) {
	s.mu.Lock()
	rows, err := s.db.Query(`
		SELECT id FROM response_jobs
		WHERE tenant_id = ? AND endpoint_id = ? AND kind = ? AND json_valid(request_json)
		  AND json_extract(json_extract(request_json, '$.payload'), '$.script_id') = ?
		ORDER BY requested_at DESC LIMIT ?
	`, tenantID, endpointID, string(ActionKindScriptExec), scriptID, limit)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.mu.Unlock()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := make([]*JobRecord, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetJob(tenantID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, nil
}

// RecordFinishedScriptJob stores a package run that happened outside the hub
// (root access to a machine that takes no hub-signed scripts) as an ordinary
// finished job, so the run records stay the one place results live. It carries
// no grant: nothing here was authorized by the hub or offered to an agent.
func (s *Store) RecordFinishedScriptJob(tenantID, endpointID, requestedBy, payloadJSON string, result *JobResult) (*JobRecord, error) {
	if tenantID == "" || endpointID == "" || result == nil {
		return nil, errors.New("missing required job fields")
	}
	state := StateSucceeded
	if result.ExitCode != 0 || result.ErrorCode != "" {
		state = StateFailed
	}
	result.State = state
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	request, err := json.Marshal(map[string]string{"payload": payloadJSON})
	if err != nil {
		return nil, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	job := &JobRecord{
		ID: uuid.New().String(), TenantID: tenantID, EndpointID: endpointID, Kind: ActionKindScriptExec,
		RequestedBy: requestedBy, RequestedAt: now, State: state, StartedAt: &now, CompletedAt: &now,
		RequestJSON: string(request), ResultJSON: string(resultJSON), ErrorCode: result.ErrorCode, CreatedAt: now, UpdatedAt: now,
	}
	_, err = s.db.Exec(`
		INSERT INTO response_jobs (
			id, tenant_id, endpoint_id, kind, requested_by, requested_at, state, started_at, completed_at,
			attempt, authorization_grant_id, request_json, result_json, error_code, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?, ?)
	`, job.ID, job.TenantID, job.EndpointID, string(job.Kind), job.RequestedBy, now, string(state), now, now,
		job.RequestJSON, job.ResultJSON, job.ErrorCode, now, now)
	if err != nil {
		return nil, err
	}
	_ = s.recordAudit(tenantID, endpointID, job.ID, "", "", state, requestedBy, "recorded from a run on the machine itself")
	return job, nil
}
