package response

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
