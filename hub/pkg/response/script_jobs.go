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
