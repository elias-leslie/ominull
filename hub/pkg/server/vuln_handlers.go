package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"ominull/hub/pkg/vuln"
)

// handleSoftwareInventory handles reporting and querying endpoint software packages.
func (s *Server) handleSoftwareInventory(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.vulnStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "vulnerability store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		endpointID := r.URL.Query().Get("endpoint_id")
		source := r.URL.Query().Get("source")
		search := r.URL.Query().Get("search")
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50
		if limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		offset := 0
		if offsetStr != "" {
			if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		page, err := s.vulnStore.ListSoftwareInventory(vuln.SoftwareFilter{
			TenantID:   tenantID,
			EndpointID: endpointID,
			Source:     source,
			Search:     search,
			Limit:      limit,
			Offset:     offset,
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to query software inventory: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			EndpointID string                   `json:"endpoint_id"`
			Source     string                   `json:"source,omitempty"`
			Packages   []vuln.InstalledSoftware `json:"packages"`
			Items      []vuln.InstalledSoftware `json:"items,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EndpointID == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid software payload: endpoint_id is required")
			return
		}

		packages := req.Packages
		if len(packages) == 0 && len(req.Items) > 0 {
			packages = req.Items
		}

		var err error
		if req.Source != "" {
			err = s.vulnStore.ReplaceSoftwareInventoryBySource(tenantID, req.EndpointID, req.Source, packages)
		} else {
			err = s.vulnStore.ReplaceSoftwareInventory(tenantID, req.EndpointID, packages)
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to save software inventory: "+err.Error())
			return
		}

		// Automatically correlate against active CVE catalog
		matches, _ := s.vulnStore.CorrelateEndpoint(tenantID, req.EndpointID)
		if len(matches) > 0 {
			s.audit(r, "VULNERABILITIES_CORRELATED", req.EndpointID, fmt.Sprintf("Identified %d CVE matches on %s", len(matches), req.EndpointID))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"endpoint_id": req.EndpointID,
			"source":      req.Source,
			"recorded":    len(packages),
			"matches":     len(matches),
		})
		return
	}

	if r.Method == http.MethodDelete {
		endpointID := r.URL.Query().Get("endpoint_id")
		if endpointID == "" {
			writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
			return
		}
		if err := s.vulnStore.DeleteSoftwareInventory(tenantID, endpointID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to delete software inventory: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "deleted",
			"endpoint_id": endpointID,
		})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleVulnerabilities handles querying and syncing the CVE catalog.
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.vulnStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "vulnerability store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		endpointID := r.URL.Query().Get("endpoint_id")
		matches, err := s.vulnStore.ListMatches(tenantID, endpointID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerabilities: "+err.Error())
			return
		}
		if matches == nil {
			matches = []*vuln.VulnerabilityMatch{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vulnerabilities": matches,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Vulnerabilities []vuln.Vulnerability `json:"vulnerabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid cve payload: "+err.Error())
			return
		}

		if err := s.vulnStore.IngestVulnerabilities(req.Vulnerabilities); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to ingest CVEs: "+err.Error())
			return
		}

		s.audit(r, "CVE_FEED_SYNCED", "system", fmt.Sprintf("Ingested %d CVE records", len(req.Vulnerabilities)))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"synced": len(req.Vulnerabilities),
		})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}
