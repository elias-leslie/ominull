package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// handleVulnerabilities handles querying and syncing the CVE catalog and correlated matches.
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	// Both the catalog and /sync alias reach this handler.
	if r.Method != http.MethodGet && r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.vulnStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "vulnerability store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		scope := r.URL.Query().Get("scope")
		view := r.URL.Query().Get("view")
		snapshotID := r.URL.Query().Get("snapshot_id")
		catalogParam := r.URL.Query().Get("catalog")

		if scope == "catalog" || view == "catalog" || catalogParam == "true" || snapshotID != "" {
			limit := 50
			if lStr := r.URL.Query().Get("limit"); lStr != "" {
				if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
					limit = parsed
				}
			}
			offset := 0
			if oStr := r.URL.Query().Get("offset"); oStr != "" {
				if parsed, err := strconv.Atoi(oStr); err == nil && parsed >= 0 {
					offset = parsed
				}
			}

			filter := vuln.VulnFilter{
				SnapshotID: snapshotID,
				Search:     r.URL.Query().Get("search"),
				Severity:   r.URL.Query().Get("severity"),
				Limit:      limit,
				Offset:     offset,
			}
			if kevStr := r.URL.Query().Get("is_kev"); kevStr != "" {
				b := (kevStr == "true" || kevStr == "1")
				filter.IsKEV = &b
			}

			vulns, total, err := s.vulnStore.GetVulnerabilitiesForSnapshot(filter)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to query vulnerability catalog: "+err.Error())
				return
			}
			if vulns == nil {
				vulns = []vuln.Vulnerability{}
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"snapshot_id":     snapshotID,
				"vulnerabilities": vulns,
				"total":           total,
				"limit":           limit,
				"offset":          offset,
			})
			return
		}

		endpointID := r.URL.Query().Get("endpoint_id")
		statusParam := vuln.MatchStatus(r.URL.Query().Get("status"))
		matches, err := s.vulnStore.ListMatchesFiltered(tenantID, endpointID, statusParam)
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
			Vulnerabilities []vuln.Vulnerability      `json:"vulnerabilities"`
			CISAKEV         []vuln.CISAKEVItem        `json:"cisa_kev"`
			EPSS            map[string]vuln.EPSSScore `json:"epss"`
			RawNVD          string                    `json:"raw_nvd"`
			RawCISAKEV      string                    `json:"raw_cisa_kev"`
			RawEPSS         string                    `json:"raw_epss"`
			SnapshotID      string                    `json:"snapshot_id"`
			Metadata        string                    `json:"metadata"`
			Activate        *bool                     `json:"activate"`
			Online          bool                      `json:"online"`
			NVDURL          string                    `json:"nvd_url"`
			CISAKEVURL      string                    `json:"cisa_kev_url"`
			EPSSURL         string                    `json:"epss_url"`
			MaxNVDResults   int                       `json:"max_nvd_results"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid cve payload: "+err.Error())
			return
		}

		if req.Online {
			// Request bodies may select the built-in feeds or disable one;
			// custom mirrors require trusted programmatic configuration.
			if (req.NVDURL != "" && req.NVDURL != "disabled" && req.NVDURL != vuln.DefaultNVD20URL) ||
				(req.CISAKEVURL != "" && req.CISAKEVURL != "disabled" && req.CISAKEVURL != vuln.DefaultCISAKEVURL) ||
				(req.EPSSURL != "" && req.EPSSURL != "disabled" && req.EPSSURL != vuln.DefaultEPSSURL) {
				writeJSONError(w, http.StatusBadRequest, "online sync supports only the built-in feed URLs")
				return
			}
			opts := vuln.FeedSyncOptions{
				NVDURL:        req.NVDURL,
				CISAKEVURL:    req.CISAKEVURL,
				EPSSURL:       req.EPSSURL,
				MaxNVDResults: req.MaxNVDResults,
			}
			snap, err := vuln.SyncFeeds(r.Context(), s.vulnStore, opts, req.SnapshotID, req.Metadata)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "online feed sync failed: "+err.Error())
				return
			}
			s.audit(r, "VULN_FEED_SYNCED", snap.ID, fmt.Sprintf("Synced %d CVEs, %d KEVs into snapshot %s", snap.NVDCount, snap.CISAKEVCount, snap.ID))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "synchronized",
				"snapshot_id":    snap.ID,
				"nvd_count":      snap.NVDCount,
				"cisa_kev_count": snap.CISAKEVCount,
				"epss_count":     snap.EPSSCount,
				"activated":      true,
			})
			return
		}

		hasData := len(req.Vulnerabilities) > 0 || len(req.CISAKEV) > 0 || len(req.EPSS) > 0 ||
			req.RawNVD != "" || req.RawCISAKEV != "" || req.RawEPSS != ""

		if !hasData {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "synchronized",
				"synced": 0,
			})
			return
		}

		allVulns := req.Vulnerabilities
		if req.RawNVD != "" {
			parsed, err := vuln.ParseNVD20(strings.NewReader(req.RawNVD))
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to parse raw NVD payload: "+err.Error())
				return
			}
			allVulns = append(allVulns, parsed...)
		}

		allKEVs := req.CISAKEV
		if req.RawCISAKEV != "" {
			parsed, err := vuln.ParseCISAKEV(strings.NewReader(req.RawCISAKEV))
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to parse raw CISA KEV payload: "+err.Error())
				return
			}
			allKEVs = append(allKEVs, parsed...)
		}

		allEPSS := req.EPSS
		if req.RawEPSS != "" {
			parsed, err := vuln.ParseEPSSJSON(strings.NewReader(req.RawEPSS))
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to parse raw EPSS payload: "+err.Error())
				return
			}
			if allEPSS == nil {
				allEPSS = parsed
			} else {
				for k, v := range parsed {
					allEPSS[k] = v
				}
			}
		}

		snapID := req.SnapshotID
		if snapID == "" {
			snapID = fmt.Sprintf("snap-%s", time.Now().UTC().Format("20060102-150405"))
		}
		metadata := req.Metadata
		if metadata == "" {
			metadata = `{"source":"api_upload"}`
		}

		if _, err := s.vulnStore.CreateSnapshot(snapID, metadata); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create snapshot: "+err.Error())
			return
		}

		if err := s.vulnStore.IngestSnapshotData(snapID, allVulns, allKEVs, allEPSS); err != nil {
			_ = s.vulnStore.FailSnapshot(snapID, err.Error())
			writeJSONError(w, http.StatusInternalServerError, "failed to ingest snapshot data: "+err.Error())
			return
		}

		shouldActivate := true
		if req.Activate != nil {
			shouldActivate = *req.Activate
		}

		if shouldActivate {
			if err := s.vulnStore.ActivateSnapshot(snapID); err != nil {
				_ = s.vulnStore.FailSnapshot(snapID, err.Error())
				writeJSONError(w, http.StatusInternalServerError, "failed to activate snapshot: "+err.Error())
				return
			}
		}

		s.audit(r, "CVE_FEED_SYNCED", snapID, fmt.Sprintf("Ingested %d CVEs, %d KEVs into snapshot %s (activated=%v)", len(allVulns), len(allKEVs), snapID, shouldActivate))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "synchronized",
			"synced":         len(allVulns),
			"snapshot_id":    snapID,
			"nvd_count":      len(allVulns),
			"cisa_kev_count": len(allKEVs),
			"epss_count":     len(allEPSS),
			"activated":      shouldActivate,
		})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleVulnerabilitySnapshots handles listing snapshots and retrieving active snapshot metadata.
func (s *Server) handleVulnerabilitySnapshots(w http.ResponseWriter, r *http.Request) {
	if s.vulnStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "vulnerability store not initialized")
		return
	}

	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/vulnerabilities/snapshots")
	path = strings.Trim(path, "/")

	if path == "active" {
		snap, err := s.vulnStore.GetActiveSnapshot()
		if err == vuln.ErrNoActiveSnapshot {
			writeJSONError(w, http.StatusNotFound, "no active vulnerability feed snapshot")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to get active snapshot: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"snapshot": snap,
		})
		return
	}

	snapshots, err := s.vulnStore.ListSnapshots()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list snapshots: "+err.Error())
		return
	}
	if snapshots == nil {
		snapshots = []*vuln.FeedSnapshot{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"snapshots": snapshots,
	})
}
