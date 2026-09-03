package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"ominull/hub/pkg/evidence"
)

var safeFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleEvidenceBundles handles bundle listing and creation.
func (s *Server) handleEvidenceBundles(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.evidenceStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		id := r.URL.Query().Get("id")
		if id != "" {
			bundle, err := s.evidenceStore.GetBundle(tenantID, id)
			if err != nil {
				if errors.Is(err, evidence.ErrTenantMismatch) {
					writeJSONError(w, http.StatusForbidden, "forbidden")
					return
				}
				writeJSONError(w, http.StatusNotFound, "bundle not found")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(bundle)
			return
		}

		// List bundles for tenant
		bundles, err := s.evidenceStore.ListBundles(tenantID, 50)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to list bundles: "+err.Error())
			return
		}
		if bundles == nil {
			bundles = []*evidence.EvidenceBundle{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"bundles": bundles,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			EndpointID   string `json:"endpoint_id"`
			JobID        string `json:"job_id"`
			Profile      string `json:"profile"`
			RetentionTTL int    `json:"retention_ttl_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}

		ttl := 30 * 24 * time.Hour
		if req.RetentionTTL > 0 {
			ttl = time.Duration(req.RetentionTTL) * time.Hour
		}

		bundle, err := s.evidenceStore.CreateBundle(tenantID, req.EndpointID, req.JobID, req.Profile, ttl)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create bundle: "+err.Error())
			return
		}

		s.audit(r, "EVIDENCE_BUNDLE_CREATED", bundle.ID, fmt.Sprintf("Created evidence bundle for %s profile %s", req.EndpointID, req.Profile))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(bundle)
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleEvidenceItems handles registering and uploading encrypted artifacts (chunked or single-shot).
func (s *Server) handleEvidenceItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.evidenceStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	// 1. Explicit Item Registration (Action = create)
	action := r.URL.Query().Get("action")
	if action == "create" {
		var req struct {
			BundleID        string `json:"bundle_id"`
			Name            string `json:"name"`
			ContentType     string `json:"content_type"`
			ExpectedSize    int64  `json:"expected_size"`
			CollectorStatus string `json:"collector_status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" || req.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid item registration payload")
			return
		}
		if req.CollectorStatus == "" {
			req.CollectorStatus = "collected"
		}
		if req.ContentType == "" {
			req.ContentType = "application/octet-stream"
		}

		if callerEndpoint := r.Header.Get("X-Device-Endpoint-ID"); callerEndpoint != "" {
			bundle, err := s.evidenceStore.GetBundle(tenantID, req.BundleID)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "bundle not found")
				return
			}
			if bundle.EndpointID != callerEndpoint {
				writeJSONError(w, http.StatusForbidden, "device credential cannot register item for another endpoint")
				return
			}
		}

		item, err := s.evidenceStore.CreateItem(tenantID, req.BundleID, req.Name, req.ContentType, req.ExpectedSize, req.CollectorStatus)
		if err != nil {
			if errors.Is(err, evidence.ErrTenantMismatch) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if errors.Is(err, evidence.ErrQuotaExceeded) {
				writeJSONError(w, http.StatusInsufficientStorage, err.Error())
				return
			}
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(item)
		return
	}

	// 2. Bound incoming upload body to 8MB max chunk size
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024*1024)

	// Check if this is a chunked upload
	chunkIndexStr := r.Header.Get("X-Chunk-Index")
	itemID := r.URL.Query().Get("item_id")

	if chunkIndexStr != "" && itemID != "" {
		chunkIndex, err := strconv.Atoi(chunkIndexStr)
		if err != nil || chunkIndex < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid X-Chunk-Index")
			return
		}
		offset, err := strconv.ParseInt(r.Header.Get("X-Chunk-Offset"), 10, 64)
		if err != nil || offset < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid X-Chunk-Offset")
			return
		}
		totalSize, err := strconv.ParseInt(r.Header.Get("X-Total-Size"), 10, 64)
		if err != nil || totalSize <= 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid X-Total-Size")
			return
		}

		chunkData, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "failed to read chunk data: "+err.Error())
			return
		}

		item, err := s.evidenceStore.StoreItemChunk(tenantID, itemID, chunkIndex, offset, totalSize, chunkData)
		if err != nil {
			if errors.Is(err, evidence.ErrTenantMismatch) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if errors.Is(err, evidence.ErrRangeOverlap) {
				writeJSONError(w, http.StatusConflict, err.Error())
				return
			}
			if errors.Is(err, evidence.ErrQuotaExceeded) {
				writeJSONError(w, http.StatusInsufficientStorage, err.Error())
				return
			}
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(item)
		return
	}

	// 3. Single-shot upload fallback
	bundleID := r.URL.Query().Get("bundle_id")
	name := r.URL.Query().Get("name")
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	collectorStatus := r.URL.Query().Get("status")
	if collectorStatus == "" {
		collectorStatus = "collected"
	}

	if bundleID == "" || name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing bundle_id or name")
		return
	}

	if callerEndpoint := r.Header.Get("X-Device-Endpoint-ID"); callerEndpoint != "" {
		bundle, err := s.evidenceStore.GetBundle(tenantID, bundleID)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "bundle not found")
			return
		}
		if bundle.EndpointID != callerEndpoint {
			writeJSONError(w, http.StatusForbidden, "device credential cannot upload to another endpoint's bundle")
			return
		}
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read body: "+err.Error())
		return
	}

	item, err := s.evidenceStore.StoreItem(tenantID, bundleID, name, contentType, collectorStatus, data)
	if err != nil {
		if errors.Is(err, evidence.ErrTenantMismatch) {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, evidence.ErrQuotaExceeded) {
			writeJSONError(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to store evidence item: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(item)
}

// handleEvidenceFinalize handles bundle completion and receipt generation.
func (s *Server) handleEvidenceFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.evidenceStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	var req struct {
		BundleID string             `json:"bundle_id"`
		Manifest *evidence.Manifest `json:"manifest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" || req.Manifest == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid finalize payload")
		return
	}

	if callerEndpoint := r.Header.Get("X-Device-Endpoint-ID"); callerEndpoint != "" {
		bundle, err := s.evidenceStore.GetBundle(tenantID, req.BundleID)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "bundle not found")
			return
		}
		if bundle.EndpointID != callerEndpoint {
			writeJSONError(w, http.StatusForbidden, "device credential cannot finalize another endpoint's bundle")
			return
		}
	}

	receipt, err := s.evidenceStore.FinalizeBundle(tenantID, req.BundleID, req.Manifest)
	if err != nil {
		if errors.Is(err, evidence.ErrTenantMismatch) {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "failed to finalize bundle: "+err.Error())
		return
	}

	s.audit(r, "EVIDENCE_BUNDLE_FINALIZED", req.BundleID, fmt.Sprintf("Finalized evidence bundle receipt %s", receipt.ReceiptHash))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

// handleEvidenceHold handles toggling legal hold.
func (s *Server) handleEvidenceHold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.evidenceStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	var req struct {
		BundleID string `json:"bundle_id"`
		Hold     bool   `json:"hold"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}

	actor := s.operatorFromRequest(r)
	if actor == "" {
		actor = "operator"
	}
	if req.Reason == "" {
		req.Reason = "Compliance hold update"
	}

	if err := s.evidenceStore.SetLegalHold(tenantID, req.BundleID, actor, req.Reason, req.Hold); err != nil {
		if errors.Is(err, evidence.ErrTenantMismatch) {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to set legal hold: "+err.Error())
		return
	}

	s.audit(r, "EVIDENCE_LEGAL_HOLD_TOGGLED", req.BundleID, fmt.Sprintf("Set legal hold = %v by %s (reason: %s)", req.Hold, actor, req.Reason))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"legal_hold": req.Hold,
		"actor":      actor,
		"reason":     req.Reason,
	})
}

// handleEvidenceExport streams decrypted bundle artifacts as a tar.gz archive.
func (s *Server) handleEvidenceExport(w http.ResponseWriter, r *http.Request) {
	if s.evidenceStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	bundleID := r.URL.Query().Get("id")
	if bundleID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing bundle id")
		return
	}

	bundle, err := s.evidenceStore.GetBundle(tenantID, bundleID)
	if err != nil {
		if errors.Is(err, evidence.ErrTenantMismatch) {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSONError(w, http.StatusNotFound, "bundle not found")
		return
	}

	safeEndpoint := bundle.EndpointID
	if !safeFilenameRe.MatchString(safeEndpoint) {
		safeEndpoint = "endpoint"
	}
	shortBundleID := bundleID
	if len(shortBundleID) > 8 {
		shortBundleID = shortBundleID[:8]
	}

	filename := fmt.Sprintf("evidence_%s_%s.tar.gz", safeEndpoint, shortBundleID)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	if err := s.evidenceStore.ExportBundleToTarGz(tenantID, bundleID, w); err != nil {
		return
	}

	s.audit(r, "EVIDENCE_EXPORTED", bundleID, "Exported evidence archive")
}
