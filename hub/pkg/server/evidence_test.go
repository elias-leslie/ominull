package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/evidence"
	storage "ominull/hub/pkg/storage"
)

func TestServer_EvidenceAPI(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	endpointID := "linux-ep-evidence-1"

	// 1. Create Evidence Bundle
	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": endpointID,
		"job_id":      "job-test-evid-01",
		"profile":     "diagnostic",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create bundle returned %d: %s", w.Code, w.Body.String())
	}

	var bundle evidence.EvidenceBundle
	if err := json.NewDecoder(w.Body).Decode(&bundle); err != nil {
		t.Fatalf("failed to decode bundle: %v", err)
	}

	// 2. Upload Evidence Item (Single-shot)
	itemData := []byte("uname -a: Linux host 6.1.0\nuptime: up 12 days\n")
	itemURL := "/api/v1/evidence/items?bundle_id=" + bundle.ID + "&name=system.txt&status=collected"
	reqItem := httptest.NewRequest(http.MethodPost, itemURL, bytes.NewReader(itemData))
	reqItem.Header.Set("X-API-Key", "test-admin-key-12345")
	reqItem.Header.Set("Content-Type", "text/plain")
	wItem := httptest.NewRecorder()
	handler.ServeHTTP(wItem, reqItem)

	if wItem.Code != http.StatusCreated {
		t.Fatalf("upload item returned %d: %s", wItem.Code, wItem.Body.String())
	}

	// 3. Finalize Bundle
	finalizeBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundle.ID,
		"manifest": evidence.Manifest{
			BundleID:   bundle.ID,
			EndpointID: endpointID,
			TenantID:   "default",
			JobID:      "job-test-evid-01",
			Profile:    "diagnostic",
			Items: []evidence.ManifestItem{
				{Name: "system.txt", SizeBytes: int64(len(itemData)), SHA256: evidence.ComputeDigest(itemData), CollectorStatus: "collected"},
			},
		},
	})
	reqFin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/finalize", bytes.NewReader(finalizeBody))
	reqFin.Header.Set("X-API-Key", "test-admin-key-12345")
	reqFin.Header.Set("Content-Type", "application/json")
	wFin := httptest.NewRecorder()
	handler.ServeHTTP(wFin, reqFin)

	if wFin.Code != http.StatusOK {
		t.Fatalf("finalize returned %d: %s", wFin.Code, wFin.Body.String())
	}

	var receipt evidence.EvidenceReceipt
	if err := json.NewDecoder(wFin.Body).Decode(&receipt); err != nil {
		t.Fatalf("failed to decode receipt: %v", err)
	}
	if receipt.ReceiptHash == "" {
		t.Fatalf("empty receipt hash")
	}

	// 4. Test Legal Hold Toggle
	holdBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundle.ID,
		"hold":      true,
		"reason":    "Subpoena compliance",
	})
	reqHold := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles/hold", bytes.NewReader(holdBody))
	reqHold.Header.Set("X-API-Key", "test-admin-key-12345")
	reqHold.Header.Set("Content-Type", "application/json")
	wHold := httptest.NewRecorder()
	handler.ServeHTTP(wHold, reqHold)

	if wHold.Code != http.StatusOK {
		t.Fatalf("hold returned %d: %s", wHold.Code, wHold.Body.String())
	}

	// 5. Test Export
	reqExport := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/export?id="+bundle.ID, nil)
	reqExport.Header.Set("X-API-Key", "test-admin-key-12345")
	wExport := httptest.NewRecorder()
	handler.ServeHTTP(wExport, reqExport)

	if wExport.Code != http.StatusOK {
		t.Fatalf("export returned %d: %s", wExport.Code, wExport.Body.String())
	}

	gr, err := gzip.NewReader(wExport.Body)
	if err != nil {
		t.Fatalf("gzip reader failed: %v", err)
	}
	tr := tar.NewReader(gr)
	foundFiles := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next failed: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("readall failed: %v", err)
		}
		foundFiles[hdr.Name] = data
	}

	expectedPath := filepath.Join(bundle.ID, "system.txt")
	content, ok := foundFiles[expectedPath]
	if !ok {
		t.Fatalf("expected file %s in archive", expectedPath)
	}
	if !bytes.Equal(content, itemData) {
		t.Fatalf("exported content mismatch: %q vs %q", string(content), string(itemData))
	}
	if len(foundFiles[filepath.Join(bundle.ID, "manifest.json")]) == 0 {
		t.Fatalf("expected manifest.json in archive")
	}
	if len(foundFiles[filepath.Join(bundle.ID, "receipt.json")]) == 0 {
		t.Fatalf("expected receipt.json in archive")
	}
}

func TestServer_EvidenceChunkedUploadAPI(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	endpointID := "chunk-ep-1"

	// 1. Create Bundle
	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": endpointID,
		"job_id":      "job-chunk-01",
		"profile":     "diagnostic",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("bundle creation failed: %s", w.Body.String())
	}
	var bundle evidence.EvidenceBundle
	_ = json.NewDecoder(w.Body).Decode(&bundle)

	// 2. Register Item (Action=create)
	totalSize := int64(30)
	regBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id":     bundle.ID,
		"name":          "memory.dmp",
		"content_type":  "application/octet-stream",
		"expected_size": totalSize,
	})
	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?action=create", bytes.NewReader(regBody))
	reqReg.Header.Set("X-API-Key", "test-admin-key-12345")
	reqReg.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	handler.ServeHTTP(wReg, reqReg)
	if wReg.Code != http.StatusCreated {
		t.Fatalf("item registration failed: %s", wReg.Body.String())
	}
	var item evidence.EvidenceItem
	_ = json.NewDecoder(wReg.Body).Decode(&item)

	// 3. Upload in two 15-byte chunks
	chunk1 := []byte("0123456789abcde")
	chunk2 := []byte("fghijklmno01234")

	reqC1 := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?item_id="+item.ID, bytes.NewReader(chunk1))
	reqC1.Header.Set("X-API-Key", "test-admin-key-12345")
	reqC1.Header.Set("X-Chunk-Index", "0")
	reqC1.Header.Set("X-Chunk-Offset", "0")
	reqC1.Header.Set("X-Total-Size", fmt.Sprintf("%d", totalSize))
	wC1 := httptest.NewRecorder()
	handler.ServeHTTP(wC1, reqC1)
	if wC1.Code != http.StatusOK {
		t.Fatalf("chunk 1 failed: %s", wC1.Body.String())
	}

	reqC2 := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?item_id="+item.ID, bytes.NewReader(chunk2))
	reqC2.Header.Set("X-API-Key", "test-admin-key-12345")
	reqC2.Header.Set("X-Chunk-Index", "1")
	reqC2.Header.Set("X-Chunk-Offset", "15")
	reqC2.Header.Set("X-Total-Size", fmt.Sprintf("%d", totalSize))
	wC2 := httptest.NewRecorder()
	handler.ServeHTTP(wC2, reqC2)
	if wC2.Code != http.StatusOK {
		t.Fatalf("chunk 2 failed: %s", wC2.Body.String())
	}

	var completedItem evidence.EvidenceItem
	_ = json.NewDecoder(wC2.Body).Decode(&completedItem)
	if completedItem.Status != "completed" {
		t.Fatalf("expected completed status, got %s", completedItem.Status)
	}
}

func TestServer_EvidenceTenantScoping(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()

	now := time.Now().UTC()
	_ = srv.store.CreateTenant(storage.Tenant{ID: "tenant-alpha", Name: "Alpha", APIKey: "key-alpha", CreatedAt: now})
	_ = srv.store.CreateTenant(storage.Tenant{ID: "tenant-beta", Name: "Beta", APIKey: "key-beta", CreatedAt: now})

	// 1. Tenant Alpha creates a bundle
	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": "ep-alpha-1",
		"job_id":      "job-alpha-01",
		"profile":     "diagnostic",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "key-alpha")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("bundle creation failed: %s", w.Body.String())
	}
	var bundle evidence.EvidenceBundle
	_ = json.NewDecoder(w.Body).Decode(&bundle)

	// 2. Tenant Beta attempts to get bundle -> 403 Forbidden
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/bundles?id="+bundle.ID, nil)
	reqGet.Header.Set("X-API-Key", "key-beta")
	wGet := httptest.NewRecorder()
	handler.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant bundle get, got %d", wGet.Code)
	}

	// 3. Tenant Beta attempts to upload item to Tenant Alpha bundle -> 403 Forbidden
	itemData := []byte("malicious item")
	reqItem := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?bundle_id="+bundle.ID+"&name=mal.txt&tenant_id=tenant-beta", bytes.NewReader(itemData))
	reqItem.Header.Set("X-API-Key", "test-admin-key-12345")
	wItem := httptest.NewRecorder()
	handler.ServeHTTP(wItem, reqItem)
	if wItem.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant item upload, got %d", wItem.Code)
	}

	// 4. Tenant Beta attempts to finalize Tenant Alpha bundle -> 403 Forbidden
	finBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundle.ID,
		"manifest": evidence.Manifest{
			BundleID: bundle.ID,
			TenantID: "tenant-beta",
		},
	})
	reqFin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/finalize?tenant_id=tenant-beta", bytes.NewReader(finBody))
	reqFin.Header.Set("X-API-Key", "test-admin-key-12345")
	wFin := httptest.NewRecorder()
	handler.ServeHTTP(wFin, reqFin)
	if wFin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant finalize, got %d", wFin.Code)
	}

	// 5. Tenant Beta attempts to toggle hold -> 403 Forbidden
	holdBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundle.ID,
		"hold":      true,
	})
	reqHold := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles/hold?tenant_id=tenant-beta", bytes.NewReader(holdBody))
	reqHold.Header.Set("X-API-Key", "test-admin-key-12345")
	wHold := httptest.NewRecorder()
	handler.ServeHTTP(wHold, reqHold)
	if wHold.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant hold, got %d", wHold.Code)
	}

	// 6. Tenant Beta attempts to export -> 403 Forbidden
	reqExp := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/export?id="+bundle.ID+"&tenant_id=tenant-beta", nil)
	reqExp.Header.Set("X-API-Key", "test-admin-key-12345")
	wExp := httptest.NewRecorder()
	handler.ServeHTTP(wExp, reqExp)
	if wExp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant export, got %d", wExp.Code)
	}
}

func TestServer_EvidenceDeviceCredentialScoping(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()

	now := time.Now().UTC()
	_ = srv.store.CreateTenant(storage.Tenant{ID: "tenant-gamma", Name: "Gamma", APIKey: "key-gamma", CreatedAt: now})

	// Register two endpoints in tenant "tenant-gamma"
	_ = srv.store.UpsertEndpoint(storage.Endpoint{
		ID: "ep-gamma-1", TenantID: "tenant-gamma", Hostname: "host-1", OS: "Linux", IP: "10.0.0.1", Status: "online",
	})
	_ = srv.store.UpsertEndpoint(storage.Endpoint{
		ID: "ep-gamma-2", TenantID: "tenant-gamma", Hostname: "host-2", OS: "Linux", IP: "10.0.0.2", Status: "online",
	})

	cred1, _, err := srv.store.IssueDeviceCredential("ep-gamma-1")
	if err != nil {
		t.Fatalf("IssueDeviceCredential 1 failed: %v", err)
	}
	cred2, _, err := srv.store.IssueDeviceCredential("ep-gamma-2")
	if err != nil {
		t.Fatalf("IssueDeviceCredential 2 failed: %v", err)
	}

	// Create a bundle specifically for ep-gamma-1 in tenant-gamma
	createBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": "ep-gamma-1",
		"job_id":      "job-gamma-01",
		"profile":     "diagnostic",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/bundles", bytes.NewReader(createBody))
	req.Header.Set("X-API-Key", "key-gamma")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("bundle creation failed: %s", w.Body.String())
	}
	var bundle evidence.EvidenceBundle
	_ = json.NewDecoder(w.Body).Decode(&bundle)

	// Device 2 attempts to upload item to ep-gamma-1's bundle -> 403 Forbidden
	badUpload := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?bundle_id="+bundle.ID+"&name=rogue.txt", bytes.NewReader([]byte("data")))
	badUpload.Header.Set("X-Ominull-Device-Credential", cred2)
	wBadUpload := httptest.NewRecorder()
	handler.ServeHTTP(wBadUpload, badUpload)
	if wBadUpload.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-device item upload, got %d", wBadUpload.Code)
	}

	// Device 1 uploads valid item to its own bundle -> 201 Created
	itemData := []byte("ep-1 legitimate telemetry evidence")
	goodUpload := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/items?bundle_id="+bundle.ID+"&name=legit.txt", bytes.NewReader(itemData))
	goodUpload.Header.Set("X-Ominull-Device-Credential", cred1)
	wGoodUpload := httptest.NewRecorder()
	handler.ServeHTTP(wGoodUpload, goodUpload)
	if wGoodUpload.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for device 1 upload, got %d: %s", wGoodUpload.Code, wGoodUpload.Body.String())
	}

	// Device 2 attempts to finalize ep-gamma-1's bundle -> 403 Forbidden
	badFinBody, _ := json.Marshal(map[string]interface{}{
		"bundle_id": bundle.ID,
		"manifest": evidence.Manifest{
			BundleID:   bundle.ID,
			EndpointID: "ep-gamma-1",
			TenantID:   "tenant-gamma",
			JobID:      "job-gamma-01",
			Profile:    "diagnostic",
			Items: []evidence.ManifestItem{
				{Name: "legit.txt", SizeBytes: int64(len(itemData)), SHA256: evidence.ComputeDigest(itemData), CollectorStatus: "collected"},
			},
		},
	})
	badFin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/finalize", bytes.NewReader(badFinBody))
	badFin.Header.Set("X-Ominull-Device-Credential", cred2)
	wBadFin := httptest.NewRecorder()
	handler.ServeHTTP(wBadFin, badFin)
	if wBadFin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-device finalize, got %d", wBadFin.Code)
	}

	// Device 1 finalizes its own bundle -> 200 OK
	goodFin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/finalize", bytes.NewReader(badFinBody))
	goodFin.Header.Set("X-Ominull-Device-Credential", cred1)
	wGoodFin := httptest.NewRecorder()
	handler.ServeHTTP(wGoodFin, goodFin)
	if wGoodFin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for device 1 finalize, got %d: %s", wGoodFin.Code, wGoodFin.Body.String())
	}
}

func TestServer_EvidencePruneAPI(t *testing.T) {
	server, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	handler := server.Handler()

	tenantID := "tenant-prune-test"
	b1, err := server.evidenceStore.CreateBundle(tenantID, "ep-1", "job-1", "quick", -1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle 1 failed: %v", err)
	}
	_, err = server.evidenceStore.StoreItem(tenantID, b1.ID, "prune1.txt", "text/plain", "collected", []byte("prune data"))
	if err != nil {
		t.Fatalf("StoreItem failed: %v", err)
	}

	b2, err := server.evidenceStore.CreateBundle(tenantID, "ep-1", "job-2", "quick", -1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle 2 failed: %v", err)
	}
	if err := server.evidenceStore.SetLegalHold(tenantID, b2.ID, "legal-counsel", "court order", true); err != nil {
		t.Fatalf("SetLegalHold failed: %v", err)
	}

	// 1. Non-admin request -> 401 or 403
	reqNoAdmin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/prune", nil)
	reqNoAdmin.Header.Set("X-API-Key", "invalid-or-non-admin")
	wNoAdmin := httptest.NewRecorder()
	handler.ServeHTTP(wNoAdmin, reqNoAdmin)
	if wNoAdmin.Code != http.StatusUnauthorized && wNoAdmin.Code != http.StatusForbidden {
		t.Fatalf("expected 401 or 403 for unauthorized prune, got %d", wNoAdmin.Code)
	}

	// 2. Admin request -> 200 OK with pruned count 1
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/prune", nil)
	reqAdmin.Header.Set("X-API-Key", "test-admin-key-12345")
	wAdmin := httptest.NewRecorder()
	handler.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin prune, got %d: %s", wAdmin.Code, wAdmin.Body.String())
	}

	var res map[string]interface{}
	if err := json.Unmarshal(wAdmin.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if pruned, ok := res["pruned_bundles"].(float64); !ok || int(pruned) != 1 {
		t.Fatalf("expected 1 pruned bundle, got: %v", res["pruned_bundles"])
	}

	// Verify b1 is deleted
	if _, err := server.evidenceStore.GetBundle(tenantID, b1.ID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("expected b1 to be deleted, got: %v", err)
	}
	// Verify b2 is preserved
	if b2Got, err := server.evidenceStore.GetBundle(tenantID, b2.ID); err != nil || b2Got == nil {
		t.Fatalf("expected b2 to be preserved under legal hold, got: %v", err)
	}
}
