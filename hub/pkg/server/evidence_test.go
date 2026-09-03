package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ominull/hub/pkg/evidence"
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
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar next failed: %v", err)
	}
	expectedPath := filepath.Join(bundle.ID, "system.txt")
	if hdr.Name != expectedPath {
		t.Fatalf("expected file %s, got %s", expectedPath, hdr.Name)
	}
	content, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("readall failed: %v", err)
	}
	if !bytes.Equal(content, itemData) {
		t.Fatalf("exported content mismatch: %q vs %q", string(content), string(itemData))
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
