package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupTestStore(t *testing.T) (*Store, string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "ominull-evid-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tempDir, "evidence.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("sql.Open failed: %v", err)
	}

	keyPath := filepath.Join(tempDir, "evidence.key")
	masterKey, err := LoadOrCreateMasterKey(keyPath)
	if err != nil {
		_ = db.Close()
		_ = os.RemoveAll(tempDir)
		t.Fatalf("LoadOrCreateMasterKey failed: %v", err)
	}

	storageDir := filepath.Join(tempDir, "objects")
	store, err := NewStore(db, storageDir, masterKey)
	if err != nil {
		_ = db.Close()
		_ = os.RemoveAll(tempDir)
		t.Fatalf("NewStore failed: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.RemoveAll(tempDir)
	}

	return store, storageDir, cleanup
}

func TestEvidence_FullLifecycleAndExport(t *testing.T) {
	store, storageDir, cleanup := setupTestStore(t)
	defer cleanup()

	tenantID := "tenant-alpha"
	endpointID := "linux-ep-01"
	jobID := "job-forensic-01"

	// 1. Create Bundle
	bundle, err := store.CreateBundle(tenantID, endpointID, jobID, "diagnostic", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}
	if bundle.Status != BundleStatusCollecting {
		t.Fatalf("expected collecting status, got %s", bundle.Status)
	}

	// 2. Store Items (Encrypted at Rest with Canonical AAD)
	item1Data := []byte(`{"os":"Linux 6.1","hostname":"linux-ep-01","uptime":86400}`)
	item1, err := store.StoreItem(tenantID, bundle.ID, "system_info.json", "application/json", "collected", item1Data)
	if err != nil {
		t.Fatalf("StoreItem 1 failed: %v", err)
	}
	if item1.SizeBytes != int64(len(item1Data)) {
		t.Fatalf("item size mismatch: %d vs %d", item1.SizeBytes, len(item1Data))
	}

	// Verify object on disk is encrypted (not plain text)
	objFile := filepath.Join(storageDir, item1.StorageDigest)
	rawBytes, err := os.ReadFile(objFile)
	if err != nil {
		t.Fatalf("failed to read object file %s: %v", objFile, err)
	}
	if bytes.Contains(rawBytes, []byte("linux-ep-01")) {
		t.Fatalf("evidence object is not encrypted on disk!")
	}

	item2Data := []byte("PID  COMMAND\n1    systemd\n1200 ominulld\n")
	_, err = store.StoreItem(tenantID, bundle.ID, "process_table.txt", "text/plain", "collected", item2Data)
	if err != nil {
		t.Fatalf("StoreItem 2 failed: %v", err)
	}

	// 3. Finalize Bundle with Manifest and Receipt
	manifest := &Manifest{
		BundleID:    bundle.ID,
		EndpointID:  endpointID,
		TenantID:    tenantID,
		JobID:       jobID,
		Profile:     "diagnostic",
		CollectedAt: time.Now().UTC(),
		Items: []ManifestItem{
			{Name: "process_table.txt", SizeBytes: int64(len(item2Data)), SHA256: ComputeDigest(item2Data), CollectorStatus: "collected"},
			{Name: "system_info.json", SizeBytes: int64(len(item1Data)), SHA256: ComputeDigest(item1Data), CollectorStatus: "collected"},
		},
	}

	receipt, err := store.FinalizeBundle(tenantID, bundle.ID, manifest)
	if err != nil {
		t.Fatalf("FinalizeBundle failed: %v", err)
	}
	if receipt.ReceiptHash == "" || receipt.PreviousReceiptSHA256 == "" {
		t.Fatalf("invalid receipt: %+v", receipt)
	}

	// 4. Export to Tar.gz and Verify Safe Path Layout
	var archiveBuf bytes.Buffer
	if err := store.ExportBundleToTarGz(tenantID, bundle.ID, &archiveBuf); err != nil {
		t.Fatalf("ExportBundleToTarGz failed: %v", err)
	}

	gr, err := gzip.NewReader(&archiveBuf)
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	foundFiles := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar reading error: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading tar file %s failed: %v", hdr.Name, err)
		}
		foundFiles[hdr.Name] = content
	}

	expectedSystemPath := filepath.Join(bundle.ID, "system_info.json")
	if !bytes.Equal(foundFiles[expectedSystemPath], item1Data) {
		t.Fatalf("extracted system_info.json content mismatch")
	}
}

func TestEvidence_ChunkedUploadAndResume(t *testing.T) {
	store, _, cleanup := setupTestStore(t)
	defer cleanup()

	tenantID := "tenant-beta"
	bundle, err := store.CreateBundle(tenantID, "ep-win-01", "job-100", "full", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	fullPayload := []byte("Chunk0-Payload-AAA|Chunk1-Payload-BBB|Chunk2-Payload-CCC")
	totalSize := int64(len(fullPayload))

	c0 := []byte("Chunk0-Payload-AAA|")
	c1 := []byte("Chunk1-Payload-BBB|")
	c2 := []byte("Chunk2-Payload-CCC")

	// 1. Register Item
	item, err := store.CreateItem(tenantID, bundle.ID, "memory_strings.bin", "application/octet-stream", totalSize, "collected")
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}
	if item.Status != "uploading" {
		t.Fatalf("expected uploading status, got %s", item.Status)
	}

	// 2. Upload Chunk 0
	_, err = store.StoreItemChunk(tenantID, item.ID, 0, 0, totalSize, c0)
	if err != nil {
		t.Fatalf("StoreItemChunk 0 failed: %v", err)
	}

	// 3. Idempotent Retry of Chunk 0 succeeds
	_, err = store.StoreItemChunk(tenantID, item.ID, 0, 0, totalSize, c0)
	if err != nil {
		t.Fatalf("Idempotent retry of Chunk 0 failed: %v", err)
	}

	// 4. Overlapping Range is Rejected
	overlapChunk := []byte("overlap-bad")
	_, err = store.StoreItemChunk(tenantID, item.ID, 1, 5, totalSize, overlapChunk)
	if !errors.Is(err, ErrRangeOverlap) {
		t.Fatalf("expected ErrRangeOverlap, got: %v", err)
	}

	// 5. Out-of-bounds offset rejected
	_, err = store.StoreItemChunk(tenantID, item.ID, 2, totalSize+10, totalSize, c1)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange, got: %v", err)
	}

	// 6. Upload Chunk 1
	offset1 := int64(len(c0))
	_, err = store.StoreItemChunk(tenantID, item.ID, 1, offset1, totalSize, c1)
	if err != nil {
		t.Fatalf("StoreItemChunk 1 failed: %v", err)
	}

	// 7. Upload Chunk 2 (completing upload)
	offset2 := offset1 + int64(len(c1))
	completedItem, err := store.StoreItemChunk(tenantID, item.ID, 2, offset2, totalSize, c2)
	if err != nil {
		t.Fatalf("StoreItemChunk 2 failed: %v", err)
	}
	if completedItem.Status != "completed" {
		t.Fatalf("expected completed status, got %s", completedItem.Status)
	}

	// 8. Decrypt and verify assembled content
	decrypted, err := store.ReadItemData(tenantID, item.ID)
	if err != nil {
		t.Fatalf("ReadItemData failed: %v", err)
	}
	if !bytes.Equal(decrypted, fullPayload) {
		t.Fatalf("assembled payload mismatch: got %q want %q", string(decrypted), string(fullPayload))
	}
}

func TestEvidence_QuotaExceeded(t *testing.T) {
	store, _, cleanup := setupTestStore(t)
	defer cleanup()

	tenantID := "tenant-quota"
	bundle, err := store.CreateBundle(tenantID, "ep-quota", "job-q", "ir", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	// Restrict quota to 50 bytes
	store.SetTenantQuota(50)

	// Small item fits
	_, err = store.StoreItem(tenantID, bundle.ID, "small.txt", "text/plain", "collected", []byte("12345"))
	if err != nil {
		t.Fatalf("small item failed: %v", err)
	}

	// Large item exceeding 50 bytes is rejected
	largeData := make([]byte, 100)
	_, err = store.StoreItem(tenantID, bundle.ID, "large.txt", "text/plain", "collected", largeData)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got: %v", err)
	}
}

func TestEvidence_TenantIsolation(t *testing.T) {
	store, _, cleanup := setupTestStore(t)
	defer cleanup()

	// Tenant A creates bundle
	bundleA, err := store.CreateBundle("tenant-A", "ep-A", "job-A", "diag", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle tenant-A failed: %v", err)
	}

	itemA, err := store.StoreItem("tenant-A", bundleA.ID, "fileA.txt", "text/plain", "collected", []byte("secret A"))
	if err != nil {
		t.Fatalf("StoreItem tenant-A failed: %v", err)
	}

	// Tenant B attempts to read Bundle A -> rejected
	_, err = store.GetBundle("tenant-B", bundleA.ID)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch for GetBundle, got: %v", err)
	}

	// Tenant B attempts to read Item A data -> rejected
	_, err = store.ReadItemData("tenant-B", itemA.ID)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch for ReadItemData, got: %v", err)
	}

	// Tenant B attempts to store item in Bundle A -> rejected
	_, err = store.StoreItem("tenant-B", bundleA.ID, "fileB.txt", "text/plain", "collected", []byte("bad"))
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch for StoreItem, got: %v", err)
	}

	// Tenant B attempts to export Bundle A -> rejected
	var buf bytes.Buffer
	err = store.ExportBundleToTarGz("tenant-B", bundleA.ID, &buf)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch for ExportBundleToTarGz, got: %v", err)
	}

	// Tenant B attempts to set legal hold on Bundle A -> rejected
	err = store.SetLegalHold("tenant-B", bundleA.ID, "attacker", "fraud", true)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch for SetLegalHold, got: %v", err)
	}
}
