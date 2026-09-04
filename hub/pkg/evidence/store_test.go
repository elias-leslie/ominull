package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	epPub, epPriv, _ := ed25519.GenerateKey(rand.Reader)
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
	manifestSig := ed25519.Sign(epPriv, manifest.CanonicalBytes())
	manifest.Signature = hex.EncodeToString(manifestSig)

	receipt, err := store.FinalizeBundle(tenantID, bundle.ID, manifest, hex.EncodeToString(epPub))
	if err != nil {
		t.Fatalf("FinalizeBundle failed: %v", err)
	}
	if receipt.ReceiptHash == "" || receipt.PreviousReceiptSHA256 == "" || receipt.ReceiptSignature == "" {
		t.Fatalf("invalid receipt: %+v", receipt)
	}
	if err := VerifyReceiptSignature(receipt, store.ReceiptPublicKeyHex()); err != nil {
		t.Fatalf("receipt signature verification failed: %v", err)
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

	expectedManifestPath := filepath.Join(bundle.ID, "manifest.json")
	if len(foundFiles[expectedManifestPath]) == 0 {
		t.Fatalf("expected manifest.json in exported archive")
	}

	expectedReceiptPath := filepath.Join(bundle.ID, "receipt.json")
	if len(foundFiles[expectedReceiptPath]) == 0 {
		t.Fatalf("expected receipt.json in exported archive")
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

func TestEvidence_ManifestAndReceiptSignatures(t *testing.T) {
	store, _, cleanup := setupTestStore(t)
	defer cleanup()

	tenantID := "tenant-sig"
	bundle, err := store.CreateBundle(tenantID, "ep-sig-1", "job-sig", "profile", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	payload := []byte("critical volatile memory dump")
	item, err := store.StoreItem(tenantID, bundle.ID, "dump.raw", "application/octet-stream", "collected", payload)
	if err != nil {
		t.Fatalf("StoreItem failed: %v", err)
	}

	epPub, epPriv, _ := ed25519.GenerateKey(rand.Reader)
	epPubHex := hex.EncodeToString(epPub)

	manifest := &Manifest{
		BundleID:    bundle.ID,
		EndpointID:  "ep-sig-1",
		TenantID:    tenantID,
		JobID:       "job-sig",
		Profile:     "profile",
		CollectedAt: time.Now().UTC(),
		Items: []ManifestItem{
			{Name: item.Name, SizeBytes: item.SizeBytes, SHA256: item.SHA256, CollectorStatus: "collected"},
		},
	}

	// 1. Missing signature when key is registered -> fails
	_, err = store.FinalizeBundle(tenantID, bundle.ID, manifest, epPubHex)
	if err == nil {
		t.Fatal("expected error on unsigned manifest")
	}

	// 2. Corrupt / invalid signature -> fails
	manifest.Signature = "deadbeef12345678"
	_, err = store.FinalizeBundle(tenantID, bundle.ID, manifest, epPubHex)
	if err == nil {
		t.Fatal("expected error on invalid signature format")
	}

	// 3. Valid signature from wrong key -> fails
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	manifest.Signature = hex.EncodeToString(ed25519.Sign(roguePriv, manifest.CanonicalBytes()))
	_, err = store.FinalizeBundle(tenantID, bundle.ID, manifest, epPubHex)
	if err == nil {
		t.Fatal("expected error on signature signed with wrong key")
	}

	// 4. Valid signature -> succeeds
	manifest.Signature = hex.EncodeToString(ed25519.Sign(epPriv, manifest.CanonicalBytes()))
	receipt, err := store.FinalizeBundle(tenantID, bundle.ID, manifest, epPubHex)
	if err != nil {
		t.Fatalf("valid FinalizeBundle failed: %v", err)
	}

	// 5. Verify receipt signature against hub receipt key
	if err := VerifyReceiptSignature(receipt, store.ReceiptPublicKeyHex()); err != nil {
		t.Fatalf("receipt signature failed verification: %v", err)
	}

	// 6. Tampered receipt fails verification
	tamperedReceipt := *receipt
	tamperedReceipt.ManifestSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyReceiptSignature(&tamperedReceipt, store.ReceiptPublicKeyHex()); err == nil {
		t.Fatal("expected tampered receipt to fail verification")
	}
}

func TestEvidence_RetentionPruningAndLegalHold(t *testing.T) {
	store, storageDir, cleanup := setupTestStore(t)
	defer cleanup()

	tenantID := "tenant-retention"

	// Bundle 1: Expired (retention period was in the past), legal_hold = false
	b1, err := store.CreateBundle(tenantID, "ep-1", "job-1", "quick", -1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle 1 failed: %v", err)
	}
	item1, err := store.StoreItem(tenantID, b1.ID, "file1.txt", "text/plain", "collected", []byte("file1 content"))
	if err != nil {
		t.Fatalf("StoreItem 1 failed: %v", err)
	}
	obj1Path := filepath.Join(storageDir, item1.StorageDigest)
	if _, err := os.Stat(obj1Path); err != nil {
		t.Fatalf("expected object 1 on disk: %v", err)
	}

	// Bundle 2: Expired, but legal_hold = true
	b2, err := store.CreateBundle(tenantID, "ep-1", "job-2", "quick", -1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle 2 failed: %v", err)
	}
	item2, err := store.StoreItem(tenantID, b2.ID, "file2.txt", "text/plain", "collected", []byte("file2 content"))
	if err != nil {
		t.Fatalf("StoreItem 2 failed: %v", err)
	}
	if err := store.SetLegalHold(tenantID, b2.ID, "sec-officer", "litigation hold", true); err != nil {
		t.Fatalf("SetLegalHold failed: %v", err)
	}
	obj2Path := filepath.Join(storageDir, item2.StorageDigest)

	// Bundle 3: Future retention expiration
	b3, err := store.CreateBundle(tenantID, "ep-1", "job-3", "quick", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateBundle 3 failed: %v", err)
	}
	_, err = store.StoreItem(tenantID, b3.ID, "file3.txt", "text/plain", "collected", []byte("file3 content"))
	if err != nil {
		t.Fatalf("StoreItem 3 failed: %v", err)
	}

	// Run PruneExpiredBundles
	pruned, err := store.PruneExpiredBundles(time.Now().UTC())
	if err != nil {
		t.Fatalf("PruneExpiredBundles failed: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected exactly 1 bundle pruned, got %d", pruned)
	}

	// Verify Bundle 1 is gone from DB and disk
	if _, err := store.GetBundle(tenantID, b1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for b1, got: %v", err)
	}
	if _, err := os.Stat(obj1Path); !os.IsNotExist(err) {
		t.Fatalf("expected object 1 file on disk to be removed")
	}

	// Verify Bundle 2 (legal hold) is preserved
	if b2Got, err := store.GetBundle(tenantID, b2.ID); err != nil || b2Got == nil {
		t.Fatalf("expected b2 to be preserved under legal hold: %v", err)
	}
	if _, err := os.Stat(obj2Path); err != nil {
		t.Fatalf("expected object 2 on disk to be preserved: %v", err)
	}

	// Verify Bundle 3 (unexpired) is preserved
	if b3Got, err := store.GetBundle(tenantID, b3.ID); err != nil || b3Got == nil {
		t.Fatalf("expected b3 to be preserved: %v", err)
	}
}
