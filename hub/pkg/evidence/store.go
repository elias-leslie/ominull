package evidence

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrTenantMismatch = errors.New("tenant mismatch")
	ErrQuotaExceeded  = errors.New("evidence storage quota exceeded")
	ErrRangeOverlap   = errors.New("chunk byte range overlaps existing chunk")
	ErrInvalidRange   = errors.New("invalid chunk range")
)

// Store manages evidence bundle metadata in SQLite and encrypted objects on disk.
type Store struct {
	mu                  sync.Mutex
	db                  *sql.DB
	storageDir          string
	masterKey           *MasterKey
	maxTenantQuotaBytes int64 // Maximum allowed bytes per tenant (0 = unlimited)
	receiptKey          ed25519.PrivateKey
	receiptPubKey       ed25519.PublicKey
}

// NewStore initializes an evidence store with quota management and atomic object writes.
func NewStore(db *sql.DB, storageDir string, masterKey *MasterKey) (*Store, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}
	if masterKey == nil {
		return nil, errors.New("nil masterKey")
	}
	if storageDir == "" {
		storageDir = "/var/lib/ominull/evidence"
	}

	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create evidence storage dir: %w", err)
	}

	receiptKeyPath := filepath.Join(storageDir, "receipt.key")
	receiptKey, receiptPubKey, err := LoadOrCreateReceiptKey(receiptKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/create receipt key: %w", err)
	}

	s := &Store{
		db:                  db,
		storageDir:          storageDir,
		masterKey:           masterKey,
		maxTenantQuotaBytes: 10 * 1024 * 1024 * 1024, // 10 GB default per tenant
		receiptKey:          receiptKey,
		receiptPubKey:       receiptPubKey,
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("evidence migration failed: %w", err)
	}
	return s, nil
}

// ReceiptPublicKey returns the hub's Ed25519 public key used for signing receipts.
func (s *Store) ReceiptPublicKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receiptPubKey
}

// ReceiptPublicKeyHex returns the hex-encoded hub Ed25519 public key.
func (s *Store) ReceiptPublicKeyHex() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hex.EncodeToString(s.receiptPubKey)
}

// SetTenantQuota overrides the per-tenant maximum storage quota.
func (s *Store) SetTenantQuota(maxBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxTenantQuotaBytes = maxBytes
}

func (s *Store) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS evidence_bundles (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		job_id TEXT NOT NULL,
		profile TEXT NOT NULL,
		status TEXT NOT NULL,
		total_bytes INTEGER DEFAULT 0,
		item_count INTEGER DEFAULT 0,
		legal_hold INTEGER DEFAULT 0,
		legal_hold_actor TEXT DEFAULT '',
		legal_hold_reason TEXT DEFAULT '',
		retention_expires_at TIMESTAMP NOT NULL,
		manifest_sha256 TEXT,
		receipt_sha256 TEXT,
		created_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_evidence_bundles_tenant ON evidence_bundles(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_evidence_bundles_endpoint ON evidence_bundles(endpoint_id);

	CREATE TABLE IF NOT EXISTS evidence_items (
		id TEXT PRIMARY KEY,
		bundle_id TEXT NOT NULL,
		name TEXT NOT NULL,
		content_type TEXT NOT NULL,
		size_bytes INTEGER NOT NULL,
		received_bytes INTEGER DEFAULT 0,
		sha256 TEXT NOT NULL,
		collector_status TEXT NOT NULL,
		storage_digest TEXT NOT NULL,
		encrypted_key TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_evidence_items_bundle ON evidence_items(bundle_id);

	CREATE TABLE IF NOT EXISTS evidence_chunks (
		item_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		offset INTEGER NOT NULL,
		length INTEGER NOT NULL,
		sha256 TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		PRIMARY KEY(item_id, chunk_index)
	);
	CREATE INDEX IF NOT EXISTS idx_evidence_chunks_item ON evidence_chunks(item_id);

	CREATE TABLE IF NOT EXISTS evidence_receipts (
		receipt_id TEXT PRIMARY KEY,
		bundle_id TEXT NOT NULL UNIQUE,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		manifest_sha256 TEXT NOT NULL,
		storage_objects_sha256 TEXT NOT NULL,
		previous_receipt_sha256 TEXT NOT NULL,
		ingested_at TIMESTAMP NOT NULL,
		receipt_hash TEXT NOT NULL,
		receipt_signature TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_evidence_receipts_tenant ON evidence_receipts(tenant_id);
	`
	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec("ALTER TABLE evidence_bundles ADD COLUMN manifest_raw TEXT DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE evidence_receipts ADD COLUMN receipt_signature TEXT DEFAULT ''")
	return nil
}

// checkQuotaAndDisk verifies that the tenant has sufficient storage quota and disk free space.
func (s *Store) checkQuotaAndDisk(tenantID string, incomingBytes int64) error {
	// 1. Tenant quota check
	if s.maxTenantQuotaBytes > 0 {
		var currentUsage int64
		err := s.db.QueryRow(`
			SELECT COALESCE(SUM(total_bytes), 0) FROM evidence_bundles WHERE tenant_id = ?
		`, tenantID).Scan(&currentUsage)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to query tenant storage usage: %w", err)
		}
		if currentUsage+incomingBytes > s.maxTenantQuotaBytes {
			return fmt.Errorf("%w: tenant %s used %d bytes, requested %d bytes, quota %d bytes",
				ErrQuotaExceeded, tenantID, currentUsage, incomingBytes, s.maxTenantQuotaBytes)
		}
	}

	// 2. Server filesystem free space check
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.storageDir, &stat); err == nil {
		freeBytes := int64(stat.Bavail) * int64(stat.Bsize)
		// Require at least 50MB free disk space headroom
		if freeBytes-incomingBytes < 50*1024*1024 {
			return errors.New("insufficient server disk space for evidence storage")
		}
	}

	return nil
}

// writeObjectAtomic writes encrypted bytes to an object file using temporary files, fsync, and atomic rename.
func (s *Store) writeObjectAtomic(digest string, data []byte) error {
	finalPath := filepath.Join(s.storageDir, digest)

	// Idempotent write check: if object already exists, check size
	if info, err := os.Lstat(finalPath); err == nil {
		if info.Size() == int64(len(data)) {
			return nil
		}
		return fmt.Errorf("object exists but size mismatch for digest %s", digest)
	}

	prefix := digest
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	tmpFile, err := os.CreateTemp(s.storageDir, "tmp_obj_"+prefix+"_*")
	if err != nil {
		return fmt.Errorf("failed to create temp evidence file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write evidence payload: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("fsync failed on temp evidence file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close failed on temp evidence file: %w", err)
	}

	// Guard against symlink replacement at finalPath
	if targetInfo, err := os.Lstat(finalPath); err == nil {
		if targetInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination %s is a symlink", finalPath)
		}
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	return nil
}

// CreateBundle creates a new evidence collection bundle record.
func (s *Store) CreateBundle(tenantID, endpointID, jobID, profile string, retentionTTL time.Duration) (*EvidenceBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if retentionTTL == 0 {
		retentionTTL = 30 * 24 * time.Hour // default 30 days
	}
	now := time.Now().UTC()

	bundle := &EvidenceBundle{
		ID:                 uuid.New().String(),
		TenantID:           tenantID,
		EndpointID:         endpointID,
		JobID:              jobID,
		Profile:            profile,
		Status:             BundleStatusCollecting,
		TotalBytes:         0,
		ItemCount:          0,
		LegalHold:          false,
		RetentionExpiresAt: now.Add(retentionTTL),
		CreatedAt:          now,
	}

	_, err := s.db.Exec(`
		INSERT INTO evidence_bundles (
			id, tenant_id, endpoint_id, job_id, profile, status,
			total_bytes, item_count, legal_hold, retention_expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, bundle.ID, bundle.TenantID, bundle.EndpointID, bundle.JobID, bundle.Profile, string(bundle.Status),
		bundle.TotalBytes, bundle.ItemCount, 0, bundle.RetentionExpiresAt, bundle.CreatedAt)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// CreateItem registers an evidence item for chunked or direct upload.
func (s *Store) CreateItem(tenantID, bundleID, name, contentType string, expectedSize int64, collectorStatus string) (*EvidenceItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify bundle ownership
	var bundleTenantID string
	err := s.db.QueryRow(`SELECT tenant_id FROM evidence_bundles WHERE id = ?`, bundleID).Scan(&bundleTenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if bundleTenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	// Validate artifact name (prevent path traversal)
	cleanName := filepath.Clean(name)
	if strings.Contains(cleanName, "..") || filepath.IsAbs(cleanName) || cleanName == "." || cleanName == "" {
		return nil, fmt.Errorf("invalid artifact name: %q", name)
	}

	// Check quota
	if err := s.checkQuotaAndDisk(tenantID, expectedSize); err != nil {
		return nil, err
	}

	itemID := uuid.New().String()
	now := time.Now().UTC()
	item := &EvidenceItem{
		ID:              itemID,
		BundleID:        bundleID,
		Name:            cleanName,
		ContentType:     contentType,
		SizeBytes:       expectedSize,
		ReceivedBytes:   0,
		SHA256:          "",
		CollectorStatus: collectorStatus,
		StorageDigest:   "",
		EncryptedKey:    "",
		Status:          "uploading",
		CreatedAt:       now,
	}

	_, err = s.db.Exec(`
		INSERT INTO evidence_items (
			id, bundle_id, name, content_type, size_bytes, received_bytes,
			sha256, collector_status, storage_digest, encrypted_key, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, item.ID, item.BundleID, item.Name, item.ContentType, item.SizeBytes, item.ReceivedBytes,
		item.SHA256, item.CollectorStatus, item.StorageDigest, item.EncryptedKey, item.Status, item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return item, nil
}

// StoreItemChunk writes a chunk of evidence data, verifies range boundaries, detects overlaps,
// and assembles the encrypted object once all chunks are received.
func (s *Store) StoreItemChunk(tenantID, itemID string, chunkIndex int, offset, totalSize int64, chunkData []byte) (*EvidenceItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if offset < 0 || len(chunkData) == 0 || offset+int64(len(chunkData)) > totalSize {
		return nil, fmt.Errorf("%w: offset=%d len=%d total=%d", ErrInvalidRange, offset, len(chunkData), totalSize)
	}

	// Verify item and bundle ownership
	var it EvidenceItem
	var bundleTenantID string
	err := s.db.QueryRow(`
		SELECT i.id, i.bundle_id, i.name, i.content_type, i.size_bytes, i.received_bytes,
		       i.sha256, i.collector_status, i.status, i.created_at, b.tenant_id
		FROM evidence_items i
		JOIN evidence_bundles b ON i.bundle_id = b.id
		WHERE i.id = ?
	`, itemID).Scan(&it.ID, &it.BundleID, &it.Name, &it.ContentType, &it.SizeBytes, &it.ReceivedBytes,
		&it.SHA256, &it.CollectorStatus, &it.Status, &it.CreatedAt, &bundleTenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if bundleTenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	if it.Status == "completed" {
		return &it, nil // already assembled
	}

	chunkSHA := ComputeDigest(chunkData)
	chunkLen := int64(len(chunkData))

	// Check existing chunks for overlaps or idempotent retries
	rows, err := s.db.Query(`
		SELECT chunk_index, offset, length, sha256 FROM evidence_chunks WHERE item_id = ?
	`, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cIdx int
		var cOff, cLen int64
		var cHash string
		if err := rows.Scan(&cIdx, &cOff, &cLen, &cHash); err != nil {
			return nil, err
		}

		if cIdx == chunkIndex {
			if cOff == offset && cLen == chunkLen && cHash == chunkSHA {
				// Idempotent retry
				return &it, nil
			}
			return nil, fmt.Errorf("conflicting chunk %d re-upload", chunkIndex)
		}

		// Check range overlap
		if !(offset+chunkLen <= cOff || offset >= cOff+cLen) {
			return nil, fmt.Errorf("%w: incoming [%d, %d) overlaps with existing chunk [%d, %d)",
				ErrRangeOverlap, offset, offset+chunkLen, cOff, cOff+cLen)
		}
	}

	// Write chunk to staging assembly file
	stagingPath := filepath.Join(s.storageDir, fmt.Sprintf("staging_%s.bin", itemID))
	f, err := os.OpenFile(stagingPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open staging file: %w", err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek staging file failed: %w", err)
	}
	if _, err := f.Write(chunkData); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write staging file failed: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync staging file failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(`
		INSERT INTO evidence_chunks (item_id, chunk_index, offset, length, sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, itemID, chunkIndex, offset, chunkLen, chunkSHA, now)
	if err != nil {
		return nil, err
	}

	newReceived := it.ReceivedBytes + chunkLen
	_, err = s.db.Exec(`UPDATE evidence_items SET received_bytes = ? WHERE id = ?`, newReceived, itemID)
	if err != nil {
		return nil, err
	}
	it.ReceivedBytes = newReceived

	// If all bytes received, assemble, encrypt, and complete item
	if newReceived == totalSize {
		assembledData, err := os.ReadFile(stagingPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read complete staging file: %w", err)
		}
		if int64(len(assembledData)) != totalSize {
			return nil, fmt.Errorf("assembled size mismatch: got %d want %d", len(assembledData), totalSize)
		}

		dataKey, err := GenerateDataKey()
		if err != nil {
			return nil, err
		}
		wrappedKeyHex, err := WrapDataKey(s.masterKey, dataKey)
		if err != nil {
			return nil, err
		}

		aad := CanonicalItemAAD(tenantID, it.BundleID, it.ID, it.Name, 0, totalSize)
		ciphertext, err := EncryptItemData(dataKey, assembledData, aad)
		if err != nil {
			return nil, err
		}

		plainSHA := ComputeDigest(assembledData)
		storageDigest := ComputeDigest(ciphertext)

		if err := s.writeObjectAtomic(storageDigest, ciphertext); err != nil {
			return nil, err
		}

		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		_, err = tx.Exec(`
			UPDATE evidence_items
			SET status = 'completed', sha256 = ?, storage_digest = ?, encrypted_key = ?, completed_at = ?
			WHERE id = ?
		`, plainSHA, storageDigest, wrappedKeyHex, now, itemID)
		if err != nil {
			return nil, err
		}

		_, err = tx.Exec(`
			UPDATE evidence_bundles
			SET total_bytes = total_bytes + ?, item_count = item_count + 1
			WHERE id = ?
		`, totalSize, it.BundleID)
		if err != nil {
			return nil, err
		}

		if err := tx.Commit(); err != nil {
			return nil, err
		}

		_ = os.Remove(stagingPath)
		it.Status = "completed"
		it.SHA256 = plainSHA
		it.StorageDigest = storageDigest
		it.CompletedAt = &now
	}

	return &it, nil
}

// StoreItem writes and encrypts an evidence item into the store in a single bounded atomic operation.
func (s *Store) StoreItem(tenantID, bundleID, name, contentType, collectorStatus string, plaintext []byte) (*EvidenceItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify bundle ownership
	var bundleTenantID string
	err := s.db.QueryRow(`SELECT tenant_id FROM evidence_bundles WHERE id = ?`, bundleID).Scan(&bundleTenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if bundleTenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	// Validate name
	cleanName := filepath.Clean(name)
	if strings.Contains(cleanName, "..") || filepath.IsAbs(cleanName) || cleanName == "." || cleanName == "" {
		return nil, fmt.Errorf("invalid artifact name: %q", name)
	}

	totalSize := int64(len(plaintext))
	if err := s.checkQuotaAndDisk(tenantID, totalSize); err != nil {
		return nil, err
	}

	itemID := uuid.New().String()
	dataKey, err := GenerateDataKey()
	if err != nil {
		return nil, err
	}
	wrappedKeyHex, err := WrapDataKey(s.masterKey, dataKey)
	if err != nil {
		return nil, err
	}

	aad := CanonicalItemAAD(tenantID, bundleID, itemID, cleanName, 0, totalSize)
	ciphertext, err := EncryptItemData(dataKey, plaintext, aad)
	if err != nil {
		return nil, err
	}

	plainSHA := ComputeDigest(plaintext)
	storageDigest := ComputeDigest(ciphertext)

	if err := s.writeObjectAtomic(storageDigest, ciphertext); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	item := &EvidenceItem{
		ID:              itemID,
		BundleID:        bundleID,
		Name:            cleanName,
		ContentType:     contentType,
		SizeBytes:       totalSize,
		ReceivedBytes:   totalSize,
		SHA256:          plainSHA,
		CollectorStatus: collectorStatus,
		StorageDigest:   storageDigest,
		EncryptedKey:    wrappedKeyHex,
		Status:          "completed",
		CreatedAt:       now,
		CompletedAt:     &now,
	}

	_, err = tx.Exec(`
		INSERT INTO evidence_items (
			id, bundle_id, name, content_type, size_bytes, received_bytes,
			sha256, collector_status, storage_digest, encrypted_key, status, created_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, item.ID, item.BundleID, item.Name, item.ContentType, item.SizeBytes, item.ReceivedBytes,
		item.SHA256, item.CollectorStatus, item.StorageDigest, item.EncryptedKey, item.Status, item.CreatedAt, item.CompletedAt)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`
		UPDATE evidence_bundles
		SET total_bytes = total_bytes + ?, item_count = item_count + 1
		WHERE id = ?
	`, item.SizeBytes, bundleID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return item, nil
}

// GetBundle returns a bundle record by ID, ensuring strict tenant scoping.
func (s *Store) GetBundle(tenantID, bundleID string) (*EvidenceBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b EvidenceBundle
	var compAt sql.NullTime
	var manSHA, recSHA sql.NullString
	var hold int

	err := s.db.QueryRow(`
		SELECT id, tenant_id, endpoint_id, job_id, profile, status,
		       total_bytes, item_count, legal_hold, legal_hold_actor, legal_hold_reason,
		       retention_expires_at, manifest_sha256, receipt_sha256, created_at, completed_at
		FROM evidence_bundles WHERE id = ?
	`, bundleID).Scan(
		&b.ID, &b.TenantID, &b.EndpointID, &b.JobID, &b.Profile, &b.Status,
		&b.TotalBytes, &b.ItemCount, &hold, &b.LegalHoldActor, &b.LegalHoldReason,
		&b.RetentionExpiresAt, &manSHA, &recSHA, &b.CreatedAt, &compAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if b.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	b.LegalHold = (hold == 1)
	if compAt.Valid {
		b.CompletedAt = &compAt.Time
	}
	if manSHA.Valid {
		b.ManifestSHA256 = manSHA.String
	}
	if recSHA.Valid {
		b.ReceiptSHA256 = recSHA.String
	}
	return &b, nil
}

// ListBundles lists bundles for a given tenant.
func (s *Store) ListBundles(tenantID string, limit int) ([]*EvidenceBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT id, tenant_id, endpoint_id, job_id, profile, status,
		       total_bytes, item_count, legal_hold, legal_hold_actor, legal_hold_reason,
		       retention_expires_at, manifest_sha256, receipt_sha256, created_at, completed_at
		FROM evidence_bundles
		WHERE tenant_id = ?
		ORDER BY created_at DESC LIMIT ?
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bundles []*EvidenceBundle
	for rows.Next() {
		var b EvidenceBundle
		var compAt sql.NullTime
		var manSHA, recSHA sql.NullString
		var hold int
		if err := rows.Scan(
			&b.ID, &b.TenantID, &b.EndpointID, &b.JobID, &b.Profile, &b.Status,
			&b.TotalBytes, &b.ItemCount, &hold, &b.LegalHoldActor, &b.LegalHoldReason,
			&b.RetentionExpiresAt, &manSHA, &recSHA, &b.CreatedAt, &compAt,
		); err != nil {
			return nil, err
		}
		b.LegalHold = (hold == 1)
		if compAt.Valid {
			b.CompletedAt = &compAt.Time
		}
		if manSHA.Valid {
			b.ManifestSHA256 = manSHA.String
		}
		if recSHA.Valid {
			b.ReceiptSHA256 = recSHA.String
		}
		bundles = append(bundles, &b)
	}

	return bundles, nil
}

// ReadItemData decrypts and returns an evidence item's plaintext payload.
func (s *Store) ReadItemData(tenantID, itemID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var it EvidenceItem
	var bundleTenantID string
	err := s.db.QueryRow(`
		SELECT i.id, i.bundle_id, i.name, i.size_bytes, i.storage_digest, i.encrypted_key, b.tenant_id
		FROM evidence_items i
		JOIN evidence_bundles b ON i.bundle_id = b.id
		WHERE i.id = ?
	`, itemID).Scan(&it.ID, &it.BundleID, &it.Name, &it.SizeBytes, &it.StorageDigest, &it.EncryptedKey, &bundleTenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if bundleTenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	dataKey, err := UnwrapDataKey(s.masterKey, it.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap item data key: %w", err)
	}

	objectPath := filepath.Join(s.storageDir, it.StorageDigest)
	ciphertext, err := os.ReadFile(objectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage object: %w", err)
	}

	aad := CanonicalItemAAD(tenantID, it.BundleID, it.ID, it.Name, 0, it.SizeBytes)
	plaintext, err := DecryptItemData(dataKey, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("item authentication failed: %w", err)
	}

	return plaintext, nil
}

// FinalizeBundle completes a bundle, validates manifest item integrity, and generates a chained signed receipt.
func (s *Store) FinalizeBundle(tenantID, bundleID string, manifest *Manifest, endpointEvidencePubKeyHex string) (*EvidenceReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var bTenantID, endpointID string
	err := s.db.QueryRow(`SELECT tenant_id, endpoint_id FROM evidence_bundles WHERE id = ?`, bundleID).Scan(&bTenantID, &endpointID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if bTenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	// 1. Verify endpoint evidence signature if an endpoint evidence signing key is registered
	if endpointEvidencePubKeyHex != "" {
		if err := VerifyManifestSignature(manifest, endpointEvidencePubKeyHex); err != nil {
			return nil, fmt.Errorf("invalid endpoint manifest signature: %w", err)
		}
	}

	manifestBytes := manifest.CanonicalBytes()
	manifestSHA := ComputeDigest(manifestBytes)

	// Verify all manifest items against stored items
	rows, err := s.db.Query(`
		SELECT name, size_bytes, sha256, storage_digest, status
		FROM evidence_items
		WHERE bundle_id = ?
		ORDER BY name ASC
	`, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	storedItems := make(map[string]EvidenceItem)
	var storageDigests []string
	for rows.Next() {
		var it EvidenceItem
		if err := rows.Scan(&it.Name, &it.SizeBytes, &it.SHA256, &it.StorageDigest, &it.Status); err != nil {
			return nil, err
		}
		storedItems[it.Name] = it
		storageDigests = append(storageDigests, it.StorageDigest)
	}

	if len(manifest.Items) != len(storedItems) {
		return nil, fmt.Errorf("manifest item count (%d) mismatch with stored items (%d)",
			len(manifest.Items), len(storedItems))
	}

	for _, mItem := range manifest.Items {
		sItem, exists := storedItems[mItem.Name]
		if !exists {
			return nil, fmt.Errorf("manifest item %s not found in stored items", mItem.Name)
		}
		if sItem.Status != "completed" {
			return nil, fmt.Errorf("item %s upload is not completed", mItem.Name)
		}
		if sItem.SizeBytes != mItem.SizeBytes {
			return nil, fmt.Errorf("item %s size mismatch: manifest=%d stored=%d", mItem.Name, mItem.SizeBytes, sItem.SizeBytes)
		}
		if sItem.SHA256 != mItem.SHA256 {
			return nil, fmt.Errorf("item %s SHA-256 mismatch", mItem.Name)
		}
	}

	digestsBytes, _ := json.Marshal(storageDigests)
	storageSHA := ComputeDigest(digestsBytes)

	// Fetch previous receipt for deterministic chaining
	var prevHash string
	_ = s.db.QueryRow(`
		SELECT receipt_hash FROM evidence_receipts
		WHERE tenant_id = ?
		ORDER BY ingested_at DESC, receipt_id DESC LIMIT 1
	`, tenantID).Scan(&prevHash)
	if prevHash == "" {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()
	receipt := &EvidenceReceipt{
		ReceiptID:             uuid.New().String(),
		BundleID:              bundleID,
		TenantID:              tenantID,
		EndpointID:            endpointID,
		ManifestSHA256:        manifestSHA,
		StorageObjectsSHA256:  storageSHA,
		PreviousReceiptSHA256: prevHash,
		IngestedAt:            now,
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()
	receiptSig := ed25519.Sign(s.receiptKey, receipt.CanonicalBytes())
	receipt.ReceiptSignature = hex.EncodeToString(receiptSig)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO evidence_receipts (
			receipt_id, bundle_id, tenant_id, endpoint_id, manifest_sha256,
			storage_objects_sha256, previous_receipt_sha256, ingested_at, receipt_hash, receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, receipt.ReceiptID, receipt.BundleID, receipt.TenantID, receipt.EndpointID, receipt.ManifestSHA256,
		receipt.StorageObjectsSHA256, receipt.PreviousReceiptSHA256, receipt.IngestedAt, receipt.ReceiptHash, receipt.ReceiptSignature)
	if err != nil {
		return nil, err
	}

	manifestRawBytes, _ := json.Marshal(manifest)
	_, err = tx.Exec(`
		UPDATE evidence_bundles
		SET status = ?, manifest_sha256 = ?, receipt_sha256 = ?, manifest_raw = ?, completed_at = ?
		WHERE id = ?
	`, string(BundleStatusCompleted), manifestSHA, receipt.ReceiptHash, string(manifestRawBytes), now, bundleID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return receipt, nil
}

// SetLegalHold toggles the legal hold status of a bundle with operator auditing.
func (s *Store) SetLegalHold(tenantID, bundleID, actor, reason string, hold bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var bTenantID string
	err := s.db.QueryRow(`SELECT tenant_id FROM evidence_bundles WHERE id = ?`, bundleID).Scan(&bTenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if bTenantID != tenantID {
		return ErrTenantMismatch
	}

	val := 0
	if hold {
		val = 1
	}
	_, err = s.db.Exec(`
		UPDATE evidence_bundles
		SET legal_hold = ?, legal_hold_actor = ?, legal_hold_reason = ?
		WHERE id = ?
	`, val, actor, reason, bundleID)
	return err
}

// ExportBundleToTarGz reads and decrypts all bundle items and streams them to a tar.gz archive.
// The archive includes:
// - bundleID/<sanitized_item_name> (decrypted item contents)
// - bundleID/manifest.json (canonical endpoint manifest if bundle is finalized)
// - bundleID/receipt.json (hub-signed integrity receipt if bundle is finalized)
func (s *Store) ExportBundleToTarGz(tenantID, bundleID string, out io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var bTenantID string
	var manifestRaw sql.NullString
	err := s.db.QueryRow(`SELECT tenant_id, manifest_raw FROM evidence_bundles WHERE id = ?`, bundleID).Scan(&bTenantID, &manifestRaw)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if bTenantID != tenantID {
		return ErrTenantMismatch
	}

	rows, err := s.db.Query(`
		SELECT id, name, content_type, size_bytes, sha256, storage_digest, encrypted_key, created_at
		FROM evidence_items WHERE bundle_id = ? ORDER BY name ASC
	`, bundleID)
	if err != nil {
		return err
	}
	defer rows.Close()

	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	var totalExported int64
	const maxExportBytes = 10 * 1024 * 1024 * 1024 // 10 GB limit

	// 1. Include manifest.json if present
	if manifestRaw.Valid && manifestRaw.String != "" {
		mBytes := []byte(manifestRaw.String)
		hdr := &tar.Header{
			Name:    filepath.Join(bundleID, "manifest.json"),
			Mode:    0600,
			Size:    int64(len(mBytes)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(mBytes); err != nil {
			return err
		}
		totalExported += int64(len(mBytes))
	}

	// 2. Include receipt.json if finalized
	var rec EvidenceReceipt
	err = s.db.QueryRow(`
		SELECT receipt_id, bundle_id, tenant_id, endpoint_id, manifest_sha256,
		       storage_objects_sha256, previous_receipt_sha256, ingested_at, receipt_hash, receipt_signature
		FROM evidence_receipts WHERE bundle_id = ?
	`, bundleID).Scan(&rec.ReceiptID, &rec.BundleID, &rec.TenantID, &rec.EndpointID,
		&rec.ManifestSHA256, &rec.StorageObjectsSHA256, &rec.PreviousReceiptSHA256,
		&rec.IngestedAt, &rec.ReceiptHash, &rec.ReceiptSignature)
	if err == nil {
		recBytes, _ := json.MarshalIndent(rec, "", "  ")
		hdr := &tar.Header{
			Name:    filepath.Join(bundleID, "receipt.json"),
			Mode:    0600,
			Size:    int64(len(recBytes)),
			ModTime: rec.IngestedAt,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(recBytes); err != nil {
			return err
		}
		totalExported += int64(len(recBytes))
	}

	// 3. Stream each decrypted item
	for rows.Next() {
		var it EvidenceItem
		if err := rows.Scan(&it.ID, &it.Name, &it.ContentType, &it.SizeBytes, &it.SHA256, &it.StorageDigest, &it.EncryptedKey, &it.CreatedAt); err != nil {
			return err
		}

		if totalExported+it.SizeBytes > maxExportBytes {
			return fmt.Errorf("%w: export exceeded maximum archive size limit (%d bytes)", ErrQuotaExceeded, maxExportBytes)
		}

		dataKey, err := UnwrapDataKey(s.masterKey, it.EncryptedKey)
		if err != nil {
			return fmt.Errorf("failed to unwrap item key for %s: %w", it.Name, err)
		}

		objectPath := filepath.Join(s.storageDir, it.StorageDigest)
		ciphertext, err := os.ReadFile(objectPath)
		if err != nil {
			return fmt.Errorf("failed to read object %s: %w", it.StorageDigest, err)
		}

		aad := CanonicalItemAAD(tenantID, bundleID, it.ID, it.Name, 0, it.SizeBytes)
		plaintext, err := DecryptItemData(dataKey, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("failed to decrypt item %s: %w", it.Name, err)
		}

		// Safe sanitized filename (basename only, no path traversal)
		safeName := filepath.Base(it.Name)
		hdr := &tar.Header{
			Name:    filepath.Join(bundleID, safeName),
			Mode:    0600,
			Size:    int64(len(plaintext)),
			ModTime: it.CreatedAt,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(plaintext); err != nil {
			return err
		}
		totalExported += int64(len(plaintext))
	}
	return nil
}

// PruneExpiredBundles purges completed bundles that have exceeded their retention period and are not on legal hold.
// Associated unreferenced encrypted storage objects on disk are securely deleted.
func (s *Store) PruneExpiredBundles(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT id, tenant_id FROM evidence_bundles
		WHERE retention_expires_at <= ? AND legal_hold = 0
	`, now)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type expiredBundle struct {
		id       string
		tenantID string
	}
	var expired []expiredBundle
	for rows.Next() {
		var eb expiredBundle
		if err := rows.Scan(&eb.id, &eb.tenantID); err == nil {
			expired = append(expired, eb)
		}
	}
	rows.Close()

	if len(expired) == 0 {
		return 0, nil
	}

	prunedCount := 0
	for _, eb := range expired {
		// Collect storage digests for items in this bundle
		itemRows, err := s.db.Query(`SELECT storage_digest FROM evidence_items WHERE bundle_id = ?`, eb.id)
		if err != nil {
			continue
		}
		var digests []string
		for itemRows.Next() {
			var d string
			if err := itemRows.Scan(&d); err == nil && d != "" {
				digests = append(digests, d)
			}
		}
		itemRows.Close()

		tx, err := s.db.Begin()
		if err != nil {
			continue
		}

		_, _ = tx.Exec(`DELETE FROM evidence_chunks WHERE item_id IN (SELECT id FROM evidence_items WHERE bundle_id = ?)`, eb.id)
		_, _ = tx.Exec(`DELETE FROM evidence_items WHERE bundle_id = ?`, eb.id)
		_, _ = tx.Exec(`DELETE FROM evidence_receipts WHERE bundle_id = ?`, eb.id)
		_, _ = tx.Exec(`DELETE FROM evidence_bundles WHERE id = ?`, eb.id)

		if err := tx.Commit(); err != nil {
			continue
		}

		// Delete unreferenced files from disk
		for _, d := range digests {
			var refCount int
			_ = s.db.QueryRow(`SELECT count(*) FROM evidence_items WHERE storage_digest = ?`, d).Scan(&refCount)
			if refCount == 0 {
				_ = os.Remove(filepath.Join(s.storageDir, d))
			}
		}

		prunedCount++
	}

	return prunedCount, nil
}
