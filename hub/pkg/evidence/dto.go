package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// BundleStatus represents the ingestion state of an evidence collection.
type BundleStatus string

const (
	BundleStatusCollecting BundleStatus = "collecting"
	BundleStatusCompleted  BundleStatus = "completed"
	BundleStatusPartial    BundleStatus = "partial"
	BundleStatusFailed     BundleStatus = "failed"
)

// EvidenceBundle represents a verified collection package from an endpoint.
type EvidenceBundle struct {
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	EndpointID         string       `json:"endpoint_id"`
	JobID              string       `json:"job_id"`
	Profile            string       `json:"profile"` // diagnostic, live_volatile, ir_standard
	Status             BundleStatus `json:"status"`
	TotalBytes         int64        `json:"total_bytes"`
	ItemCount          int          `json:"item_count"`
	LegalHold          bool         `json:"legal_hold"`
	LegalHoldActor     string       `json:"legal_hold_actor,omitempty"`
	LegalHoldReason    string       `json:"legal_hold_reason,omitempty"`
	RetentionExpiresAt time.Time    `json:"retention_expires_at"`
	ManifestSHA256     string       `json:"manifest_sha256,omitempty"`
	ReceiptSHA256      string       `json:"receipt_sha256,omitempty"`
	CreatedAt          time.Time    `json:"created_at"`
	CompletedAt        *time.Time   `json:"completed_at,omitempty"`
}

// EvidenceItem represents an individual forensic artifact within a bundle.
type EvidenceItem struct {
	ID              string     `json:"id"`
	BundleID        string     `json:"bundle_id"`
	Name            string     `json:"name"` // e.g. "processes.json", "network_sockets.txt"
	ContentType     string     `json:"content_type"`
	SizeBytes       int64      `json:"size_bytes"`
	ReceivedBytes   int64      `json:"received_bytes"`
	SHA256          string     `json:"sha256"`
	CollectorStatus string     `json:"collector_status"` // collected, truncated, empty, failed
	StorageDigest   string     `json:"storage_digest,omitempty"`
	EncryptedKey    string     `json:"-"` // Never expose wrapped data key in normal API responses
	Status          string     `json:"status"` // uploading, completed, failed
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// EvidenceChunk represents an uploaded byte range for an evidence item.
type EvidenceChunk struct {
	ItemID     string    `json:"item_id"`
	ChunkIndex int       `json:"chunk_index"`
	Offset     int64     `json:"offset"`
	Length     int64     `json:"length"`
	SHA256     string    `json:"sha256"`
	CreatedAt  time.Time `json:"created_at"`
}

// EvidenceReceipt is a tamper-evident cryptographic receipt for a finalized evidence bundle.
type EvidenceReceipt struct {
	ReceiptID             string    `json:"receipt_id"`
	BundleID              string    `json:"bundle_id"`
	TenantID              string    `json:"tenant_id"`
	EndpointID            string    `json:"endpoint_id"`
	ManifestSHA256        string    `json:"manifest_sha256"`
	StorageObjectsSHA256  string    `json:"storage_objects_sha256"`
	PreviousReceiptSHA256 string    `json:"previous_receipt_sha256"`
	IngestedAt            time.Time `json:"ingested_at"`
	ReceiptHash           string    `json:"receipt_hash"` // SHA-256 of canonical receipt fields
	ReceiptSignature      string    `json:"receipt_signature,omitempty"`
}

// CanonicalBytes returns deterministic length-prefixed bytes for the receipt.
func (r *EvidenceReceipt) CanonicalBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("OMINULL-RECEIPT-V2\x00")
	writeLPStr(&buf, r.ReceiptID)
	writeLPStr(&buf, r.BundleID)
	writeLPStr(&buf, r.TenantID)
	writeLPStr(&buf, r.EndpointID)
	writeLPStr(&buf, r.ManifestSHA256)
	writeLPStr(&buf, r.StorageObjectsSHA256)
	writeLPStr(&buf, r.PreviousReceiptSHA256)
	_ = binary.Write(&buf, binary.BigEndian, r.IngestedAt.Unix())
	return buf.Bytes()
}

// ComputeReceiptHash computes the SHA-256 hash of the receipt.
func (r *EvidenceReceipt) ComputeReceiptHash() string {
	h := sha256.Sum256(r.CanonicalBytes())
	return hex.EncodeToString(h[:])
}

// Manifest represents the endpoint-signed catalog of collected artifacts.
type Manifest struct {
	BundleID    string         `json:"bundle_id"`
	EndpointID  string         `json:"endpoint_id"`
	TenantID    string         `json:"tenant_id"`
	JobID       string         `json:"job_id"`
	Profile     string         `json:"profile"`
	CollectedAt time.Time      `json:"collected_at"`
	Items       []ManifestItem `json:"items"`
	Signature   string         `json:"signature,omitempty"`
}

// CanonicalBytes returns deterministic length-prefixed bytes of the manifest for signing/verifying.
func (m *Manifest) CanonicalBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("OMINULL-MANIFEST-V2\x00")
	writeLPStr(&buf, m.BundleID)
	writeLPStr(&buf, m.EndpointID)
	writeLPStr(&buf, m.TenantID)
	writeLPStr(&buf, m.JobID)
	writeLPStr(&buf, m.Profile)
	_ = binary.Write(&buf, binary.BigEndian, m.CollectedAt.Unix())
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(m.Items)))
	for _, it := range m.Items {
		writeLPStr(&buf, it.Name)
		_ = binary.Write(&buf, binary.BigEndian, it.SizeBytes)
		writeLPStr(&buf, it.SHA256)
		writeLPStr(&buf, it.CollectorStatus)
	}
	return buf.Bytes()
}

// ManifestItem describes an artifact listed in the manifest.
type ManifestItem struct {
	Name            string `json:"name"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	CollectorStatus string `json:"collector_status"`
}

func writeLPStr(buf *bytes.Buffer, s string) {
	b := []byte(s)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(b)))
	buf.Write(b)
}
