package vuln

import (
	"time"
)

// MatchStatus describes the verdict of correlating installed software with a CVE.
type MatchStatus string

const (
	MatchStatusMatched          MatchStatus = "matched"
	MatchStatusPossible         MatchStatus = "possible"
	MatchStatusNotAffected      MatchStatus = "not_affected"
	MatchStatusInsufficientData MatchStatus = "insufficient_data"
)

// SoftwareConfidence indicates the certainty/provenance of an inventory record.
type SoftwareConfidence string

const (
	ConfidenceAuthoritative SoftwareConfidence = "authoritative"
	ConfidenceInferred      SoftwareConfidence = "inferred"
)

// InstalledSoftware represents an authoritative or inferred package record reported by an endpoint.
type InstalledSoftware struct {
	ID           string             `json:"id"`
	TenantID     string             `json:"tenant_id"`
	EndpointID   string             `json:"endpoint_id"`
	Source       string             `json:"source"`                 // dpkg, rpm, win_registry, win_package, macos_app
	Vendor       string             `json:"vendor"`                 // Normalized vendor (e.g. "debian", "microsoft", "canonical")
	Product      string             `json:"product"`                // Normalized package/product name
	Version      string             `json:"version"`                // Normalized version string
	Architecture string             `json:"architecture,omitempty"` // e.g. "amd64", "x86_64", "all"
	InstallScope string             `json:"install_scope,omitempty"` // "system", "user"
	Confidence   SoftwareConfidence `json:"confidence"`             // authoritative, inferred
	RawVendor    string             `json:"raw_vendor,omitempty"`   // Raw maintainer / publisher string from system
	RawProduct   string             `json:"raw_product,omitempty"`  // Raw package name or display name
	RawVersion   string             `json:"raw_version,omitempty"`  // Raw version string before normalization
	ObservedAt   time.Time          `json:"observed_at"`
}

// SoftwareFilter provides tenant-scoped querying criteria for installed software.
type SoftwareFilter struct {
	TenantID   string `json:"tenant_id"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Source     string `json:"source,omitempty"`
	Search     string `json:"search,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// SoftwareInventoryPage represents paginated software inventory results.
type SoftwareInventoryPage struct {
	Total    int                 `json:"total"`
	Packages []InstalledSoftware `json:"packages"`
	Limit    int                 `json:"limit"`
	Offset   int                 `json:"offset"`
}

// Vulnerability represents an ingested CVE record from NVD or CISA KEV.
type Vulnerability struct {
	CVEID       string    `json:"cve_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	CVSS        float64   `json:"cvss"`
	IsKEV       bool      `json:"is_kev"`
	EPSS        float64   `json:"epss,omitempty"`
	CPEPattern  string    `json:"cpe_pattern"`
	PublishedAt time.Time `json:"published_at"`
}

// VulnerabilityMatch represents an explainable correlation between installed software and a CVE.
type VulnerabilityMatch struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	EndpointID  string      `json:"endpoint_id"`
	SoftwareID  string      `json:"software_id"`
	ProductName string      `json:"product_name"`
	Version     string      `json:"version"`
	CVEID       string      `json:"cve_id"`
	Severity    string      `json:"severity"`
	IsKEV       bool        `json:"is_kev"`
	Status      MatchStatus `json:"status"`
	Confidence  float64     `json:"confidence"`
	MatchReason string      `json:"match_reason"`
	DetectedAt  time.Time   `json:"detected_at"`
}
