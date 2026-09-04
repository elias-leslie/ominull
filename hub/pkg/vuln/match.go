package vuln

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CalculatePriorityScore computes a 0.0-100.0 priority score while ensuring all source values remain independent.
func CalculatePriorityScore(cvss float64, isKEV bool, epss float64, severity string, confidence float64) float64 {
	// 1. Base CVSS contributes up to 60.0 points
	score := cvss * 6.0

	// 2. CISA KEV membership adds 25.0 points (active exploitation in the wild)
	if isKEV {
		score += 25.0
	}

	// 3. FIRST EPSS probability adds up to 15.0 points
	if epss > 0.0 {
		score += epss * 15.0
	}

	// 4. Weight by detection confidence (0.50 to 1.0)
	if confidence > 0.0 && confidence < 1.0 {
		score = score * confidence
	}

	if score > 100.0 {
		score = 100.0
	} else if score < 0.0 {
		score = 0.0
	}

	return math.Round(score*10) / 10
}

// CorrelateSoftwareItem evaluates an installed software item against a vulnerability record.
// Returns a match candidate if relevant, or nil if no product overlap exists.
func CorrelateSoftwareItem(sw InstalledSoftware, v Vulnerability, snapshotID string) *VulnerabilityMatch {
	// Try parsing CPEPattern as JSON []CPEMatchCriteria, or raw CPE formatted string
	var criteriaList []CPEMatchCriteria
	if err := json.Unmarshal([]byte(v.CPEPattern), &criteriaList); err != nil || len(criteriaList) == 0 {
		if strings.HasPrefix(v.CPEPattern, "cpe:2.3:") || strings.HasPrefix(v.CPEPattern, "cpe:/") {
			criteriaList = []CPEMatchCriteria{{Criteria: v.CPEPattern}}
		}
	}
	if len(criteriaList) > 0 {
		var notAffectedCandidate *VulnerabilityMatch

		for _, crit := range criteriaList {
			cpe, err := ParseCPE(crit.Criteria)
			if err != nil {
				continue
			}

			prodMatched, prodConf := cpe.MatchesProduct(sw.Vendor, sw.Product)
			if !prodMatched {
				continue
			}

			status, reason, rangeStr := EvaluateVersionRange(sw.Version, crit)

			evidenceObj := VulnerabilityMatchEvidence{
				SoftwareID:        sw.ID,
				Vendor:            sw.Vendor,
				Product:           sw.Product,
				Version:           sw.Version,
				RawVersion:        sw.RawVersion,
				Source:            sw.Source,
				CPE:               crit.Criteria,
				VulnerableRange:   rangeStr,
				VersionComparison: reason,
				SnapshotID:        snapshotID,
			}
			evidenceJSON, _ := json.Marshal(evidenceObj)

			conf := prodConf
			if sw.Confidence == ConfidenceInferred {
				conf *= 0.85
			}

			priority := CalculatePriorityScore(v.CVSS, v.IsKEV, v.EPSS, v.Severity, conf)

			match := &VulnerabilityMatch{
				ID:             uuid.New().String(),
				TenantID:       sw.TenantID,
				EndpointID:     sw.EndpointID,
				SoftwareID:     sw.ID,
				ProductName:    sw.Product,
				Version:        sw.Version,
				CVEID:          v.CVEID,
				Severity:       v.Severity,
				CVSS:           v.CVSS,
				IsKEV:          v.IsKEV,
				EPSS:           v.EPSS,
				PriorityScore:  priority,
				Status:         status,
				Confidence:     conf,
				MatchReason:    reason,
				FeedSnapshotID: snapshotID,
				Evidence:       string(evidenceJSON),
				DetectedAt:     time.Now().UTC(),
			}

			if status == MatchStatusMatched {
				return match
			}

			if status == MatchStatusNotAffected && notAffectedCandidate == nil {
				notAffectedCandidate = match
			}
		}

		if notAffectedCandidate != nil {
			return notAffectedCandidate
		}
	}

	// Fallback to substring matching for legacy CVE definitions
	if v.CPEPattern != "" && strings.Contains(strings.ToLower(sw.Product), strings.ToLower(v.CPEPattern)) {
		conf := 0.80
		if strings.EqualFold(sw.Product, v.CPEPattern) {
			conf = 0.95
		}
		priority := CalculatePriorityScore(v.CVSS, v.IsKEV, v.EPSS, v.Severity, conf)

		evidenceObj := VulnerabilityMatchEvidence{
			SoftwareID:        sw.ID,
			Vendor:            sw.Vendor,
			Product:           sw.Product,
			Version:           sw.Version,
			RawVersion:        sw.RawVersion,
			Source:            sw.Source,
			CPE:               v.CPEPattern,
			VulnerableRange:   "unspecified",
			VersionComparison: fmt.Sprintf("Pattern '%s' matched installed product '%s'", v.CPEPattern, sw.Product),
			SnapshotID:        snapshotID,
		}
		evidenceJSON, _ := json.Marshal(evidenceObj)

		return &VulnerabilityMatch{
			ID:             uuid.New().String(),
			TenantID:       sw.TenantID,
			EndpointID:     sw.EndpointID,
			SoftwareID:     sw.ID,
			ProductName:    sw.Product,
			Version:        sw.Version,
			CVEID:          v.CVEID,
			Severity:       v.Severity,
			CVSS:           v.CVSS,
			IsKEV:          v.IsKEV,
			EPSS:           v.EPSS,
			PriorityScore:  priority,
			Status:         MatchStatusMatched,
			Confidence:     conf,
			MatchReason:    fmt.Sprintf("Installed package '%s' v%s matched CPE pattern '%s'", sw.Product, sw.Version, v.CPEPattern),
			FeedSnapshotID: snapshotID,
			Evidence:       string(evidenceJSON),
			DetectedAt:     time.Now().UTC(),
		}
	}

	return nil
}
