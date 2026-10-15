package server

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"ominull/hub/pkg/evidence"
)

// /console/evidence lists the evidence the hub keeps: collections from hosts
// and sealed terminal recordings, newest first; ?id= is one bundle with its
// chain of custody (manifest hash, signed receipt), what it holds, its legal
// hold and export. The hub renders both; web/evidence.js (built from
// web-src/evidence.ts) applies or releases a hold, and reloads the page while
// the bundle is still arriving.

const evidenceListLimit = 100

var evidenceProfileNames = map[string]string{
	"diagnostic":       "Diagnostic collection",
	"live_volatile":    "Live state collection",
	"ir_standard":      "Full triage collection",
	"terminal_session": "Terminal recording",
}

func evidenceProfileName(profile string) string {
	if name, ok := evidenceProfileNames[profile]; ok {
		return name
	}
	if profile == "" {
		return "Evidence"
	}
	return profile
}

func evidenceStatusLabel(status evidence.BundleStatus) (string, string) {
	switch status {
	case evidence.BundleStatusCollecting:
		return "Still arriving", "info"
	case evidence.BundleStatusCompleted:
		return "Complete", "ok"
	case evidence.BundleStatusPartial:
		return "Partly collected", "warn"
	case evidence.BundleStatusFailed:
		return "Failed", "crit"
	}
	return string(status), "idle"
}

func evidenceItemLabel(status string) (string, string) {
	switch status {
	case "collected":
		return "Collected", "ok"
	case "truncated":
		return "Cut short", "warn"
	case "empty":
		return "Empty", "warn"
	case "permission_denied":
		return "Permission denied", "crit"
	case "failed":
		return "Failed", "crit"
	case "":
		return "Unknown", "idle"
	}
	return status, "idle"
}

type evidenceRow struct {
	ID, Kind, HostID, Host, When, Size string
	Label, Tone                        string
	Items                              int
	Held                               bool
}

type evidenceItemRow struct {
	Name, Label, Tone, Size string
}

type evidenceView struct {
	ID, Kind, HostID, Host, Label, Tone string
	Meta                                []jobMeta
	Held                                bool
	HoldBy, HoldWhy                     string
	Sealed                              bool
	Manifest, Receipt                   string
	Items                               []evidenceItemRow
	ItemsProblem                        string
	JobID                               string
	// Arriving: the agent has not finished sending; the page reloads itself.
	Arriving bool
	// Expiry is when retention deletes the bundle once no hold keeps it.
	Expiry       string
	ExpiryPassed bool
}

type evidencePageBody struct {
	Off      bool
	CanAct   bool
	Rows     []evidenceRow
	Held     int
	Zone     string
	View     *evidenceView
	Gone     string
	Problems []string
}

func (s *Server) handleEvidencePage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.requirePageViewer(w, r)
	if !ok {
		return
	}
	body := s.buildEvidencePage(viewer, r.URL.Query().Get("id"), time.Now())
	data := pageData{Title: "Evidence", Operator: viewer.Email, Role: viewer.Role, Back: "forensics", Body: body}
	if body.View != nil && body.Gone == "" && (body.CanAct || body.View.Arriving) {
		data.Script = "evidence.js"
	}
	s.servePage(w, r, "evidence", data)
}

func (s *Server) buildEvidencePage(viewer accessOperator, bundleID string, now time.Time) evidencePageBody {
	body := evidencePageBody{}
	if !s.responseEnabled || s.evidenceStore == nil {
		body.Off = true
		return body
	}
	body.CanAct = roleAllows(viewer.Role, http.MethodPost)
	loc := s.store.GetDetectionTuning().Location()
	body.Zone = loc.String()
	if body.Zone == "Local" {
		body.Zone = now.In(loc).Format("MST")
	}
	names := map[string]string{}
	if endpoints, err := s.store.ListEndpoints(""); err == nil {
		for _, ep := range endpoints {
			names[ep.ID] = ep.Hostname
		}
	}
	host := func(id string) string {
		if name := names[id]; name != "" {
			return name
		}
		return id
	}
	stamp := func(t time.Time) string { return pageStamp(t, now, loc) }

	if bundleID != "" {
		b, err := s.evidenceStore.GetBundle("default", bundleID)
		if err != nil {
			if errors.Is(err, evidence.ErrNotFound) || errors.Is(err, evidence.ErrTenantMismatch) {
				body.Gone = "No evidence with ID “" + bundleID + "”."
			} else {
				body.Gone = "The evidence could not be read: " + err.Error()
			}
			body.View = &evidenceView{ID: bundleID}
			return body
		}
		body.View = s.buildEvidenceView(b, host(b.EndpointID), stamp, now)
		return body
	}

	bundles, err := s.evidenceStore.ListBundles("default", evidenceListLimit)
	if err != nil {
		body.Problems = append(body.Problems, "Evidence could not be read: "+err.Error())
	}
	for _, b := range bundles {
		label, tone := evidenceStatusLabel(b.Status)
		if b.LegalHold {
			body.Held++
		}
		body.Rows = append(body.Rows, evidenceRow{
			ID: b.ID, Kind: evidenceProfileName(b.Profile), HostID: b.EndpointID, Host: host(b.EndpointID),
			When: stamp(b.CreatedAt), Size: humanBytes(b.TotalBytes), Label: label, Tone: tone,
			Items: b.ItemCount, Held: b.LegalHold,
		})
	}
	return body
}

func (s *Server) buildEvidenceView(b *evidence.EvidenceBundle, hostName string, stamp func(time.Time) string, now time.Time) *evidenceView {
	label, tone := evidenceStatusLabel(b.Status)
	v := &evidenceView{
		ID: b.ID, Kind: evidenceProfileName(b.Profile), HostID: b.EndpointID, Host: hostName,
		Label: label, Tone: tone, Held: b.LegalHold, HoldBy: b.LegalHoldActor, HoldWhy: b.LegalHoldReason,
		Manifest: b.ManifestSHA256, Receipt: b.ReceiptSHA256, Sealed: b.ManifestSHA256 != "" && b.ReceiptSHA256 != "",
		JobID: b.JobID, Arriving: b.Status == evidence.BundleStatusCollecting,
	}
	if !b.RetentionExpiresAt.IsZero() {
		v.Expiry = stamp(b.RetentionExpiresAt)
		v.ExpiryPassed = !b.RetentionExpiresAt.After(now)
	}
	add := func(label, value string) {
		if value != "" {
			v.Meta = append(v.Meta, jobMeta{label, value})
		}
	}
	add("Host", hostName)
	add("Kind", v.Kind)
	add("Collected", stamp(b.CreatedAt))
	if b.CompletedAt != nil {
		add("Finished", stamp(*b.CompletedAt))
	}
	add("Size", humanBytes(b.TotalBytes))
	add("Files", strconv.Itoa(b.ItemCount))
	if b.LegalHold {
		add("Kept until", "the hold is released")
	} else {
		add("Kept until", v.Expiry)
	}

	items, err := s.evidenceStore.GetBundleItems("default", b.ID)
	if err != nil {
		v.ItemsProblem = "The file list could not be read: " + err.Error()
	}
	for _, it := range items {
		l, t := evidenceItemLabel(it.CollectorStatus)
		v.Items = append(v.Items, evidenceItemRow{Name: it.Name, Label: l, Tone: t, Size: humanBytes(it.SizeBytes)})
	}
	return v
}

// humanBytes prints a size the way the console does: B, KB, MB, GB.
func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return strconv.FormatFloat(float64(n)/1024, 'f', 1, 64) + " KB"
	case n < 1024*1024*1024:
		return strconv.FormatFloat(float64(n)/(1024*1024), 'f', 1, 64) + " MB"
	}
	return strconv.FormatFloat(float64(n)/(1024*1024*1024), 'f', 1, 64) + " GB"
}
