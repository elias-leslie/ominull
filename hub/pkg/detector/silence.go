package detector

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
)

// An agent that stops reporting.
//
// Every detector in this product is downstream of telemetry, so the cheapest
// way to defeat all of them at once is to stop the agent - MITRE tracks that as
// T1562.001. It is also what a rebuilt host, a crashed service, a flat battery
// or a lost route looks like, and all four are worth knowing about. Until now
// the console computed "offline" when somebody happened to be looking at the
// endpoints page, recorded nothing, and alerted on nothing: a host could go
// dark on a Friday and nobody would be told.
//
// The rule is deliberately dull. One finding when a host goes quiet, nothing
// further while it stays quiet, and a recovery note when it comes back which
// re-arms the alert. That is the shape Wazuh has used for agent disconnection
// for years, and the reason it is trusted is that it does not repeat itself.

const (
	// silenceSweepInterval is how often the fleet is checked. The threshold is
	// measured in minutes, so a minute of granularity is enough.
	silenceSweepInterval = 60 * time.Second

	silenceAnomalyType  = "ENDPOINT_SILENT"
	recoveryAnomalyType = "ENDPOINT_RETURNED"
)

// silenceWatch remembers which endpoints have already been reported, so a host
// that stays dark is one finding rather than one a minute.
//
// observed records every endpoint this process has already made a decision
// about. It is what separates "this hub just started and the host was already
// dark" from "the host came back and went dark again": the first must not
// repeat a finding the operator is looking at, and the second is a new event
// that must be reported even though the previous finding is still open.
type silenceWatch struct {
	mu       sync.Mutex
	reported map[string]time.Time
	observed map[string]bool
}

func newSilenceWatch() *silenceWatch {
	return &silenceWatch{reported: make(map[string]time.Time), observed: make(map[string]bool)}
}

// StartSilenceWatch sweeps the fleet until the context is cancelled.
func (e *Engine) StartSilenceWatch(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(silenceSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.SweepSilence(time.Now().UTC())
			}
		}
	}()
}

// SweepSilence raises a finding for every endpoint that has gone quiet, and a
// recovery note for every one that has come back.
func (e *Engine) SweepSilence(now time.Time) {
	cfg := e.settings()
	if !cfg.SilenceOn {
		return
	}

	endpoints, err := e.store.ListEndpoints("")
	if err != nil {
		log.Printf("[-] The silence sweep could not read the endpoint inventory: %v", err)
		return
	}

	threshold := time.Duration(cfg.SilenceAfterMinutes) * time.Minute
	for _, endpoint := range endpoints {
		if !watchableEndpoint(endpoint) {
			continue
		}
		quiet := now.Sub(endpoint.LastSeenAt)
		if quiet > threshold {
			e.reportSilence(endpoint, quiet, threshold, now)
			continue
		}
		e.reportReturn(endpoint, now)
	}
}

// watchableEndpoint excludes the hosts for which silence means nothing.
//
// A retired endpoint is meant to be gone. An endpoint mid-enrolment has never
// reported and is not yet a fleet member; alerting on it would make every
// enrolment code that was generated and not redeemed into an incident. The
// diagnostic endpoints the mTLS probe creates are the same case in miniature.
func watchableEndpoint(endpoint storage.Endpoint) bool {
	if endpoint.Status == "retired" || strings.HasPrefix(endpoint.ID, "diagnostic-") {
		return false
	}
	if endpoint.DriverVersion == "enrolling" {
		return false
	}
	return !endpoint.LastSeenAt.IsZero()
}

func (e *Engine) reportSilence(endpoint storage.Endpoint, quiet, threshold time.Duration, now time.Time) {
	e.silence.mu.Lock()
	_, already := e.silence.reported[endpoint.ID]
	firstSight := !e.silence.observed[endpoint.ID]
	if !already {
		e.silence.reported[endpoint.ID] = now
	}
	e.silence.observed[endpoint.ID] = true
	e.silence.mu.Unlock()
	if already {
		return
	}

	// A hub restart loses the map above, so the database is asked - but only
	// about a host this process has not decided on before. A host that returned
	// and went dark again is a new event, and would otherwise be swallowed by
	// its own still-open previous finding.
	if firstSight {
		open, err := e.store.HasOpenAnomaly(endpoint.ID, silenceAnomalyType)
		if err != nil {
			log.Printf("[-] The silence sweep could not check for an existing finding on %s: %v", endpoint.ID, err)
		}
		if open {
			return
		}
	}

	name := endpointName(endpoint)
	title := fmt.Sprintf("Agent stopped reporting on %s", name)
	description := fmt.Sprintf("%s last reported %s ago, past the %s this hub waits before calling a host silent. Every behavioural detector on this endpoint is blind until it returns, which is what stopping the agent is for; it is also what a rebuilt, crashed or disconnected host looks like.",
		name, quiet.Truncate(time.Minute), threshold)

	anomaly := storage.AnomalyAlert{
		ID:          uuid.New().String(),
		TenantID:    endpoint.TenantID,
		LocationID:  endpoint.LocationID,
		EndpointID:  endpoint.ID,
		Hostname:    endpoint.Hostname,
		AnomalyType: silenceAnomalyType,
		// Impair Defenses: Disable or Modify Tools. A host going quiet is not
		// proof of that, but it is the only reading in which it matters, and
		// the innocent explanations are all cheap to check.
		Technique:   "T1562.001",
		Severity:    "HIGH",
		Title:       title,
		Description: description,
		Details: fmt.Sprintf("Last seen: %s | Silent for: %s | Threshold: %s | OS: %s | Address: %s",
			endpoint.LastSeenAt.UTC().Format(time.RFC3339), quiet.Truncate(time.Minute), threshold, endpoint.OS, endpoint.IP),
		Evidence:  silenceEvidence(endpoint, quiet, threshold),
		Timestamp: now,
	}
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] The silence finding for %s could not be written: %v", endpoint.ID, err)
		return
	}
	log.Printf("[!] ANOMALY ALERT [HIGH]: %s (silent for %s)", title, quiet.Truncate(time.Minute))
}

func (e *Engine) reportReturn(endpoint storage.Endpoint, now time.Time) {
	e.silence.mu.Lock()
	since, wasReported := e.silence.reported[endpoint.ID]
	delete(e.silence.reported, endpoint.ID)
	e.silence.observed[endpoint.ID] = true
	e.silence.mu.Unlock()
	if !wasReported {
		return
	}

	name := endpointName(endpoint)
	anomaly := storage.AnomalyAlert{
		ID:          uuid.New().String(),
		TenantID:    endpoint.TenantID,
		LocationID:  endpoint.LocationID,
		EndpointID:  endpoint.ID,
		Hostname:    endpoint.Hostname,
		AnomalyType: recoveryAnomalyType,
		Severity:    "LOW",
		Title:       fmt.Sprintf("Agent reporting again on %s", name),
		Description: fmt.Sprintf("%s is reporting again after %s of silence. The gap is left in place: what happened on a host while it was not being watched is the question the silence finding was asking.",
			name, now.Sub(since).Truncate(time.Minute)),
		Details:   fmt.Sprintf("Returned: %s | Silent since: %s", now.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339)),
		Timestamp: now,
	}
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] The recovery note for %s could not be written: %v", endpoint.ID, err)
		return
	}
	log.Printf("[*] ANOMALY ALERT [LOW]: %s", anomaly.Title)
}

func endpointName(endpoint storage.Endpoint) string {
	if strings.TrimSpace(endpoint.Hostname) != "" {
		return endpoint.Hostname
	}
	return endpoint.ID
}

func silenceEvidence(endpoint storage.Endpoint, quiet, threshold time.Duration) string {
	return fmt.Sprintf(`{"last_seen_at":%q,"silent_seconds":%d,"threshold_seconds":%d,"os":%q,"role_tag":%q,"is_isolated":%t}`,
		endpoint.LastSeenAt.UTC().Format(time.RFC3339), int64(quiet.Seconds()), int64(threshold.Seconds()),
		endpoint.OS, endpoint.RoleTag, endpoint.IsIsolated)
}
