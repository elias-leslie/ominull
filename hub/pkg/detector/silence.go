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
	// dark records which reported hosts were reported as a dark sensor.
	dark map[string]bool
}

func newSilenceWatch() *silenceWatch {
	return &silenceWatch{reported: make(map[string]time.Time), observed: make(map[string]bool), dark: make(map[string]bool)}
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
	// Silence is part of the floor (DetectionTuning.normalised): no setting
	// switches this sweep off.
	cfg := e.settings()

	endpoints, err := e.store.ListEndpoints("")
	if err != nil {
		log.Printf("[-] The silence sweep could not read the endpoint inventory: %v", err)
		return
	}

	fleet, err := e.store.AicoFleet()
	if err != nil {
		log.Printf("[-] The silence sweep could not read Aico's machine view: %v", err)
	}
	newest := storage.NewestEndpoints(endpoints)
	for _, endpoint := range endpoints {
		view := fleet
		if newest[storage.ShortHost(endpoint.Hostname)] != endpoint.ID {
			view = storage.AicoFleet{}
		}
		e.sweepEndpoint(endpoint, cfg, view, now)
	}
}

func (e *Engine) sweepEndpoint(endpoint storage.Endpoint, cfg storage.DetectionTuning, fleet storage.AicoFleet, now time.Time) {
	quiet, threshold, dark, watched := silentFor(endpoint, cfg, fleet, now)
	switch {
	case !watched:
		e.reportUnwatched(endpoint, now)
	case quiet > threshold:
		e.reportSilence(endpoint, now.Sub(endpoint.LastSeenAt), threshold, dark, now)
	case now.Sub(endpoint.LastSeenAt) <= threshold:
		// A machine just up has its grace; its agent has not come back yet.
		e.reportReturn(endpoint, now)
	}
}

// silentFor is how long an endpoint has been quiet and how long it may be;
// watched is false for a host whose silence means nothing. Aico says whether
// the machine is meant to be running: off, the agent's silence means nothing
// (Aico itself tells the owner if the machine should be on); up, it means the
// sensor is dark, counted from when the machine came up. A host Aico cannot
// speak for keeps its stored presence.
func silentFor(endpoint storage.Endpoint, cfg storage.DetectionTuning, fleet storage.AicoFleet, now time.Time) (quiet, threshold time.Duration, dark, watched bool) {
	if !watchableEndpoint(endpoint) {
		return 0, 0, false, false
	}
	base := time.Duration(cfg.SilenceAfterMinutes) * time.Minute
	switch m, word := fleet.Word(endpoint.Hostname, now, cfg); word {
	case storage.AicoSaysOff:
		return 0, 0, false, false
	case storage.AicoSaysUp:
		from := endpoint.LastSeenAt
		if m.UpSince.After(from) {
			from = m.UpSince
		}
		return now.Sub(from), base, true, true
	}
	// An intermittent laptop is shut most evenings: its absences are not
	// findings, or not yet.
	threshold, watched = endpoint.QuietAllowance(base)
	return now.Sub(endpoint.LastSeenAt), threshold, false, watched
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

func (e *Engine) reportSilence(endpoint storage.Endpoint, quiet, threshold time.Duration, dark bool, now time.Time) {
	e.silence.mu.Lock()
	_, already := e.silence.reported[endpoint.ID]
	wasDark := e.silence.dark[endpoint.ID]
	firstSight := !e.silence.observed[endpoint.ID]
	if !already {
		e.silence.reported[endpoint.ID] = now
	}
	if dark {
		e.silence.dark[endpoint.ID] = true
	}
	e.silence.observed[endpoint.ID] = true
	e.silence.mu.Unlock()
	// A finding from while Aico's word had lapsed may only have been recorded:
	// it does not stand in for the page a dark sensor owes.
	if already && (wasDark || !dark) {
		return
	}

	// A hub restart loses the map above, so the database is asked - but only
	// about a host this process has not decided on before. A host that returned
	// and went dark again is a new event, and would otherwise be swallowed by
	// its own still-open previous finding.
	if firstSight && e.sink == nil {
		var open bool
		var err error
		if dark {
			open, err = e.store.HasOpenDarkSensor(endpoint.ID, silenceAnomalyType)
		} else {
			open, err = e.store.HasOpenAnomaly(endpoint.ID, silenceAnomalyType)
		}
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
	if dark {
		title = fmt.Sprintf("Sensor dark on %s: the machine is up, its agent is not reporting", name)
		description = fmt.Sprintf("Aico says %s is up, but its agent last reported %s ago. Every behavioural detector on this endpoint is blind until it returns, which is what stopping the agent is for; it is also what a crashed agent looks like.",
			name, quiet.Truncate(time.Minute))
	}

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
		Evidence:  silenceEvidence(endpoint, quiet, threshold, dark),
		Timestamp: now,
	}
	if e.sink != nil { // a drill: nothing is stored
		e.stampClass(&anomaly)
		e.sink(anomaly)
		return
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
	delete(e.silence.dark, endpoint.ID)
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

// reportUnwatched closes the book on a host reported as silent that has since
// been switched off or retired: if it comes up later with a dark sensor, that is
// a new event, not the old finding going on.
func (e *Engine) reportUnwatched(endpoint storage.Endpoint, now time.Time) {
	e.silence.mu.Lock()
	since, wasReported := e.silence.reported[endpoint.ID]
	delete(e.silence.reported, endpoint.ID)
	delete(e.silence.dark, endpoint.ID)
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
		Title:       fmt.Sprintf("Agent no longer expected on %s", name),
		Description: fmt.Sprintf("%s is off or retired, so its agent's silence since %s no longer means anything. The gap before that is left in place.",
			name, since.UTC().Format(time.RFC3339)),
		Details:   fmt.Sprintf("Noted: %s | Silent since: %s", now.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339)),
		Timestamp: now,
	}
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] The note for %s could not be written: %v", endpoint.ID, err)
	}
}

func endpointName(endpoint storage.Endpoint) string {
	if strings.TrimSpace(endpoint.Hostname) != "" {
		return endpoint.Hostname
	}
	return endpoint.ID
}

func silenceEvidence(endpoint storage.Endpoint, quiet, threshold time.Duration, dark bool) string {
	return fmt.Sprintf(`{"last_seen_at":%q,"silent_seconds":%d,"threshold_seconds":%d,"os":%q,"role_tag":%q,"presence":%q,"is_isolated":%t,"sensor_dark":%t}`,
		endpoint.LastSeenAt.UTC().Format(time.RFC3339), int64(quiet.Seconds()), int64(threshold.Seconds()),
		endpoint.OS, endpoint.RoleTag, endpoint.Presence, endpoint.IsIsolated, dark)
}
