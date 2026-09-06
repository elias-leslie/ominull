package detector

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

type IsolateFunc func(endpointID string, reason string) error

type bandwidthStats struct {
	count int64
	mean  float64
	m2    float64
}

// observe scores a transfer against the baseline built from the transfers
// before it, and only then folds it into that baseline.
//
// The order matters and used to be the other way round. Scoring a value against
// a distribution that already contains it suppresses exactly the outliers this
// detector exists to find: the new point pulls the mean toward itself and
// inflates the standard deviation it is then divided by, which bounds the
// z-score at roughly (n-1)/sqrt(n) however extreme the value really is. A
// 500 MB transfer from a process whose every previous transfer was a kilobyte
// scored 5.4 against a baseline of thirty, and the same transfer against a
// baseline of four could not have reached 3.5 at all - so the fixed threshold
// was mostly measuring how many samples had been collected, and the alerts that
// did fire came almost entirely from the absolute-size branch beside it.
//
// The returned counts and moments describe the baseline as it stood before this
// value, which is what the alert then quotes.
func (b *bandwidthStats) observe(val float64) (mean float64, stddev float64, z float64, baseline int64) {
	baseline = b.count
	mean = b.mean
	if baseline >= 2 {
		variance := b.m2 / float64(baseline-1)
		stddev = math.Sqrt(variance)
		if stddev > 0 {
			z = (val - mean) / stddev
		}
	}

	b.count++
	delta := val - b.mean
	b.mean += delta / float64(b.count)
	delta2 := val - b.mean
	b.m2 += delta * delta2

	return mean, stddev, z, baseline
}

type Engine struct {
	store          *storage.Store
	onAutoIsolate  IsolateFunc
	eventsChan     <-chan storage.Event
	mu             sync.Mutex
	portHistory    map[string][]portAccess         // endpointID -> accesses
	bwTracker      map[string]*bandwidthStats      // endpoint:process -> bandwidth stats
	beaconTracker  map[string]*beaconWindow        // endpoint:dstIP:process -> beacon window
	lateralTargets map[string]map[string]time.Time // endpointID -> targetIP -> timestamp
	alertCooldown  map[string]time.Time            // alertKey -> last triggered time
	unattributed   map[string]*unattributedRun     // endpointID -> destinations we could not name
	tuning         storage.DetectionTuning
	tuningAt       time.Time
	cancel         context.CancelFunc
}

// tuningCacheTTL keeps the detector off the database on every packet without
// making an operator wait for a restart to see their change take effect.
const tuningCacheTTL = 15 * time.Second

// settings returns the current tuning, re-reading it at most every few seconds.
func (e *Engine) settings() storage.DetectionTuning {
	e.mu.Lock()
	if time.Since(e.tuningAt) < tuningCacheTTL && e.tuningAt.After(time.Time{}) {
		t := e.tuning
		e.mu.Unlock()
		return t
	}
	e.mu.Unlock()

	t := e.store.GetDetectionTuning()

	e.mu.Lock()
	e.tuning = t
	e.tuningAt = time.Now()
	e.mu.Unlock()
	return t
}

// InvalidateTuning drops the cache so a save in the console is visible at once.
func (e *Engine) InvalidateTuning() {
	e.mu.Lock()
	e.tuningAt = time.Time{}
	e.mu.Unlock()
}

// warmingUp reports whether an endpoint is too new to be judged. Every one of a
// freshly installed host's ordinary conversations is a first-seen destination,
// and its operating system's keepalives are the most regular traffic it will
// ever produce. Holding behavioural detections for a day is the difference
// between a console worth reading and one nobody opens.
func warmingUp(ep storage.Endpoint, cfg storage.DetectionTuning, now time.Time) (bool, time.Duration) {
	if cfg.WarmupHours <= 0 || ep.CreatedAt.IsZero() {
		return false, 0
	}
	window := time.Duration(cfg.WarmupHours) * time.Hour
	age := now.Sub(ep.CreatedAt)
	if age >= window {
		return false, 0
	}
	return true, window - age
}

type portAccess struct {
	port uint16
	t    time.Time
}

func New(store *storage.Store, eventsChan <-chan storage.Event, onAutoIsolate IsolateFunc) *Engine {
	return &Engine{
		store:          store,
		eventsChan:     eventsChan,
		onAutoIsolate:  onAutoIsolate,
		portHistory:    make(map[string][]portAccess),
		bwTracker:      make(map[string]*bandwidthStats),
		beaconTracker:  make(map[string]*beaconWindow),
		lateralTargets: make(map[string]map[string]time.Time),
		alertCooldown:  make(map[string]time.Time),
		unattributed:   make(map[string]*unattributedRun),
	}
}

func (e *Engine) Start(ctx context.Context) {
	subCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	if e.eventsChan == nil {
		return
	}

	go func() {
		for {
			select {
			case <-subCtx.Done():
				return
			case ev, ok := <-e.eventsChan:
				if !ok {
					return
				}
				e.Evaluate(ev)
			}
		}
	}()
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *Engine) shouldSuppressAlert(key string, cooldown time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	last, exists := e.alertCooldown[key]
	now := time.Now()
	if exists && now.Sub(last) < cooldown {
		return true
	}
	e.alertCooldown[key] = now
	return false
}

func (e *Engine) recordAlert(alert storage.Alert) {
	if err := e.store.CreateAlert(alert); err != nil {
		log.Printf("[-] alert write failed for %s/%s: %v", alert.EndpointID, alert.Title, err)
	}
}

func (e *Engine) recordAnomaly(anomaly storage.AnomalyAlert) {
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] anomaly write failed for %s/%s: %v", anomaly.EndpointID, anomaly.Title, err)
	}
}

func (e *Engine) autoIsolate(endpointID, reason string) {
	if e.onAutoIsolate == nil {
		return
	}
	if err := e.onAutoIsolate(endpointID, reason); err != nil {
		log.Printf("[-] automatic isolation failed for %s: %v", endpointID, err)
	}
}

func (e *Engine) Evaluate(ev storage.Event) {
	// Compatibility path for callers outside the batch ingestion seam. The
	// production HTTP path records communication profiles in one batch before
	// it calls EvaluateBatch.
	if err := e.store.RecordNetworkComms(ev, ev.EndpointID, ""); err != nil {
		log.Printf("[-] communication profile write failed for %s: %v", ev.EndpointID, err)
	}
	e.evaluate(ev, nil)
}

// BatchSnapshot contains the state shared by every event in one authenticated
// telemetry request. The ingestion module obtains it before persistence so
// detector decisions retain the old "first seen" ordering without repeating
// database reads for every event.
type BatchSnapshot struct {
	Endpoint   storage.Endpoint
	Geo        map[string]threatintel.GeoRecord
	Exclusions []storage.Exclusion
	FirstSeen  map[string]bool
	LocationID string
}

// EvaluateBatch runs the detector only after the caller has durably accepted
// the batch. Shared endpoint, policy, exclusion and GeoIP state is read once.
func (e *Engine) EvaluateBatch(events []storage.Event, snapshot BatchSnapshot) {
	for _, ev := range events {
		e.evaluate(ev, &snapshot)
	}
}

func (e *Engine) evaluate(ev storage.Event, snapshot *BatchSnapshot) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	cleanPath := strings.ReplaceAll(ev.ProcessPath, "\\", "/")
	procName := filepath.Base(cleanPath)
	if procName == "." || procName == "/" || procName == "" {
		procName = "system"
	}
	procLower := strings.ToLower(cleanPath)

	// GeoIP and ASN resolution. The batch path resolves each unique
	// destination once and passes the result here.
	var geo threatintel.GeoRecord
	if snapshot != nil {
		geo = snapshot.Geo[ev.DstIP]
	} else {
		geo = threatintel.ResolveGeoIP(ev.DstIP)
	}
	if ev.Country == "" || ev.Country == "US" {
		ev.Country = geo.Country
	}

	// 0.1 Check Active Custom Exclusions (Pinholes & Allowlists)
	if snapshot != nil {
		if storage.MatchesExclusion(ev, snapshot.LocationID, snapshot.Exclusions) {
			return // Traffic matches verified security tool or operational exclusion
		}
	} else if e.store.IsExclusionMatch(ev, "") {
		return // Traffic matches verified security tool or operational exclusion
	}

	var endpoint storage.Endpoint
	if snapshot != nil {
		endpoint = snapshot.Endpoint
	} else {
		ep, err := e.store.GetEndpoint(ev.EndpointID)
		if err != nil {
			log.Printf("[-] endpoint lookup failed for detector event %s: %v", ev.EndpointID, err)
		}
		if ep != nil {
			endpoint = *ep
		} else {
			endpoint = storage.Endpoint{ID: ev.EndpointID, RoleTag: "workstation"}
		}
	}

	// 1. Automated Threat Nullification for Feed Matches (Feodo Tracker / Emerging Threats)
	if ev.Action == "BLOCK" {
		alertKey := fmt.Sprintf("nullify:%s:%s", ev.EndpointID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, 10*time.Second) {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       "Critical Threat Nullification Triggered",
				Description: fmt.Sprintf("Confirmed C2 threat connection to %s (%s, %s) blocked by the endpoint firewall.", ev.DstIP, geo.CountryName, geo.Org),
				Severity:    "CRITICAL",
				Mitigated:   true,
			}
			e.recordAlert(alert)
			e.recordAnomaly(storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "THREAT_INTEL_MATCH",
				Severity:    "CRITICAL",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     fmt.Sprintf("%s", describeOwner(geo)),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] DETECTION ALERT [CRITICAL]: %s on endpoint %s (%s)", alert.Title, alert.EndpointID, ev.DstIP)

			e.autoIsolate(ev.EndpointID, "Automated Threat Nullification: "+alert.Title)
		}
	}

	// The behavioural detectors below are the ones an operator tunes. They read
	// one cached settings row rather than the numbers that used to be compiled
	// into them.
	cfg := e.settings()
	warming, warmLeft := warmingUp(endpoint, cfg, now)

	// 2. Diurnal Time-of-Day Hourly Behavioral Profiling & Off-Hours Detection
	//
	// The window used to be hours 2 to 5 UTC with no zone anywhere near it,
	// which on this side of the Atlantic is late evening - so ordinary evening
	// use of a workstation was reported as off-hours activity, over and over.
	// It is now a window in a named zone, and it defaults to the operator's own.
	hr := now.In(cfg.Location()).Hour()
	isOffHours := cfg.IsOffHours(now)
	roleIsWorkstation := endpoint.RoleTag == "workstation" || endpoint.RoleTag == ""

	isInteractiveShell := strings.HasSuffix(procLower, "powershell.exe") ||
		strings.HasSuffix(procLower, "pwsh.exe") ||
		strings.HasSuffix(procLower, "cmd.exe") ||
		strings.HasSuffix(procLower, "wscript.exe") ||
		strings.HasSuffix(procLower, "cscript.exe") ||
		strings.HasSuffix(procLower, "curl") ||
		strings.HasSuffix(procLower, "curl.exe") ||
		strings.HasSuffix(procLower, "wget") ||
		strings.HasSuffix(procLower, "nc") ||
		strings.HasSuffix(procLower, "ncat") ||
		strings.HasSuffix(procLower, "netcat") ||
		strings.HasSuffix(procLower, "/sh") ||
		strings.HasSuffix(procLower, "/bash") ||
		strings.HasSuffix(procLower, "/zsh") ||
		strings.HasSuffix(procLower, "/dash") ||
		strings.HasSuffix(procLower, "python") ||
		strings.HasSuffix(procLower, "python3") ||
		strings.HasSuffix(procLower, "python.exe")

	// Both lists are the operator's, held in the database and shown in the
	// console, not a table compiled into this file.
	isTrustedSys := cfg.IsQuietProcess(strings.ToLower(procName))
	isTrustedDst := cfg.IsQuietOrg(geo.Org)

	// Off-hours activity triggers ONLY for interactive shells / script
	// interpreters, NEVER for standard OS system daemons.
	if roleIsWorkstation && isOffHours && isInteractiveShell && !isTrustedSys && !warming &&
		ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) {
		alertKey := fmt.Sprintf("offhours:%s:%s:%s", ev.EndpointID, ev.DstIP, procName)
		if !e.shouldSuppressAlert(alertKey, time.Duration(cfg.FirstSeenCooldown)*time.Minute) {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       fmt.Sprintf("Off-Hours Workstation Activity Detected (%02d:00 %s)", hr, cfg.Location()),
				Description: fmt.Sprintf("Interactive shell %s initiated external connection to %s:%d (%s) during off-hours baseline on %s.", procName, ev.DstIP, ev.DstPort, geo.CountryName, ev.EndpointID),
				Severity:    "HIGH",
				Mitigated:   false,
			}
			e.recordAlert(alert)
			e.recordAnomaly(storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "OFF_HOURS_ACTIVITY",
				Severity:    "HIGH",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     fmt.Sprintf("Time: %02d:%02d %s | Off-hours window: %s | Process: %s | GeoIP: %s (%s)", hr, now.In(cfg.Location()).Minute(), cfg.Location(), cfg.OffHoursLabel(), ev.ProcessPath, geo.Country, geo.Org),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] ANOMALY ALERT [HIGH]: %s on %s -> %s:%d", alert.Title, ev.EndpointID, ev.DstIP, ev.DstPort)
		}
	}

	// 3. Statistical Outlier: Bandwidth Exfiltration Spikes
	//
	// Three gates were missing here that every other detector below has, and
	// each one produced alerts on the live fleet:
	//
	//   - the quiet-process list was never consulted, so svchost.exe - the
	//     first name in the shipped list - reported exfiltration spikes;
	//   - the destination was never checked, so the fleet's own agent
	//     heartbeating to the hub on the LAN, and a container talking to its
	//     own database on a bridge network, were both "exfiltration";
	//   - the baseline was four samples, which is not a baseline, and every
	//     finding was CRITICAL whatever the evidence behind it.
	//
	// Bytes leaving for a host inside the estate are a different question from
	// bytes leaving the estate, and this detector is about the second one.
	if ev.Direction == "OUTBOUND" && ev.BytesOut > 0 && !isPrivateIP(ev.DstIP) && !isTrustedSys {
		bwKey := fmt.Sprintf("%s:%s", ev.EndpointID, procName)
		e.mu.Lock()
		stats, exists := e.bwTracker[bwKey]
		if !exists {
			stats = &bandwidthStats{}
			e.bwTracker[bwKey] = stats
		}
		mean, stddev, zScore, samples := stats.observe(float64(ev.BytesOut))
		e.mu.Unlock()

		baselined := samples >= int64(cfg.BandwidthMinSamples)
		outlier := baselined && zScore > 3.5 && ev.BytesOut > 50000
		// A burst large enough to matter on its own account, reported even
		// without a baseline - but as the weaker finding it is, because with no
		// baseline there is nothing to say it is unusual for this process.
		burst := ev.BytesOut > 10*1024*1024
		if outlier || burst {
			alertKey := fmt.Sprintf("bwspike:%s:%s", ev.EndpointID, procName)
			// The severity follows the evidence rather than the detector's
			// name. A transfer four standard deviations out is worth a look; one
			// far past that, against a real baseline, is the finding this
			// detector was written for.
			bwSeverity := "HIGH"
			if outlier && zScore > 8 {
				bwSeverity = "CRITICAL"
			}
			if cfg.BandwidthOn && !warming && !e.shouldSuppressAlert(alertKey, time.Duration(cfg.BandwidthCooldown)*time.Minute) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       bandwidthTitle(baselined, zScore, ev.BytesOut),
					Description: bandwidthDescription(baselined, procName, ev.BytesOut, ev.DstIP, ev.DstPort, mean, stddev, zScore, samples),
					Severity:    bwSeverity,
					Mitigated:   false,
				}
				e.recordAlert(alert)
				e.recordAnomaly(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "BANDWIDTH_SPIKE",
					Severity:    bwSeverity,
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Measured: %d bytes | Samples: %d | Baseline Mean: %.0f bytes | StdDev: %.0f | Z-Score: %.2f | %s", ev.BytesOut, samples, mean, stddev, zScore, describeOwner(geo)),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [%s]: %s on %s -> %d bytes (Z=%.2f over %d samples)", bwSeverity, alert.Title, ev.EndpointID, ev.BytesOut, zScore, samples)
			}
		}
	}

	// 4. Statistical Outlier: C2 Beaconing Detection
	//
	// The scoring lives in beacon.go. What matters here is that a beacon is now
	// a conversation with a long, uniform history rather than four packets in a
	// row, and that whatever the detector decided travels into the alert so the
	// operator can disagree with it.
	// The quiet-organisation exemption used to apply only on port 443, so a
	// keepalive to a network owner the operator had already declared normal was
	// still reported as C2 the moment it used that owner's own service port:
	// Chrome and the ChatGPT client holding Google's push channel open on 5228
	// scored 1.00 with 0% payload variation, which is what a keepalive is. An
	// owner the operator trusts is trusted at whatever port they answer on; the
	// way to stop trusting them is to take them off the list.
	if cfg.BeaconOn && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!isTrustedSys && !isTrustedDst {
		beaconKey := fmt.Sprintf("%s:%s:%s", ev.EndpointID, ev.DstIP, procName)
		e.mu.Lock()
		bWin, exists := e.beaconTracker[beaconKey]
		if !exists {
			bWin = &beaconWindow{}
			e.beaconTracker[beaconKey] = bWin
		}
		bev, isBeacon := bWin.record(now, ev.BytesOut, cfg)
		e.mu.Unlock()

		if isBeacon && !warming {
			alertKey := fmt.Sprintf("beacon:%s:%s:%s", ev.EndpointID, ev.DstIP, procName)
			if !e.shouldSuppressAlert(alertKey, time.Duration(cfg.BeaconCooldownMin)*time.Minute) {
				// The severity follows the evidence. A conversation that only
				// just cleared the bar is worth looking at; one that is
				// metronomic to within a few percent for an hour is not the
				// same finding and should not wear the same word.
				severity := "MEDIUM"
				if bev.Score >= 0.90 && bev.SpanMinutes >= 30 {
					severity = "HIGH"
				}
				alert := storage.Alert{
					ID:         uuid.New().String(),
					TenantID:   ev.TenantID,
					EndpointID: ev.EndpointID,
					Timestamp:  now,
					Title:      fmt.Sprintf("Periodic beaconing to %s (every ~%.0fs)", ev.DstIP, bev.MeanInterval),
					Description: fmt.Sprintf(
						"%s has connected to %s:%d %d times over %.0f minutes at a near-constant interval of %.1fs (%.0f%% jitter), with payloads varying by %.0f%%.",
						procName, ev.DstIP, ev.DstPort, bev.Samples, bev.SpanMinutes, bev.MeanInterval, bev.CoefVariation*100, bev.SizeVariation*100),
					Severity:  severity,
					Mitigated: false,
				}
				e.recordAlert(alert)
				e.recordAnomaly(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "C2_BEACONING",
					Severity:    severity,
					Title:       alert.Title,
					Description: alert.Description,
					Details: fmt.Sprintf("%s | threshold %.2f | %s",
						bev.Summary(), cfg.BeaconScore, describeOwner(geo)),
					// The same numbers the sentence above is built from, kept
					// as numbers. The console can then show how far past the
					// threshold this verdict actually was, and sort a page of
					// beacon alerts by strength, instead of re-reading prose.
					Evidence:    bev.JSON(cfg.BeaconScore),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [%s]: beaconing %s -> %s:%d (%s)", severity, ev.EndpointID, ev.DstIP, ev.DstPort, bev.Summary())
			}
		} else if isBeacon && warming {
			log.Printf("[*] Held a beacon finding on %s -> %s: the endpoint is %s into its %dh learning period (%s)",
				ev.EndpointID, ev.DstIP, (time.Duration(cfg.WarmupHours)*time.Hour - warmLeft).Round(time.Minute), cfg.WarmupHours, bev.Summary())
		}
	}

	// 5. Statistical Outlier: Rare First-Seen External Destination (Ignoring major CDNs/Clouds)
	firstSeen := false
	if snapshot != nil {
		firstSeen = snapshot.FirstSeen[ev.DstIP]
	} else {
		firstSeen = e.store.IsFirstSeenDestination(ev.TenantID, ev.DstIP)
	}
	if cfg.FirstSeenOn && !warming && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!isTrustedDst && !isTrustedSys && firstSeen {
		// Keyed on the network owner, not the address. A destination is
		// first-seen exactly once, so a per-address key could never repeat and
		// the cooldown never suppressed anything - which is how this detector
		// came to be 62%% of every alert on the fleet. What an analyst wants to
		// know is that the estate has started talking to somebody new, and one
		// counterparty bringing forty edge addresses is one of those, not
		// forty. An address whose owner is unknown falls back to the address,
		// because then the address is all there is.
		// An address with no owner has no key that can repeat either, so the
		// per-address fallback brought the same defect back in a smaller form:
		// an ordinary workstation browsing the web reaches a dozen unnamed
		// addresses an hour and raised one alert for each. Those are folded
		// into a single rolling finding per endpoint, which is the question an
		// analyst actually has - "is this host reaching places we cannot
		// name?" - and it carries the count of everything folded into it.
		attributed := geo.Resolved() && strings.TrimSpace(geo.Org) != ""
		severity := "MEDIUM"
		alertKey := fmt.Sprintf("firstseen:%s:%s", ev.TenantID, strings.ToLower(strings.TrimSpace(geo.Org)))
		if !attributed {
			severity = "LOW"
			alertKey = fmt.Sprintf("firstseen:%s:unattributed:%s", ev.TenantID, ev.EndpointID)
			e.noteUnattributed(ev.EndpointID, ev.DstIP, now)
		}
		if !e.shouldSuppressAlert(alertKey, time.Duration(cfg.FirstSeenCooldown)*time.Minute) {
			title := firstSeenTitle(geo)
			description := fmt.Sprintf("Endpoint %s established a first connection to %s:%d (%s).", ev.EndpointID, ev.DstIP, ev.DstPort, describeOwner(geo))
			details := fmt.Sprintf("Process: %s | %s", ev.ProcessPath, describeOwner(geo))
			if !attributed {
				run := e.takeUnattributed(ev.EndpointID)
				title = unattributedTitle(run)
				description = unattributedDescription(ev.EndpointID, ev.DstIP, ev.DstPort, run)
				details = fmt.Sprintf("Process: %s | %s | %s", ev.ProcessPath, describeOwner(geo), unattributedDetails(run, cfg.FirstSeenCooldown))
			}
			e.recordAnomaly(storage.AnomalyAlert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "NOVEL_DESTINATION",
				Severity:    severity,
				Title:       title,
				Description: description,
				Details:     details,
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[*] ANOMALY ALERT [%s]: First-seen destination %s (%s) contacted by %s", severity, ev.DstIP, describeOwner(geo), ev.EndpointID)
		}
	}

	// 6. Rapid Port Sweeps / Reconnaissance (Evaluated per-process)
	procKey := strings.ToLower(filepath.Base(ev.ProcessPath))
	if procKey == "" || procKey == "." {
		procKey = "unknown"
	}
	if ev.Direction == "OUTBOUND" && ev.DstPort > 0 && !isTrustedSys && !isKnownInfrastructureProcess(ev.ProcessPath) && !cfg.IsQuietProcess(procKey) {
		sweepKey := fmt.Sprintf("%s:%s", ev.EndpointID, procKey)
		e.mu.Lock()
		history := e.portHistory[sweepKey]
		var recent []portAccess
		seenPorts := make(map[uint16]bool)
		for _, p := range history {
			if now.Sub(p.t) <= 10*time.Second {
				recent = append(recent, p)
				seenPorts[p.port] = true
			}
		}
		recent = append(recent, portAccess{port: ev.DstPort, t: now})
		seenPorts[ev.DstPort] = true
		e.portHistory[sweepKey] = recent
		distinctCount := len(seenPorts)
		e.mu.Unlock()

		portThreshold := 30
		if isInteractiveShell {
			portThreshold = 15
		}
		if distinctCount >= portThreshold {
			alertKey := fmt.Sprintf("portsweep:%s:%s", ev.EndpointID, procKey)
			if !e.shouldSuppressAlert(alertKey, 10*time.Minute) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       "High-Velocity Port Sweep Detected",
					Description: fmt.Sprintf("Process %s (PID %d) initiated connections to %d distinct destination ports within 10 seconds.", ev.ProcessPath, ev.ProcessID, distinctCount),
					Severity:    "HIGH",
					Mitigated:   false,
				}
				e.recordAlert(alert)
				e.recordAnomaly(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "PORT_SCAN_RECON",
					Severity:    "HIGH",
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Distinct Ports: %d in 10s window | Process: %s", distinctCount, ev.ProcessPath),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s (%s)", alert.Title, alert.EndpointID, procKey)
			}
		}
	}

	// 7. Topological Graph Outlier: Internal Lateral Movement / Subnet Fan-Out (Evaluated per-process)
	if isPrivateIP(ev.DstIP) && ev.Direction == "OUTBOUND" && ev.DstIP != "127.0.0.1" &&
		!isBridgeOrContainerSubnet(ev.DstIP) && !isTrustedSys && !isKnownInfrastructureProcess(ev.ProcessPath) && !cfg.IsQuietProcess(procKey) {

		e.mu.Lock()
		lateralKey := fmt.Sprintf("%s:%s", ev.EndpointID, procKey)
		targetMap, exists := e.lateralTargets[lateralKey]
		if !exists {
			targetMap = make(map[string]time.Time)
			e.lateralTargets[lateralKey] = targetMap
		}
		// Clean targets older than 60 seconds
		for ip, t := range targetMap {
			if now.Sub(t) > 60*time.Second {
				delete(targetMap, ip)
			}
		}
		targetMap[ev.DstIP] = now
		distinctTargets := len(targetMap)
		e.mu.Unlock()

		isOffHours := now.Hour() >= 22 || now.Hour() <= 5
		isWorkstation := endpoint.RoleTag == "workstation" || endpoint.RoleTag == ""

		// Thresholds:
		// - Interactive shell / script interpreter (cmd.exe, powershell, python, bash, nmap): >= 6 distinct LAN hosts (or >= 3 off-hours)
		// - Standard compiled app: >= 20 distinct LAN hosts (or >= 10 off-hours)
		threshold := 20
		if isInteractiveShell {
			threshold = 6
			if isOffHours && isWorkstation {
				threshold = 3
			}
		} else if isOffHours && isWorkstation {
			threshold = 10
		}

		if distinctTargets >= threshold {
			alertKey := fmt.Sprintf("lateral_sweep:%s:%s", ev.EndpointID, procKey)
			if !e.shouldSuppressAlert(alertKey, 10*time.Minute) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       fmt.Sprintf("Lateral Port Sweep / Internal Fan-Out (%d Hosts)", distinctTargets),
					Description: fmt.Sprintf("Process %s on %s initiated rapid internal connection sweep to %d distinct hosts on subnet within 60 seconds.", ev.ProcessPath, ev.EndpointID, distinctTargets),
					Severity:    "CRITICAL",
					Mitigated:   false,
				}
				e.recordAlert(alert)
				e.recordAnomaly(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "LATERAL_PORT_SWEEP",
					Severity:    "CRITICAL",
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Internal Fan-Out: %d unique hosts | Window: 60s | Process: %s | Off-Hours: %t", distinctTargets, ev.ProcessPath, isOffHours),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [CRITICAL]: %s on %s (%s) -> %d targets in 60s", alert.Title, ev.EndpointID, procKey, distinctTargets)
			}
		}
	}

	// 8. Suspicious Shell / Script Engine External Connection
	if isInteractiveShell && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) {
		alertKey := fmt.Sprintf("shell:%s:%s", ev.EndpointID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, 15*time.Second) {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       "Suspicious Interactive Shell External Egress",
				Description: fmt.Sprintf("Script interpreter %s established outbound connection to external IP %s:%d (%s).", ev.ProcessPath, ev.DstIP, ev.DstPort, geo.CountryName),
				Severity:    "HIGH",
				Mitigated:   false,
			}
			e.recordAlert(alert)
			e.recordAnomaly(storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "NOVEL_PROCESS_EGRESS",
				Severity:    "HIGH",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     fmt.Sprintf("Interpreter: %s | Target: %s:%d (%s, %s)", ev.ProcessPath, ev.DstIP, ev.DstPort, geo.Country, geo.Org),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s (%s:%d)", alert.Title, alert.EndpointID, ev.DstIP, ev.DstPort)
		}
	}

	// 8. Sensitive Port External Exposure
	if ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) && (ev.DstPort == 445 || ev.DstPort == 3389 || ev.DstPort == 23 || ev.DstPort == 135) {
		alertKey := fmt.Sprintf("sensport:%s:%d", ev.EndpointID, ev.DstPort)
		if !e.shouldSuppressAlert(alertKey, 15*time.Second) {
			anomaly := storage.AnomalyAlert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "SENSITIVE_PORT_EGRESS",
				Severity:    "CRITICAL",
				Title:       fmt.Sprintf("Sensitive Port %d Egress to External IP", ev.DstPort),
				Description: fmt.Sprintf("Process %s attempted outbound connection on sensitive management/file-sharing port %d to %s (%s).", ev.ProcessPath, ev.DstPort, ev.DstIP, geo.CountryName),
				Details:     fmt.Sprintf("Port: %d | Target: %s (%s, %s) | Process: %s", ev.DstPort, ev.DstIP, geo.Country, geo.Org, ev.ProcessPath),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			}
			e.recordAnomaly(anomaly)
			log.Printf("[!] ANOMALY ALERT [CRITICAL]: %s on endpoint %s", anomaly.Title, anomaly.EndpointID)
		}
	}

}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// isBridgeOrContainerSubnet checks if an IP belongs to standard local bridge/container subnets
func isBridgeOrContainerSubnet(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 172.17.0.0/16 through 172.31.0.0/16 (Docker / Podman default bridges)
		if v4[0] == 172 && v4[1] >= 17 && v4[1] <= 31 {
			return true
		}
		// 10.244.0.0/16 and 10.96.0.0/12 (Kubernetes pod / service CIDRs)
		if v4[0] == 10 && (v4[1] == 244 || v4[1] >= 96 && v4[1] <= 111) {
			return true
		}
	}
	return false
}

// isKnownInfrastructureProcess checks if a process is a container runtime, local DNS resolver, or test runner
func isKnownInfrastructureProcess(procPath string) bool {
	p := strings.ToLower(procPath)
	base := filepath.Base(p)
	if strings.HasSuffix(p, ".test") || strings.Contains(p, "go-build") {
		return true
	}
	switch base {
	case "docker-proxy", "dockerd", "containerd", "runc", "dnsmasq",
		"systemd-resolved", "kubelet", "cilium-agent", "avahi-daemon",
		"coredns", "named", "unbound", "wireguard-go":
		return true
	}
	return false
}

// describeOwner renders what is known about a destination's network, and says
// so plainly when that is nothing.
//
// Alert text used to be built as "GeoIP: %s (%s)" straight from the resolver,
// which answered every address because it hashed the ones it did not know into
// a list of plausible countries and owners. With that removed, an unattributable
// address has an empty organisation, and printing it through the old format
// produced "GeoIP: UNKNOWN ()" - an operator reading that cannot tell a lookup
// that failed from a network with no name.
func describeOwner(geo threatintel.GeoRecord) string {
	if !geo.Resolved() {
		return "network owner not resolved (no offline attribution for this address)"
	}
	country := strings.TrimSpace(geo.CountryName)
	if country == "" {
		country = strings.TrimSpace(geo.Country)
	}
	if asn := strings.TrimSpace(geo.ASN); asn != "" {
		return fmt.Sprintf("%s (%s, %s)", geo.Org, asn, country)
	}
	return fmt.Sprintf("%s (%s)", geo.Org, country)
}

// firstSeenTitle names the counterparty when there is one to name. "First-Seen
// Destination IP Contacted (CA)" was a country the resolver had invented; a
// title has to carry something the reader can act on or admit it does not.
// unattributedRun is the set of first-seen destinations on one endpoint that
// the offline attribution table could not name, held between alerts so the one
// alert that does go out can say how many there were rather than sending one
// alert per address.
type unattributedRun struct {
	count int
	first string
	since time.Time
	last  time.Time
}

func (e *Engine) noteUnattributed(endpointID, dstIP string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	run := e.unattributed[endpointID]
	if run == nil {
		run = &unattributedRun{first: dstIP, since: at}
		e.unattributed[endpointID] = run
	}
	run.count++
	run.last = at
}

// takeUnattributed reads the run and clears it, so the next alert counts only
// what happened after this one.
func (e *Engine) takeUnattributed(endpointID string) unattributedRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	run := e.unattributed[endpointID]
	if run == nil {
		return unattributedRun{count: 1}
	}
	out := *run
	delete(e.unattributed, endpointID)
	return out
}

func unattributedTitle(run unattributedRun) string {
	if run.count > 1 {
		return fmt.Sprintf("%d first connections to unattributed networks", run.count)
	}
	return "First connection to an unattributed network"
}

func unattributedDescription(endpointID, dstIP string, dstPort uint16, run unattributedRun) string {
	if run.count > 1 {
		window := run.last.Sub(run.since).Round(time.Minute)
		if window < time.Minute {
			window = time.Minute
		}
		return fmt.Sprintf("Endpoint %s reached %d addresses for the first time in %s, none of which the offline attribution table can name. The most recent was %s:%d; the first was %s.",
			endpointID, run.count, window, dstIP, dstPort, run.first)
	}
	return fmt.Sprintf("Endpoint %s established a first connection to %s:%d, an address the offline attribution table cannot name.", endpointID, dstIP, dstPort)
}

func unattributedDetails(run unattributedRun, cooldownMinutes int) string {
	if run.count > 1 {
		return fmt.Sprintf("%d unnamed destinations folded into this finding; further ones are folded for the next %d minutes", run.count, cooldownMinutes)
	}
	return fmt.Sprintf("further unnamed destinations on this endpoint are folded into this finding for the next %d minutes", cooldownMinutes)
}

func firstSeenTitle(geo threatintel.GeoRecord) string {
	if geo.Resolved() {
		return fmt.Sprintf("First connection to %s", geo.Org)
	}
	return "First connection to an unattributed network"
}

// bandwidthTitle distinguishes a transfer measured against a real baseline from
// one large enough to report on its own. Both used to be reported with a
// z-score, including the burst case where the score was computed against
// whatever handful of samples happened to exist.
func bandwidthTitle(baselined bool, zScore float64, bytesOut int64) string {
	if baselined {
		return "Outbound volume " + deviations(zScore) + " above this process's baseline"
	}
	return fmt.Sprintf("Large outbound transfer (%d bytes, no baseline yet)", bytesOut)
}

// deviations renders a z-score at a precision that means something. A process
// whose every previous transfer was the same size has almost no variance, so a
// genuine outlier against it scores in the millions; printing that to one
// decimal place reads as a broken number rather than as a large one.
func deviations(z float64) string {
	switch {
	case z >= 1000:
		return "more than 1,000 standard deviations"
	case z >= 100:
		return fmt.Sprintf("%.0f standard deviations", z)
	default:
		return fmt.Sprintf("%.1f standard deviations", z)
	}
}

func bandwidthDescription(baselined bool, procName string, bytesOut int64, dstIP string, dstPort uint16, mean, stddev, zScore float64, samples int64) string {
	if baselined {
		return fmt.Sprintf("Process %s transmitted %d bytes to %s:%d. Its baseline over the %d transfers before this one is %.0f bytes (standard deviation %.0f), which puts this one %s out.",
			procName, bytesOut, dstIP, dstPort, samples, mean, stddev, deviations(zScore))
	}
	return fmt.Sprintf("Process %s transmitted %d bytes to %s:%d. Only %d transfers have been observed for it, which is too few to say whether that is unusual for this process.",
		procName, bytesOut, dstIP, dstPort, samples)
}
