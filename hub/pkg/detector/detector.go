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

func (b *bandwidthStats) update(val float64) (mean float64, stddev float64, z float64) {
	b.count++
	delta := val - b.mean
	b.mean += delta / float64(b.count)
	delta2 := val - b.mean
	b.m2 += delta * delta2

	if b.count < 2 {
		return b.mean, 0, 0
	}

	variance := b.m2 / float64(b.count-1)
	stddev = math.Sqrt(variance)
	if stddev > 0 {
		z = (val - b.mean) / stddev
	}
	return b.mean, stddev, z
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
				Details:     fmt.Sprintf("GeoIP: %s (%s) | ASN: %s | Org: %s", geo.Country, geo.CountryName, geo.ASN, geo.Org),
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

	// 3. Statistical Outlier: Bandwidth Exfiltration Spikes (Z-Score > 3.5)
	if ev.Direction == "OUTBOUND" && ev.BytesOut > 0 {
		bwKey := fmt.Sprintf("%s:%s", ev.EndpointID, procName)
		e.mu.Lock()
		stats, exists := e.bwTracker[bwKey]
		if !exists {
			stats = &bandwidthStats{}
			e.bwTracker[bwKey] = stats
		}
		mean, stddev, zScore := stats.update(float64(ev.BytesOut))
		e.mu.Unlock()

		// Trigger anomaly if Z-score > 3.5 and outbound bytes > 50,000, or huge burst (>10MB)
		if (zScore > 3.5 && ev.BytesOut > 50000 && stats.count >= 4) || (ev.BytesOut > 10*1024*1024) {
			alertKey := fmt.Sprintf("bwspike:%s:%s", ev.EndpointID, procName)
			if cfg.BandwidthOn && !warming && !e.shouldSuppressAlert(alertKey, time.Duration(cfg.BandwidthCooldown)*time.Minute) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       fmt.Sprintf("Bandwidth Exfiltration Spike (Z-Score: %.2f)", zScore),
					Description: fmt.Sprintf("Process %s transmitted %d bytes to %s:%d (Baseline Mean: %.0f bytes, StdDev: %.0f, Z: %.2f).", procName, ev.BytesOut, ev.DstIP, ev.DstPort, mean, stddev, zScore),
					Severity:    "CRITICAL",
					Mitigated:   false,
				}
				e.recordAlert(alert)
				e.recordAnomaly(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "BANDWIDTH_SPIKE",
					Severity:    "CRITICAL",
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Measured: %d bytes | Baseline Mean: %.0f bytes | StdDev: %.0f | Z-Score: %.2f | GeoIP: %s (%s)", ev.BytesOut, mean, stddev, zScore, geo.Country, geo.Org),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [CRITICAL]: %s on %s -> %d bytes (Z=%.2f)", alert.Title, ev.EndpointID, ev.BytesOut, zScore)
			}
		}
	}

	// 4. Statistical Outlier: C2 Beaconing Detection
	//
	// The scoring lives in beacon.go. What matters here is that a beacon is now
	// a conversation with a long, uniform history rather than four packets in a
	// row, and that whatever the detector decided travels into the alert so the
	// operator can disagree with it.
	if cfg.BeaconOn && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!isTrustedSys && !(isTrustedDst && ev.DstPort == 443) {
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
					Details: fmt.Sprintf("%s | threshold %.2f | GeoIP: %s (%s)",
						bev.Summary(), cfg.BeaconScore, geo.Country, geo.Org),
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
		alertKey := fmt.Sprintf("firstseen:%s:%s", ev.TenantID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, time.Duration(cfg.FirstSeenCooldown)*time.Minute) {
			e.recordAnomaly(storage.AnomalyAlert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "NOVEL_DESTINATION",
				Severity:    "MEDIUM",
				Title:       fmt.Sprintf("First-Seen Destination IP Contacted (%s)", geo.Country),
				Description: fmt.Sprintf("Endpoint %s established first organizational connection to novel destination %s:%d (%s, %s).", ev.EndpointID, ev.DstIP, ev.DstPort, geo.CountryName, geo.Org),
				Details:     fmt.Sprintf("Process: %s | GeoIP: %s (%s) | ASN: %s | Org: %s", ev.ProcessPath, geo.Country, geo.CountryName, geo.ASN, geo.Org),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[*] ANOMALY ALERT [MEDIUM]: First-seen destination %s (%s, %s) contacted by %s", ev.DstIP, geo.Country, geo.Org, ev.EndpointID)
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
