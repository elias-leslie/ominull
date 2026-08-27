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

type beaconWindow struct {
	timestamps []time.Time
}

func (bw *beaconWindow) record(t time.Time) (avgInterval float64, jitter float64, count int, isBeacon bool) {
	// Keep last 8 timestamps
	bw.timestamps = append(bw.timestamps, t)
	if len(bw.timestamps) > 8 {
		bw.timestamps = bw.timestamps[len(bw.timestamps)-8:]
	}

	count = len(bw.timestamps)
	if count < 4 {
		return 0, 0, count, false
	}

	// Calculate inter-arrival intervals
	var deltas []float64
	var sum float64
	for i := 1; i < count; i++ {
		d := bw.timestamps[i].Sub(bw.timestamps[i-1]).Seconds()
		if d < 0.1 {
			continue // Skip immediate duplicate bursts
		}
		deltas = append(deltas, d)
		sum += d
	}

	if len(deltas) < 3 {
		return 0, 0, count, false
	}

	avgInterval = sum / float64(len(deltas))
	if avgInterval < 1.0 || avgInterval > 300.0 {
		return avgInterval, 0, count, false
	}

	// Calculate standard deviation of intervals (jitter)
	var varSum float64
	for _, d := range deltas {
		diff := d - avgInterval
		varSum += diff * diff
	}
	jitter = math.Sqrt(varSum / float64(len(deltas)))

	// Beacon criteria: mean interval between 1s and 120s with low jitter (stddev < 1.5s or jitter < 15% of interval)
	if jitter <= 1.5 || (avgInterval > 5.0 && jitter/avgInterval < 0.15) {
		isBeacon = true
	}

	return avgInterval, jitter, count, isBeacon
}

type Engine struct {
	store          *storage.Store
	onAutoIsolate  IsolateFunc
	eventsChan     <-chan storage.Event
	mu             sync.Mutex
	portHistory    map[string][]portAccess               // endpointID -> accesses
	bwTracker      map[string]*bandwidthStats            // endpoint:process -> bandwidth stats
	beaconTracker  map[string]*beaconWindow              // endpoint:dstIP:process -> beacon window
	lateralTargets map[string]map[string]time.Time       // endpointID -> targetIP -> timestamp
	alertCooldown  map[string]time.Time                  // alertKey -> last triggered time
	cancel         context.CancelFunc
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

func (e *Engine) Evaluate(ev storage.Event) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	cleanPath := strings.ReplaceAll(ev.ProcessPath, "\\", "/")
	procName := filepath.Base(cleanPath)
	if procName == "." || procName == "/" || procName == "" {
		procName = "kernel"
	}
	procLower := strings.ToLower(cleanPath)

	// In-flight GeoIP & ASN Resolution
	geo := threatintel.ResolveGeoIP(ev.DstIP)
	if ev.Country == "" || ev.Country == "US" {
		ev.Country = geo.Country
	}

	// 0. Update Hierarchical Communications Baseline Profile
	_ = e.store.RecordNetworkComms(ev, ev.EndpointID, "")

	// 0.1 Check Active Custom Exclusions (Pinholes & Allowlists)
	if e.store.IsExclusionMatch(ev, "") {
		return // Traffic matches verified security tool or operational exclusion
	}

	// 0.2 Check 4-Tier Hierarchical Policy Engine (Global -> Client -> Location -> Endpoint/Role)
	ep, _ := e.store.GetEndpoint(ev.EndpointID)
	var endpoint storage.Endpoint
	if ep != nil {
		endpoint = *ep
	} else {
		endpoint = storage.Endpoint{ID: ev.EndpointID, RoleTag: "workstation"}
	}

	matchedPolicy, policyAction := e.store.EvaluatePolicyHierarchy(ev, endpoint)
	if matchedPolicy != nil && policyAction != "" {
		if policyAction == "BLOCK" {
			ev.Action = "BLOCK"
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       fmt.Sprintf("4-Tier Policy Block: %s (%s Tier)", matchedPolicy.Name, strings.ToUpper(matchedPolicy.Scope)),
				Description: fmt.Sprintf("Outbound flow to %s:%d matching policy '%s' was blocked at endpoint %s.", ev.DstIP, ev.DstPort, matchedPolicy.Name, ev.EndpointID),
				Severity:    "HIGH",
				Mitigated:   true,
			}
			_ = e.store.CreateAlert(alert)
			_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "POLICY_BLOCK",
				Severity:    "HIGH",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     fmt.Sprintf("Scope: %s (%s) | Rule: %s %s", matchedPolicy.Scope, matchedPolicy.ScopeValue, matchedPolicy.RuleType, matchedPolicy.RuleValue),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] POLICY BLOCK [%s]: %s on %s -> %s:%d", matchedPolicy.Scope, matchedPolicy.Name, ev.EndpointID, ev.DstIP, ev.DstPort)
			return
		} else if policyAction == "QUARANTINE" {
			if e.onAutoIsolate != nil {
				_ = e.onAutoIsolate(ev.EndpointID, "Policy Rule Isolation Triggered: "+matchedPolicy.Name)
			}
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
				Description: fmt.Sprintf("Confirmed C2 threat connection to %s (%s, %s) blocked at ring-0. Host quarantine verified.", ev.DstIP, geo.CountryName, geo.Org),
				Severity:    "CRITICAL",
				Mitigated:   true,
			}
			_ = e.store.CreateAlert(alert)
			_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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

			if e.onAutoIsolate != nil {
				_ = e.onAutoIsolate(ev.EndpointID, "Automated Threat Nullification: "+alert.Title)
			}
		}
	}

	// 2. Diurnal Time-of-Day Hourly Behavioral Profiling & Off-Hours Detection
	hr := now.Hour()
	isOffHours := hr >= 22 || hr <= 5 // 22:00 to 05:59 UTC (e.g. 02:00 AM)
	roleIsWorkstation := endpoint.RoleTag == "workstation" || endpoint.RoleTag == ""

	isInteractiveShell := strings.HasSuffix(procLower, "powershell.exe") ||
		strings.HasSuffix(procLower, "cmd.exe") ||
		strings.HasSuffix(procLower, "wscript.exe") ||
		strings.HasSuffix(procLower, "cscript.exe") ||
		strings.HasSuffix(procLower, "curl") ||
		strings.HasSuffix(procLower, "curl.exe") ||
		strings.HasSuffix(procLower, "nc") ||
		strings.HasSuffix(procLower, "ncat") ||
		strings.HasSuffix(procLower, "/sh") ||
		strings.HasSuffix(procLower, "/bash") ||
		strings.HasSuffix(procLower, "/zsh") ||
		strings.HasSuffix(procLower, "python") ||
		strings.HasSuffix(procLower, "python3") ||
		strings.HasSuffix(procLower, "python.exe")

	if roleIsWorkstation && isOffHours && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) {
		alertKey := fmt.Sprintf("offhours:%s:%s", ev.EndpointID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, 15*time.Second) {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       fmt.Sprintf("Off-Hours Workstation Activity Detected (%02d:00 UTC)", hr),
				Description: fmt.Sprintf("Process %s initiated external connection to %s:%d (%s) during off-hours baseline on %s.", procName, ev.DstIP, ev.DstPort, geo.CountryName, ev.EndpointID),
				Severity:    "HIGH",
				Mitigated:   false,
			}
			_ = e.store.CreateAlert(alert)
			_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "OFF_HOURS_ACTIVITY",
				Severity:    "HIGH",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     fmt.Sprintf("Time: %02d:%02d UTC | Expected: Idle Workstation Baseline | GeoIP: %s (%s)", hr, now.Minute(), geo.Country, geo.Org),
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
			if !e.shouldSuppressAlert(alertKey, 20*time.Second) {
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
				_ = e.store.CreateAlert(alert)
				_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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

	// 4. Statistical Outlier: C2 Beaconing Detection (Periodic Interval + Low Jitter)
	if ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) {
		beaconKey := fmt.Sprintf("%s:%s:%s", ev.EndpointID, ev.DstIP, procName)
		e.mu.Lock()
		bWin, exists := e.beaconTracker[beaconKey]
		if !exists {
			bWin = &beaconWindow{}
			e.beaconTracker[beaconKey] = bWin
		}
		avgInterval, jitter, pulseCount, isBeacon := bWin.record(now)
		e.mu.Unlock()

		if isBeacon {
			alertKey := fmt.Sprintf("beacon:%s:%s", ev.EndpointID, ev.DstIP)
			if !e.shouldSuppressAlert(alertKey, 30*time.Second) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       fmt.Sprintf("Periodic C2 Beaconing Detected (~%.1fs Interval)", avgInterval),
					Description: fmt.Sprintf("Process %s established %d periodic connections to %s:%d with fixed interval (~%.1fs) and low jitter (±%.2fs).", procName, pulseCount, ev.DstIP, ev.DstPort, avgInterval, jitter),
					Severity:    "HIGH",
					Mitigated:   false,
				}
				_ = e.store.CreateAlert(alert)
				_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "C2_BEACONING",
					Severity:    "HIGH",
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Interval: %.2fs | Jitter: ±%.2fs | Pulses Observed: %d | GeoIP: %s (%s)", avgInterval, jitter, pulseCount, geo.Country, geo.Org),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [HIGH]: %s on %s -> %s:%d (~%.1fs, jitter ±%.2fs)", alert.Title, ev.EndpointID, ev.DstIP, ev.DstPort, avgInterval, jitter)
			}
		}
	}

	// 5. Statistical Outlier: Rare First-Seen External Destination
	if ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) && e.store.IsFirstSeenDestination(ev.TenantID, ev.DstIP) {
		alertKey := fmt.Sprintf("firstseen:%s:%s", ev.TenantID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, 60*time.Second) {
			_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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

	// 6. Rapid Port Sweeps / Reconnaissance
	if ev.Direction == "OUTBOUND" && ev.DstPort > 0 {
		e.mu.Lock()
		history := e.portHistory[ev.EndpointID]
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
		e.portHistory[ev.EndpointID] = recent
		distinctCount := len(seenPorts)
		e.mu.Unlock()

		if distinctCount >= 15 {
			alertKey := fmt.Sprintf("portsweep:%s", ev.EndpointID)
			if !e.shouldSuppressAlert(alertKey, 15*time.Second) {
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
				_ = e.store.CreateAlert(alert)
				_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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
				log.Printf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s", alert.Title, alert.EndpointID)
			}
		}
	}

	// 7. Topological Graph Outlier: Internal Lateral Port Sweep / Subnet Fan-Out
	if isPrivateIP(ev.DstIP) && ev.Direction == "OUTBOUND" && ev.DstIP != "127.0.0.1" {
		e.mu.Lock()
		targetMap, exists := e.lateralTargets[ev.EndpointID]
		if !exists {
			targetMap = make(map[string]time.Time)
			e.lateralTargets[ev.EndpointID] = targetMap
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
		if (distinctTargets >= 5) || (distinctTargets >= 3 && isOffHours && isWorkstation) {
			alertKey := fmt.Sprintf("lateral_sweep:%s", ev.EndpointID)
			if !e.shouldSuppressAlert(alertKey, 20*time.Second) {
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       fmt.Sprintf("Lateral Port Sweep / Internal Fan-Out (%d Hosts)", distinctTargets),
					Description: fmt.Sprintf("Endpoint %s initiated rapid internal connection sweep to %d distinct hosts on subnet within 60 seconds.", ev.EndpointID, distinctTargets),
					Severity:    "CRITICAL",
					Mitigated:   false,
				}
				_ = e.store.CreateAlert(alert)
				_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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
				log.Printf("[!] ANOMALY ALERT [CRITICAL]: %s on %s -> %d targets in 60s", alert.Title, ev.EndpointID, distinctTargets)
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
			_ = e.store.CreateAlert(alert)
			_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
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
			_ = e.store.CreateAnomalyAlert(anomaly)
			log.Printf("[!] ANOMALY ALERT [CRITICAL]: %s on endpoint %s", anomaly.Title, anomaly.EndpointID)
		}
	}

	// 10. In-Flight DPI: Suspicious DGA Domain & High-Entropy C2 SNI
	targetDomain := ev.SNI
	if targetDomain == "" {
		targetDomain = ev.Domain
	}
	if targetDomain != "" && len(targetDomain) >= 12 {
		entropy := calcEntropy(targetDomain)
		hasSuspiciousTLD := strings.HasSuffix(targetDomain, ".top") ||
			strings.HasSuffix(targetDomain, ".xyz") ||
			strings.HasSuffix(targetDomain, ".cc") ||
			strings.HasSuffix(targetDomain, ".su") ||
			strings.HasSuffix(targetDomain, ".tk") ||
			strings.HasSuffix(targetDomain, ".biz")

		if entropy >= 3.85 || (entropy >= 3.5 && hasSuspiciousTLD) {
			alertKey := fmt.Sprintf("dga:%s:%s", ev.EndpointID, targetDomain)
			if !e.shouldSuppressAlert(alertKey, 15*time.Second) {
				sev := "HIGH"
				if entropy >= 4.1 || hasSuspiciousTLD {
					sev = "CRITICAL"
				}
				alert := storage.Alert{
					ID:          uuid.New().String(),
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Timestamp:   now,
					Title:       fmt.Sprintf("Suspicious DGA / High-Entropy Domain Detected (%s)", targetDomain),
					Description: fmt.Sprintf("Process %s contacted high-entropy domain %s (Shannon Entropy: %.2f) via %s.", procName, targetDomain, entropy, ev.DstIP),
					Severity:    sev,
					Mitigated:   false,
				}
				_ = e.store.CreateAlert(alert)
				_ = e.store.CreateAnomalyAlert(storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "SUSPICIOUS_DGA_DOMAIN",
					Severity:    sev,
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Target Domain: %s | Shannon Entropy: %.2f | Dst IP: %s:%d", targetDomain, entropy, ev.DstIP, ev.DstPort),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [%s]: %s on %s -> %s (Entropy: %.2f)", sev, alert.Title, ev.EndpointID, targetDomain, entropy)
			}
		}
	}
}

func calcEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	entropy := 0.0
	total := float64(len(s))
	for _, count := range counts {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

