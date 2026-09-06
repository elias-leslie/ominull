package detector

import (
	"context"
	"encoding/json"
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

// bandwidthRingSize bounds what a process's baseline is built from. Sixty-four
// transfers is enough to describe an ordinary working volume and recent enough
// that a machine whose job changed last week is judged on what it does now.
const bandwidthRingSize = 64

type bandwidthStats struct {
	samples []float64 // most recent first bandwidthRingSize transfers, unordered
	next    int
	count   int64
}

// observe scores a transfer against the baseline built from the transfers
// before it, and only then folds it into that baseline.
//
// The order matters and used to be the other way round. Scoring a value against
// a distribution that already contains it suppresses exactly the outliers this
// detector exists to find: the new point pulls the centre toward itself and
// inflates the spread it is then divided by.
//
// The statistic is the modified z-score, 0.6745·(x−median)/MAD, not the mean
// and standard deviation this used to compute. Network transfer sizes are
// heavy-tailed - a browser sends a few kilobytes a hundred times and eight
// megabytes once - and a mean with a standard deviation is not robust to that:
// one large ordinary upload lifts both, so the next ordinary upload scores
// modestly while the first scored fifty. The median and the median absolute
// deviation are unmoved by a handful of extreme values, which is the whole
// reason the robust statistics literature reaches for them on data shaped like
// this.
//
// The returned centre, spread and count describe the baseline as it stood
// before this value, which is what the alert then quotes.
func (b *bandwidthStats) observe(val float64) (median float64, mad float64, z float64, baseline int64) {
	baseline = b.count
	median, mad = b.summary()

	switch {
	case baseline < 2:
		// Nothing to compare against yet.
	case mad > 0:
		z = 0.6745 * (val - median) / mad
	case median > 0 && val > median:
		// A process whose transfers are all the same size has a MAD of zero,
		// and dividing by it would be an infinity dressed up as a score. What
		// the operator wants to know is how many times its usual volume this
		// transfer was, expressed on the same scale as the threshold beside it.
		z = 3.5 * (val / median)
	}

	if len(b.samples) < bandwidthRingSize {
		b.samples = append(b.samples, val)
	} else {
		b.samples[b.next] = val
		b.next = (b.next + 1) % bandwidthRingSize
	}
	b.count++

	return median, mad, z, baseline
}

// summary returns the median and the median absolute deviation of the retained
// samples. medianOf copies before sorting, so the ring keeps its insertion
// order and the oldest entry stays the one overwritten next.
func (b *bandwidthStats) summary() (median float64, mad float64) {
	if len(b.samples) == 0 {
		return 0, 0
	}
	median = medianOf(b.samples)

	deviations := make([]float64, len(b.samples))
	for i, v := range b.samples {
		deviations[i] = math.Abs(v - median)
	}
	return median, medianOf(deviations)
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
	silence        *silenceWatch                   // endpoints already reported as gone quiet
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
		silence:        newSilenceWatch(),
	}
}

func (e *Engine) Start(ctx context.Context) {
	subCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Alerting on absence does not depend on events arriving - that is the
	// point of it - so it starts before the events channel is checked.
	e.StartSilenceWatch(subCtx)

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

func (e *Engine) recordAnomaly(ev storage.Event, geo threatintel.GeoRecord, anomaly storage.AnomalyAlert) {
	anomaly.Evidence = withFlowContext(anomaly.Evidence, ev, geo)
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] anomaly write failed for %s/%s: %v", anomaly.EndpointID, anomaly.Title, err)
	}
}

// withFlowContext folds what the agent already reported about the process into
// the finding's structured evidence.
//
// Every flow arrives carrying the command line, the user it ran as, the
// executable's hash and the parent process id, and no detector read any of
// them: an analyst deciding whether a finding mattered had to leave the alert
// and go looking. The detector's own numbers stay exactly as they were; this
// only adds the context around them.
func withFlowContext(evidence string, ev storage.Event, geo threatintel.GeoRecord) string {
	fields := map[string]any{}
	if strings.TrimSpace(evidence) != "" {
		if err := json.Unmarshal([]byte(evidence), &fields); err != nil {
			// A detector that wrote something other than a JSON object keeps
			// what it wrote; losing its numbers to add context would be a poor
			// trade.
			return evidence
		}
	}

	set := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			fields[key] = value
		}
	}
	set("command_line", ev.CommandLine)
	set("user_identity", ev.UserIdentity)
	set("executable_sha256", ev.ExecutableSHA256)
	set("process_instance_id", ev.ProcessInstanceID)
	set("attribution_status", ev.AttributionStatus)
	set("destination_owner", geo.Org)
	set("destination_asn", geo.ASN)
	set("destination_tenancy", geo.Tenancy)
	set("attribution_source", geo.Source)
	if ev.ProcessID != 0 {
		fields["process_id"] = ev.ProcessID
	}
	if ev.ParentPID != 0 {
		// An interpreter spawned by a shell is the shape every beaconing
		// write-up describes, and the parent is how an analyst sees it.
		fields["parent_pid"] = ev.ParentPID
	}
	if strings.TrimSpace(ev.ParentProcessInstanceID) != "" {
		fields["parent_process_instance_id"] = ev.ParentProcessInstanceID
	}

	if len(fields) == 0 {
		return evidence
	}
	blob, err := json.Marshal(fields)
	if err != nil {
		return evidence
	}
	return string(blob)
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
			e.recordAnomaly(ev, geo, storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "THREAT_INTEL_MATCH",
				Technique:   "T1071",
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

	isInteractiveShell := isInterpreterOrShell(procName)

	// Both lists are the operator's, held in the database and shown in the
	// console, not a table compiled into this file.
	isTrustedSys := cfg.IsQuietProcess(strings.ToLower(procName))
	isTrustedDst := cfg.IsQuietOrg(geo.Org)

	// isVouched is the narrower question: this process, to this owner. A quiet
	// org alone silenced every process on every port to networks that front a
	// large part of the web - which is where beaconing hides, not where it is
	// absent. The beacon and volume detectors below ask this instead.
	isVouched := cfg.IsVouchedPair(procName, geo.Org, geo.Tenancy)

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
			e.recordAnomaly(ev, geo, storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "OFF_HOURS_ACTIVITY",
				Technique:   "T1029",
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
		median, mad, zScore, samples := stats.observe(float64(ev.BytesOut))
		e.mu.Unlock()

		baselined := samples >= int64(cfg.BandwidthMinSamples)
		// The floor was 50KB, which a browser clears on a single page load, and
		// the destination was not consulted at all: production's first CRITICAL
		// after the scoring fix was chrome sending 255KB to Google, 51 standard
		// deviations out because a browser's transfer sizes are heavy-tailed
		// and nothing about that is exfiltration. An operator who has vouched
		// for a network has already answered this question, and a megabyte is
		// the smallest transfer worth waking someone for.
		outlier := baselined && zScore > 3.5 && ev.BytesOut > 1024*1024 && !isVouched
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
					Description: bandwidthDescription(baselined, procName, ev.BytesOut, ev.DstIP, ev.DstPort, median, mad, zScore, samples),
					Severity:    bwSeverity,
					Mitigated:   false,
				}
				e.recordAnomaly(ev, geo, storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "BANDWIDTH_SPIKE",
					Technique:   "T1030",
					Severity:    bwSeverity,
					Title:       alert.Title,
					Description: alert.Description,
					Details:     fmt.Sprintf("Measured: %d bytes | Samples: %d | Usual transfer: %.0f bytes | Median absolute deviation: %.0f | Modified Z: %.2f | %s", ev.BytesOut, samples, median, mad, zScore, describeOwner(geo)),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				log.Printf("[!] ANOMALY ALERT [%s]: %s on %s -> %d bytes (Z=%.2f over %d samples)", bwSeverity, alert.Title, ev.EndpointID, ev.BytesOut, zScore, samples)
			}
		}
	}

	// 3b. Bulk egress to a cloud storage service (MITRE DET0570)
	//
	// This is the one case where being vouched for is not an answer. Staging
	// data in the same file-sharing service the estate uses every day is the
	// technique - the traffic is meant to look ordinary, and any tuning that
	// silences "chrome to a storage provider" silences the exfiltration with
	// it. So a large single transfer to a storage service is reported whatever
	// the quiet lists say, at a volume high enough that ordinary document work
	// does not reach it.
	if cfg.BandwidthOn && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		ev.BytesOut >= cloudStorageEgressBytes && isCloudStorageDestination(geo, ev) {
		alertKey := fmt.Sprintf("storageegress:%s:%s:%s", ev.EndpointID, procName, strings.ToLower(geo.Org))
		if !warming && !e.shouldSuppressAlert(alertKey, time.Duration(cfg.BandwidthCooldown)*time.Minute) {
			title := fmt.Sprintf("Bulk upload to cloud storage (%s)", describeStorageService(geo, ev))
			description := fmt.Sprintf("Process %s uploaded %s to %s at %s:%d. Volume to a storage service is reported even when the process and network are expected here, because using a service the estate already trusts is what this technique looks like.",
				procName, humanBytes(ev.BytesOut), describeStorageService(geo, ev), ev.DstIP, ev.DstPort)
			e.recordAnomaly(ev, geo, storage.AnomalyAlert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "CLOUD_STORAGE_EGRESS",
				Technique:   "T1567.002",
				Severity:    "HIGH",
				Title:       title,
				Description: description,
				Details:     fmt.Sprintf("Measured: %d bytes | Threshold: %d bytes | Process: %s | %s", ev.BytesOut, int64(cloudStorageEgressBytes), ev.ProcessPath, describeOwner(geo)),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] ANOMALY ALERT [HIGH]: %s on %s -> %d bytes", title, ev.EndpointID, ev.BytesOut)
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
	//
	// That exemption is now the process talking to the owner rather than the
	// owner alone. "Cloudflare is normal here" silenced every process reaching a
	// network that fronts much of the web, and an implant beaconing through a
	// CDN is the case this detector exists for. Chrome to Cloudflare stays
	// quiet; python or curl to the same network is a finding again.
	//
	// One exception, learned from production: a browser is not a candidate for
	// this detector on a network that resolves. Browsers hold keepalives open
	// to whatever the user is looking at - Chrome scored five separate beacon
	// findings against five Google Cloud addresses in one minute, all of them
	// ordinary web sessions, because a site being hosted on rented compute says
	// nothing about the browser talking to it. Browser-borne exfiltration shows
	// up in the volume and storage rules above, which still apply in full.
	browserToKnownNetwork := cfg.IsQuietClient(procName) && geo.Resolved()
	if cfg.BeaconOn && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!isTrustedSys && !isVouched && !browserToKnownNetwork {
		beaconKey := fmt.Sprintf("%s:%s:%s", ev.EndpointID, ev.DstIP, procName)
		e.mu.Lock()
		bWin, exists := e.beaconTracker[beaconKey]
		if !exists {
			bWin = &beaconWindow{}
			e.beaconTracker[beaconKey] = bWin
		}
		bev, isBeacon := bWin.record(now, ev.BytesOut, ev.BytesIn+ev.BytesOut, cfg)
		e.mu.Unlock()

		if isBeacon && !warming {
			// Keyed on the counterparty, not the address, for the same reason
			// the first-seen detector is: one CDN-fronted service answers from
			// a dozen addresses, and python3.13 holding one conversation open
			// produced four identical findings naming four Cloudflare and
			// Akamai addresses. The address is still in the finding; it is just
			// not what decides whether this is news.
			beaconOwner := strings.ToLower(strings.TrimSpace(geo.Org))
			if beaconOwner == "" {
				beaconOwner = ev.DstIP
			}
			alertKey := fmt.Sprintf("beacon:%s:%s:%s", ev.EndpointID, procName, beaconOwner)
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
					Title:      fmt.Sprintf("Periodic beaconing by %s to %s (every ~%.0fs)", procName, describeCounterparty(geo, ev), bev.MeanInterval),
					Description: fmt.Sprintf(
						"%s has connected to %s:%d %d times over %.0f minutes at a near-constant interval of %.1fs (%.0f%% jitter), with payloads varying by %.0f%%.",
						procName, ev.DstIP, ev.DstPort, bev.Samples, bev.SpanMinutes, bev.MeanInterval, bev.CoefVariation*100, bev.SizeVariation*100),
					Severity:  severity,
					Mitigated: false,
				}
				e.recordAnomaly(ev, geo, storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "C2_BEACONING",
					Technique:   "T1071.001",
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
			e.recordAnomaly(ev, geo, storage.AnomalyAlert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "NOVEL_DESTINATION",
				Technique:   "T1071",
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
				e.recordAnomaly(ev, geo, storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "PORT_SCAN_RECON",
					Technique:   "T1046",
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
				e.recordAnomaly(ev, geo, storage.AnomalyAlert{
					ID:          alert.ID,
					TenantID:    ev.TenantID,
					EndpointID:  ev.EndpointID,
					Hostname:    endpoint.Hostname,
					AnomalyType: "LATERAL_PORT_SWEEP",
					Technique:   "T1021",
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

	// 8. Interpreter or shell reaching the internet
	//
	// This fired on every external connection any interpreter made, at HIGH,
	// keyed per destination address with a fifteen-second cooldown and no quiet
	// list of any kind. That was survivable only while the interpreter match was
	// broken: correcting it so python3.13 is recognised turned one ordinary
	// application worker on one workstation into seventy-one HIGH findings in a
	// morning, each naming a different CDN address for the same conversation.
	//
	// "An interpreter talked to the internet" is not a finding on its own - it
	// describes every developer machine and most servers. What is worth saying
	// is that an interpreter has started talking to a counterparty nobody has
	// vouched for, so the finding is keyed on the owner, holds for the tuned
	// first-seen period, and takes its severity from what is actually known
	// about the destination.
	if isInteractiveShell && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!isTrustedSys && !isVouched && !warming {
		owner := strings.ToLower(strings.TrimSpace(geo.Org))
		if owner == "" {
			owner = "unattributed"
		}
		alertKey := fmt.Sprintf("shell:%s:%s:%s", ev.EndpointID, strings.ToLower(procName), owner)
		if !e.shouldSuppressAlert(alertKey, time.Duration(cfg.FirstSeenCooldown)*time.Minute) {
			// Rented compute and unnamed networks are where an interpreter
			// reaching out is worth waking someone for. A named vendor or edge
			// network is worth recording and looking at in the morning.
			severity := "MEDIUM"
			switch {
			case !geo.Resolved() || geo.Tenancy == storage.TenancyHosting:
				severity = "HIGH"
			case ev.DstPort != 443 && ev.DstPort != 80:
				severity = "HIGH"
			}

			title := fmt.Sprintf("Script interpreter %s reaching %s", procName, describeCounterparty(geo, ev))
			description := fmt.Sprintf("%s connected out to %s:%d (%s). Nothing has vouched for this program talking to this counterparty; if it is expected here, mark it so and this conversation stops being reported.",
				procName, ev.DstIP, ev.DstPort, describeCounterparty(geo, ev))

			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       title,
				Description: description,
				Severity:    severity,
				Mitigated:   false,
			}
			e.recordAnomaly(ev, geo, storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				AnomalyType: "NOVEL_PROCESS_EGRESS",
				Technique:   "T1059",
				Severity:    severity,
				Title:       title,
				Description: description,
				Details:     fmt.Sprintf("Interpreter: %s | Target: %s:%d | %s | Command: %s", ev.ProcessPath, ev.DstIP, ev.DstPort, describeOwner(geo), firstLine(ev.CommandLine)),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			})
			log.Printf("[!] ANOMALY ALERT [%s]: %s on endpoint %s (%s:%d)", severity, title, alert.EndpointID, ev.DstIP, ev.DstPort)
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
				Technique:   "T1021",
				Severity:    "CRITICAL",
				Title:       fmt.Sprintf("Sensitive Port %d Egress to External IP", ev.DstPort),
				Description: fmt.Sprintf("Process %s attempted outbound connection on sensitive management/file-sharing port %d to %s (%s).", ev.ProcessPath, ev.DstPort, ev.DstIP, geo.CountryName),
				Details:     fmt.Sprintf("Port: %d | Target: %s (%s, %s) | Process: %s", ev.DstPort, ev.DstIP, geo.Country, geo.Org, ev.ProcessPath),
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			}
			e.recordAnomaly(ev, geo, anomaly)
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
// isInterpreterOrShell matches the base name of the process, not the tail of
// its path.
//
// The suffix test this replaces was wrong in both directions, and both showed
// up in production. "python3.13" does not end in "python3", so the interpreter
// behind most of this fleet's beacon-shaped traffic was never recognised; and
// any path ending in the two letters "nc" - /usr/bin/sync, a vnc client,
// zsync - was treated as netcat.
func isInterpreterOrShell(procName string) bool {
	base := strings.ToLower(strings.TrimSpace(procName))
	base = strings.TrimSuffix(base, ".exe")
	if base == "" {
		return false
	}

	switch base {
	case "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32",
		"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh",
		"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
		"python", "python2", "python3", "pythonw",
		"perl", "ruby", "php", "node", "nodejs", "deno", "bun",
		"osascript", "java", "lua", "tclsh":
		return true
	}

	// Versioned interpreters: python3.13, perl5.38, php8.3, ruby3.2. The
	// version is what the suffix match kept missing.
	for _, family := range []string{"python", "perl", "php", "ruby", "node", "lua"} {
		if !strings.HasPrefix(base, family) {
			continue
		}
		rest := strings.TrimPrefix(base, family)
		if rest == "" {
			return true
		}
		if isVersionSuffix(rest) {
			return true
		}
	}
	return false
}

// isVersionSuffix accepts what follows an interpreter's name in a versioned
// binary - "3", "3.13", "5.38" - and nothing else, so "pythonic-agent" and
// "nodeguard" are not interpreters.
func isVersionSuffix(rest string) bool {
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return rest[0] >= '0' && rest[0] <= '9'
}

// cloudStorageEgressBytes is the volume at which a single upload to a storage
// service is worth reporting on its own. Ten megabytes is the figure MITRE's
// detection strategy for exfiltration to cloud storage uses, and it is well
// above the document-sized traffic that fills an ordinary working day.
const cloudStorageEgressBytes = 10 * 1024 * 1024

// storageServices are the counterparties whose whole purpose is holding files.
// Matched against the resolved network owner and, when the agent reports one,
// the destination name.
var storageServices = []string{
	"dropbox", "box.com", "box, inc", "mega.nz", "mega limited", "backblaze",
	"wasabi", "pcloud", "sync.com", "mediafire", "wetransfer", "sendspace",
	"file.io", "anonfiles", "gofile", "storj", "icedrive", "koofr",
	"amazon s3", "google drive", "onedrive", "sharepoint", "azure blob",
	"digitalocean spaces", "linode object storage", "cloudflare r2",
}

// isCloudStorageDestination decides whether this destination is a place files
// are put. It reads the owner, and the destination name when the agent has one
// - which today it rarely does, so the owner carries most of this until the
// router work brings names.
func isCloudStorageDestination(geo threatintel.GeoRecord, ev storage.Event) bool {
	haystacks := []string{
		strings.ToLower(geo.Org),
		strings.ToLower(ev.Domain),
		strings.ToLower(ev.SNI),
	}
	for _, haystack := range haystacks {
		if strings.TrimSpace(haystack) == "" {
			continue
		}
		for _, service := range storageServices {
			if strings.Contains(haystack, service) {
				return true
			}
		}
	}
	return false
}

func describeStorageService(geo threatintel.GeoRecord, ev storage.Event) string {
	for _, candidate := range []string{ev.SNI, ev.Domain, geo.Org} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return "an unnamed storage service"
}

// humanBytes renders a transfer the way the finding reads out loud.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

// describeCounterparty names the far end the way the finding reads: the owner
// when one is known, the address when it is not.
func describeCounterparty(geo threatintel.GeoRecord, ev storage.Event) string {
	for _, candidate := range []string{ev.SNI, ev.Domain, geo.Org} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return "an unnamed network (" + ev.DstIP + ")"
}

// firstLine keeps a command line to something an alert row can hold. A worker
// invoked with a page of arguments is common, and the first part is the part
// that says what it is.
func firstLine(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "not reported"
	}
	if idx := strings.IndexAny(cmd, "\r\n"); idx >= 0 {
		cmd = cmd[:idx]
	}
	if len(cmd) > 160 {
		return cmd[:157] + "..."
	}
	return cmd
}

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
		return "Outbound volume " + deviations(zScore) + " above this process's usual volume"
	}
	return fmt.Sprintf("Large outbound transfer (%d bytes, no baseline yet)", bytesOut)
}

// deviations renders the modified z-score at a precision that means something.
// A process whose every previous transfer was the same size has almost no
// spread, so a genuine outlier against it scores enormously; printing that to
// one decimal place reads as a broken number rather than as a large one.
func deviations(z float64) string {
	switch {
	case z >= 1000:
		return "more than 1,000 deviations"
	case z >= 100:
		return fmt.Sprintf("%.0f deviations", z)
	default:
		return fmt.Sprintf("%.1f deviations", z)
	}
}

func bandwidthDescription(baselined bool, procName string, bytesOut int64, dstIP string, dstPort uint16, median, mad, zScore float64, samples int64) string {
	if baselined {
		return fmt.Sprintf("Process %s transmitted %d bytes to %s:%d. Its usual transfer over the %d before this one is %.0f bytes (median absolute deviation %.0f), which puts this one %s out.",
			procName, bytesOut, dstIP, dstPort, samples, median, mad, deviations(zScore))
	}
	return fmt.Sprintf("Process %s transmitted %d bytes to %s:%d. Only %d transfers have been observed for it, which is too few to say whether that is unusual for this process.",
		procName, bytesOut, dstIP, dstPort, samples)
}
