package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/netaddr"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

type IsolateFunc func(endpointID string, reason string) error

type Engine struct {
	store          *storage.Store
	onAutoIsolate  IsolateFunc
	eventsChan     <-chan storage.Event
	mu             sync.Mutex
	portHistory    map[string][]portAccess            // endpointID -> accesses
	beaconTracker  *windowCache[*beaconWindow]        // bounded endpoint/peer/process histories
	lateralTargets map[string]map[string]*sweepTarget // endpointID:process -> targetIP -> last seen and ports
	inventory      map[string]map[string]bool         // tenant -> enrolled endpoint addresses (admin_fanout.go)
	inventoryAt    map[string]time.Time
	alertCooldown  map[string]time.Time // alertKey -> last triggered time
	silence        *silenceWatch        // endpoints already reported as gone quiet
	classes        classCache           // endpoints the classifier reads (class.go)
	tuning         storage.DetectionTuning
	tuningAt       time.Time
	cancel         context.CancelFunc

	// sink, when set, receives findings instead of the store, and no device
	// memory is written; pinned, when set, is the tuning used. Both are
	// for the floor drill (drill.go), which evaluates synthetic events through
	// a throwaway engine and stores nothing.
	sink   func(storage.AnomalyAlert)
	pinned *storage.DetectionTuning
}

// tuningCacheTTL keeps the detector off the database on every packet without
// making an operator wait for a restart to see their change take effect.
const tuningCacheTTL = 15 * time.Second

// settings returns the current tuning, re-reading it at most every few seconds.
func (e *Engine) settings() storage.DetectionTuning {
	if e.pinned != nil {
		return *e.pinned
	}
	e.mu.Lock()
	if time.Since(e.tuningAt) < tuningCacheTTL && e.tuningAt.After(time.Time{}) {
		t := e.tuning
		e.mu.Unlock()
		return t
	}
	e.mu.Unlock()

	// The floor (floor.go) runs wherever the saved row is weaker; the
	// Aico push's detection-policy note names each such place.
	t, _ := ClampToFloor(e.store.GetDetectionTuning())

	e.mu.Lock()
	e.tuning = t
	e.tuningAt = time.Now()
	e.mu.Unlock()
	return t
}

// alertf logs a finding the engine raised; the floor drill's synthetic
// findings are not logged as alerts.
func (e *Engine) alertf(format string, args ...any) {
	if e.sink == nil {
		log.Printf(format, args...)
	}
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
		beaconTracker:  newWindowCache[*beaconWindow](8192),
		lateralTargets: make(map[string]map[string]*sweepTarget),
		inventory:      make(map[string]map[string]bool),
		inventoryAt:    make(map[string]time.Time),
		alertCooldown:  make(map[string]time.Time),
		silence:        newSilenceWatch(),
	}
}

func (e *Engine) Start(ctx context.Context) {
	subCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Alerting on absence does not depend on events arriving - that is the
	// point of it - so it starts before the events channel is checked.
	// Every finding is classified before it is written, whoever writes it.
	e.store.SetAlertClassifier(e.stampClass)
	e.StartSilenceWatch(subCtx)
	go e.backfillHuntTier()
	// Events arriving meanwhile are safe: a runtime first seen live starts
	// learning, and the seed then moves its baseline start back to when the
	// profiles first saw it (storage.SeedAgentDestinations).
	go e.SeedAgentBaselines()

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

// recordAnomaly writes a finding, classed (page, record or digest) and with
// its hunt tier.
//
// It happens here rather than at each detector so that no branch can forget
// to do it. A held finding is written in full - the evidence, the severity,
// the technique - and only its visibility changes.
func (e *Engine) recordAnomaly(ev storage.Event, geo threatintel.GeoRecord, ep storage.Endpoint, anomaly storage.AnomalyAlert) error {
	anomaly.Evidence = withFlowContext(anomaly.Evidence, ev, geo)
	if ev.SrcIP != "" {
		if asset, err := e.store.GetAsset(ev.SrcIP); err == nil && asset != nil && (asset.TenantID == "" || asset.TenantID == anomaly.TenantID) {
			fields := map[string]any{}
			if json.Unmarshal([]byte(anomaly.Evidence), &fields) == nil && fields != nil {
				fields["source_asset_id"] = asset.ID
				raw, _ := json.Marshal(fields)
				anomaly.Evidence = string(raw)
			}
		}
	}

	applyTier(&anomaly, ep, e.settings(), func() bool { return e.store.RunsAgentRuntimes(anomaly.TenantID, anomaly.EndpointID) })
	// The role is the endpoint's as this event saw it, which the classifier's
	// cached endpoint list may not hold yet (a new enrolment, the drill).
	if ep.ID != "" {
		fields := map[string]any{}
		if json.Unmarshal([]byte(anomaly.Evidence), &fields) == nil && fields != nil {
			if _, ok := fields["source_role"]; !ok {
				fields["source_role"] = e.classContext().RoleOf(ep)
				raw, _ := json.Marshal(fields)
				anomaly.Evidence = string(raw)
			}
		}
	}
	e.stampClass(&anomaly)
	if e.sink != nil {
		e.sink(anomaly)
		return nil
	}
	if err := e.store.CreateAnomalyAlert(anomaly); err != nil {
		log.Printf("[-] anomaly write failed for %s/%s: %v", anomaly.EndpointID, anomaly.Title, err)
		return err
	}
	return nil
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
	fields["protocol"] = ev.Protocol
	fields["protocol_name"] = storage.ProtocolName(int(ev.Protocol))
	if ev.Observation.Source != "" {
		fields["observation"] = ev.Observation
	}
	set("source_ip", ev.SrcIP)
	set("command_line", ev.CommandLine)
	set("user_identity", ev.UserIdentity)
	set("executable_sha256", ev.ExecutableSHA256)
	set("process_instance_id", ev.ProcessInstanceID)
	set("attribution_status", ev.AttributionStatus)
	set("domain", ev.Domain)
	set("sni", ev.SNI)
	set("actor", ev.Actor)
	fields["bytes_out"] = ev.BytesOut
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
	FirstSeen  map[string]bool
	LocationID string
}

// EvaluateBatch runs the detector only after the caller has durably accepted
// the batch. Shared endpoint, policy and GeoIP state is read once.
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
	if ev.ThreatMatch != nil {
		alertKey := fmt.Sprintf("nullify:%s:%s", ev.EndpointID, ev.DstIP)
		if !e.shouldSuppressAlert(alertKey, 10*time.Second) {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       fmt.Sprintf("%s connected to threat-listed %s", firstNonEmpty(endpoint.Hostname, ev.EndpointID), ev.DstIP),
				Description: fmt.Sprintf("Traffic matched indicator %s from %s (%s, confidence %d%%). Endpoint reported action: %s.", ev.ThreatMatch.Value, ev.ThreatMatch.Source, ev.ThreatMatch.ThreatType, ev.ThreatMatch.Confidence, ev.Action),
				Severity:    "CRITICAL",
				Mitigated:   ev.Action == "BLOCK",
			}
			intel := storage.AnomalyAlert{
				ID:          alert.ID,
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Hostname:    endpoint.Hostname,
				Evidence:    intelEvidence(ev),
				AnomalyType: "THREAT_INTEL_MATCH",
				Technique:   "T1071",
				Severity:    "CRITICAL",
				Title:       alert.Title,
				Description: alert.Description,
				Details:     alert.Description,
				ProcessPath: ev.ProcessPath,
				DstIP:       ev.DstIP,
				DstPort:     ev.DstPort,
				Timestamp:   now,
			}
			e.recordAnomaly(ev, geo, endpoint, intel)
			e.alertf("[!] DETECTION ALERT [CRITICAL]: %s on endpoint %s (%s)", alert.Title, alert.EndpointID, ev.DstIP)

			// A match pages at intel_page_confidence and isolates only the
			// roles in auto_isolate_roles: one stale feed entry an agent
			// touches during research must not cut the agent workstation or
			// the hypervisor off the network.
			cx := e.classContext()
			role := cx.RoleOf(endpoint)
			if class, _ := cx.Classify(intel); class == storage.ClassPage && cx.cfg.AutoIsolates(role) {
				e.autoIsolate(ev.EndpointID, "Automated Threat Nullification: "+alert.Title)
			} else {
				e.alertf("[i] threat-intelligence match on %s (%s role, confidence %d%%) not isolated automatically", ev.EndpointID, role, ev.ThreatMatch.Confidence)
			}
		}
	}

	e.checkSensitivePort(ev, geo, endpoint, now)

	// The detectors read one cached settings row rather than the numbers that
	// used to be compiled into them.
	cfg := e.settings()
	e.checkDecoy(ev, geo, endpoint, cfg, now)
	role := e.classContext().RoleOf(endpoint)
	isOffHours := cfg.IsOffHours(now)
	isInteractiveShell := isInterpreterOrShell(procName)

	// Expected rules are the operator's, held in the database and shown in
	// the console, not a table compiled into this file.
	//
	// They name programs by path, so a process whose agent found that its
	// reported path is not the file it runs (a user namespace bind mount over a
	// listed path, a container's own path) matches none of them.
	quietPath := ev.ProcessPath
	if ev.AttributionStatus == pathMismatch {
		quietPath = ""
	}

	// The sweeps and the resolver bypass are floor rules too: no expected
	// rule silences them.
	e.checkSweeps(ev, geo, endpoint, cfg, quietPath, isInteractiveShell, isOffHours, now)
	e.checkLabEscape(ev, geo, endpoint, cfg, role, quietPath, now)
	e.checkResolverBypass(ev, geo, endpoint, cfg, procName, isInteractiveShell, now)
	// The floor drill (a sink) writes no device memory into the live store.
	if e.sink == nil {
		e.checkNewPlace(ev, geo, endpoint, cfg, quietPath, now)
	}

	// The behavioural detectors below are the ones an operator tunes.
	warming, warmLeft := warmingUp(endpoint, cfg, now)

	// Every place an operator can say "this is normal here" is one question to
	// one matcher: the tuning's expected rules (storage.ExpectCtx). A program is
	// named by its installed path, so a process whose agent found that its
	// reported path is not the file it runs matches no rule that names a
	// program; a workload (an interpreter and what it runs) is vouched only
	// when its path matched too (vouchedWorkload).
	vouched := vouchedWorkload(ev.ProcessPath, ev.CommandLine, ev.AttributionStatus)
	expect := expectedFor(cfg, expectCtx(ev, geo, endpoint, role, quietPath, vouched))

	// Agent runtimes are judged against their own baselines.
	e.checkAgentEgress(ev, geo, endpoint, cfg, procName, isInteractiveShell, warming, expect, now)

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
		ev.BytesOut >= cloudStorageEgressBytes && isCloudStorageDestination(geo, ev) && !expect(storage.KindCloudStorage) {
		alertKey := fmt.Sprintf("storageegress:%s:%s:%s", ev.EndpointID, procName, strings.ToLower(geo.Org))
		if !warming && !e.shouldSuppressAlert(alertKey, time.Duration(cfg.BandwidthCooldown)*time.Minute) {
			title := fmt.Sprintf("Bulk upload to cloud storage (%s)", describeStorageService(geo, ev))
			description := fmt.Sprintf("Process %s uploaded %s to %s at %s:%d. Volume to a storage service is reported even when the process and network are expected here, because using a service the estate already trusts is what this technique looks like.",
				procName, humanBytes(ev.BytesOut), describeStorageService(geo, ev), ev.DstIP, ev.DstPort)
			e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
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
			e.alertf("[!] ANOMALY ALERT [HIGH]: %s on %s -> %d bytes", title, ev.EndpointID, ev.BytesOut)
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
	//
	// Rented compute is the exception to the exception: a browser extension or
	// an injected page calling home to a rented machine is the beacon this
	// detector is for, and "the browser" was only ever a program name.
	// A collection cadence is not a packet cadence. Keep legacy behavior for
	// older agents, but require one intact socket-I/O observation from new ones.
	cadenceUsable := ev.Observation.Source == "" ||
		(ev.Observation.Timing == "socket_io" && ev.Observation.Count == 1 && ev.Observation.Lost == 0 && !ev.Observation.Incomplete &&
			ev.Observation.FirstAt != nil && ev.Observation.LastAt != nil && ev.Observation.FirstAt.Equal(*ev.Observation.LastAt))
	beaconKey := fmt.Sprintf("%q:%q:%d:%q:%d", ev.EndpointID, ev.DstIP, ev.DstPort, cleanPath, ev.Protocol)
	if !cadenceUsable {
		e.mu.Lock()
		e.beaconTracker.remove(beaconKey)
		if ev.Observation.Lost > 0 || ev.Observation.Incomplete {
			// Collector loss can concern any peer from this endpoint/transport.
			prefix, suffix := fmt.Sprintf("%q:", ev.EndpointID), fmt.Sprintf(":%d", ev.Protocol)
			e.beaconTracker.removeMatching(func(key string) bool { return strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) })
		}
		e.mu.Unlock()
	}

	if cfg.BeaconOn && cadenceUsable && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) &&
		!expect(storage.KindBeacon) {
		e.mu.Lock()
		bWin := e.beaconTracker.get(beaconKey, func() *beaconWindow { return &beaconWindow{} })
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
			cooldown := time.Duration(cfg.BeaconCooldownMin) * time.Minute
			// A beacon is first raised once it has the minimum samples and
			// span, usually minutes in. One that later holds at
			// beacon_page_score for half an hour is raised once more (the
			// strong key), since that is the shape that can page.
			strong := bev.Score >= cfg.BeaconPageScore && bev.SpanMinutes >= float64(cfg.BeaconPageSpanMin)
			first := !e.shouldSuppressAlert(alertKey, cooldown)
			raise, strengthened := first, false
			if strong && !e.shouldSuppressAlert(alertKey+":strong", cooldown) && !first {
				raise, strengthened = true, true
			}
			if raise {
				// The severity follows the evidence. A conversation that only
				// just cleared the bar is worth looking at; one that is
				// metronomic to within a few percent for an hour is not the
				// same finding and should not wear the same word.
				severity := "MEDIUM"
				if strong {
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
				e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
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
					Evidence:    e.beaconClassEvidence(bev.JSON(cfg.BeaconScore), ev, cfg, procName, beaconOwner, strengthened),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				e.alertf("[!] ANOMALY ALERT [%s]: beaconing %s -> %s:%d (%s)", severity, ev.EndpointID, ev.DstIP, ev.DstPort, bev.Summary())
			}
		} else if isBeacon && warming {
			e.alertf("[*] Held a beacon finding on %s -> %s: the endpoint is %s into its %dh learning period (%s)",
				ev.EndpointID, ev.DstIP, (time.Duration(cfg.WarmupHours)*time.Hour - warmLeft).Round(time.Minute), cfg.WarmupHours, bev.Summary())
		}
	}
}

// checkSensitivePort raises the sensitive-port floor: SMB, RDP, telnet or RPC
// leaving the network. It runs before expected rules, so none can hide it.
func (e *Engine) checkSensitivePort(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, now time.Time) {
	if ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) && FloorPort(int(ev.DstPort)) {
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
			e.recordAnomaly(ev, geo, endpoint, anomaly)
			e.alertf("[!] ANOMALY ALERT [CRITICAL]: %s on endpoint %s", anomaly.Title, anomaly.EndpointID)
		}
	}
}

func isPrivateIP(ipStr string) bool {
	return netaddr.IsLocal(ipStr)
}

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
// intelEvidence is what a threat-list match carries for the classifier and
// the feed: the list's confidence and threat type, and whether the endpoint
// let the connection through.
func intelEvidence(ev storage.Event) string {
	raw, _ := json.Marshal(map[string]any{"intel_confidence": ev.ThreatMatch.Confidence, "intel_type": ev.ThreatMatch.ThreatType,
		"intel_source": ev.ThreatMatch.Source, "action": ev.Action})
	return string(raw)
}

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

// pathMismatch is the attribution status an agent reports when the path the
// kernel gives for a process's executable does not name, on the host, the file
// that runs.
const pathMismatch = storage.AttributionPathMismatch

// isKnownInfrastructureProcess reports a container runtime or local resolver,
// by the path it is installed at and the account it runs as, whose job is to
// reach many ports and hosts. Base names and build-cache test binaries
// ("go-build", ".test") used to count, and any program could be given either
// from a writable directory; a path alone still could, bind-mounted over the
// real one in a user namespace or preloaded into it, by a login user - who
// cannot run it as the system or the daemon's own account.
func isKnownInfrastructureProcess(procPath, user string) bool {
	accounts, ok := knownInfrastructurePaths[storage.ProcessPathKey(procPath)]
	if !ok {
		return false
	}
	if storage.IsServiceAccount(user, "") {
		return true
	}
	for _, account := range accounts {
		if storage.IsServiceAccount(user, account) {
			return true
		}
	}
	return false
}

// knownInfrastructurePaths maps each path to the service accounts its daemon
// drops to, beyond root.
var knownInfrastructurePaths = map[string][]string{
	"/usr/bin/docker-proxy": nil, "/usr/libexec/docker/docker-proxy": nil,
	"/usr/bin/dockerd": nil, "/usr/bin/containerd": nil, "/usr/bin/runc": nil,
	"/usr/sbin/dnsmasq":                 {"nobody", "dnsmasq", "libvirt-dnsmasq"},
	"/usr/lib/systemd/systemd-resolved": {"systemd-resolve"},
	"/usr/bin/kubelet":                  nil, "/usr/bin/cilium-agent": nil,
	"/usr/sbin/avahi-daemon": {"avahi"},
	"/usr/bin/coredns":       {"coredns"}, "/usr/sbin/named": {"bind", "named"},
	"/usr/sbin/unbound": {"unbound"}, "/usr/bin/wireguard-go": nil,
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

// InvalidateCollectorWindows handles health-only heartbeats too: an empty
// event batch does not make a known observation gap disappear.
func (e *Engine) InvalidateCollectorWindows(endpointID string) {
	prefix := fmt.Sprintf("%q:", endpointID)
	e.mu.Lock()
	defer e.mu.Unlock()
	match := func(key string) bool { return strings.HasPrefix(key, prefix) }
	e.beaconTracker.removeMatching(match)
}
func (e *Engine) ObservationCoverage() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{"window_capacity": 8192, "beacon_windows": len(e.beaconTracker.entries), "beacon_evictions": e.beaconTracker.evictions}
}

// servedFlow says the local end of this flow is a listening socket answering a
// client. The agent reports every TCP socket it reads as OUTBOUND with its own
// local port as the source port, so an accepted connection arrives as the
// server's service port talking to the client's ephemeral port, once per
// client socket: to the sweep rules that is one host reaching many ports and
// hosts, which is what a busy listener (a web console, a proxy) looks like
// from the inside. A source port below the network's ephemeral range talking
// to one inside it is the listener's side (tuning ephemeral_port_from); an
// agent that marks a flow INBOUND needs no inference, since only OUTBOUND
// flows are judged.
func servedFlow(ev storage.Event, cfg storage.DetectionTuning) bool {
	from := uint16(cfg.EphemeralPortFrom)
	return ev.SrcPort > 0 && ev.SrcPort < from && ev.DstPort >= from
}

// checkSweeps runs the port-sweep and lateral-sweep floor rules. They run
// before the expected rules and do not consult them: they are
// operator data, and a sweep is how an intruder maps and moves, whatever the
// program's path says. Only the installed infrastructure in code (a container
// runtime, a local resolver, run as its own account) is exempt.
func (e *Engine) checkSweeps(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	quietPath string, isInteractiveShell, isOffHours bool, now time.Time) {
	// 6. Rapid Port Sweeps / Reconnaissance (Evaluated per-process)
	procKey := strings.ToLower(filepath.Base(ev.ProcessPath))
	if procKey == "" || procKey == "." {
		procKey = "unknown"
	}
	// A scan of the host's own loopback is a program talking to itself, and a
	// served flow (a listener answering a client) is the other side's
	// connection seen from here: neither is this host scanning.
	served := servedFlow(ev, cfg)
	if ev.Direction == "OUTBOUND" && ev.DstPort > 0 && !netaddr.IsLoopback(ev.DstIP) && !served &&
		!isKnownInfrastructureProcess(quietPath, ev.UserIdentity) {
		sweepKey := fmt.Sprintf("%s:%s", ev.EndpointID, procKey)
		e.mu.Lock()
		history := e.portHistory[sweepKey]
		var recent []portAccess
		seenPorts := make(map[uint16]bool)
		for _, p := range history {
			if now.Sub(p.t) <= portSweepWindow {
				recent = append(recent, p)
				seenPorts[p.port] = true
			}
		}
		recent = append(recent, portAccess{port: ev.DstPort, t: now})
		seenPorts[ev.DstPort] = true
		e.portHistory[sweepKey] = recent
		distinctCount := len(seenPorts)
		e.mu.Unlock()

		portThreshold := portSweepPorts
		if isInteractiveShell {
			portThreshold = portSweepShellPorts
		}
		if distinctCount >= portThreshold {
			alertKey := fmt.Sprintf("portsweep:%s:%s", ev.EndpointID, procKey)
			if !e.shouldSuppressAlert(alertKey, sweepCooldown) {
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
				e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
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
					Evidence:    scanEvidence(e.classContext().ZoneOf(ev.DstIP), distinctCount),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				e.alertf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s (%s)", alert.Title, alert.EndpointID, procKey)
			}
		}
	}

	// 7. Topological Graph Outlier: Internal Lateral Movement / Subnet Fan-Out (Evaluated per-process)
	destination, _ := netaddr.Parse(ev.DstIP)
	unicastHost := destination.IsGlobalUnicast() || destination.IsLinkLocalUnicast()
	if isPrivateIP(ev.DstIP) && unicastHost && ev.Direction == "OUTBOUND" && !served && !netaddr.IsLoopback(ev.DstIP) &&
		!cfg.IsContainerAddress(ev.DstIP) && !isKnownInfrastructureProcess(quietPath, ev.UserIdentity) {

		e.mu.Lock()
		lateralKey := fmt.Sprintf("%s:%s", ev.EndpointID, procKey)
		targetMap, exists := e.lateralTargets[lateralKey]
		if !exists {
			targetMap = make(map[string]*sweepTarget)
			e.lateralTargets[lateralKey] = targetMap
		}
		// Clean targets older than 60 seconds
		for ip, t := range targetMap {
			if now.Sub(t.at) > lateralWindow {
				delete(targetMap, ip)
			}
		}
		target := targetMap[ev.DstIP]
		if target == nil {
			target = &sweepTarget{ports: map[uint16]bool{}, actors: map[string]bool{}}
			targetMap[ev.DstIP] = target
		}
		target.at = now
		target.ports[ev.DstPort] = true
		target.actors[ev.Actor] = true
		distinctTargets := len(targetMap)
		window := make(map[string]*sweepTarget, len(targetMap))
		for ip, t := range targetMap {
			window[ip] = &sweepTarget{at: t.at, ports: maps.Clone(t.ports), actors: maps.Clone(t.actors)}
		}
		e.mu.Unlock()

		// Off-hours is the operator's window in the operator's zone (the
		// tuning), as for every other detector. This used to be 22-05 UTC,
		// which is early evening in the Americas.
		isWorkstation := endpoint.RoleTag == "workstation" || endpoint.RoleTag == ""

		// The thresholds are the floor (floor.go): fewer hosts for a shell or
		// interpreter (cmd.exe, powershell, python, bash, nmap), fewer again
		// off-hours on a workstation.
		threshold := lateralHosts
		if isInteractiveShell {
			threshold = lateralShellHosts
			if isOffHours && isWorkstation {
				threshold = lateralShellHostsOffHours
			}
		} else if isOffHours && isWorkstation {
			threshold = lateralHostsOffHours
		}

		routine, why := false, ""
		if distinctTargets >= threshold {
			routine, why = adminFanout(cfg, endpoint, expectCtx(ev, geo, endpoint, e.classContext().RoleOf(endpoint), quietPath, ""), window, func(ip string) bool { return e.inventoried(ev.TenantID, ip) })
			if routine {
				e.alertf("[i] lateral sweep not raised on %s (%s): routine administration, %s", ev.EndpointID, procKey, why)
			}
		}
		if distinctTargets >= threshold && !routine {
			// A sweep reaching a floor port has its own cooldown: an earlier
			// sweep on ordinary ports (explained, a note) cannot hide it.
			floor := sweepFloorPorts(window)
			alertKey := fmt.Sprintf("lateral_sweep:%s:%s", ev.EndpointID, procKey)
			if len(floor) > 0 {
				alertKey = fmt.Sprintf("lateral_sweep_floor:%s:%s", ev.EndpointID, procKey)
			}
			if !e.shouldSuppressAlert(alertKey, sweepCooldown) {
				zoneHosts := map[string]int{}
				cx := e.classContext()
				for ip := range window {
					zoneHosts[cx.ZoneOf(ip)]++
				}
				sweepEvidence, _ := json.Marshal(map[string]any{"sweep_targets": sweepTargetList(window), "sweep_window_seconds": 60, "admin_rule": why,
					"sweep_actor": sweepActor(window), "floor_ports": floor, "zone_hosts": zoneHosts})
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
				e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
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
					Evidence:    string(sweepEvidence),
					ProcessPath: ev.ProcessPath,
					DstIP:       ev.DstIP,
					DstPort:     ev.DstPort,
					Timestamp:   now,
				})
				e.alertf("[!] ANOMALY ALERT [CRITICAL]: %s on %s (%s) -> %d targets in 60s", alert.Title, ev.EndpointID, procKey, distinctTargets)
			}
		}
	}
}
