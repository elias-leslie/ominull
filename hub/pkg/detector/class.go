package detector

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"ominull/hub/pkg/netaddr"
	"ominull/hub/pkg/storage"
)

// Alert classes: page, record, digest.
//
// Every finding is written with its evidence. What changes is who hears about
// it. A page is pushed to the owner (through Nightshift) and asked about once
// per incident; a record is kept, searchable and counted; a digest is one
// daily line per group. The page list is fixed and short: a confident
// threat-intelligence hit, a decoy touched, a bulk upload to a new place,
// upload volume past a runtime's baseline, a rare metronomic beacon or one to
// a tunnel front, an always-on infrastructure host gone, a lab escape,
// sensitive-port egress, a sweep that reaches a floor port or many home hosts,
// and a port scan from a host that has no reason to scan. Network novelty
// (new destinations, new programs reaching out, the hour of day) is recorded,
// never paged: on a machine where AI agents work around the clock it
// describes ordinary work.
//
// Classify judges a stored finding, so the replay, the feed and the detector
// all use this one function. The detector stamps the facts it knew at the
// time (zones, prevalence, confidence) into the evidence; a finding written
// before those facts existed is judged from what it carries.

// Zones a sweep target falls in.
const (
	zoneLocal    = "local"
	zoneExternal = "external"
	zoneLab      = "lab"
	zoneInfra    = "infra"
	zoneHome     = "home"
)

// ClassContext is what classifying needs beyond the finding: the tuning, the
// enrolled endpoints and which of them have run an agent runtime.
type ClassContext struct {
	cfg      storage.DetectionTuning
	byID     map[string]storage.Endpoint
	byIP     map[string]storage.Endpoint
	observed map[string]bool
}

// NewClassContext builds a context from the endpoints; observed names the
// endpoint ids whose telemetry has shown an agent runtime.
func NewClassContext(cfg storage.DetectionTuning, endpoints []storage.Endpoint, observed map[string]bool) *ClassContext {
	cx := &ClassContext{cfg: cfg, byID: map[string]storage.Endpoint{}, byIP: map[string]storage.Endpoint{}, observed: observed}
	for _, ep := range endpoints {
		cx.byID[ep.ID] = ep
		if ep.Status != "retired" && ep.IP != "" {
			cx.byIP[ep.IP] = ep
		}
	}
	return cx
}

// RoleOf names an endpoint's role: an explicit role tag (agent, lab, infra,
// personal), else agent when the tuning names it agent-heavy or its telemetry
// has shown an agent runtime, lab when it is a parked guest or inside the lab
// networks, infra when it is a server or inside the infrastructure networks,
// and personal otherwise (laptops and desktops).
func (cx *ClassContext) RoleOf(ep storage.Endpoint) string {
	switch r := strings.ToLower(strings.TrimSpace(ep.RoleTag)); r {
	case storage.RoleAgent, storage.RoleLab, storage.RoleInfra, storage.RolePersonal:
		return r
	}
	switch {
	case cx.cfg.IsAgentHeavy(ep) || (cx.cfg.AgentHeavyObserved && cx.observed[ep.ID]):
		return storage.RoleAgent
	case storage.NormalizePresence(ep.Presence) == storage.PresenceParked || cx.cfg.IsLabAddress(ep.IP):
		return storage.RoleLab
	case cx.cfg.IsInfraAddress(ep.IP) || strings.EqualFold(ep.RoleTag, "server"):
		return storage.RoleInfra
	}
	return storage.RolePersonal
}

func (cx *ClassContext) roleOfID(id string) string {
	ep, ok := cx.byID[id]
	if !ok {
		ep = storage.Endpoint{ID: id}
	}
	return cx.RoleOf(ep)
}

// ZoneOf places an address: loopback, the internet, the lab or
// infrastructure networks, an enrolled endpoint's zone by its role, and the
// home network for every other private address.
func (cx *ClassContext) ZoneOf(ip string) string {
	switch {
	case netaddr.IsLoopback(ip) || cx.cfg.IsContainerAddress(ip):
		// The host's own containers are as local as its loopback.
		return zoneLocal
	case !isPrivateIP(ip):
		return zoneExternal
	case cx.cfg.IsLabAddress(ip):
		return zoneLab
	case cx.cfg.IsInfraAddress(ip):
		return zoneInfra
	}
	if ep, ok := cx.byIP[ip]; ok {
		switch cx.RoleOf(ep) {
		case storage.RoleLab:
			return zoneLab
		case storage.RolePersonal:
			return zoneHome
		default:
			return zoneInfra
		}
	}
	return zoneHome
}

// classEvidence is what Classify reads from a finding's evidence.
type classEvidence struct {
	Class      string         `json:"class"`
	Targets    []sweepEntry   `json:"sweep_targets"`
	FloorPorts *[]int         `json:"floor_ports"`
	ZoneHosts  map[string]int `json:"zone_hosts"`
	TargetZone string         `json:"target_zone"`
	SourceRole string         `json:"source_role"`
	IntelConf  *int           `json:"intel_confidence"`
	Score      float64        `json:"score"`
	Span       float64        `json:"span_minutes"`
	Devices    *int           `json:"beacon_devices"`
	DevicesUnk bool           `json:"beacon_devices_unknown"`
	LastSeenAt string         `json:"last_seen_at"`
	Tunnel     bool           `json:"tunnel_service"`
	Browser    bool           `json:"browser"`
	Upload     *int64         `json:"first_upload_bytes"`
	SensorDark bool           `json:"sensor_dark"`
	Domain     string         `json:"domain"`
	SNI        string         `json:"sni"`
	Owner      string         `json:"destination_owner"`
	Dest       string         `json:"destination"`
}

type sweepEntry struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
}

var (
	intelConfidence = regexp.MustCompile(`confidence (\d+)%`)
	agentSentTitle  = regexp.MustCompile(` sent .+ to a destination it never has`)
)

// Classify names a finding's class and why.
func (cx *ClassContext) Classify(a storage.AnomalyAlert) (string, string) {
	var ev classEvidence
	if strings.TrimSpace(a.Evidence) != "" {
		_ = json.Unmarshal([]byte(a.Evidence), &ev)
	}
	role := ev.SourceRole
	if role == "" {
		role = cx.roleOfID(a.EndpointID)
	}
	page := func(why string) (string, string) { return storage.ClassPage, why }
	record := func(why string) (string, string) { return storage.ClassRecord, why }
	digest := func(why string) (string, string) { return storage.ClassDigest, why }

	switch a.AnomalyType {
	case "THREAT_INTEL_MATCH":
		conf := -1
		if ev.IntelConf != nil {
			conf = *ev.IntelConf
		} else if m := intelConfidence.FindStringSubmatch(a.Description); m != nil {
			conf, _ = strconv.Atoi(m[1])
		}
		if conf < 0 || conf >= cx.cfg.IntelPageConfidence {
			return page(fmt.Sprintf("threat-intelligence match at confidence %d%% (pages from %d%%)", conf, cx.cfg.IntelPageConfidence))
		}
		return record(fmt.Sprintf("threat-intelligence match at confidence %d%%, below the %d%% that pages", conf, cx.cfg.IntelPageConfidence))
	case "DECOY_TOUCH":
		return page("a decoy address nothing legitimate uses was reached")
	case "SENSITIVE_PORT_EGRESS":
		return page("SMB, RDP, telnet or RPC left the network")
	case "AGENT_UPLOAD_VOLUME":
		return page("upload volume past the runtime's own baseline")
	case "NEW_PLACE_UPLOAD":
		return page("bulk upload to a place this device never reached before")
	case "LAB_ESCAPE":
		return page("a lab host reached outside the lab")
	case "AGENT_NEW_DESTINATION":
		if ev.Upload != nil || agentSentTitle.MatchString(a.Title) {
			return page("bulk upload to a destination the runtime never reached before")
		}
		return record("a first visit is recorded, never paged")
	case "PORT_SCAN_RECON":
		zone := ev.TargetZone
		if zone == "" {
			zone = cx.ZoneOf(a.DstIP)
		}
		switch {
		case zone == zoneLocal:
			return record("a scan of the host's own loopback")
		case role != storage.RoleAgent && role != storage.RoleLab:
			return page(fmt.Sprintf("a port scan from %s host", roleArticle(role)))
		case zone == zoneHome || zone == zoneInfra:
			return page(fmt.Sprintf("a port scan aimed at the %s zone", zone))
		}
		return record(fmt.Sprintf("a port scan from %s host into the %s zone", roleArticle(role), zone))
	case "LATERAL_PORT_SWEEP":
		return cx.classifySweep(a, ev, role)
	case "C2_BEACONING":
		port := a.DstPort
		switch {
		case ev.Tunnel && !ev.Browser:
			return page("a program beaconing to a shared tunnel front")
		case (port == 53 || port == 853 || port == 3478) && knownResolverOrLocal(a.DstIP):
			return digest("resolver forwarding or a STUN keepalive")
		case ev.Score < cx.cfg.BeaconPageScore || ev.Span < float64(cx.cfg.BeaconPageSpanMin):
		case ev.Devices != nil && *ev.Devices <= cx.cfg.BeaconRareDevices:
			return page(fmt.Sprintf("a metronomic beacon (score %.2f over %.0f min) to a destination %d device(s) reach", ev.Score, ev.Span, *ev.Devices))
		case ev.Devices == nil && ev.DevicesUnk:
			return page(fmt.Sprintf("a metronomic beacon (score %.2f over %.0f min); how many devices reach it is unknown", ev.Score, ev.Span))
		}
		return digest("a periodic conversation that is not rare or not strong enough to page")
	case "ENDPOINT_SILENT":
		ep, known := cx.byID[a.EndpointID]
		switch {
		case ev.SensorDark:
			return page("the host is still on the network while its sensor is dark")
		case !known || storage.NormalizePresence(ep.Presence) != storage.PresenceAlwaysOn:
			return record("the hub does not expect this host to be on all the time")
		case cx.RoleOf(ep) == storage.RoleInfra:
			return page("an always-on infrastructure host stopped reporting")
		}
		return record(fmt.Sprintf("%s host stopped reporting; expected stops are Nightshift's to explain", roleArticle(cx.RoleOf(ep))))
	case "ENDPOINT_RETURNED", "CLOUD_STORAGE_EGRESS":
		return digest("reported in the daily digest")
	case "BANDWIDTH_SPIKE":
		return record("a per-connection rate outlier; exfiltration pages as a new-place upload")
	case "AGENT_DNS_BYPASS":
		return record("lookups outside the estate's resolvers are a visibility gap, recorded")
	case "OFF_HOURS_ACTIVITY", "NOVEL_PROCESS_EGRESS":
		return record("network novelty is recorded, never paged")
	case "NOVEL_DESTINATION":
		if strings.HasPrefix(a.ID, "alert-disc-") {
			return digest("a new device on the LAN, in the daily digest")
		}
		return record("network novelty is recorded, never paged")
	case "COLLECTOR_HEALTH", "DETECTION_HEALTH":
		return record("collector or detection health, not an alert")
	}
	return page("a detector without a class pages until it is given one")
}

var sweepHostsInTitle = regexp.MustCompile(`\((\d+) Hosts?\)`)

// classifySweep pages a sweep that reached a floor port, a lab host reaching
// outside the lab, a fan-out to lan_sweep_hosts or more home hosts, or, from
// any host but the agent workstation, that many home and infrastructure hosts
// together. Everything else (an agent workstation's ssh round of its lab and
// infrastructure hosts) is recorded.
func (cx *ClassContext) classifySweep(a storage.AnomalyAlert, ev classEvidence, role string) (string, string) {
	var floor []int
	if ev.FloorPorts != nil {
		floor = *ev.FloorPorts
	} else {
		seen := map[int]bool{}
		for _, t := range ev.Targets {
			for _, p := range t.Ports {
				if FloorPort(p) && !seen[p] {
					seen[p] = true
					floor = append(floor, p)
				}
			}
		}
		if FloorPort(int(a.DstPort)) && !seen[int(a.DstPort)] {
			floor = append(floor, int(a.DstPort))
		}
	}
	if len(floor) > 0 {
		sort.Ints(floor)
		return storage.ClassPage, fmt.Sprintf("the sweep reached floor port(s) %s", joinPorts(floor))
	}
	zones := ev.ZoneHosts
	if zones == nil {
		zones = map[string]int{}
		for _, t := range ev.Targets {
			zones[cx.ZoneOf(t.IP)]++
		}
		hosts := len(ev.Targets)
		if m := sweepHostsInTitle.FindStringSubmatch(a.Title); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > hosts {
				// Hosts the evidence did not list count as home hosts.
				zones[zoneHome] += n - hosts
			}
		}
	}
	outside := zones[zoneHome] + zones[zoneInfra]
	switch {
	case role == storage.RoleLab && outside >= cx.cfg.LabEscapeHosts:
		return storage.ClassPage, fmt.Sprintf("a lab host reached %d host(s) outside the lab", outside)
	case role != storage.RoleAgent && outside >= cx.cfg.LANSweepHosts:
		// Only the agent workstation makes routine rounds of the
		// infrastructure hosts.
		return storage.ClassPage, fmt.Sprintf("fan-out from %s host to %d home and infrastructure hosts (pages from %d)", roleArticle(role), outside, cx.cfg.LANSweepHosts)
	case zones[zoneHome] >= cx.cfg.LANSweepHosts:
		return storage.ClassPage, fmt.Sprintf("fan-out to %d home hosts (pages from %d)", zones[zoneHome], cx.cfg.LANSweepHosts)
	}
	return storage.ClassRecord, fmt.Sprintf("%s host reaching %d lab, %d infrastructure and %d home host(s)", roleArticle(role), zones[zoneLab], zones[zoneInfra], zones[zoneHome])
}

// roleArticle names a role with its article: "an agent", "an infrastructure".
func roleArticle(role string) string {
	switch role {
	case storage.RoleAgent:
		return "an agent"
	case storage.RoleInfra:
		return "an infrastructure"
	}
	return "a " + role
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// incidentFamily groups detectors whose alerts about one device and one
// counterparty are one incident.
func incidentFamily(t string) string {
	switch t {
	case "LATERAL_PORT_SWEEP", "PORT_SCAN_RECON", "LAB_ESCAPE":
		return "sweep"
	case "AGENT_NEW_DESTINATION", "NEW_PLACE_UPLOAD", "AGENT_UPLOAD_VOLUME", "CLOUD_STORAGE_EGRESS", "BANDWIDTH_SPIKE":
		return "upload"
	case "ENDPOINT_SILENT", "ENDPOINT_RETURNED":
		return "presence"
	}
	return strings.ToLower(t)
}

// incidentKey is device + rule family + counterparty.
func incidentKey(a storage.AnomalyAlert, ev classEvidence) string {
	fam := incidentFamily(a.AnomalyType)
	party := ""
	switch fam {
	case "presence":
		// Each outage is its own incident: a host that returned and went
		// dark again pages again.
		party = ev.LastSeenAt
	case "threat_intel_match":
		party = a.DstIP
	case "sweep":
		// One detector's sweep of one target: a lab escape is not hidden in
		// an open sweep incident, nor a scan of one host in another's.
		party = strings.ToLower(a.AnomalyType) + ":"
		switch {
		case ev.FloorPorts != nil && len(*ev.FloorPorts) > 0:
			party += "floor:" + joinPorts(*ev.FloorPorts)
		case a.AnomalyType == "LAB_ESCAPE":
			party += firstNonEmpty(ev.TargetZone, "outside")
		case a.AnomalyType == "PORT_SCAN_RECON":
			party += a.DstIP
		default:
			party += "fanout"
		}
	default:
		party = strings.ToLower(firstNonEmpty(ev.Dest, registrable(ev.Domain), registrable(ev.SNI), ev.Owner, a.DstIP))
	}
	return a.EndpointID + "|" + fam + "|" + party
}

// knownResolverOrLocal says whether a DNS-port destination is a resolver the
// estate expects: a private address or a well-known public resolver. A
// beacon on port 53 straight to any other public address is not forwarding.
func knownResolverOrLocal(ip string) bool {
	if isPrivateIP(ip) {
		return true
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && publicResolvers[a.Unmap()]
}

func registrable(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return ""
	}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return reg
	}
	return name
}

var sevRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// classCache keeps the endpoints the classifier reads, re-read once a minute.
type classCache struct {
	mu       sync.Mutex
	at       time.Time
	eps      []storage.Endpoint
	observed map[string]bool
}

// classContext returns a context on the current tuning and endpoints.
func (e *Engine) classContext() *ClassContext {
	e.classes.mu.Lock()
	defer e.classes.mu.Unlock()
	if e.classes.eps == nil || time.Since(e.classes.at) > inventoryTTL {
		if eps, err := e.store.ListEndpoints(""); err == nil {
			e.classes.eps = eps
			e.classes.observed = map[string]bool{}
			for _, ep := range eps {
				if e.store.RunsAgentRuntimes(ep.TenantID, ep.ID) {
					e.classes.observed[ep.ID] = true
				}
			}
			e.classes.at = time.Now()
		} else if e.classes.eps == nil {
			e.classes.eps = []storage.Endpoint{}
		}
	}
	return NewClassContext(e.settings(), e.classes.eps, e.classes.observed)
}

// stampClass classifies a finding before it is written: its class and reason
// in the evidence, record and digest findings held like hunt leads, and a
// page joined to its incident (incident, incident_key, escalation).
func (e *Engine) stampClass(a *storage.AnomalyAlert) {
	fields := map[string]any{}
	if strings.TrimSpace(a.Evidence) != "" && json.Unmarshal([]byte(a.Evidence), &fields) != nil {
		fields = map[string]any{"detector_evidence": a.Evidence}
	}
	if fields == nil {
		fields = map[string]any{}
	}
	if c, _ := fields["class"].(string); c != "" {
		return // already stamped
	}
	cx := e.classContext()
	if _, ok := fields["source_role"]; !ok && a.EndpointID != "" {
		fields["source_role"] = cx.roleOfID(a.EndpointID)
		raw, _ := json.Marshal(fields)
		a.Evidence = string(raw)
	}
	class, why := cx.Classify(*a)
	fields["class"], fields["class_reason"] = class, why
	if class != storage.ClassPage {
		if a.HeldReason == "" {
			a.HeldReason = storage.HeldHunt
		}
	} else {
		var ev classEvidence
		_ = json.Unmarshal([]byte(a.Evidence), &ev)
		key := incidentKey(*a, ev)
		fields["incident_key"] = key
		hours := time.Duration(cx.cfg.PageIncidentHours) * time.Hour
		at := a.Timestamp
		if at.IsZero() {
			at = time.Now().UTC()
		}
		id, worst, err := "", "", error(nil)
		if e.sink == nil {
			id, worst, err = e.store.OpenIncident(a.TenantID, a.EndpointID, key, at.Add(-hours))
			if err != nil {
				log.Printf("[-] incident lookup for %s failed, opening a new one: %v", a.EndpointID, err)
			}
		}
		switch {
		case id == "":
			fields["incident"] = "inc-" + a.ID
		case sevRank[a.Severity] > sevRank[worst]:
			fields["incident"], fields["escalation"] = id, true
		default:
			// Same incident, no worse: kept with it, not pushed again.
			fields["incident"] = id
			if a.HeldReason == "" {
				a.HeldReason = storage.HeldIncident
			}
		}
	}
	raw, _ := json.Marshal(fields)
	a.Evidence = string(raw)
}
