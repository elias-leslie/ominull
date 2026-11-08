package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/netaddr"
)

var ErrInvalidDetectionTuning = errors.New("invalid detection tuning")

// DetectionTuning is every number the behavioural detectors used to have
// compiled into them. It is one row, edited in the console, because the answer
// to "why did this alert fire?" has to be readable by the person deciding
// whether to act on it - and the answer to "stop it firing" has to be
// something they can do without a release.
type DetectionTuning struct {
	// OffHoursStart and OffHoursEnd bound the window, in hours, in the zone
	// named by OffHoursZone. The window wraps midnight when start > end.
	OffHoursStart int    `json:"off_hours_start"`
	OffHoursEnd   int    `json:"off_hours_end"`
	OffHoursZone  string `json:"off_hours_zone"`
	OffHoursOn    bool   `json:"off_hours_enabled"`

	// BeaconMinSamples, BeaconMinSpanMinutes and BeaconScore are the evidence
	// a periodic conversation has to produce before it is called a beacon.
	BeaconOn          bool    `json:"beacon_enabled"`
	BeaconMinSamples  int     `json:"beacon_min_samples"`
	BeaconMinSpanMin  int     `json:"beacon_min_span_minutes"`
	BeaconMinInterval int     `json:"beacon_min_interval_seconds"`
	BeaconMaxInterval int     `json:"beacon_max_interval_seconds"`
	BeaconScore       float64 `json:"beacon_score_threshold"`
	BeaconCooldownMin int     `json:"beacon_cooldown_minutes"`

	// BandwidthOn and BandwidthCooldown govern the bulk cloud-storage upload
	// report. The first-seen, off-hours and bandwidth-spike findings were
	// retired; a saved row that still holds their fields loads without them.
	BandwidthOn       bool `json:"bandwidth_enabled"`
	BandwidthCooldown int  `json:"bandwidth_cooldown_minutes"`

	// SilenceOn and SilenceAfterMinutes are the alert-on-absence rule: an agent
	// that stops reporting is a finding, not a gap.
	//
	// Every detector in this product needs telemetry to say anything at all, so
	// the cheapest way to defeat all of them at once is to stop the agent -
	// MITRE tracks it as T1562.001, and it is what a host being rebuilt,
	// crashing, or losing its route looks like too. Wazuh alerts on the same
	// condition after its keepalive window; fifteen minutes is that order.
	SilenceOn           bool `json:"silence_enabled"`
	SilenceAfterMinutes int  `json:"silence_after_minutes"`

	// WarmupHours is how long after an endpoint first reports that behavioural
	// detections are held rather than raised. A host installed an hour ago has
	// no baseline to be anomalous against, and every one of its ordinary
	// first-boot conversations is a first-seen destination.
	WarmupHours int `json:"warmup_hours"`

	// ExpectedRules are the operator's answers to "this is normal here": the
	// one list every detector consults before it raises something that can be
	// made expected (expected_rules.go). A rule names a program, a destination,
	// a host and the findings it covers; the floor rules cannot be covered.
	ExpectedRules []ExpectedRule `json:"expected_rules"`

	// ContainerCIDRs are explicit lateral-movement exemptions, never guessed from private address space.
	ContainerCIDRs []string `json:"container_cidrs"`

	// AgentRuntimes name the AI agent runtimes whose egress is judged against
	// their own baselines (detector/agent_egress.go): where each has gone
	// before, and how much it sends in an ordinary hour.
	AgentEgressOn      bool           `json:"agent_egress_enabled"`
	AgentRuntimes      []AgentRuntime `json:"agent_runtimes"`
	AgentBaselineDays  int            `json:"agent_baseline_days"`
	AgentUploadFloorMB int            `json:"agent_upload_floor_mb"`
	AgentUploadFactor  int            `json:"agent_upload_factor"`

	// AgentHeavyEndpoints and AgentHeavyRoles name the endpoints (by id) and
	// role tags where AI agents run programs and open connections all day.
	// The behavioural detectors are hunt leads everywhere (anomaly_tier.go);
	// on these endpoints they are also muted to LOW, because there they
	// describe the agents' ordinary work.
	AgentHeavyEndpoints []string `json:"agent_heavy_endpoints"`
	AgentHeavyRoles     []string `json:"agent_heavy_roles"`
	// AgentHeavyObserved also counts an endpoint as agent-heavy once its own
	// telemetry has shown one of the agent runtimes (agent_runtimes).
	AgentHeavyObserved bool `json:"agent_heavy_observed"`

	// Roles and zones (detector/class.go). LabCIDRs are the lab networks
	// (target VMs, labnet) and InfraCIDRs the estate's own infrastructure
	// (hypervisor, gateway, vault, guests without an agent): a sweep from an
	// agent workstation into either is recorded, never paged, and anything a
	// lab host reaches outside the lab is a lab escape, which pages. Enrolled
	// endpoints take their zone from their role without being listed.
	LabCIDRs   []string `json:"lab_cidrs"`
	InfraCIDRs []string `json:"infra_cidrs"`
	// DecoyAddrs are LAN addresses ("ip" or "ip:port") nothing legitimate
	// uses: any connection to one pages, whatever the role or exclusion.
	DecoyAddrs []string `json:"decoy_addrs"`
	// DecoyNames are DNS names nothing legitimate looks up (the host in a
	// planted credential or config): a lookup of one, or of a name under it,
	// from any device in the gateway's DNS log pages.
	DecoyNames []string `json:"decoy_names"`
	// DomainIntelFeeds are bad-domain lists (hosts-file or one name per
	// line) matched against the gateway's DNS log; a listed name pages as a
	// threat-list match when the feed's confidence reaches
	// IntelPageConfidence. An abuse.ch URL may hold {auth_key}, filled from
	// the hub's abuse.ch key file.
	DomainIntelFeeds []DomainIntelFeed `json:"domain_intel_feeds"`
	// TunnelServices are shared fronts (name suffixes) where beacon rarity
	// means nothing: a non-browser program beaconing to one pages.
	TunnelServices []string `json:"tunnel_services"`
	// BeaconBrowsers are the program names (no path, no .exe) of the web
	// browsers: a browser tab holding a tunnel-fronted page open is a person
	// reading it, not an implant, so it does not page.
	BeaconBrowsers []string `json:"beacon_browsers"`

	// IntelPageConfidence is the threat-intelligence confidence (percent) at
	// which a match pages; below it the match is recorded.
	IntelPageConfidence int `json:"intel_page_confidence"`
	// AutoIsolateRoles are the roles (agent, lab, infra, personal) a paging
	// threat-intelligence match isolates automatically. The agent and infra
	// roles are left out by default: cutting the agent workstation or the
	// hypervisor off the network is worse than the match.
	AutoIsolateRoles []string `json:"auto_isolate_roles"`

	// PageIncidentHours is how long one incident (device, rule family,
	// counterparty) stays open: later alerts add to its count and only an
	// escalation asks again.
	PageIncidentHours int `json:"page_incident_hours"`

	// AicoFleetFreshMinutes is how old Aico's machine view may be before the
	// silence watch stops acting on it and falls back to stored presence.
	AicoFleetFreshMinutes int `json:"aico_fleet_fresh_minutes"`
	// AicoFleetOffMemoryHours is how long a machine Aico last called off, and
	// which is not meant to be always on, stays off once Aico's word lapses.
	AicoFleetOffMemoryHours int `json:"aico_fleet_off_memory_hours"`

	// LANSweepHosts is how many home-zone hosts one process may reach in the
	// sweep window before it pages; LabEscapeHosts how many hosts outside
	// the lab a lab host may reach before it pages.
	LANSweepHosts  int `json:"lan_sweep_hosts"`
	LabEscapeHosts int `json:"lab_escape_hosts"`

	// A beacon pages when its score is at least BeaconPageScore over at least
	// BeaconPageSpanMin minutes and the destination is seen from at most
	// BeaconRareDevices devices; any other beacon is in the daily digest.
	BeaconPageScore   float64 `json:"beacon_page_score"`
	BeaconPageSpanMin int     `json:"beacon_page_span_min"`
	BeaconRareDevices int     `json:"beacon_rare_devices"`

	// A program sending NewDestUploadMB or more to a place its device never
	// reached, within NewDestWindowMin of first reaching it, pages.
	NewDestUploadMB  int `json:"new_dest_upload_mb"`
	NewDestWindowMin int `json:"new_dest_window_min"`

	// MaxPlausibleRateMbps is the fastest rate a flow can really have. A
	// counter that claims more (a wrapped or underflowed Windows counter) is
	// collector trouble, noted as such, never an alert or a baseline sample.
	MaxPlausibleRateMbps int `json:"max_plausible_rate_mbps"`

	// EphemeralPortFrom is the first port the network's clients take for their
	// own end of a connection (Linux 32768, Windows and the IANA range 49152).
	// A flow from a port below it to a port at or above it is a listener
	// answering a client, which is served, not this host reaching out: the
	// sweep and lab-escape rules leave it alone.
	EphemeralPortFrom int `json:"ephemeral_port_from"`

	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// DefaultDetectionTuning is what a hub that has never been tuned runs.
//
// The beacon numbers are deliberately far stricter than the ones they replace.
// Four observations three intervals apart, with a sub-1.5-second standard
// deviation, describes any chatty local service; it fired on a freshly
// installed workstation whose only conversations were its own operating
// system's keepalives. Twelve intervals spanning ten minutes, judged on
// relative dispersion rather than an absolute number of seconds, does not.
func DefaultDetectionTuning() DetectionTuning {
	// Normalised on the way out so it is byte-for-byte comparable with a saved
	// row. The console shows "these settings differ from the shipped values" by
	// comparing the two, and an unsorted default list made every hub report two
	// differences it did not have.
	return defaultDetectionTuning().normalised()
}

func defaultDetectionTuning() DetectionTuning {
	return DetectionTuning{
		OffHoursStart: 22,
		OffHoursEnd:   5,
		OffHoursZone:  "Local",
		OffHoursOn:    true,

		AgentEgressOn:      true,
		AgentHeavyObserved: true,
		AgentRuntimes:      defaultAgentRuntimes(),
		AgentBaselineDays:  7,
		AgentUploadFloorMB: 100,
		AgentUploadFactor:  5,

		BeaconOn:          true,
		BeaconMinSamples:  12,
		BeaconMinSpanMin:  10,
		BeaconMinInterval: 5,
		BeaconMaxInterval: 3600,
		BeaconScore:       0.80,
		BeaconCooldownMin: 30,

		BandwidthOn:       true,
		BandwidthCooldown: 5,

		SilenceOn:           true,
		SilenceAfterMinutes: 15,

		WarmupHours: 24,

		ExpectedRules: seedExpectedRules(),

		DomainIntelFeeds:        defaultDomainIntelFeeds(),
		TunnelServices:          defaultTunnelServices(),
		BeaconBrowsers:          defaultBeaconBrowsers(),
		IntelPageConfidence:     IntelPageConfidenceDefault,
		AutoIsolateRoles:        []string{RoleLab, RolePersonal},
		PageIncidentHours:       24,
		AicoFleetFreshMinutes:   10,
		AicoFleetOffMemoryHours: 24,
		LANSweepHosts:           10,
		LabEscapeHosts:          1,
		BeaconPageScore:         0.90,
		BeaconPageSpanMin:       30,
		BeaconRareDevices:       1,
		NewDestUploadMB:         1,
		NewDestWindowMin:        60,
		MaxPlausibleRateMbps:    10000,
		EphemeralPortFrom:       32768,
	}
}

// defaultDomainIntelFeeds are abuse.ch's host files (a free Auth-Key, in the
// hub's abuse.ch key file, fills {auth_key}). ThreatFox lists botnet C2 and
// payload-delivery domains and pages; URLhaus lists hosts serving malware,
// often hacked ordinary sites, so a lookup is recorded, not paged. An empty
// list in the saved row turns them off.
func defaultDomainIntelFeeds() []DomainIntelFeed {
	return []DomainIntelFeed{
		{Name: "threatfox", URL: "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/hostfile.txt", Confidence: 90},
		{Name: "urlhaus", URL: "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/hostfile.txt", Confidence: 70},
	}
}

// MaxDomainIntelFeeds bounds the lists held in memory (each up to 2M names).
const MaxDomainIntelFeeds = 8

// DomainIntelFeed is one bad-domain list the hub fetches.
type DomainIntelFeed struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Confidence int    `json:"confidence"`
}

// IntelPageConfidenceDefault is the threat-intelligence confidence at which a
// match pages unless the tuning says otherwise.
const IntelPageConfidenceDefault = 75

// Endpoint roles (detector/class.go).
const (
	RoleAgent    = "agent"
	RoleLab      = "lab"
	RoleInfra    = "infra"
	RolePersonal = "personal"
)

// defaultTunnelServices are the shared tunnel and paste fronts where an
// implant's beacon looks like everyone else's traffic.
func defaultTunnelServices() []string {
	return []string{"trycloudflare.com", "workers.dev", "ngrok.io", "ngrok.app", "ngrok-free.app",
		"loca.lt", "serveo.net", "localhost.run", "pastebin.com", "transfer.sh"}
}

// defaultBeaconBrowsers are the common web browsers by program name.
func defaultBeaconBrowsers() []string {
	return []string{"chrome", "chromium", "chromium-browser", "firefox", "msedge", "brave", "safari", "opera", "vivaldi"}
}

func (s *Store) initDetectionTuningSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS detection_tuning (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		settings TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		updated_by TEXT NOT NULL DEFAULT ''
	);`)
	if err != nil {
		return err
	}
	s.migrateExpectedRules(time.Now().UTC())
	return nil
}

// GetDetectionTuning returns the stored tuning, or the defaults if the hub has
// never been tuned. A row that cannot be parsed - a downgrade, a hand-edited
// database - falls back to the defaults rather than leaving every detector at
// its zero value, which would silently switch all of them off.
func (s *Store) GetDetectionTuning() DetectionTuning {
	var raw string
	var updated time.Time
	var by string
	err := s.db.QueryRow(`SELECT settings, updated_at, updated_by FROM detection_tuning WHERE id = 1`).
		Scan(&raw, &updated, &by)
	if err == sql.ErrNoRows {
		return DefaultDetectionTuning()
	}
	if err != nil {
		return DefaultDetectionTuning()
	}
	t := DefaultDetectionTuning()
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return DefaultDetectionTuning()
	}
	t.UpdatedAt = updated
	t.UpdatedBy = by
	t = t.normalised()
	// A rule the checks refuse covers nothing (DetectionTuningProblem says so).
	t.ExpectedRules, _ = readableRules(t.ExpectedRules)
	return t
}

// SaveDetectionTuning writes the tuning after clamping it. Anything a form can
// send, a form will eventually send: a zero sample count would make every pair
// of packets a beacon, and a threshold above one would switch the detector off
// without saying so.
func (s *Store) SaveDetectionTuning(t DetectionTuning, by string) (DetectionTuning, error) {
	t, err := PrepareDetectionTuning(t)
	if err != nil {
		return t, err
	}
	blob, err := json.Marshal(t)
	if err != nil {
		return t, err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`
		INSERT INTO detection_tuning (id, settings, updated_at, updated_by)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET settings = excluded.settings,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		string(blob), now, by)
	if err != nil {
		return t, err
	}
	t.UpdatedAt = now
	t.UpdatedBy = by
	return t, nil
}

// PrepareDetectionTuning normalises and checks a draft without saving it, so a
// replay, and the authority signing a loosening, judge exactly what a save would
// store.
func PrepareDetectionTuning(t DetectionTuning) (DetectionTuning, error) {
	t = t.normalised()
	for i, raw := range t.ContainerCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !privatePrefix(p) {
			return t, fmt.Errorf("%w: container network %q must lie wholly inside private IPv4 or IPv6 space", ErrInvalidDetectionTuning, raw)
		}
		t.ContainerCIDRs[i] = p.Masked().String()
	}
	t.ContainerCIDRs = tidyList(t.ContainerCIDRs)
	// An expired rule covers nothing; a save drops it, which only tightens.
	t.ExpectedRules = withoutExpired(t.ExpectedRules, time.Now())
	if err := validExpectedRules(t.ExpectedRules); err != nil {
		return t, err
	}
	t, err := t.validZones()
	if err != nil {
		return t, err
	}
	return t, nil
}

// DetectionTuningProblem says what is wrong with the saved tuning row, or ""
// when it is sound (or the hub has never been tuned). A row that cannot be
// read runs as the shipped defaults (GetDetectionTuning), and one holding an
// entry a save would refuse is read more widely than anyone could have
// written it; neither may pass unnoticed.
func (s *Store) DetectionTuningProblem() string {
	var raw string
	err := s.db.QueryRow(`SELECT settings FROM detection_tuning WHERE id = 1`).Scan(&raw)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		return "the saved detection tuning could not be read (" + err.Error() + "), so the shipped defaults run"
	}
	t := DefaultDetectionTuning()
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return "the saved detection tuning is not valid JSON (" + err.Error() + "), so the shipped defaults run"
	}
	if _, err := PrepareDetectionTuning(t); err != nil {
		return "the saved detection tuning holds an entry a save would refuse: " + err.Error()
	}
	return ""
}

func (t DetectionTuning) normalised() DetectionTuning {
	clampInt := func(v, lo, hi, def int) int {
		if v == 0 {
			return def
		}
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	t.OffHoursStart = ((t.OffHoursStart % 24) + 24) % 24
	t.OffHoursEnd = ((t.OffHoursEnd % 24) + 24) % 24
	if strings.TrimSpace(t.OffHoursZone) == "" {
		t.OffHoursZone = "Local"
	}
	t.BeaconMinSamples = clampInt(t.BeaconMinSamples, 6, 200, 12)
	t.BeaconMinSpanMin = clampInt(t.BeaconMinSpanMin, 1, 1440, 10)
	t.BeaconMinInterval = clampInt(t.BeaconMinInterval, 1, 3600, 5)
	t.BeaconMaxInterval = clampInt(t.BeaconMaxInterval, 10, 86400, 3600)
	if t.BeaconMaxInterval <= t.BeaconMinInterval {
		t.BeaconMaxInterval = t.BeaconMinInterval + 10
	}
	if t.BeaconScore <= 0 || t.BeaconScore > 1 {
		t.BeaconScore = 0.80
	}
	t.BeaconCooldownMin = clampInt(t.BeaconCooldownMin, 1, 1440, 30)
	t.BandwidthCooldown = clampInt(t.BandwidthCooldown, 1, 1440, 5)
	// Below five minutes this reports every reboot and every flaky link; above
	// a day it is not alerting on absence, it is noticing it eventually.
	t.SilenceAfterMinutes = clampInt(t.SilenceAfterMinutes, 5, 1440, 15)
	// Silence is part of the floor: a host that stops reporting blinds every
	// other detector, so no saved row switches it off.
	t.SilenceOn = true
	if t.WarmupHours < 0 {
		t.WarmupHours = 0
	}
	if t.WarmupHours > 720 {
		t.WarmupHours = 720
	}
	t.ExpectedRules = tidyRules(t.ExpectedRules)
	t.ContainerCIDRs = tidyList(t.ContainerCIDRs)
	t.AgentHeavyEndpoints = tidyList(t.AgentHeavyEndpoints)
	t.AgentHeavyRoles = tidyList(t.AgentHeavyRoles)
	t.AgentRuntimes = tidyAgentRuntimes(t.AgentRuntimes)
	t.AgentBaselineDays = clampInt(t.AgentBaselineDays, 1, 90, 7)
	t.AgentUploadFloorMB = clampInt(t.AgentUploadFloorMB, 1, 100000, 100)
	t.AgentUploadFactor = clampInt(t.AgentUploadFactor, 2, 100, 5)
	t.LabCIDRs = tidyList(t.LabCIDRs)
	t.InfraCIDRs = tidyList(t.InfraCIDRs)
	t.DecoyAddrs = tidyList(t.DecoyAddrs)
	t.DecoyNames = tidyList(t.DecoyNames)
	for i := range t.DecoyNames {
		t.DecoyNames[i] = strings.TrimSuffix(t.DecoyNames[i], ".")
	}
	t.DecoyNames = tidyList(t.DecoyNames)
	if t.DomainIntelFeeds == nil {
		t.DomainIntelFeeds = defaultDomainIntelFeeds()
	}
	t.DomainIntelFeeds = tidyFeeds(t.DomainIntelFeeds)
	t.TunnelServices = tidyList(t.TunnelServices)
	if t.BeaconBrowsers == nil {
		t.BeaconBrowsers = defaultBeaconBrowsers()
	}
	t.BeaconBrowsers = tidyList(t.BeaconBrowsers)
	t.AutoIsolateRoles = tidyList(t.AutoIsolateRoles)
	t.IntelPageConfidence = clampInt(t.IntelPageConfidence, 1, 100, IntelPageConfidenceDefault)
	t.PageIncidentHours = clampInt(t.PageIncidentHours, 1, 168, 24)
	t.AicoFleetFreshMinutes = clampInt(t.AicoFleetFreshMinutes, 2, 1440, 10)
	t.AicoFleetOffMemoryHours = clampInt(t.AicoFleetOffMemoryHours, 1, 168, 24)
	t.LANSweepHosts = clampInt(t.LANSweepHosts, 2, 256, 10)
	t.LabEscapeHosts = clampInt(t.LabEscapeHosts, 1, 256, 1)
	if t.BeaconPageScore <= 0 || t.BeaconPageScore > 1 {
		t.BeaconPageScore = 0.90
	}
	t.BeaconPageSpanMin = clampInt(t.BeaconPageSpanMin, 5, 240, 30)
	t.BeaconRareDevices = clampInt(t.BeaconRareDevices, 1, 1000, 1)
	t.NewDestUploadMB = clampInt(t.NewDestUploadMB, 1, 100000, 1)
	t.NewDestWindowMin = clampInt(t.NewDestWindowMin, 1, 1440, 60)
	t.MaxPlausibleRateMbps = clampInt(t.MaxPlausibleRateMbps, 100, 1000000, 10000)
	t.EphemeralPortFrom = clampInt(t.EphemeralPortFrom, 1024, 65535, 32768)
	return t
}

// validZones checks the lab and infrastructure networks (private prefixes
// that do not overlap), the decoys (private address, optional port), the
// tunnel fronts (names) and the auto-isolate roles.
func (t DetectionTuning) validZones() (DetectionTuning, error) {
	prefixes := func(list []string, what string) ([]string, []netip.Prefix, error) {
		out, ps := make([]string, 0, len(list)), make([]netip.Prefix, 0, len(list))
		for _, raw := range list {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				if a, aerr := netip.ParseAddr(raw); aerr == nil {
					p, err = a.Prefix(a.BitLen())
				}
			}
			if err != nil || !privatePrefix(p) {
				return nil, nil, fmt.Errorf("%w: %s %q must be an address or network inside private IPv4 or IPv6 space", ErrInvalidDetectionTuning, what, raw)
			}
			out, ps = append(out, p.Masked().String()), append(ps, p.Masked())
		}
		return tidyList(out), ps, nil
	}
	var lab, infra []netip.Prefix
	var err error
	if t.LabCIDRs, lab, err = prefixes(t.LabCIDRs, "lab network"); err != nil {
		return t, err
	}
	if t.InfraCIDRs, infra, err = prefixes(t.InfraCIDRs, "infrastructure network"); err != nil {
		return t, err
	}
	for _, l := range lab {
		for _, i := range infra {
			if l.Overlaps(i) {
				return t, fmt.Errorf("%w: lab network %s overlaps infrastructure network %s; a host is in one zone", ErrInvalidDetectionTuning, l, i)
			}
		}
	}
	for _, d := range t.DecoyAddrs {
		if _, _, ok := ParseDecoy(d); !ok {
			return t, fmt.Errorf("%w: decoy %q must be a private address, optionally with :port", ErrInvalidDetectionTuning, d)
		}
	}
	for _, name := range t.DecoyNames {
		if !DNSName(name) {
			return t, fmt.Errorf("%w: decoy name %q must be a DNS name such as s3.archive.lan", ErrInvalidDetectionTuning, name)
		}
	}
	if len(t.DomainIntelFeeds) > MaxDomainIntelFeeds {
		return t, fmt.Errorf("%w: at most %d domain feeds", ErrInvalidDetectionTuning, MaxDomainIntelFeeds)
	}
	seenFeed := map[string]bool{}
	for _, f := range t.DomainIntelFeeds {
		u, err := url.Parse(f.URL)
		if f.Name == "" || len(f.Name) > 64 || strings.ContainsAny(f.Name, " /\\") || seenFeed[f.Name] {
			return t, fmt.Errorf("%w: domain feed name %q must be a short unique word such as threatfox", ErrInvalidDetectionTuning, f.Name)
		}
		seenFeed[f.Name] = true
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return t, fmt.Errorf("%w: domain feed %s must have an https URL", ErrInvalidDetectionTuning, f.Name)
		}
		if f.Confidence < 1 || f.Confidence > 100 {
			return t, fmt.Errorf("%w: domain feed %s confidence must be 1-100", ErrInvalidDetectionTuning, f.Name)
		}
	}
	for _, name := range t.TunnelServices {
		if name == "" || strings.ContainsAny(name, " /:@*") || !strings.Contains(name, ".") {
			return t, fmt.Errorf("%w: tunnel service %q must be a domain name such as trycloudflare.com", ErrInvalidDetectionTuning, name)
		}
	}
	for _, name := range t.BeaconBrowsers {
		if name == "" || strings.ContainsAny(name, " /\\:*") || strings.HasSuffix(name, ".exe") {
			return t, fmt.Errorf("%w: browser %q must be a program name such as firefox, without a path or .exe", ErrInvalidDetectionTuning, name)
		}
	}
	for _, r := range t.AutoIsolateRoles {
		switch r {
		case RoleAgent, RoleLab, RoleInfra, RolePersonal:
		default:
			return t, fmt.Errorf("%w: auto-isolate role %q must be agent, lab, infra or personal", ErrInvalidDetectionTuning, r)
		}
	}
	return t, nil
}

// ParseDecoy reads a decoy entry: a private address and, optionally, a port
// (0 = any port).
func ParseDecoy(entry string) (netip.Addr, uint16, bool) {
	if ap, err := netip.ParseAddrPort(entry); err == nil {
		a := ap.Addr().Unmap()
		return a, ap.Port(), ap.Port() != 0 && privatePrefix(netip.PrefixFrom(a, a.BitLen()))
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	a = a.Unmap()
	return a, 0, privatePrefix(netip.PrefixFrom(a, a.BitLen()))
}

// DNSName reports a lower-case DNS name of at least two labels: letters,
// digits, hyphens and underscores, 63 bytes a label, 253 in all.
func DNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// DecoyName returns the decoy name a looked-up name is, or lies under.
func (t DetectionTuning) DecoyName(domain string) (string, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, d := range t.DecoyNames {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return d, true
		}
	}
	return "", false
}

func tidyFeeds(in []DomainIntelFeed) []DomainIntelFeed {
	out := make([]DomainIntelFeed, 0, len(in))
	for _, f := range in {
		f.Name = strings.ToLower(strings.TrimSpace(f.Name))
		f.URL = strings.TrimSpace(f.URL)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// IsDecoy says whether a connection to ip:port touches a decoy.
func (t DetectionTuning) IsDecoy(ip string, port uint16) bool {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, d := range t.DecoyAddrs {
		if da, dp, ok := ParseDecoy(d); ok && da == a && (dp == 0 || dp == port) {
			return true
		}
	}
	return false
}

func inPrefixes(list []string, raw string) bool {
	a, err := netaddr.Parse(raw)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, cidr := range list {
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// IsLabAddress and IsInfraAddress place an address in the lab or
// infrastructure zone by the tuning's networks.
func (t DetectionTuning) IsLabAddress(raw string) bool   { return inPrefixes(t.LabCIDRs, raw) }
func (t DetectionTuning) IsInfraAddress(raw string) bool { return inPrefixes(t.InfraCIDRs, raw) }

// IsTunnelService says whether a name is one of the shared tunnel fronts.
func (t DetectionTuning) IsTunnelService(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return false
	}
	for _, s := range t.TunnelServices {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// IsBrowser says whether a program is one of the web browsers, by name.
func (t DetectionTuning) IsBrowser(procPath string) bool {
	name := strings.ToLower(strings.TrimSpace(procPath))
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, ".exe")
	for _, b := range t.BeaconBrowsers {
		if name != "" && name == b {
			return true
		}
	}
	return false
}

// AutoIsolates says whether a paging threat-intelligence match isolates an
// endpoint of this role.
func (t DetectionTuning) AutoIsolates(role string) bool {
	for _, r := range t.AutoIsolateRoles {
		if r == role {
			return true
		}
	}
	return false
}

// AdminFanoutMaxDefault is how many inventoried hosts one admin fan-out may
// reach in the sweep window before it pages anyway.
const AdminFanoutMaxDefault = 8

func privatePrefix(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is4In6() {
		return false
	}
	for _, space := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		private := netip.MustParsePrefix(space)
		if p.Bits() >= private.Bits() && private.Contains(p.Masked().Addr()) {
			return true
		}
	}
	return false
}

func tidyList(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func splitPair(v string) (proc, org string, ok bool) {
	at := strings.LastIndex(v, "@")
	if at <= 0 || at == len(v)-1 {
		return "", "", false
	}
	proc = strings.ToLower(strings.TrimSpace(v[:at]))
	org = strings.ToLower(strings.TrimSpace(v[at+1:]))
	if proc == "" || org == "" {
		return "", "", false
	}
	return proc, org, true
}

// Location resolves the configured zone. "Local" means the hub's own zone,
// which is the honest default: an operator who has not said otherwise means
// the hours they keep, not UTC.
func (t DetectionTuning) Location() *time.Location {
	switch strings.ToLower(strings.TrimSpace(t.OffHoursZone)) {
	case "", "local":
		return time.Local
	case "utc":
		return time.UTC
	}
	if loc, err := time.LoadLocation(t.OffHoursZone); err == nil {
		return loc
	}
	return time.Local
}

// IsOffHours answers for an instant in the configured zone, handling a window
// that wraps midnight - which the interesting one always does.
func (t DetectionTuning) IsOffHours(at time.Time) bool {
	if !t.OffHoursOn {
		return false
	}
	h := at.In(t.Location()).Hour()
	if t.OffHoursStart == t.OffHoursEnd {
		return false
	}
	if t.OffHoursStart < t.OffHoursEnd {
		return h >= t.OffHoursStart && h < t.OffHoursEnd
	}
	return h >= t.OffHoursStart || h < t.OffHoursEnd
}

// ProcessPathKey is the form a process path is compared in: forward slashes,
// lower case, without the kernel's " (deleted)" suffix - the same reading
// detector.WorkloadOf gives an installed program.
func ProcessPathKey(path string) string {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"))
	return strings.TrimSuffix(p, " (deleted)")
}

// A quiet path entry is a path, optionally followed by clauses that narrow it:
// "/usr/lib/systemd/systemd-resolved user:systemd-resolve" matches only while
// the program runs as that account, and "... sha256:<64 hex>" only that build.
const (
	quietHashClause = "sha256:"
	quietUserClause = "user:"
)

// quietPath is one quiet entry taken apart.
type quietPath struct {
	pattern, sha, account string
	hasSHA, hasAccount    bool
}

// splitQuietPath separates a quiet path entry from its trailing clauses.
func splitQuietPath(entry string) quietPath {
	q := quietPath{pattern: entry}
	for {
		i := strings.LastIndex(q.pattern, " ")
		if i < 0 {
			return q
		}
		clause := q.pattern[i+1:]
		switch {
		case strings.HasPrefix(clause, quietHashClause) && !q.hasSHA:
			q.sha, q.hasSHA = strings.TrimPrefix(clause, quietHashClause), true
		case strings.HasPrefix(clause, quietUserClause) && !q.hasAccount:
			q.account, q.hasAccount = strings.TrimPrefix(clause, quietUserClause), true
		default:
			return q
		}
		q.pattern = strings.TrimRight(q.pattern[:i], " ")
	}
}

// IsServiceAccount reports a process running as the system itself, or as the
// one service account an entry names. Any program can be started from a
// listed path by a login user - bind-mounted over it in a user namespace, or
// with its own library preloaded into the real one - but no login user can
// start it as root, SYSTEM or a daemon's own account. An event whose account
// was not read is not one of these.
func IsServiceAccount(user, account string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	switch u {
	case "":
		return false
	case "root", "system", `nt authority\system`, `nt authority\local service`, `nt authority\network service`:
		return true
	}
	return account != "" && u == strings.ToLower(account)
}

// IsASN reports an entry written as an AS number ("AS15169", any case).
func IsASN(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return len(v) > 2 && strings.HasPrefix(v, "as") && strings.Trim(v[2:], "0123456789") == ""
}

// OwnerMatches is the one way a quiet entry names a network: by its AS number,
// or by its exact resolved name. A fragment of a name used to be enough, and
// "amazon" or "google" also named every machine rented inside their clouds.
func OwnerMatches(owner, asn, org string) bool {
	owner = strings.ToLower(strings.TrimSpace(owner))
	if owner == "" {
		return false
	}
	if IsASN(owner) {
		return strings.EqualFold(owner, strings.TrimSpace(asn))
	}
	return owner == strings.ToLower(strings.TrimSpace(org))
}

// isInlineWorkload reports a workload that runs code given on its command
// line or on stdin (detector.WorkloadOf spells both "-c"). That is what an
// injected one-liner looks like, so it is never known.
func isInlineWorkload(w string) bool {
	return strings.HasSuffix(w, " -c") || strings.HasSuffix(w, " -e") || strings.HasSuffix(w, " -")
}

// literalPath accepts an absolute path whose first directory and file name are
// spelled out, so a wildcard can stand for a release directory but not for
// "any script three levels deep".
func literalPath(p string) error {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q is not an absolute path", p)
	case len(segs) < 2 || strings.Contains(segs[0], "*"):
		return fmt.Errorf("%q does not name its first directory", p)
	case strings.Trim(segs[len(segs)-1], "*.") == "" || strings.HasPrefix(segs[len(segs)-1], "*"):
		return fmt.Errorf("%q leaves its file name to a wildcard", p)
	}
	return nil
}

// isPathWorkload reports a workload that is an executable's path rather than
// an interpreter and what it runs.
func isPathWorkload(w string) bool {
	return strings.HasPrefix(w, "/") || (len(w) > 2 && w[1] == ':' && w[2] == '/')
}

// matchWorkload matches pattern against workload, "*" spanning any run of
// characters within one path segment of one argument: never a "/" or a space.
func matchWorkload(pattern, workload string) bool {
	if pattern == "" {
		return workload == ""
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(workload); i++ {
			if matchWorkload(pattern[1:], workload[i:]) {
				return true
			}
			if i < len(workload) && (workload[i] == '/' || workload[i] == ' ') {
				return false
			}
		}
		return false
	}
	return workload != "" && pattern[0] == workload[0] && matchWorkload(pattern[1:], workload[1:])
}

// OffHoursLabel renders the window the way it is shown next to an alert.
func (t DetectionTuning) OffHoursLabel() string {
	return fmt.Sprintf("%02d:00-%02d:00 %s", t.OffHoursStart, t.OffHoursEnd, t.Location())
}

// IsContainerAddress matches only operator-configured container networks.
func (t DetectionTuning) IsContainerAddress(raw string) bool {
	a, err := netaddr.Parse(raw)
	if err != nil {
		return false
	}
	for _, cidr := range t.ContainerCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err == nil && p.Contains(a.WithZone("")) {
			return true
		}
	}
	return false
}
