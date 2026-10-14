package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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

	FirstSeenOn       bool `json:"first_seen_enabled"`
	FirstSeenCooldown int  `json:"first_seen_cooldown_minutes"`
	BandwidthOn       bool `json:"bandwidth_enabled"`
	BandwidthCooldown int  `json:"bandwidth_cooldown_minutes"`

	// BandwidthMinSamples is how many transfers a process must have made before
	// its mean and standard deviation are treated as a baseline. This was four,
	// compiled in: four observations do not describe a process's normal volume,
	// and the first genuinely large upload after them scores an enormous
	// z-score against the noise of the previous three.
	BandwidthMinSamples int `json:"bandwidth_min_samples"`

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

	// QuietProcesses and QuietOrgs are the operator's own answers to "this is
	// normal here". Matched on the process base name and on a substring of the
	// resolved network owner.
	QuietProcesses []string `json:"quiet_processes"`
	QuietOrgs      []string `json:"quiet_orgs"`

	// QuietClients are the processes whose regular traffic to a vouched network
	// is expected: browsers, updaters, this agent.
	//
	// A quiet org on its own is far wider than it reads. "Cloudflare is normal
	// here" silences every process on every port to a network that fronts a
	// large part of the web, which is exactly where beaconing is easiest to
	// hide - the published allowlist is the point of the technique. Silence is
	// therefore granted to a process talking to a vouched network, never to the
	// network alone: chrome to Cloudflare is ordinary, python to Cloudflare is
	// the finding.
	QuietClients []string `json:"quiet_clients"`

	// QuietPairs are one-off exceptions, written "process@owner" - the shape
	// the console's Expected button and the learning proposals produce.
	QuietPairs []string `json:"quiet_pairs"`

	// ContainerCIDRs are explicit lateral-movement exemptions, never guessed from private address space.
	ContainerCIDRs []string `json:"container_cidrs"`

	// KnownWorkloads name the long-running programs whose outbound
	// conversations are their job, each with the reason it is known.
	//
	// An interpreter's base name says almost nothing: on a developer machine
	// every service, test run and one-off script is "python3.13", so vouching
	// for "python3.13 to Google" would vouch for all of them, including the
	// script a prompt-injected agent writes. A workload is the interpreter
	// together with the program it runs (see detector.WorkloadOf), so a market
	// data worker or a web-research crawler can be named without naming every
	// other python on the host. Inline code (-c, -e) is never a workload.
	//
	// A known workload silences only the novelty findings: a new destination,
	// an interpreter reaching out, activity off-hours. Beaconing, upload volume
	// and threat-intelligence matches still judge it, so a known crawler that
	// starts sending data out is still reported.
	KnownWorkloads []KnownWorkload `json:"known_workloads"`

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

		FirstSeenOn:         true,
		FirstSeenCooldown:   30,
		BandwidthOn:         true,
		BandwidthCooldown:   5,
		BandwidthMinSamples: 20,

		SilenceOn:           true,
		SilenceAfterMinutes: 15,

		WarmupHours: 24,

		QuietProcesses: defaultQuietProcesses(),
		QuietOrgs:      defaultQuietOrgs(),
		QuietClients:   defaultQuietClients(),
	}
}

// defaultQuietProcesses is a starting point, not a security boundary. Every
// name here is an operating system component whose whole job is to talk to its
// vendor on a timer; leaving them in makes the detector describe the platform
// rather than the intruder. They are listed in the console and can be removed.
func defaultQuietProcesses() []string {
	return []string{
		// Windows
		"svchost.exe", "services.exe", "lsass.exe", "system", "ntoskrnl.exe",
		"spoolsv.exe", "dwm.exe", "searchhost.exe", "tiworker.exe",
		"trustedinstaller.exe", "msmpeng.exe", "usocoreworker.exe",
		// Linux
		"systemd", "systemd-resolved", "systemd-timesyncd", "chronyd", "ntpd",
		"snapd", "packagekitd", "unattended-upgr", "dbus-daemon",
		// This fleet's own agent, which heartbeats on a fixed interval and is
		// therefore the most perfect beacon on any host it is installed on.
		// "ominull_agent.exe" was the Windows entry and is not a file that
		// exists; the service binary is ominulld.exe, so the Windows agent was
		// never actually quiet and reported its own hub traffic as an
		// exfiltration spike.
		"ominull-agent", "ominulld", "ominulld.exe", "ominull_agent.exe",
		// Trusted communication clients with known regular keepalive intervals
		"telegram", "telegram-desktop", "Telegram.exe",
	}
}

// defaultQuietClients are the processes that talk to vendor networks all day by
// design. Being on this list silences nothing on its own: it only means that
// this process talking to an already-vouched owner is unremarkable.
func defaultQuietClients() []string {
	return []string{
		// Browsers, which account for most traffic to CDN and vendor networks.
		"chrome", "chrome.exe", "chromium", "firefox", "firefox.exe",
		"msedge.exe", "safari", "brave", "brave.exe", "opera.exe",
		// Platform updaters and stores.
		"svchost.exe", "usocoreworker.exe", "msmpeng.exe", "snapd",
		"packagekitd", "unattended-upgr", "softwareupdated", "nsurlsessiond",
		// This fleet's own agent, which is the most regular talker on any host
		// it is installed on.
		"ominull-agent", "ominulld", "ominulld.exe",
		// Chat and assistant clients with fixed keepalives. These hold a
		// websocket open and ping it on a timer, which is regular, uniform and
		// entirely ordinary - the shape the beacon detector exists to find,
		// produced by an application the operator installed on purpose.
		"telegram", "telegram-desktop", "telegram.exe",
		"chatgpt", "chatgpt.exe", "claude-desktop", "claude", "claude.exe",
	}
}

func defaultQuietOrgs() []string {
	return []string{"apple", "microsoft", "google", "cloudflare", "amazon", "akamai", "fastly", "telegram"}
}

func (s *Store) initDetectionTuningSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS detection_tuning (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		settings TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		updated_by TEXT NOT NULL DEFAULT ''
	);`)
	return err
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
	return t.normalised()
}

// SaveDetectionTuning writes the tuning after clamping it. Anything a form can
// send, a form will eventually send: a zero sample count would make every pair
// of packets a beacon, and a threshold above one would switch the detector off
// without saying so.
func (s *Store) SaveDetectionTuning(t DetectionTuning, by string) (DetectionTuning, error) {
	t = t.normalised()
	for i, raw := range t.ContainerCIDRs {
		p, err := netip.ParsePrefix(raw)
		valid := false
		if err == nil && !p.Addr().Is4In6() {
			for _, space := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
				private := netip.MustParsePrefix(space)
				if p.Bits() >= private.Bits() && private.Contains(p.Masked().Addr()) {
					valid = true
					break
				}
			}
		}
		if !valid {
			return t, fmt.Errorf("%w: container network %q must lie wholly inside private IPv4 or IPv6 space", ErrInvalidDetectionTuning, raw)
		}
		t.ContainerCIDRs[i] = p.Masked().String()
	}
	for _, k := range t.KnownWorkloads {
		if err := k.validate(); err != nil {
			return t, fmt.Errorf("%w: %v", ErrInvalidDetectionTuning, err)
		}
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
// replay judges exactly what a save would store.
func PrepareDetectionTuning(t DetectionTuning) (DetectionTuning, error) {
	t = t.normalised()
	for _, k := range t.KnownWorkloads {
		if err := k.validate(); err != nil {
			return t, fmt.Errorf("%w: %v", ErrInvalidDetectionTuning, err)
		}
	}
	return t, nil
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
	t.FirstSeenCooldown = clampInt(t.FirstSeenCooldown, 1, 1440, 30)
	t.BandwidthCooldown = clampInt(t.BandwidthCooldown, 1, 1440, 5)
	t.BandwidthMinSamples = clampInt(t.BandwidthMinSamples, 4, 1000, 20)
	// Below five minutes this reports every reboot and every flaky link; above
	// a day it is not alerting on absence, it is noticing it eventually.
	t.SilenceAfterMinutes = clampInt(t.SilenceAfterMinutes, 5, 1440, 15)
	if t.WarmupHours < 0 {
		t.WarmupHours = 0
	}
	if t.WarmupHours > 720 {
		t.WarmupHours = 720
	}
	t.QuietProcesses = tidyList(t.QuietProcesses)
	t.QuietOrgs = tidyList(t.QuietOrgs)
	t.QuietClients = tidyList(t.QuietClients)
	t.QuietPairs = tidyPairs(t.QuietPairs)
	t.ContainerCIDRs = tidyList(t.ContainerCIDRs)
	t.KnownWorkloads = tidyWorkloads(t.KnownWorkloads)
	t.AgentHeavyEndpoints = tidyList(t.AgentHeavyEndpoints)
	t.AgentHeavyRoles = tidyList(t.AgentHeavyRoles)
	t.AgentRuntimes = tidyAgentRuntimes(t.AgentRuntimes)
	t.AgentBaselineDays = clampInt(t.AgentBaselineDays, 1, 90, 7)
	t.AgentUploadFloorMB = clampInt(t.AgentUploadFloorMB, 1, 100000, 100)
	t.AgentUploadFactor = clampInt(t.AgentUploadFactor, 2, 100, 5)
	return t
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

// tidyPairs keeps only entries shaped "process@owner". A pair missing either
// half would otherwise widen into "this process anywhere" or "this owner for
// anything", which is the failure the pair exists to avoid.
func tidyPairs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		proc, org, ok := splitPair(v)
		if !ok {
			continue
		}
		v = proc + "@" + org
		if seen[v] {
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

// IsQuietProcess matches on the base name, lower-cased.
func (t DetectionTuning) IsQuietProcess(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	for _, q := range t.QuietProcesses {
		if q == base {
			return true
		}
	}
	return false
}

// IsQuietOrg matches a substring of the resolved network owner, because the
// same operator writes "Apple" and reads "APPLE-ENGINEERING, Apple Inc.".
func (t DetectionTuning) IsQuietOrg(org string) bool {
	org = strings.ToLower(org)
	if strings.TrimSpace(org) == "" {
		return false
	}
	for _, q := range t.QuietOrgs {
		if strings.Contains(org, q) {
			return true
		}
	}
	return false
}

// IsQuietClient matches the process base name against the expected-client list.
func (t DetectionTuning) IsQuietClient(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	if base == "" {
		return false
	}
	for _, q := range t.QuietClients {
		if q == base {
			return true
		}
	}
	return false
}

// IsVouchedPair answers the only question that should silence a conversation:
// is this process, talking to this owner, expected here?
//
// Two things can refuse. Rented compute is never vouched for whatever its
// owner's name is - an EC2 instance is Amazon's address and somebody else's
// machine - and a process nobody has vouched for is a finding even on the most
// ordinary network in the estate.
func (t DetectionTuning) IsVouchedPair(procBase, org, tenancy string) bool {
	procBase = strings.ToLower(strings.TrimSpace(procBase))
	org = strings.ToLower(strings.TrimSpace(org))
	if procBase == "" || org == "" {
		return false
	}
	if strings.TrimSpace(tenancy) == TenancyHosting {
		return false
	}

	// An explicit pair is the operator naming this exact conversation.
	for _, entry := range t.QuietPairs {
		proc, owner, ok := splitPair(entry)
		if !ok || proc != procBase {
			continue
		}
		if strings.Contains(org, owner) {
			return true
		}
	}

	return t.IsQuietOrg(org) && t.IsQuietClient(procBase)
}

// KnownWorkload is one program whose outbound conversations are its job.
//
// Workload is a pattern over detector.WorkloadOf's output, where "*" stands
// for any run of characters within one path segment of one argument (never a
// "/" or a space), so a release directory named by its hash can be matched
// without matching every directory. Owner is a substring of the network
// owner, or "*" for a program whose destinations are arbitrary by design,
// such as a web crawler. Reason is required: an exclusion nobody can explain
// later is one nobody can remove.
//
// IncludeRented widens an interpreter's "*" to rented compute and unnamed
// addresses, which it otherwise never covers (see KnownWorkloadFor). It is
// for a program whose job is those destinations - a crawler fetching sites
// hosted on cloud machines, a worker reading data providers with no
// registered name - and its reason should say so.
type KnownWorkload struct {
	Workload      string `json:"workload"`
	Owner         string `json:"owner"`
	Reason        string `json:"reason"`
	IncludeRented bool   `json:"include_rented,omitempty"`
}

// AnyOwner is the Owner of a workload known to reach arbitrary destinations.
const AnyOwner = "*"

func (k KnownWorkload) validate() error {
	if strings.Trim(k.Workload, "* ") == "" || strings.HasPrefix(k.Workload, "*") {
		return fmt.Errorf("known workload %q names no program", k.Workload)
	}
	// An interpreter is only a known program together with what it runs:
	// "python3.13 *" would be every python on the host, "python3 -m *" every
	// module, and "node npm ci" is named only by argv[0], which the process
	// chooses (exec -a). The program must be a module after -m, a jar after
	// -jar, or a script by its absolute path, and must be spelled out.
	if !isPathWorkload(k.Workload) {
		tokens := strings.Fields(k.Workload)
		if len(tokens) < 2 {
			return fmt.Errorf("known workload %q is an interpreter without the program it runs", k.Workload)
		}
		prog := tokens[len(tokens)-1]
		switch flag := ""; {
		case len(tokens) >= 3 && tokens[len(tokens)-2] == "-m":
			flag = "-m"
			if strings.Contains(prog, "*") {
				return fmt.Errorf("known workload %q: a module after %s is named exactly", k.Workload, flag)
			}
		case len(tokens) >= 3 && tokens[len(tokens)-2] == "-jar":
			if err := literalPath(prog); err != nil {
				return fmt.Errorf("known workload %q: the jar %v", k.Workload, err)
			}
		default:
			if err := literalPath(prog); err != nil {
				return fmt.Errorf("known workload %q must end with the program it runs (an absolute script path, -m module or -jar file): the script %v", k.Workload, err)
			}
		}
	}
	if k.Owner == "" {
		return fmt.Errorf("known workload %q needs an owner (a network name, or %q)", k.Workload, AnyOwner)
	}
	if k.IncludeRented && k.Owner != AnyOwner {
		return fmt.Errorf("known workload %q: include_rented widens only the owner %q; a named owner never covers rented compute", k.Workload, AnyOwner)
	}
	if strings.TrimSpace(k.Reason) == "" {
		return fmt.Errorf("known workload %q needs a reason", k.Workload)
	}
	if isInlineWorkload(k.Workload) {
		return fmt.Errorf("known workload %q is inline code, which is never a known program", k.Workload)
	}
	return nil
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

func tidyWorkloads(in []KnownWorkload) []KnownWorkload {
	seen := map[string]bool{}
	out := make([]KnownWorkload, 0, len(in))
	for _, k := range in {
		k.Workload = strings.Join(strings.Fields(k.Workload), " ")
		if isPathWorkload(k.Workload) {
			k.Workload = strings.ToLower(k.Workload) // detector.WorkloadOf lower-cases paths
		}
		k.Owner = strings.ToLower(strings.TrimSpace(k.Owner))
		k.Reason = strings.TrimSpace(k.Reason)
		key := fmt.Sprintf("%s@%s@%v", k.Workload, k.Owner, k.IncludeRented)
		if k.Workload == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workload != out[j].Workload {
			return out[i].Workload < out[j].Workload
		}
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return !out[i].IncludeRented && out[j].IncludeRented
	})
	return out
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

// KnownWorkloadFor returns the entry that makes this conversation expected:
// this workload, talking to this owner.
//
// A named owner never covers rented compute or an unnamed address, for the
// reason IsVouchedPair gives. AnyOwner covers them only for an installed
// program known by its path. An interpreter's workload is read from its own
// command line, which any process can imitate, so for an interpreter AnyOwner
// means any named network that is not rented compute - which is where a
// command-and-control server would be - unless the entry says IncludeRented.
// Either way only the novelty detectors are silenced: a disguised process
// that beacons or moves volume is still judged by the detectors that see it.
func (t DetectionTuning) KnownWorkloadFor(workload, org, tenancy string) (KnownWorkload, bool) {
	if workload == "" || isInlineWorkload(workload) {
		return KnownWorkload{}, false
	}
	org = strings.ToLower(strings.TrimSpace(org))
	named := org != "" && strings.TrimSpace(tenancy) != TenancyHosting
	for _, k := range t.KnownWorkloads {
		if !matchWorkload(k.Workload, workload) {
			continue
		}
		if k.Owner == AnyOwner && k.coversAnywhere(workload, named) {
			return k, true
		}
		if named && strings.Contains(org, k.Owner) {
			return k, true
		}
	}
	return KnownWorkload{}, false
}

// coversAnywhere is the reach of an AnyOwner entry: every destination for an
// installed program, named networks only for an interpreter unless the entry
// says IncludeRented.
func (k KnownWorkload) coversAnywhere(workload string, named bool) bool {
	return named || isPathWorkload(workload) || k.IncludeRented
}

// KnownService returns the entry naming this workload as a service: one known
// for any owner, judged with the same reach as KnownWorkloadFor. A service
// runs around the clock, so the hour it talks is not a finding; a build tool
// known for one registry is not a service, and a build at three in the
// morning is still news.
func (t DetectionTuning) KnownService(workload, org, tenancy string) (KnownWorkload, bool) {
	if workload == "" || isInlineWorkload(workload) {
		return KnownWorkload{}, false
	}
	named := strings.TrimSpace(org) != "" && strings.TrimSpace(tenancy) != TenancyHosting
	for _, k := range t.KnownWorkloads {
		if k.Owner == AnyOwner && matchWorkload(k.Workload, workload) && k.coversAnywhere(workload, named) {
			return k, true
		}
	}
	return KnownWorkload{}, false
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
