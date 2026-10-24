package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	// normal here". A process is named by its installed path (see
	// MatchesQuietPath), never its base name: malware called svchost.exe in a
	// temp directory is not svchost. A network is named by its AS number, and
	// rented compute inside that AS is never quiet (IsQuietOrg).
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

	// QuietPairs are one-off exceptions, written "path@owner" - the shape the
	// console's Expected button and the learning proposals produce. The owner
	// is an AS number or the network's exact name (OwnerMatches).
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
	// AgentRuntimeVendors name each runtime's maker, its service domains and
	// the address ranges it publishes for them (AgentRuntimeVendor). A flow
	// from the runtime to its maker's range is judged by the runtime's hourly
	// upload volume, not the per-connection bandwidth baseline. Adding a
	// domain or prefix loosens detection; removing one tightens it.
	AgentRuntimeVendors []AgentRuntimeVendor `json:"agent_runtime_vendors"`

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

	// AdminFanoutSources, AdminFanoutTargets and AdminFanoutMax describe the
	// routine administration that the lateral sweep detector does not page
	// on: ssh from one of these endpoints (by id), to port 22 only, on hosts
	// that are all inventoried (an enrolled endpoint's address, or inside
	// AdminFanoutTargets: managed hosts without an agent such as the gateway),
	// at most AdminFanoutMax of them in the window. Anything else - another
	// source, another port, one unknown host, more hosts - is judged as
	// before. Empty sources switch the rule off (detector/admin_fanout.go).
	AdminFanoutSources []string `json:"admin_fanout_sources"`
	AdminFanoutTargets []string `json:"admin_fanout_targets"`
	AdminFanoutMax     int      `json:"admin_fanout_max_hosts"`

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

		AgentEgressOn:       true,
		AgentHeavyObserved:  true,
		AgentRuntimes:       defaultAgentRuntimes(),
		AgentRuntimeVendors: defaultAgentRuntimeVendors(),
		AgentBaselineDays:   7,
		AgentUploadFloorMB:  100,
		AgentUploadFactor:   5,

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
// entry here is an operating system component whose whole job is to talk to its
// vendor on a timer; leaving them in makes the detector describe the platform
// rather than the intruder. They are listed in the console and can be removed.
//
// Each is the path the component is installed at, in directories only an
// administrator can write, and matches only while it runs as the system or as
// its own service account (IsServiceAccount): a login user can make any
// program appear at one of these paths, but not run it as that account.
// Components that were listed only because they are familiar, and in two weeks
// of this estate's traffic never reached the network, are not: an entry that
// silences nothing real is cover for whatever borrows its path.
func defaultQuietProcesses() []string {
	return []string{
		// Windows
		"c:/windows/system32/svchost.exe", "c:/windows/system32/lsass.exe",
		"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe",
		// Linux
		"/usr/lib/systemd/systemd-resolved user:systemd-resolve",
		"/usr/lib/systemd/systemd-timesyncd user:systemd-timesync",
		"/usr/sbin/chronyd user:_chrony", "/usr/sbin/chronyd user:chrony",
		"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd",
		// This fleet's own agent, which heartbeats on a fixed interval and is
		// therefore the most perfect beacon on any host it is installed on.
		"/opt/ominull/bin/ominulld", "c:/program files/ominull/ominulld.exe",
	}
}

// defaultQuietClients are the programs that talk to vendor networks all day by
// design. Being on this list silences nothing on its own: it only means that
// this program talking to an already-vouched owner is unremarkable.
func defaultQuietClients() []string {
	return []string{
		// Browsers, which account for most traffic to CDN and vendor networks.
		"/opt/google/chrome/chrome", "c:/program files/google/chrome/application/chrome.exe",
		"c:/program files (x86)/google/chrome/application/chrome.exe",
		"/usr/lib/chromium/chromium", "/snap/chromium/*/usr/lib/chromium-browser/chrome",
		"/usr/lib/firefox/firefox", "/snap/firefox/*/usr/lib/firefox/firefox",
		"c:/program files/mozilla firefox/firefox.exe",
		"c:/program files (x86)/microsoft/edge/application/msedge.exe",
		"/applications/safari.app/contents/macos/safari",
		"/opt/brave.com/brave/brave", "c:/program files/bravesoftware/brave-browser/application/brave.exe",
		// Platform updaters and stores.
		"c:/windows/system32/svchost.exe", "c:/windows/system32/usocoreworker.exe",
		"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe",
		"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd", "/usr/libexec/packagekitd",
		"/usr/libexec/nsurlsessiond",
		"/system/library/privateframeworks/softwareupdate.framework/resources/softwareupdated",
		// This fleet's own agent, which is the most regular talker on any host
		// it is installed on.
		"/opt/ominull/bin/ominulld", "c:/program files/ominull/ominulld.exe",
		// Chat and assistant clients with fixed keepalives. These hold a
		// websocket open and ping it on a timer, which is regular, uniform and
		// entirely ordinary - the shape the beacon detector exists to find,
		// produced by an application the operator installed on purpose.
		"/usr/lib/chatgpt/chatgpt", "/usr/lib/claude-desktop/claude-desktop",
	}
}

// defaultQuietOrgs are the vendors' own AS numbers: Apple, Microsoft, Google,
// Cloudflare, Amazon, Akamai and Fastly. Rented compute inside them (EC2,
// Azure, the published cloud ranges) is never quiet.
func defaultQuietOrgs() []string {
	return []string{"as714", "as8075", "as15169", "as13335", "as16509", "as20940", "as54113"}
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
	s.migrateSavedTuning(time.Now().UTC())
	return nil
}

// legacyQuietProcesses are the quiet-process entries the shipped quiet names
// become, for rewriting a row saved when the quiet lists matched base names.
// The components that never reached the network (defaultQuietProcesses) are
// left out, and so dropped from the row, like any name not here: kept, a name
// would match nothing anyway.
var legacyQuietProcesses = map[string][]string{
	"svchost.exe":       {"c:/windows/system32/svchost.exe"},
	"lsass.exe":         {"c:/windows/system32/lsass.exe"},
	"msmpeng.exe":       {"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe"},
	"systemd-resolved":  {"/usr/lib/systemd/systemd-resolved user:systemd-resolve"},
	"systemd-timesyncd": {"/usr/lib/systemd/systemd-timesyncd user:systemd-timesync"},
	"chronyd":           {"/usr/sbin/chronyd user:_chrony", "/usr/sbin/chronyd user:chrony"},
	"snapd":             {"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd"},
	"ominull-agent":     {"/opt/ominull/bin/ominulld"},
	"ominulld":          {"/opt/ominull/bin/ominulld"},
	"ominulld.exe":      {"c:/program files/ominull/ominulld.exe"},
	"ominull_agent.exe": {"c:/program files/ominull/ominulld.exe"},
}

// legacyQuietPaths are the paths the shipped expected-client and pair names
// are installed at. A program in a folder any account can write to, such as
// ~/.local/bin/rclone, is not carried over: by path alone that is whatever
// was put there last. Nor is a path where nothing ran: rclone was never at
// /usr/bin/rclone, and an unpinned entry there would vouch for whatever a
// login user presents at that path through a user namespace bind mount.
var legacyQuietPaths = map[string][]string{
	"svchost.exe":       {"c:/windows/system32/svchost.exe"},
	"usocoreworker.exe": {"c:/windows/system32/usocoreworker.exe"},
	"msmpeng.exe":       {"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe"},
	"snapd":             {"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd"},
	"packagekitd":       {"/usr/libexec/packagekitd"},
	"ominull-agent":     {"/opt/ominull/bin/ominulld"},
	"ominulld":          {"/opt/ominull/bin/ominulld"},
	"ominulld.exe":      {"c:/program files/ominull/ominulld.exe"},
	"ominull_agent.exe": {"c:/program files/ominull/ominulld.exe"},
	"chrome":            {"/opt/google/chrome/chrome"},
	"chrome.exe": {"c:/program files/google/chrome/application/chrome.exe",
		"c:/program files (x86)/google/chrome/application/chrome.exe"},
	"chromium":        {"/usr/lib/chromium/chromium", "/snap/chromium/*/usr/lib/chromium-browser/chrome"},
	"firefox":         {"/usr/lib/firefox/firefox", "/snap/firefox/*/usr/lib/firefox/firefox"},
	"firefox.exe":     {"c:/program files/mozilla firefox/firefox.exe"},
	"msedge.exe":      {"c:/program files (x86)/microsoft/edge/application/msedge.exe"},
	"safari":          {"/applications/safari.app/contents/macos/safari"},
	"brave":           {"/opt/brave.com/brave/brave"},
	"brave.exe":       {"c:/program files/bravesoftware/brave-browser/application/brave.exe"},
	"nsurlsessiond":   {"/usr/libexec/nsurlsessiond"},
	"softwareupdated": {"/system/library/privateframeworks/softwareupdate.framework/resources/softwareupdated"},
	"chatgpt":         {"/usr/lib/chatgpt/chatgpt"},
	"claude-desktop":  {"/usr/lib/claude-desktop/claude-desktop"},
}

// legacyQuietOwners are the AS numbers behind the name fragments the shipped
// quiet networks and known-workload owners used.
var legacyQuietOwners = map[string]string{
	"apple": "as714", "microsoft": "as8075", "google": "as15169", "cloudflare": "as13335",
	"amazon": "as16509", "akamai": "as20940", "fastly": "as54113", "github": "as36459",
}

// migrateQuietLists rewrites quiet entries saved when processes matched by base
// name and networks by a fragment of their name. Entries already written as
// paths and AS numbers are kept as they are, so running it twice changes
// nothing. It returns what it could not carry over.
func migrateQuietLists(t DetectionTuning) (DetectionTuning, []string) {
	var dropped []string
	paths := func(list []string, what string, valid func(string) error, legacy map[string][]string) []string {
		out := []string{}
		for _, v := range list {
			switch {
			case valid(v) == nil:
				out = append(out, v)
			case legacy[v] != nil:
				out = append(out, legacy[v]...)
			default:
				dropped = append(dropped, what+" "+v)
			}
		}
		return out
	}
	t.QuietProcesses = paths(t.QuietProcesses, "quiet process", ValidQuietPath, legacyQuietProcesses)
	t.QuietClients = paths(t.QuietClients, "expected client", validClientPath, legacyQuietPaths)

	orgs := []string{}
	for _, v := range t.QuietOrgs {
		switch {
		case IsASN(v):
			orgs = append(orgs, v)
		case legacyQuietOwners[v] != "":
			orgs = append(orgs, legacyQuietOwners[v])
		default:
			dropped = append(dropped, "quiet network "+v)
		}
	}
	t.QuietOrgs = orgs

	pairs := []string{}
	for _, v := range t.QuietPairs {
		proc, owner, ok := splitPair(v)
		procs := []string{proc}
		if validClientPath(proc) != nil {
			procs = legacyQuietPaths[proc]
		}
		if asn := legacyQuietOwners[owner]; asn != "" {
			owner = asn
		}
		if !ok || len(procs) == 0 {
			dropped = append(dropped, "expected pair "+v)
			continue
		}
		for _, p := range procs {
			pairs = append(pairs, p+"@"+owner)
		}
	}
	t.QuietPairs = pairs

	for i, k := range t.KnownWorkloads {
		if asn := legacyQuietOwners[k.Owner]; asn != "" {
			t.KnownWorkloads[i].Owner = asn
		}
	}
	return t.normalised(), dropped
}

// boundWorkloadExpiry gives each known workload saved before entries had an
// expiry one at = now + KnownWorkloadMaxLifetime. An entry that already has
// an expiry keeps it, so running it twice changes nothing and it never
// extends one. A row an older hub re-saved has lost its expiries and gets
// fresh ones here: an accepted limit of downgrading. It returns how many it
// bounded.
func boundWorkloadExpiry(t DetectionTuning, now time.Time) (DetectionTuning, int) {
	n := 0
	until := now.UTC().Add(KnownWorkloadMaxLifetime).Truncate(time.Second)
	out := make([]KnownWorkload, len(t.KnownWorkloads))
	for i, k := range t.KnownWorkloads {
		if k.ExpiresAt.IsZero() {
			k.ExpiresAt = until
			n++
		}
		out[i] = k
	}
	t.KnownWorkloads = out
	return t, n
}

// migrateSavedTuning rewrites the stored row once, on the first start that
// matches by path and AS number, and on the first start that requires known
// workloads to expire. A row it cannot save is left as it is: its old quiet
// entries match nothing now, and its known workloads without an expiry vouch
// for nothing, which is quieter for nobody (DetectionTuningProblem reports
// the row on the Nightshift feed).
func (s *Store) migrateSavedTuning(now time.Time) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM detection_tuning WHERE id = 1`).Scan(&exists); err != nil || exists == 0 {
		return
	}
	before := s.GetDetectionTuning()
	after, dropped := migrateQuietLists(before)
	after, bounded := boundWorkloadExpiry(after, now)
	was, _ := json.Marshal(quietListsOf(before))
	is, _ := json.Marshal(quietListsOf(after))
	if string(was) == string(is) {
		return
	}
	if _, err := s.SaveDetectionTuning(after, "upgrade"); err != nil {
		log.Printf("[-] Detection tuning: the saved row could not be upgraded (quiet lists as paths and AS numbers, known workloads with an expiry); old quiet entries and known workloads without an expiry now match nothing: %v", err)
		return
	}
	if len(dropped) > 0 {
		log.Printf("[+] Detection tuning: quiet lists rewritten as paths and AS numbers (dropped: %s)", strings.Join(dropped, ", "))
	}
	if bounded > 0 {
		log.Printf("[+] Detection tuning: %d known workloads saved without an expiry now expire at %s", bounded, now.UTC().Add(KnownWorkloadMaxLifetime).Format(time.RFC3339))
	}
}

// CheckNewWorkloadExpiry refuses a known workload a save adds or changes
// without an expiry in the future, or with one further out than
// KnownWorkloadMaxLifetime. An entry carried over exactly as saved may have
// expired since; the save then drops it (PrepareDetectionTuning).
func CheckNewWorkloadExpiry(before, after []KnownWorkload, now time.Time) error {
	saved := map[string]bool{}
	for _, k := range tidyWorkloads(before) {
		saved[k.Key()+"@"+k.ExpiresAt.Format(time.RFC3339)] = true
	}
	for _, k := range tidyWorkloads(after) {
		if saved[k.Key()+"@"+k.ExpiresAt.Format(time.RFC3339)] {
			continue
		}
		if !k.ExpiresAt.After(now) {
			return fmt.Errorf("%w: known workload %q needs an expires_at in the future", ErrInvalidDetectionTuning, k.Workload)
		}
		if k.ExpiresAt.After(now.Add(KnownWorkloadMaxLifetime)) {
			return fmt.Errorf("%w: known workload %q expires_at is more than %d days out; renew it when it nears expiry instead", ErrInvalidDetectionTuning, k.Workload, int(KnownWorkloadMaxLifetime.Hours()/24))
		}
	}
	return nil
}

func quietListsOf(t DetectionTuning) []any {
	return []any{t.QuietProcesses, t.QuietOrgs, t.QuietClients, t.QuietPairs, t.KnownWorkloads}
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
	live := make([]KnownWorkload, 0, len(t.KnownWorkloads))
	now := time.Now()
	for _, k := range t.KnownWorkloads {
		if err := k.validate(); err != nil {
			return t, fmt.Errorf("%w: %v", ErrInvalidDetectionTuning, err)
		}
		// An expired entry vouches for nothing; a save drops it, which only
		// tightens.
		if !k.Expired(now) {
			live = append(live, k)
		}
	}
	t.KnownWorkloads = live
	if err := t.validQuietLists(); err != nil {
		return t, err
	}
	targets, err := validAdminTargets(t.AdminFanoutTargets)
	if err != nil {
		return t, err
	}
	t.AdminFanoutTargets = targets
	vendors, err := validAgentRuntimeVendors(t.AgentRuntimeVendors)
	if err != nil {
		return t, err
	}
	t.AgentRuntimeVendors = vendors
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

// validQuietLists refuses an entry the matchers would read more widely than it
// is written, or never match: a process by name, a network by a fragment of
// its name.
func (t DetectionTuning) validQuietLists() error {
	for _, entry := range t.QuietProcesses {
		if err := ValidQuietPath(entry); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidDetectionTuning, err)
		}
	}
	for _, entry := range t.QuietClients {
		if err := validClientPath(entry); err != nil {
			return fmt.Errorf("%w: expected client %v", ErrInvalidDetectionTuning, err)
		}
	}
	for _, org := range t.QuietOrgs {
		if !IsASN(org) {
			return fmt.Errorf("%w: quiet network %q must be an AS number such as AS15169", ErrInvalidDetectionTuning, org)
		}
	}
	for _, pair := range t.QuietPairs {
		proc, _, _ := splitPair(pair)
		if err := validClientPath(proc); err != nil {
			return fmt.Errorf("%w: expected pair %q: %v", ErrInvalidDetectionTuning, pair, err)
		}
	}
	return nil
}

// validClientPath is ValidQuietPath for the expected-client and pair lists,
// which are about the programs a person runs and so are not bound to an
// account.
func validClientPath(entry string) error {
	if err := ValidQuietPath(entry); err != nil {
		return err
	}
	if splitQuietPath(entry).hasAccount {
		return fmt.Errorf("%q: only a quiet process is bound to the account it runs as", entry)
	}
	return nil
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
	// Silence is part of the floor: a host that stops reporting blinds every
	// other detector, so no saved row switches it off.
	t.SilenceOn = true
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
	t.AgentRuntimeVendors = tidyAgentRuntimeVendors(t.AgentRuntimeVendors)
	t.AgentBaselineDays = clampInt(t.AgentBaselineDays, 1, 90, 7)
	t.AgentUploadFloorMB = clampInt(t.AgentUploadFloorMB, 1, 100000, 100)
	t.AgentUploadFactor = clampInt(t.AgentUploadFactor, 2, 100, 5)
	t.AdminFanoutSources = tidyList(t.AdminFanoutSources)
	t.AdminFanoutTargets = tidyList(t.AdminFanoutTargets)
	t.AdminFanoutMax = clampInt(t.AdminFanoutMax, 2, 20, AdminFanoutMaxDefault)
	return t
}

// AdminFanoutMaxDefault is how many inventoried hosts one admin fan-out may
// reach in the sweep window before it pages anyway.
const AdminFanoutMaxDefault = 8

// validAdminTargets turns each admin fan-out target into a masked prefix (a
// bare address becomes a host prefix). Private space only: a public address
// is never "our own managed host".
func validAdminTargets(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			if a, aerr := netip.ParseAddr(raw); aerr == nil {
				p, err = a.Prefix(a.BitLen())
			}
		}
		if err != nil || !privatePrefix(p) {
			return nil, fmt.Errorf("%w: admin fan-out target %q must be an address or network inside private IPv4 or IPv6 space", ErrInvalidDetectionTuning, raw)
		}
		out = append(out, p.Masked().String())
	}
	return tidyList(out), nil
}

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

// IsAdminFanoutSource says whether an endpoint's routine ssh fan-out is
// judged by the admin rule.
func (t DetectionTuning) IsAdminFanoutSource(endpointID string) bool {
	id := strings.ToLower(strings.TrimSpace(endpointID))
	for _, s := range t.AdminFanoutSources {
		if s == id {
			return true
		}
	}
	return false
}

// IsAdminFanoutTarget says whether an address lies inside a configured
// managed-host prefix.
func (t DetectionTuning) IsAdminFanoutTarget(raw string) bool {
	a, err := netaddr.Parse(raw)
	if err != nil {
		return false
	}
	for _, cidr := range t.AdminFanoutTargets {
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Contains(a.WithZone("")) {
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

// userWritablePrefixes are directories any local account can put a program
// in. A path there names whatever was copied there last, so an entry under one
// has to pin the build it means.
var userWritablePrefixes = []string{
	"/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
	"c:/users/", "c:/windows/temp/",
}

// ValidQuietPath accepts an absolute path, "*" standing for one path segment
// as in known workloads (a versioned directory), with its first directory and
// file name spelled out, optionally followed by the account it runs as
// ("user:systemd-resolve") and the executable's SHA-256. A path in a directory
// anyone can write to must carry the hash.
func ValidQuietPath(entry string) error {
	q := splitQuietPath(entry)
	if q.hasSHA && (len(q.sha) != 64 || strings.Trim(q.sha, "0123456789abcdef") != "") {
		return fmt.Errorf("%q: the hash must be sha256: and 64 hex digits", entry)
	}
	if q.hasAccount && (q.account == "" || strings.ContainsAny(q.account, "@*")) {
		return fmt.Errorf("%q: user: must name one account, such as user:systemd-resolve", entry)
	}
	if !isPathWorkload(q.pattern) {
		return fmt.Errorf("%q is not an absolute path; a program is named by where it is installed, not by its name", entry)
	}
	for _, dir := range userWritablePrefixes {
		if strings.HasPrefix(q.pattern, dir) && !q.hasSHA {
			return fmt.Errorf("%q is in a folder any account can write to; add sha256:<hash> to name the build you mean", entry)
		}
	}
	pattern := q.pattern
	if len(pattern) > 2 && pattern[1] == ':' {
		pattern = pattern[2:]
	}
	return literalPath(pattern)
}

// MatchesQuietPath reports whether a process, by its executable path and
// (when the entry names one) its hash, is the one an expected-client or pair
// entry names. An entry that is not a path - a base name left from before
// paths were required - matches nothing, and neither does one bound to an
// account, which only the quiet-process list can check.
func MatchesQuietPath(entry, path, sha string) bool {
	q := splitQuietPath(entry)
	return !q.hasAccount && q.matches(path, sha)
}

func (q quietPath) matches(path, sha string) bool {
	key := ProcessPathKey(path)
	if key == "" || !isPathWorkload(q.pattern) || !matchWorkload(q.pattern, key) {
		return false
	}
	return !q.hasSHA || strings.EqualFold(q.sha, strings.TrimSpace(sha))
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

// QuietProcessSample is a process a quiet-process entry matches: its path with
// each "*" filled in, the hash it pins and the account it names (root when it
// names none). The floor drill runs its sweeps as this process.
func QuietProcessSample(entry string) (path, sha, user string) {
	q := splitQuietPath(entry)
	user = "root"
	if q.hasAccount {
		user = q.account
	}
	return strings.ReplaceAll(q.pattern, "*", "floor-drill"), q.sha, user
}

// IsQuietProcess matches the process's installed path, and the account it
// runs as: the system's, or the one the entry names.
func (t DetectionTuning) IsQuietProcess(path, sha, user string) bool {
	for _, entry := range t.QuietProcesses {
		q := splitQuietPath(entry)
		if q.matches(path, sha) && IsServiceAccount(user, q.account) {
			return true
		}
	}
	return false
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

// IsQuietOrg matches the destination's AS number. Rented compute is never
// quiet, whoever's AS it sits in: an EC2 instance is Amazon's address and
// somebody else's machine.
func (t DetectionTuning) IsQuietOrg(asn, tenancy string) bool {
	if strings.TrimSpace(asn) == "" || strings.TrimSpace(tenancy) == TenancyHosting {
		return false
	}
	for _, q := range t.QuietOrgs {
		if IsASN(q) && strings.EqualFold(q, strings.TrimSpace(asn)) {
			return true
		}
	}
	return false
}

// IsQuietClient matches the process's installed path against the
// expected-client list.
func (t DetectionTuning) IsQuietClient(path, sha string) bool {
	for _, q := range t.QuietClients {
		if MatchesQuietPath(q, path, sha) {
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
func (t DetectionTuning) IsVouchedPair(path, sha, asn, org, tenancy string) bool {
	if strings.TrimSpace(tenancy) == TenancyHosting {
		return false
	}

	// An explicit pair is the operator naming this exact conversation.
	for _, entry := range t.QuietPairs {
		proc, owner, ok := splitPair(entry)
		if ok && MatchesQuietPath(proc, path, sha) && OwnerMatches(owner, asn, org) {
			return true
		}
	}

	return t.IsQuietOrg(asn, tenancy) && t.IsQuietClient(path, sha)
}

// KnownWorkload is one program whose outbound conversations are its job.
//
// Workload is a pattern over detector.WorkloadOf's output, where "*" stands
// for any run of characters within one path segment of one argument (never a
// "/" or a space), so a release directory named by its hash can be matched
// without matching every directory. Owner is the network's AS number or exact
// name (OwnerMatches), or "*" for a program whose destinations are arbitrary
// by design, such as a web crawler. Reason is required: an exclusion nobody can explain
// later is one nobody can remove.
//
// IncludeRented widens an interpreter's "*" to rented compute and unnamed
// addresses, which it otherwise never covers (see KnownWorkloadFor). It is
// for a program whose job is those destinations - a crawler fetching sites
// hosted on cloud machines, a worker reading data providers with no
// registered name - and its reason should say so.
//
// ExpiresAt is when the entry stops vouching. A new entry needs one in the
// future; an entry without one, or past it, vouches for nothing. Moving it
// later loosens detection and is authorized by the authority; moving it earlier tightens.
type KnownWorkload struct {
	Workload      string    `json:"workload"`
	Owner         string    `json:"owner"`
	Reason        string    `json:"reason"`
	IncludeRented bool      `json:"include_rented,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Expired reports an entry that no longer vouches: past its expiry, or saved
// before entries had one.
func (k KnownWorkload) Expired(now time.Time) bool {
	return !now.Before(k.ExpiresAt)
}

// Key names an entry without its reason and expiry: the same
// program, owner and reach.
func (k KnownWorkload) Key() string {
	return fmt.Sprintf("%s@%s@%v", k.Workload, k.Owner, k.IncludeRented)
}

// KnownWorkloadMaxLifetime is the longest term a known workload can be added,
// changed or renewed for, like an exclusion (ExclusionMaxLifetime), and the
// expiry the upgrade gives each one saved before entries had one: bounded, so
// an entry nobody renews stops vouching.
const KnownWorkloadMaxLifetime = 90 * 24 * time.Hour

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
	if k.ExpiresAt.IsZero() {
		return fmt.Errorf("known workload %q needs an expires_at, the time it stops vouching", k.Workload)
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
	seen := map[string]int{}
	out := make([]KnownWorkload, 0, len(in))
	for _, k := range in {
		k.Workload = strings.Join(strings.Fields(k.Workload), " ")
		if isPathWorkload(k.Workload) {
			k.Workload = strings.ToLower(k.Workload) // detector.WorkloadOf lower-cases paths
		}
		k.Owner = strings.ToLower(strings.TrimSpace(k.Owner))
		k.Reason = strings.TrimSpace(k.Reason)
		if !k.ExpiresAt.IsZero() {
			k.ExpiresAt = k.ExpiresAt.UTC().Truncate(time.Second)
		}
		if k.Workload == "" {
			continue
		}
		// One entry per program, owner and reach; a duplicate keeps the later
		// expiry, so the judgment of a change sees everything it vouches for.
		if i, dup := seen[k.Key()]; dup {
			if k.ExpiresAt.After(out[i].ExpiresAt) {
				out[i].ExpiresAt = k.ExpiresAt
			}
			continue
		}
		seen[k.Key()] = len(out)
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
func (t DetectionTuning) KnownWorkloadFor(workload, asn, org, tenancy string) (KnownWorkload, bool) {
	if workload == "" || isInlineWorkload(workload) {
		return KnownWorkload{}, false
	}
	named := strings.TrimSpace(org) != "" && strings.TrimSpace(tenancy) != TenancyHosting
	now := time.Now()
	for _, k := range t.KnownWorkloads {
		if k.Expired(now) || !matchWorkload(k.Workload, workload) {
			continue
		}
		if k.Owner == AnyOwner && k.coversAnywhere(workload, named) {
			return k, true
		}
		if named && k.Owner != AnyOwner && OwnerMatches(k.Owner, asn, org) {
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
	now := time.Now()
	for _, k := range t.KnownWorkloads {
		if !k.Expired(now) && k.Owner == AnyOwner && matchWorkload(k.Workload, workload) && k.coversAnywhere(workload, named) {
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
