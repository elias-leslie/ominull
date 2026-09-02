package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

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

		BeaconOn:          true,
		BeaconMinSamples:  12,
		BeaconMinSpanMin:  10,
		BeaconMinInterval: 5,
		BeaconMaxInterval: 3600,
		BeaconScore:       0.80,
		BeaconCooldownMin: 30,

		FirstSeenOn:       true,
		FirstSeenCooldown: 30,
		BandwidthOn:       true,
		BandwidthCooldown: 5,

		WarmupHours: 24,

		QuietProcesses: defaultQuietProcesses(),
		QuietOrgs:      defaultQuietOrgs(),
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
		"ominull-agent", "ominulld", "ominull_agent.exe",
		// Trusted communication clients with known regular keepalive intervals
		"telegram", "telegram-desktop", "Telegram.exe",
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
	if t.WarmupHours < 0 {
		t.WarmupHours = 0
	}
	if t.WarmupHours > 720 {
		t.WarmupHours = 720
	}
	t.QuietProcesses = tidyList(t.QuietProcesses)
	t.QuietOrgs = tidyList(t.QuietOrgs)
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

// OffHoursLabel renders the window the way it is shown next to an alert.
func (t DetectionTuning) OffHoursLabel() string {
	return fmt.Sprintf("%02d:00-%02d:00 %s", t.OffHoursStart, t.OffHoursEnd, t.Location())
}
