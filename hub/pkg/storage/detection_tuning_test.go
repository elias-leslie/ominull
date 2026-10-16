package storage

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The console decides whether to say "these settings differ from the shipped
// values" by comparing the two the hub sends. An unsorted default made every
// hub report differences it did not have.
func TestTheShippedValuesCompareEqualToThemselves(t *testing.T) {
	a := DefaultDetectionTuning()
	b := DefaultDetectionTuning().normalised()
	if len(a.QuietProcesses) != len(b.QuietProcesses) {
		t.Fatalf("list lengths differ: %d vs %d", len(a.QuietProcesses), len(b.QuietProcesses))
	}
	for i := range a.QuietProcesses {
		if a.QuietProcesses[i] != b.QuietProcesses[i] {
			t.Fatalf("defaults are not normalised: %q vs %q", a.QuietProcesses[i], b.QuietProcesses[i])
		}
	}
}

// The window that matters wraps midnight, and it is read in a named zone. Set
// in UTC with no zone anywhere near it, hours 2 to 5 are late evening here,
// which is why ordinary evening use of a workstation was reported as off-hours.
func TestTheOffHoursWindowWrapsMidnightInItsOwnZone(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.OffHoursStart, cfg.OffHoursEnd, cfg.OffHoursZone = 22, 5, "UTC"
	cfg = cfg.normalised()

	at := func(h int) time.Time { return time.Date(2026, 3, 1, h, 30, 0, 0, time.UTC) }
	for _, h := range []int{22, 23, 0, 3, 4} {
		if !cfg.IsOffHours(at(h)) {
			t.Errorf("%02d:30 UTC should be inside 22:00-05:00", h)
		}
	}
	for _, h := range []int{5, 9, 14, 21} {
		if cfg.IsOffHours(at(h)) {
			t.Errorf("%02d:30 UTC should be outside 22:00-05:00", h)
		}
	}
}

// A window someone switched off stays off, whatever the hour.
func TestADisabledWindowIsNeverOffHours(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.OffHoursOn = false
	if cfg.IsOffHours(time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("a disabled off-hours detector still reported off-hours")
	}
}

// A quiet process is the program installed at a path, never its name: an
// implant copied to /tmp as svchost.exe or claude is not the operating
// system's svchost, and a quiet network is an AS number, never a fragment of a
// name that also covers the clouds rented inside it.
func TestQuietListsMatchInstalledPathsAndASNumbersOnly(t *testing.T) {
	cfg := DefaultDetectionTuning()
	if !cfg.IsQuietProcess(`C:\Windows\System32\SVCHOST.EXE`, "", `NT AUTHORITY\NETWORK SERVICE`) {
		t.Error("the installed svchost is not quiet; Windows paths compare case-insensitively")
	}
	for _, impostor := range []string{"svchost.exe", `C:\Users\Public\svchost.exe`, "/tmp/svchost.exe", "/tmp/systemd-resolved", "", "system"} {
		if cfg.IsQuietProcess(impostor, "", "root") {
			t.Errorf("%q is quiet by name alone", impostor)
		}
	}
	if !cfg.IsQuietProcess("/snap/snapd/28254/usr/lib/snapd/snapd", "", "root") {
		t.Error("a snap revision directory is not covered by its wildcard")
	}
	if cfg.IsQuietProcess("/snap/snapd/28254/tmp/usr/lib/snapd/snapd", "", "root") {
		t.Error("a wildcard reached across a directory boundary")
	}
	if !cfg.IsQuietClient("/opt/google/chrome/chrome", "") || cfg.IsQuietClient("/home/user/.cache/chrome", "") {
		t.Error("expected clients do not match by installed path")
	}

	if !cfg.IsQuietOrg("AS15169", TenancyVendor) {
		t.Error("Google's own AS is not quiet")
	}
	if cfg.IsQuietOrg("AS16509", TenancyHosting) {
		t.Error("rented compute inside Amazon's AS counted as quiet")
	}
	if cfg.IsQuietOrg("", TenancyVendor) || cfg.IsQuietOrg("AS396982", TenancyHosting) {
		t.Error("an unnumbered or rented destination counted as quiet")
	}
	cfg.QuietOrgs = append(cfg.QuietOrgs, "google")
	if cfg.IsQuietOrg("", "") {
		t.Error("a name fragment matched an unresolved owner")
	}
}

// An entry may also pin the build: then only an executable with that hash is
// the program, and an event that reports no hash is not.
func TestAQuietPathCanPinTheExecutableHash(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	cfg := DefaultDetectionTuning()
	cfg.QuietProcesses = []string{"/usr/bin/rclone sha256:" + sha}
	if !cfg.IsQuietProcess("/usr/bin/rclone", strings.ToUpper(sha), "root") {
		t.Error("the pinned build is not quiet")
	}
	if cfg.IsQuietProcess("/usr/bin/rclone", strings.Repeat("cd", 32), "root") || cfg.IsQuietProcess("/usr/bin/rclone", "", "root") {
		t.Error("another build, or one with no hash, matched a pinned entry")
	}
}

// A login user can make any program appear at a listed path - bind-mounted
// over it in a user namespace, or with a library preloaded into the real one -
// and the path and even the hash then read as the real component. What it
// cannot do is run that program as the system or the daemon's own account, so
// a quiet process matches only as one of those, and an event whose account was
// not read matches nothing.
func TestAQuietProcessIsQuietOnlyAsItsServiceAccount(t *testing.T) {
	cfg := DefaultDetectionTuning()
	resolved := "/usr/lib/systemd/systemd-resolved"
	for _, user := range []string{"systemd-resolve", "root"} {
		if !cfg.IsQuietProcess(resolved, "", user) {
			t.Errorf("systemd-resolved running as %s is not quiet", user)
		}
	}
	for _, user := range []string{"kasadis", "UID:1000", "", "systemd-timesync", "nobody"} {
		if cfg.IsQuietProcess(resolved, "", user) {
			t.Errorf("systemd-resolved running as %q is quiet", user)
		}
	}
	if cfg.IsQuietProcess("/snap/snapd/28254/usr/lib/snapd/snapd", "", "kasadis") ||
		cfg.IsQuietProcess("/opt/ominull/bin/ominulld", "", "kasadis") {
		t.Error("a root daemon's path was quiet for a login user")
	}
	svchost := `C:\Windows\System32\svchost.exe`
	for _, user := range []string{`NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LOCAL SERVICE`, `nt authority\network service`, "SYSTEM"} {
		if !cfg.IsQuietProcess(svchost, "", user) {
			t.Errorf("svchost running as %s is not quiet", user)
		}
	}
	if cfg.IsQuietProcess(svchost, "", `LAPTOP-85T7CI9J\Administrator`) || cfg.IsQuietProcess(svchost, "", "") {
		t.Error("svchost started by a login user, or by nobody known, is quiet")
	}
	cfg.QuietProcesses = []string{"/usr/sbin/ntpd sha256:" + strings.Repeat("ab", 32) + " user:ntp"}
	if !cfg.IsQuietProcess("/usr/sbin/ntpd", strings.Repeat("ab", 32), "ntp") ||
		cfg.IsQuietProcess("/usr/sbin/ntpd", strings.Repeat("ab", 32), "kasadis") ||
		cfg.IsQuietProcess("/usr/sbin/ntpd", "", "ntp") {
		t.Error("an entry with both a hash and an account does not need both")
	}
	if _, err := PrepareDetectionTuning(cfg); err != nil {
		t.Errorf("an entry with both clauses was refused: %v", err)
	}
	// The expected-client and pair lists are about programs a person runs and
	// carry no account; an account clause there would never be checked.
	if MatchesQuietPath("/usr/bin/rclone user:kasadis", "/usr/bin/rclone", "") {
		t.Error("an account-bound entry matched where no account is checked")
	}
}

// A folder any account can write to holds whatever was put there last, so an
// entry there names a build by its hash or is refused.
func TestAWritableFolderNeedsTheBuildPinned(t *testing.T) {
	sha := strings.Repeat("ef", 32)
	if err := ValidQuietPath("/home/*/.local/bin/rclone sha256:" + sha); err != nil {
		t.Errorf("a pinned user-local program was refused: %v", err)
	}
	for _, bad := range []string{"/home/*/.local/bin/rclone", "/tmp/x/agent", "/var/tmp/agent", "c:/users/me/app.exe"} {
		if ValidQuietPath(bad) == nil {
			t.Errorf("%s was accepted without a hash", bad)
		}
	}
	cfg := DefaultDetectionTuning()
	cfg.QuietPairs = []string{"/home/*/.local/bin/rclone sha256:" + sha + "@as15169"}
	if _, err := PrepareDetectionTuning(cfg); err != nil {
		t.Fatalf("a pinned pair was refused: %v", err)
	}
	if !cfg.IsVouchedPair("/home/me/.local/bin/rclone", sha, "AS15169", "Google LLC", TenancyVendor) ||
		cfg.IsVouchedPair("/home/me/.local/bin/rclone", "", "AS15169", "Google LLC", TenancyVendor) {
		t.Error("a pinned pair does not hold to its build")
	}
}

// The matchers would read a name or a fragment more widely than it is written,
// or never match it, so a save that holds one is refused outright.
func TestASaveRefusesNamesAndFragments(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []func(*DetectionTuning){
		func(c *DetectionTuning) { c.QuietProcesses = append(c.QuietProcesses, "svchost.exe") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, "chrome") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, "/*/chrome") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, "/opt/google/chrome/*") },
		func(c *DetectionTuning) { c.QuietProcesses = append(c.QuietProcesses, "/usr/bin/rclone sha256:abc") },
		func(c *DetectionTuning) { c.QuietOrgs = append(c.QuietOrgs, "amazon") },
		func(c *DetectionTuning) { c.QuietPairs = append(c.QuietPairs, "rclone@as15169") },
		func(c *DetectionTuning) { c.QuietPairs = append(c.QuietPairs, "/home/*/.local/bin/rclone@as15169") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, "/tmp/chrome") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, `c:/users/me/appdata/local/app.exe`) },
		func(c *DetectionTuning) { c.QuietProcesses = append(c.QuietProcesses, "/dev/shm/x/agent") },
		func(c *DetectionTuning) { c.QuietProcesses = append(c.QuietProcesses, "/usr/sbin/ntpd user:") },
		func(c *DetectionTuning) { c.QuietClients = append(c.QuietClients, "/usr/bin/rclone user:kasadis") },
		func(c *DetectionTuning) { c.QuietPairs = append(c.QuietPairs, "/usr/bin/rclone user:kasadis@as15169") },
	} {
		cfg := DefaultDetectionTuning()
		bad(&cfg)
		if _, err := s.SaveDetectionTuning(cfg, "test"); !errors.Is(err, ErrInvalidDetectionTuning) {
			t.Errorf("saved %v / %v / %v / %v: err=%v", cfg.QuietProcesses[len(cfg.QuietProcesses)-1], cfg.QuietClients[len(cfg.QuietClients)-1], cfg.QuietOrgs, cfg.QuietPairs, err)
		}
		if _, err := PrepareDetectionTuning(cfg); !errors.Is(err, ErrInvalidDetectionTuning) {
			t.Errorf("a replay draft accepted what a save refuses: %v", err)
		}
	}
}

// Pair and known-workload owners are the AS number or the exact name. A
// fragment such as "google" used to name Google Cloud's customers too.
func TestOwnersMatchExactlyOrByASNumber(t *testing.T) {
	cases := []struct {
		owner, asn, org string
		want            bool
	}{
		{"as36459", "AS36459", "GitHub, Inc.", true},
		{"github, inc.", "AS36459", "GitHub, Inc.", true},
		{"github", "AS36459", "GitHub, Inc.", false},
		{"google", "AS396982", "Google Cloud (customer range)", false},
		{"as15169", "", "Google LLC", false},
		{"", "AS15169", "Google LLC", false},
	}
	for _, c := range cases {
		if got := OwnerMatches(c.owner, c.asn, c.org); got != c.want {
			t.Errorf("OwnerMatches(%q, %q, %q) = %v, want %v", c.owner, c.asn, c.org, got, c.want)
		}
	}
	cfg := DefaultDetectionTuning()
	cfg.QuietPairs = []string{"/usr/bin/rclone@as15169"}
	if !cfg.IsVouchedPair("/usr/bin/rclone", "", "AS15169", "Google LLC", TenancyVendor) {
		t.Error("the pair did not vouch for its own conversation")
	}
	// The limit of an unpinned pair: it names a path, not a build. Any program a
	// login user presents at /usr/bin/rclone (a bind mount in a user namespace)
	// carries that path and is vouched for; only a sha256 pin tells them apart.
	if !cfg.IsVouchedPair("/usr/bin/rclone", strings.Repeat("ab", 32), "AS15169", "Google LLC", TenancyVendor) {
		t.Error("an unpinned pair is expected to match any build at its path")
	}
	pinned := cfg
	pinned.QuietPairs = []string{"/usr/bin/rclone sha256:" + strings.Repeat("cd", 32) + "@as15169"}
	if pinned.IsVouchedPair("/usr/bin/rclone", strings.Repeat("ab", 32), "AS15169", "Google LLC", TenancyVendor) ||
		!pinned.IsVouchedPair("/usr/bin/rclone", strings.Repeat("cd", 32), "AS15169", "Google LLC", TenancyVendor) {
		t.Error("a pinned pair did not tell builds at the same path apart")
	}
	if cfg.IsVouchedPair("/tmp/rclone", "", "AS15169", "Google LLC", TenancyVendor) ||
		cfg.IsVouchedPair("/usr/bin/rclone", "", "AS396982", "Google Cloud (customer range)", TenancyHosting) {
		t.Error("the pair vouched for another program or for rented compute")
	}
	cfg.KnownWorkloads = []KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "GitHub CLI"}}
	if _, ok := cfg.KnownWorkloadFor("/usr/bin/gh", "AS36459", "GitHub, Inc.", TenancyVendor); !ok {
		t.Error("a known workload did not cover its AS")
	}
	if _, ok := cfg.KnownWorkloadFor("/usr/bin/gh", "AS36459", "Rented cloud, listed by GitHub", TenancyHosting); ok {
		t.Error("a known workload covered rented compute inside its owner's AS")
	}
}

// A store that has never been tuned answers with the shipped values rather
// than a zero struct, which would read as every detector switched off.
func TestAnUntunedStoreIsNotAnEmptyStruct(t *testing.T) {
	s := newTestStore(t)
	got := s.GetDetectionTuning()
	if !got.BeaconOn || got.BeaconMinSamples == 0 {
		t.Fatalf("untuned store returned a zero configuration: %+v", got)
	}
}

// The learning period is what stops a host installed this morning reporting
// every ordinary thing it does.
func TestASavedTuningSurvivesTheRoundTrip(t *testing.T) {
	s := newTestStore(t)
	in := DefaultDetectionTuning()
	in.WarmupHours = 72
	in.BeaconScore = 0.95
	in.QuietProcesses = append(in.QuietProcesses, "C:/Program Files/Backup Helper/helper.exe")

	if _, err := s.SaveDetectionTuning(in, "someone@example.invalid"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := s.GetDetectionTuning()
	if got.WarmupHours != 72 || got.BeaconScore != 0.95 {
		t.Fatalf("round trip lost values: %+v", got)
	}
	if !got.IsQuietProcess(`c:\program files\backup helper\HELPER.EXE`, "", `NT AUTHORITY\SYSTEM`) {
		t.Error("an added path was not lower-cased on the way in")
	}
	if got.UpdatedBy != "someone@example.invalid" {
		t.Errorf("authorship not recorded: %q", got.UpdatedBy)
	}
}

// legacyTuningRow is the shape of a row saved before quiet lists were paths
// and AS numbers: the production row's quiet lists as they stood, with two of
// its known workloads.
const legacyTuningRow = `{"beacon_enabled":true,"first_seen_cooldown_minutes":240,
"quiet_processes":["chronyd","dbus-daemon","dwm.exe","lsass.exe","msmpeng.exe","ntoskrnl.exe","ntpd","ominull-agent","ominull_agent.exe","ominulld","ominulld.exe","packagekitd","searchhost.exe","services.exe","snapd","spoolsv.exe","svchost.exe","system","systemd","systemd-resolved","systemd-timesyncd","telegram","telegram-desktop","telegram.exe","tiworker.exe","trustedinstaller.exe","unattended-upgr","usocoreworker.exe"],
"quiet_orgs":["akamai","amazon","apple","cloudflare","fastly","google","microsoft","telegram"],
"quiet_clients":["brave","brave.exe","chatgpt","chatgpt.exe","chrome","chrome.exe","chromium","claude","claude-desktop","claude.exe","firefox","firefox.exe","msedge.exe","msmpeng.exe","nsurlsessiond","ominull-agent","ominulld","ominulld.exe","opera.exe","packagekitd","safari","snapd","softwareupdated","svchost.exe","telegram","telegram-desktop","telegram.exe","unattended-upgr","usocoreworker.exe"],
"quiet_pairs":["rclone@google"],
"known_workloads":[{"workload":"/usr/bin/gh","owner":"github","reason":"GitHub CLI"},{"workload":"/opt/google/chrome/chrome","owner":"*","reason":"the owner's browser"},{"workload":"/usr/bin/curl","owner":"Example Org","reason":"named exactly"}]}`

// The production row is rewritten at upgrade, not just the shipped defaults:
// every name becomes the paths that program is installed at, every fragment
// its AS number, and what has no known path is dropped rather than kept as a
// name. A second start changes nothing.
func TestTheStoredRowIsMigratedToPathsAndASNumbers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO detection_tuning (id, settings, updated_at, updated_by) VALUES (1, ?, ?, 'admin')`,
		legacyTuningRow, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.GetDetectionTuning()
	if got.UpdatedBy != "upgrade" {
		t.Errorf("the migrated row does not say it was the upgrade: %q", got.UpdatedBy)
	}
	if got.FirstSeenCooldown != 240 {
		t.Errorf("the migration lost an unrelated setting: %d", got.FirstSeenCooldown)
	}
	if _, err := PrepareDetectionTuning(got); err != nil {
		t.Fatalf("the migrated row is not one a save would accept: %v", err)
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"c:/windows/system32/svchost.exe", "/usr/lib/systemd/systemd-resolved user:systemd-resolve", "/usr/sbin/chronyd user:_chrony", "/snap/snapd/*/usr/lib/snapd/snapd", "/opt/ominull/bin/ominulld"} {
		if !has(got.QuietProcesses, want) {
			t.Errorf("quiet processes lack %s: %v", want, got.QuietProcesses)
		}
	}
	for _, gone := range []string{"system", "telegram", "unattended-upgr", "svchost.exe", "/usr/bin/dbus-daemon", "/usr/lib/systemd/systemd", "c:/windows/system32/services.exe"} {
		if has(got.QuietProcesses, gone) || has(got.QuietClients, gone) {
			t.Errorf("%q survived as a name", gone)
		}
	}
	if has(got.QuietClients, "claude") || !has(got.QuietClients, "/usr/lib/claude-desktop/claude-desktop") || !has(got.QuietClients, "/opt/google/chrome/chrome") {
		t.Errorf("expected clients were not carried over by path: %v", got.QuietClients)
	}
	if want := []string{"as13335", "as15169", "as16509", "as20940", "as54113", "as714", "as8075"}; strings.Join(got.QuietOrgs, ",") != strings.Join(want, ",") {
		t.Errorf("quiet networks = %v, want %v", got.QuietOrgs, want)
	}
	// rclone never ran from a path a pair could name safely, so its pair is dropped.
	if len(got.QuietPairs) != 0 {
		t.Errorf("expected pairs = %v, want none", got.QuietPairs)
	}
	owners := map[string]string{}
	for _, k := range got.KnownWorkloads {
		owners[k.Workload] = k.Owner
	}
	if owners["/usr/bin/gh"] != "as36459" || owners["/opt/google/chrome/chrome"] != "*" || owners["/usr/bin/curl"] != "example org" {
		t.Errorf("known-workload owners = %v", owners)
	}
	stamped := got.UpdatedAt
	s.Close()

	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if again := s.GetDetectionTuning(); !again.UpdatedAt.Equal(stamped) {
		t.Errorf("a second start rewrote the row again (%v, then %v)", stamped, again.UpdatedAt)
	}
}

// A hub that was never tuned has no row, and the upgrade does not write one:
// the shipped values stay the shipped values.
func TestAnUntunedHubGetsNoRowFromTheUpgrade(t *testing.T) {
	s := newTestStore(t)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM detection_tuning`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows=%d err=%v", n, err)
	}
}
