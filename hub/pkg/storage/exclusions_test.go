package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestExclusionRulesRefuseBroadOrStaleRows(t *testing.T) {
	now := time.Now().UTC()
	valid := Exclusion{Scope: "global", ProcessPath: "/usr/bin/docker-proxy", DstIPRange: "172.18.0.0/16",
		Port: 7070, Protocol: "tcp", Reason: "bridge", ExpiresAt: now.Add(time.Hour)}
	if p := valid.Problem(now); p != "" {
		t.Fatalf("valid exclusion refused: %s", p)
	}
	for name, mutate := range map[string]func(*Exclusion){
		"no selector":           func(e *Exclusion) { e.ProcessPath, e.DstIPRange, e.Port = "", "", 0 },
		"wildcard selectors":    func(e *Exclusion) { e.ProcessPath, e.DstIPRange, e.Port = "*", "*", 0 },
		"bad CIDR":              func(e *Exclusion) { e.DstIPRange = "10.0.0.0/33" },
		"garbage range":         func(e *Exclusion) { e.DstIPRange = "not-an-ip/8" },
		"bare name":             func(e *Exclusion) { e.ProcessPath = "python" },
		"glob":                  func(e *Exclusion) { e.ProcessPath = "/usr/bin/*" },
		"relative":              func(e *Exclusion) { e.ProcessPath = "bin/python" },
		"dot segments":          func(e *Exclusion) { e.ProcessPath = "/usr/bin/../../tmp/x" },
		"scoped without value":  func(e *Exclusion) { e.Scope, e.ScopeValue = "endpoint", "" },
		"unknown scope":         func(e *Exclusion) { e.Scope = "fleet" },
		"no reason":             func(e *Exclusion) { e.Reason = " " },
		"no expiry":             func(e *Exclusion) { e.ExpiresAt = time.Time{} },
		"expired":               func(e *Exclusion) { e.ExpiresAt = now.Add(-time.Second) },
		"unknown protocol":      func(e *Exclusion) { e.Protocol = "sctp" },
		"windows glob":          func(e *Exclusion) { e.ProcessPath = `C:\Tools\*.exe` },
		"windows relative path": func(e *Exclusion) { e.ProcessPath = `Tools\x.exe` },
	} {
		ex := valid
		mutate(&ex)
		if ex.Problem(now) == "" {
			t.Errorf("%s: accepted %+v", name, ex)
		}
	}
	win := valid
	win.ProcessPath = `C:\Program Files\Tool\tool.exe`
	if p := win.Problem(now); p != "" {
		t.Fatalf("windows path refused: %s", p)
	}
}

func TestMatchesExclusionIsExactAndFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	ev := Event{TenantID: "default", EndpointID: "ep-1", DstIP: "172.18.0.5", DstPort: 7070, Protocol: 6,
		ProcessPath: "/usr/bin/docker-proxy"}
	base := Exclusion{Scope: "global", TenantID: "default", ProcessPath: "/usr/bin/docker-proxy", DstIPRange: "172.18.0.0/16",
		Port: 7070, Protocol: "tcp", Reason: "bridge", Active: true, ExpiresAt: now.Add(time.Hour)}
	if !MatchesExclusion(ev, "", []Exclusion{base}) {
		t.Fatal("exact exclusion did not match")
	}
	for name, mutate := range map[string]func(*Exclusion){
		// Each of these used to match every flow, or every path containing it.
		"substring path":      func(e *Exclusion) { e.ProcessPath = "docker" },
		"suffix path":         func(e *Exclusion) { e.ProcessPath = "docker-proxy" },
		"unparseable CIDR":    func(e *Exclusion) { e.DstIPRange = "172.18.0.0/99" },
		"all fields empty":    func(e *Exclusion) { e.ProcessPath, e.DstIPRange, e.Port, e.Protocol = "", "", 0, "" },
		"empty scope value":   func(e *Exclusion) { e.Scope, e.ScopeValue = "endpoint", "" },
		"other endpoint":      func(e *Exclusion) { e.Scope, e.ScopeValue = "endpoint", "ep-2" },
		"other tenant scoped": func(e *Exclusion) { e.Scope, e.ScopeValue, e.TenantID = "endpoint", "ep-1", "t-9" },
		"expired":             func(e *Exclusion) { e.ExpiresAt = now.Add(-time.Second) },
		"no expiry":           func(e *Exclusion) { e.ExpiresAt = time.Time{} },
		"no reason":           func(e *Exclusion) { e.Reason = "" },
		"inactive":            func(e *Exclusion) { e.Active = false },
		"other port":          func(e *Exclusion) { e.Port = 22 },
		"case differs (unix)": func(e *Exclusion) { e.ProcessPath = "/usr/bin/Docker-Proxy" },
	} {
		ex := base
		mutate(&ex)
		if MatchesExclusion(ev, "", []Exclusion{ex}) {
			t.Errorf("%s: matched", name)
		}
	}
	scoped := base
	scoped.Scope, scoped.ScopeValue = "endpoint", "ep-1"
	if !MatchesExclusion(ev, "", []Exclusion{scoped}) {
		t.Fatal("endpoint-scoped exclusion did not match its endpoint")
	}
	winEv := Event{TenantID: "default", ProcessPath: `C:\Program Files\Tool\TOOL.exe`, DstIP: "10.0.0.1"}
	win := Exclusion{Scope: "global", TenantID: "default", ProcessPath: `c:\program files\tool\tool.exe`,
		Reason: "tool", Active: true, ExpiresAt: now.Add(time.Hour)}
	if !MatchesExclusion(winEv, "", []Exclusion{win}) {
		t.Fatal("windows path did not match without case")
	}
}

// Rows written before expiry was required get one 90-day term at upgrade and
// keep matching; the store round-trips the expiry.
func TestExclusionExpiryMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.db")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO exclusions (id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at, expires_at)
		VALUES ('ex-old', 'default', 'global', '', 'agy', '/home/u/.local/bin/agy', '', 0, '', 'telemetry', 1, ?, NULL)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	store.Close()
	before := time.Now().UTC()
	store, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ex, err := store.GetExclusion("ex-old")
	if err != nil {
		t.Fatal(err)
	}
	if ex.ExpiresAt.Before(before.Add(ExclusionMaxLifetime-time.Minute)) || ex.ExpiresAt.After(time.Now().UTC().Add(ExclusionMaxLifetime)) {
		t.Fatalf("legacy row expiry = %v, want about 90 days from the upgrade", ex.ExpiresAt)
	}
	if !MatchesExclusion(Event{TenantID: "default", ProcessPath: "/home/u/.local/bin/agy"}, "", []Exclusion{ex}) {
		t.Fatal("migrated row stopped matching")
	}
	if _, err := store.GetExclusion("missing"); err != ErrExclusionNotFound {
		t.Fatalf("missing row: %v", err)
	}
}
