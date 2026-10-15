package detector

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// adminEngine is a hub with one admin workstation, three enrolled managed
// hosts, one parked test guest and a gateway listed as a managed target.
func adminEngine(t *testing.T, edit func(*storage.DetectionTuning)) (*Engine, *storage.Store) {
	t.Helper()
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "ws-admin", Hostname: "ws-admin", IP: "10.0.0.128", RoleTag: "workstation"},
		{ID: "hv-01", Hostname: "hv-01", IP: "10.0.0.39", RoleTag: "server"},
		{ID: "vm-browser", Hostname: "vm-browser", IP: "10.0.0.234", RoleTag: "server"},
		{ID: "vm-old", Hostname: "vm-old", IP: "10.0.0.77", RoleTag: "server", Status: "retired"},
		{ID: "lab-guest", Hostname: "lab-guest", IP: "10.20.0.102", RoleTag: "workstation", Presence: storage.PresenceParked},
	} {
		ep.TenantID, ep.OS, ep.LastSeenAt, ep.CreatedAt = "default", "Linux", now, now.Add(-30*24*time.Hour)
		if ep.Status == "" {
			ep.Status = "online"
		}
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatalf("seeding %s: %v", ep.ID, err)
		}
		if ep.Presence != "" {
			if err := store.SetEndpointPresence(ep.ID, ep.Presence); err != nil {
				t.Fatalf("presence %s: %v", ep.ID, err)
			}
		}
		if ep.Status == "retired" {
			if err := store.RetireEndpoint(ep.ID); err != nil {
				t.Fatalf("retiring %s: %v", ep.ID, err)
			}
		}
	}
	tuning := store.GetDetectionTuning()
	tuning.AdminFanoutSources = []string{"ws-admin", "lab-guest"}
	tuning.AdminFanoutTargets = []string{"10.0.0.1"}
	if edit != nil {
		edit(&tuning)
	}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()
	return engine, store
}

type hop struct {
	ip   string
	port uint16
}

// fanOut sends one connection per hop from src, a second apart, at an hour
// that is off-hours in no zone's default window.
func fanOut(engine *Engine, src, proc string, hops []hop) {
	at := time.Date(2026, 10, 14, 16, 0, 0, 0, time.Local)
	for i, h := range hops {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: src, Timestamp: at.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
			DstIP: h.ip, DstPort: h.port, ProcessPath: proc,
			CommandLine: "ssh -o BatchMode=yes " + h.ip + " uptime",
		})
	}
}

func hops(port uint16, ips ...string) []hop {
	out := make([]hop, 0, len(ips))
	for _, ip := range ips {
		out = append(out, hop{ip, port})
	}
	return out
}

// managed6 is six inventoried hosts: the ssh threshold in the day is six.
var managed6 = []string{"10.0.0.1", "10.0.0.39", "10.0.0.234", "10.20.0.102", "10.0.0.39", "10.0.0.234"}

func TestAdminFanoutToInventoriedHostsDoesNotPage(t *testing.T) {
	// Repeat visits do not add hosts; reach six distinct ones with two more
	// targets listed as managed.
	engine, store := adminEngine(t, func(c *storage.DetectionTuning) {
		c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31")
	})
	fanOut(engine, "ws-admin", "/usr/bin/ssh", hops(22, append(managed6, "10.0.0.50", "10.0.0.51")...))
	if got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP"); len(got) != 0 {
		t.Fatalf("routine ssh to inventoried hosts paged: %+v", got[0].Title)
	}
}

func TestSweepsThatAreNotRoutineAdministrationStillPage(t *testing.T) {
	six := []string{"10.0.0.1", "10.0.0.39", "10.0.0.234", "10.20.0.102", "10.0.0.50", "10.0.0.51"}
	cases := []struct {
		name string
		src  string
		proc string
		hops []hop
		edit func(*storage.DetectionTuning)
		why  string
	}{
		{"one uninventoried host", "ws-admin", "/usr/bin/ssh", hops(22, "10.0.0.1", "10.0.0.39", "10.0.0.234", "10.20.0.102", "10.0.0.50", "10.0.0.9"),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50") }, "10.0.0.9 is not an inventoried host"},
		{"a retired endpoint's address", "ws-admin", "/usr/bin/ssh", hops(22, "10.0.0.1", "10.0.0.39", "10.0.0.234", "10.20.0.102", "10.0.0.50", "10.0.0.77"),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50") }, "10.0.0.77 is not an inventoried host"},
		{"another port", "ws-admin", "/usr/bin/ssh", append(hops(22, six[:5]...), hop{"10.0.0.51", 2222}),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31") }, "port 2222"},
		{"too many hosts", "ws-admin", "/usr/bin/ssh", hops(22, six...),
			func(c *storage.DetectionTuning) {
				c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31")
				c.AdminFanoutMax = 5
			}, "over the admin limit of 5"},
		{"a source nobody named", "hv-01", "/usr/bin/ssh", hops(22, six...),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31") }, "not an admin workstation"},
		{"a parked test guest", "lab-guest", "/usr/bin/ssh", hops(22, "10.0.0.1", "10.0.0.39", "10.0.0.234", "10.0.0.128", "10.0.0.50", "10.0.0.51"),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31") }, "parked test guest"},
		{"another program", "ws-admin", "/usr/bin/python3", hops(22, six...),
			func(c *storage.DetectionTuning) { c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31") }, "not the ssh client"},
		{"the rule switched off", "ws-admin", "/usr/bin/ssh", hops(22, six...),
			func(c *storage.DetectionTuning) {
				c.AdminFanoutTargets = append(c.AdminFanoutTargets, "10.0.0.50/31")
				c.AdminFanoutSources = nil
			}, "not an admin workstation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, store := adminEngine(t, tc.edit)
			fanOut(engine, tc.src, tc.proc, tc.hops)
			got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP")
			if len(got) != 1 {
				t.Fatalf("want one sweep alert, got %d", len(got))
			}
			var ev struct {
				Targets []struct {
					IP    string `json:"ip"`
					Ports []int  `json:"ports"`
				} `json:"sweep_targets"`
				Rule string `json:"admin_rule"`
			}
			if err := json.Unmarshal([]byte(got[0].Evidence), &ev); err != nil {
				t.Fatalf("evidence: %v", err)
			}
			if len(ev.Targets) != 6 || !strings.Contains(ev.Rule, tc.why) {
				t.Fatalf("evidence should name the 6 hosts and why the admin rule did not apply (%q): %+v", tc.why, ev)
			}
		})
	}
}

// A real sweep shape (the 10-host broker scan of October 13) pages whatever
// the admin rule says: many hosts, a non-admin port, unknown addresses.
func TestBrokerSweepPages(t *testing.T) {
	engine, store := adminEngine(t, nil)
	var h []hop
	for i := 10; i < 30; i++ {
		h = append(h, hop{fmt.Sprintf("10.0.0.%d", i), 1883})
	}
	fanOut(engine, "ws-admin", "unknown", h)
	if got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP"); len(got) != 1 || got[0].Severity != "CRITICAL" {
		t.Fatalf("broker sweep should page once at CRITICAL, got %d", len(got))
	}
}

// Off-hours follows the tuning's zone and switch. With the switch off, three
// ssh hosts at 23:30 UTC are not off-hours and do not reach the day
// threshold, where they used to page as off-hours by the UTC clock.
func TestSweepOffHoursUsesTheTuning(t *testing.T) {
	engine, store := adminEngine(t, func(c *storage.DetectionTuning) {
		c.AdminFanoutSources = nil
		c.OffHoursOn = false
	})
	at := time.Date(2026, 10, 14, 23, 16, 0, 0, time.UTC)
	for i, ip := range []string{"10.0.0.39", "10.0.0.1", "10.0.0.234"} {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "ws-admin", Timestamp: at.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: ip, DstPort: 22, ProcessPath: "/usr/bin/ssh"})
	}
	if got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP"); len(got) != 0 {
		t.Fatalf("off-hours by the UTC clock: %d alerts", len(got))
	}

	engine, store = adminEngine(t, func(c *storage.DetectionTuning) {
		c.AdminFanoutSources = nil
		c.OffHoursOn, c.OffHoursStart, c.OffHoursEnd, c.OffHoursZone = true, 22, 5, "America/New_York"
	})
	at = time.Date(2026, 10, 15, 3, 30, 0, 0, time.UTC) // 23:30 in New York
	for i, ip := range []string{"10.0.0.39", "10.0.0.1", "10.0.0.234"} {
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "ws-admin", Timestamp: at.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: ip, DstPort: 22, ProcessPath: "/usr/bin/ssh"})
	}
	if got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP"); len(got) != 1 {
		t.Fatalf("23:30 local is off-hours in the configured zone: want 1 alert, got %d", len(got))
	}
}

func TestAdminFanoutTargetsMustBePrivate(t *testing.T) {
	_, store := noiseEngine(t)
	tuning := store.GetDetectionTuning()
	tuning.AdminFanoutTargets = []string{"8.8.8.8"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err == nil {
		t.Fatal("a public admin target was accepted")
	}
	tuning.AdminFanoutTargets = []string{"10.0.0.1", "192.168.1.0/24"}
	saved, err := store.SaveDetectionTuning(tuning, "test")
	if err != nil || len(saved.AdminFanoutTargets) != 2 || saved.AdminFanoutTargets[0] != "10.0.0.1/32" {
		t.Fatalf("private targets: %v %v", saved.AdminFanoutTargets, err)
	}
}

// A sweep is credited to an actor only when every flow in it carries that one.
func TestSweepActor(t *testing.T) {
	t.Parallel()
	target := func(actors ...string) *sweepTarget {
		st := &sweepTarget{actors: map[string]bool{}}
		for _, a := range actors {
			st.actors[a] = true
		}
		return st
	}
	cases := []struct {
		window map[string]*sweepTarget
		want   string
	}{
		{map[string]*sweepTarget{"a": target("agent:claude:x"), "b": target("agent:claude:x")}, "agent:claude:x"},
		{map[string]*sweepTarget{"a": target("agent:claude:x"), "b": target("agent:codex:y")}, ""},
		{map[string]*sweepTarget{"a": target("agent:claude:x", "")}, ""},
		{map[string]*sweepTarget{"a": target("agent:claude:x"), "b": target("")}, ""},
		{map[string]*sweepTarget{"a": target()}, ""},
	}
	for i, c := range cases {
		if got := sweepActor(c.window); got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}

// The evidence lists ten hosts, sorted as text; the floor is worked out over
// the whole window. Twenty hosts where the ten on 445 sort last still record
// 445 as a floor port.
func TestSweepFloorPortsCoverTheWholeWindow(t *testing.T) {
	engine, store := adminEngine(t, nil)
	var h []hop
	for i := 90; i < 100; i++ {
		h = append(h, hop{fmt.Sprintf("10.0.0.%d", i), 445})
	}
	for i := 10; i < 20; i++ {
		h = append(h, hop{fmt.Sprintf("10.0.0.%d", i), 80})
	}
	fanOut(engine, "ws-admin", "/home/u/.local/bin/scan", h)
	got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP")
	if len(got) != 1 {
		t.Fatalf("want one sweep alert, got %d", len(got))
	}
	var ev struct {
		Targets []struct {
			Ports []int `json:"ports"`
		} `json:"sweep_targets"`
		Floor []int `json:"floor_ports"`
	}
	if err := json.Unmarshal([]byte(got[0].Evidence), &ev); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	for _, tg := range ev.Targets {
		if len(tg.Ports) != 1 || tg.Ports[0] != 80 {
			t.Fatalf("the listed ten should be the port-80 hosts (the case this guards): %+v", ev.Targets)
		}
	}
	if len(ev.Targets) != 10 || len(ev.Floor) != 1 || ev.Floor[0] != 445 {
		t.Fatalf("floor ports should cover all 20 hosts: %+v", ev)
	}
}

// An ordinary sweep's ten-minute cooldown does not hide a floor sweep by the
// same process right after it; a non-floor sweep records an empty list.
func TestFloorSweepIsNotHiddenByAnEarlierSweep(t *testing.T) {
	engine, store := adminEngine(t, nil)
	var h []hop
	for i := 10; i < 30; i++ {
		h = append(h, hop{fmt.Sprintf("10.0.0.%d", i), 80})
	}
	fanOut(engine, "ws-admin", "/home/u/.local/bin/scan", h)
	first := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP")
	if len(first) != 1 || !strings.Contains(first[0].Evidence, `"floor_ports":[]`) {
		t.Fatalf("ordinary sweep: %d alerts %+v", len(first), first)
	}
	h = nil
	for i := 40; i < 45; i++ {
		h = append(h, hop{fmt.Sprintf("10.0.0.%d", i), 445})
	}
	fanOut(engine, "ws-admin", "/home/u/.local/bin/scan", h)
	got := anomaliesOfType(t, store, "LATERAL_PORT_SWEEP")
	if len(got) != 2 {
		t.Fatalf("a floor sweep inside the ordinary sweep's cooldown was hidden: %d alerts", len(got))
	}
	floors := 0
	for _, a := range got {
		if strings.Contains(a.Evidence, `"floor_ports":[445]`) {
			floors++
		}
	}
	if floors != 1 {
		t.Fatalf("want one floor sweep alert, got %d", floors)
	}
}
