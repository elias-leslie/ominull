package responseauth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
)

// The owner sees a staged rollout as staged, worked out from the payload.
func TestDescribeStagedAgentUpdate(t *testing.T) {
	payload := []byte(`{"route":"/api/v1/agents/update","body":{"all":true,"version":"1.2.0","canary":["ep-1"]},"targets":["ep-1","ep-2","ep-3"]}`)
	_, summary, err := describeApproval(ActionKindAgentUpdate, payload, []string{"ep-1", "ep-2", "ep-3"}, "admin")
	if err != nil || !strings.Contains(summary, "Staged: ep-1 first; the other 2 only once the canaries run it healthily") {
		t.Fatalf("summary %q err %v", summary, err)
	}
	payload = []byte(`{"route":"/api/v1/agents/update","body":{"all":true,"version":"1.2.0","canary":["ep-9"]},"targets":["ep-1","ep-2"]}`)
	if _, _, err := describeApproval(ActionKindAgentUpdate, payload, []string{"ep-1", "ep-2"}, "admin"); err == nil {
		t.Fatal("a canary outside the targets was described")
	}
}

// The owner sees a detection-policy change field by field, derived from the
// before and after the digest covers, never from the hub's own words.
func TestDescribeDetectionPolicy(t *testing.T) {
	tuning := []string{"detection:tuning"}
	payload := []byte(`{"after":{"beacon_enabled":false,"quiet_orgs":["as1","as3"],"warmup_hours":24},"before":{"beacon_enabled":true,"quiet_orgs":["as1","as2"],"warmup_hours":24},"op":"save","policy":"detection_tuning"}`)
	action, summary, err := describeApproval(ActionKindDetection, payload, tuning, "admin (api-key)")
	if err != nil || action != "Loosen detection tuning" || summary != "beacon_enabled true -> false; quiet_orgs +as3 -as2" {
		t.Fatalf("action %q summary %q err %v", action, summary, err)
	}

	// Changes that do not all fit the statement are refused, never cut to
	// "and N more": eleven tightening numbers ahead of one quiet entry
	// would otherwise push the quiet entry out of sight.
	before, after := map[string]interface{}{"quiet_processes": []string{"/usr/sbin/chronyd"}}, map[string]interface{}{"quiet_processes": []string{"/usr/sbin/chronyd", "/usr/bin/curl"}}
	for _, k := range []string{"admin_fanout_max_hosts", "agent_baseline_days", "agent_upload_factor", "agent_upload_floor_mb", "bandwidth_cooldown_minutes",
		"bandwidth_min_samples", "beacon_cooldown_minutes", "beacon_min_interval_seconds", "beacon_min_samples", "beacon_min_span_minutes", "first_seen_cooldown_minutes",
		"warmup_hours", "silence_after_minutes", "beacon_score_threshold"} {
		before[k], after[k] = 10, 9
	}
	raw, _ := json.Marshal(map[string]interface{}{"policy": "detection_tuning", "op": "save", "before": before, "after": after})
	_, summary, err = describeApproval(ActionKindDetection, raw, tuning, "admin")
	if !errors.Is(err, ErrApprovalTooLong) || summary != "" {
		t.Fatalf("an oversized change was described as %q (err %v)", summary, err)
	}
	// Short enough, every change shows in full.
	raw, _ = json.Marshal(map[string]interface{}{"policy": "detection_tuning", "op": "save",
		"before": map[string]interface{}{"warmup_hours": 24, "quiet_processes": []string{}}, "after": map[string]interface{}{"warmup_hours": 12, "quiet_processes": []string{"/usr/bin/curl"}}})
	if _, summary, err = describeApproval(ActionKindDetection, raw, tuning, "admin"); err != nil || summary != "quiet_processes +/usr/bin/curl; warmup_hours 24 -> 12" {
		t.Fatalf("summary %q err %v", summary, err)
	}
	// A list entry shows what it matches before its reason.
	raw, _ = json.Marshal(map[string]interface{}{"policy": "detection_tuning", "op": "save",
		"before": map[string]interface{}{"known_workloads": []interface{}{}},
		"after":  map[string]interface{}{"known_workloads": []interface{}{map[string]interface{}{"workload": "/usr/bin/gh", "owner": "*", "reason": "cli"}}}})
	if _, summary, err = describeApproval(ActionKindDetection, raw, tuning, "admin"); err != nil || summary != "known_workloads +{owner=* workload=/usr/bin/gh reason=cli}" {
		t.Fatalf("workload summary %q err %v", summary, err)
	}

	exclusion := []byte(`{"after":{"active":true,"dst_ip_range":"172.18.0.0/16","expires_at":"2026-11-01T00:00:00Z","id":"","name":"bridge","port":7070,"process_path":"/usr/bin/docker-proxy","reason":"bridge","scope":"global","scope_value":"","tenant_id":"default"},"before":null,"op":"create","policy":"exclusion"}`)
	action, summary, err = describeApproval(ActionKindDetection, exclusion, []string{"exclusion:new"}, "admin")
	if err != nil || action != "Add a detection exclusion" ||
		summary != "process_path /usr/bin/docker-proxy; dst_ip_range 172.18.0.0/16; port 7070; scope global; expires_at 2026-11-01T00:00:00Z; name bridge; reason bridge" {
		t.Fatalf("exclusion action %q summary %q err %v", action, summary, err)
	}
	// A long name cannot push what the exclusion matches out of sight: the
	// match shows in full and the name and reason are shortened instead.
	long, _ := json.Marshal(map[string]interface{}{"policy": "exclusion", "op": "create", "before": nil, "after": map[string]interface{}{
		"name": strings.Repeat("n", 130), "process_path": "/usr/lib/" + strings.Repeat("p", 60), "dst_ip_range": "0.0.0.0/0",
		"scope": "global", "expires_at": "2026-11-01T00:00:00Z", "reason": strings.Repeat("r", 200)}})
	_, summary, err = describeApproval(ActionKindDetection, long, []string{"exclusion:new"}, "admin")
	if err != nil || len([]rune(summary)) > approvalMaxSummary || !strings.Contains(summary, "dst_ip_range 0.0.0.0/0") ||
		!strings.Contains(summary, "scope global") || !strings.Contains(summary, "…") || strings.Contains(summary, " more") {
		t.Fatalf("long exclusion (%d runes) %q err %v", len([]rune(summary)), summary, err)
	}
	// Host watch changes name the host and what changes about it.
	watch := []byte(`{"after":{"endpoint_id":"ep-1","hostname":"web","isolated":false,"presence":"parked","reason":"lab","status":"active"},"before":{"endpoint_id":"ep-1","hostname":"web","isolated":false,"presence":"always_on","status":"active"},"op":"presence","policy":"endpoint_watch"}`)
	if action, summary, err = describeApproval(ActionKindDetection, watch, []string{"endpoint:ep-1"}, "admin"); err != nil ||
		action != "Expect a host to go quiet" || summary != "host ep-1 (web); presence always_on -> parked; reason lab" {
		t.Fatalf("watch action %q summary %q err %v", action, summary, err)
	}
	if _, _, err = describeApproval(ActionKindDetection, watch, []string{"endpoint:ep-2"}, "admin"); err == nil {
		t.Fatal("a watch change for one host was described under another")
	}

	for name, c := range map[string]struct {
		payload string
		targets []string
	}{
		"unknown member":      {`{"after":{},"before":{},"op":"save","policy":"detection_tuning","route":"/x"}`, tuning},
		"unknown op":          {`{"after":{"a":1},"before":{"a":2},"op":"wipe","policy":"detection_tuning"}`, tuning},
		"unknown policy":      {`{"after":{"a":1},"before":{"a":2},"op":"save","policy":"isolation"}`, tuning},
		"no change":           {`{"after":{"a":1},"before":{"a":1},"op":"save","policy":"detection_tuning"}`, tuning},
		"tuning wrong target": {`{"after":{"a":1},"before":{"a":2},"op":"save","policy":"detection_tuning"}`, []string{"ep-1"}},
		"tuning no before":    {`{"after":{"a":1},"before":null,"op":"save","policy":"detection_tuning"}`, tuning},
		"exclusion target":    {`{"after":{"name":"x"},"before":null,"op":"create","policy":"exclusion"}`, tuning},
		"enable no before":    {`{"after":{"name":"x"},"before":null,"op":"enable","policy":"exclusion"}`, []string{"exclusion:ex-1"}},
		"two targets":         {`{"after":{"a":1},"before":{"a":2},"op":"save","policy":"detection_tuning"}`, []string{"detection:tuning", "exclusion:x"}},
	} {
		if _, _, err := describeApproval(ActionKindDetection, []byte(c.payload), c.targets, "admin"); err == nil {
			t.Errorf("%s: described", name)
		}
	}
}

// A learning window is shown by scope and length, and its target must name
// the same scope.
func TestDescribeALearningWindow(t *testing.T) {
	window := func(after string) []byte {
		return []byte(`{"after":` + after + `,"before":null,"op":"open","policy":"learning_window"}`)
	}
	action, summary, err := describeApproval(ActionKindDetection, window(`{"hours":2160,"note":"","scope_id":"","scope_label":"every host in every tenant","scope_type":"tenant"}`), []string{"learning:tenant:"}, "admin")
	if err != nil || action != "Open a learning window" || summary != "every host in every tenant for 90 days; holds beacon, volume and agent egress findings" {
		t.Fatalf("estate window action %q summary %q err %v", action, summary, err)
	}
	if _, summary, err = describeApproval(ActionKindDetection, window(`{"hours":1,"scope_id":"ep-1","scope_label":"web","scope_type":"endpoint","tenant_id":"default"}`), []string{"learning:endpoint:ep-1"}, "admin"); err != nil ||
		summary != "endpoint ep-1 (web) for 1 hour; holds beacon, volume and agent egress findings; tenant_id default" {
		t.Fatalf("host window summary %q err %v", summary, err)
	}
	for name, c := range map[string]struct {
		after, target string
	}{
		"other scope":   {`{"hours":2,"scope_id":"ep-1","scope_type":"endpoint"}`, "learning:endpoint:ep-2"},
		"too long":      {`{"hours":2161,"scope_id":"","scope_type":"tenant"}`, "learning:tenant:"},
		"no length":     {`{"scope_id":"","scope_type":"tenant"}`, "learning:tenant:"},
		"part hour":     {`{"hours":1.5,"scope_id":"","scope_type":"tenant"}`, "learning:tenant:"},
		"unnamed host":  {`{"hours":2,"scope_id":"","scope_type":"endpoint"}`, "learning:endpoint:"},
		"unknown scope": {`{"hours":2,"scope_id":"x","scope_type":"fleet"}`, "learning:fleet:x"},
	} {
		if _, _, err := describeApproval(ActionKindDetection, window(c.after), []string{c.target}, "admin"); err == nil {
			t.Errorf("%s: described", name)
		}
	}
	if _, _, err := describeApproval(ActionKindDetection, []byte(`{"after":{"hours":2,"scope_id":"","scope_type":"tenant"},"before":{"a":1},"op":"open","policy":"learning_window"}`), []string{"learning:tenant:"}, "admin"); err == nil {
		t.Error("a window opened over a saved one was described")
	}
}

// The hub's floor drill against the proposed policy leads the statement: what
// the change would blind, or that it blinds nothing. A payload without one
// reads as before.
func TestDescribeDetectionPolicyShowsTheDrill(t *testing.T) {
	tuning := []string{"detection:tuning"}
	for _, c := range []struct{ drill, want string }{
		{`[]`, "floor drill: blinds no floor case (the 10 MB burst yields to exclusions and quiet processes); quiet_orgs +as3"},
		{`["bandwidth burst"]`, "BLINDS 1 FLOOR CASE: bandwidth burst; quiet_orgs +as3"},
		{`["lateral sweep","port sweep","port sweep as /usr/sbin/chronyd (chrony)"]`, "BLINDS 3 FLOOR CASES: lateral sweep, port sweep and 1 more; quiet_orgs +as3"},
		{`["the drill could not run"]`, "floor drill could not run: what this blinds is unknown; quiet_orgs +as3"},
	} {
		payload := []byte(`{"after":{"quiet_orgs":["as1","as3"]},"before":{"quiet_orgs":["as1"]},"drill":` + c.drill + `,"op":"save","policy":"detection_tuning"}`)
		if _, summary, err := describeApproval(ActionKindDetection, payload, tuning, "admin"); err != nil || summary != c.want {
			t.Fatalf("drill %s: summary %q err %v", c.drill, summary, err)
		}
	}
	// A change that fits on its own is never refused for the drill: the
	// verdict shrinks to its count instead.
	long := `"/usr/lib/` + strings.Repeat("p", 220) + `"`
	payload := []byte(`{"after":{"quiet_processes":[` + long + `]},"before":{"quiet_processes":[]},"drill":["lateral sweep","port sweep","x"],"op":"save","policy":"detection_tuning"}`)
	if _, summary, err := describeApproval(ActionKindDetection, payload, tuning, "admin"); err != nil || !strings.HasPrefix(summary, "BLINDS 3 FLOOR CASES; quiet_processes +/usr/lib/ppp") {
		t.Fatalf("long change with drill: summary %q err %v", summary, err)
	}
	if _, _, err := describeApproval(ActionKindDetection, []byte(`{"after":{"quiet_orgs":["as1","as3"]},"before":{"quiet_orgs":["as1"]},"drill":"none","op":"save","policy":"detection_tuning"}`), tuning, "admin"); err == nil {
		t.Fatal("a drill that is not a list was described")
	}
}

// An enrolment window is shown by its networks, length, install budget and
// passcode; anything else in the payload is refused.
func TestDescribeAnEnrolmentWindow(t *testing.T) {
	window := func(after string) []byte {
		return []byte(`{"after":` + after + `,"before":null,"op":"open","policy":"enrolment_window"}`)
	}
	action, summary, err := describeApproval(ActionKindDetection, window(`{"cidrs":["10.0.0.0/24","10.0.1.0/24"],"hours":2,"label":"laptop reinstall","location_id":"","max_uses":2,"passcode":false,"role":"","tenant_id":""}`), []string{"enrolment:window"}, "admin")
	if err != nil || action != "Open LAN self-enrolment" ||
		summary != "unauthenticated agent installs from 10.0.0.0/24, 10.0.1.0/24; for 2 hours; at most 2 installs; no passcode; label laptop reinstall" {
		t.Fatalf("action %q summary %q err %v", action, summary, err)
	}
	for name, c := range map[string]struct{ after, target string }{
		"wrong target":   {`{"cidrs":["10.0.0.0/24"],"hours":2,"max_uses":0,"passcode":true}`, "enrolment:other"},
		"no networks":    {`{"cidrs":[],"hours":2,"max_uses":0,"passcode":true}`, "enrolment:window"},
		"too long":       {`{"cidrs":["10.0.0.0/24"],"hours":169,"max_uses":0,"passcode":true}`, "enrolment:window"},
		"no passcode":    {`{"cidrs":["10.0.0.0/24"],"hours":2,"max_uses":0}`, "enrolment:window"},
		"unknown member": {`{"cidrs":["10.0.0.0/24"],"hours":2,"max_uses":0,"passcode":true,"code":"x"}`, "enrolment:window"},
	} {
		if _, _, err := describeApproval(ActionKindDetection, window(c.after), []string{c.target}, "admin"); err == nil {
			t.Errorf("%s: described", name)
		}
	}
}

// Remote shell limits and session lengths read the way the owner says them.
func TestTerminalLengthsAndLimitsInPlainWords(t *testing.T) {
	for secs, want := range map[int64]string{14400: "4 hours", 3600: "1 hour", 5400: "1 hour 30 minutes", 2700: "45 minutes", 60: "1 minute", 3599: "1 hour"} {
		if got := spanText(secs); got != want {
			t.Errorf("spanText(%d) = %q, want %q", secs, got, want)
		}
	}
	_, summary, err := describeTerminal([]byte(`{"program":"powershell.exe"}`), []string{"ep-1"}, "admin", 14400)
	if err != nil || summary != "Interactive powershell.exe on ep-1, recorded, up to 4 hours, for admin" {
		t.Fatalf("terminal summary %q err %v", summary, err)
	}
	if _, _, err := describeTerminal([]byte(`{"program":"/bin/sh"}`), []string{"ep-1"}, "admin", 25*3600); err == nil {
		t.Fatal("a 25-hour session was described")
	}
	before := map[string]interface{}{"max_duration_seconds": 3600.0, "idle_timeout_seconds": 900.0, "max_per_endpoint": 3.0, "max_per_tenant": 8.0}
	after := map[string]interface{}{"max_duration_seconds": 14400.0, "idle_timeout_seconds": 1800.0, "max_per_endpoint": 3.0, "max_per_tenant": 10.0}
	got, err := TerminalLimitsWording(before, after)
	if err != nil || got != "Remote shell: sessions run up to 4 hours (was 1 hour); idle sessions end after 30 minutes (was 15 minutes); 10 open in all (was 8)" {
		t.Fatalf("wording %q err %v", got, err)
	}
	if _, err := TerminalLimitsWording(before, before); err == nil {
		t.Fatal("a change that changes nothing was described")
	}
	extra := map[string]interface{}{"max_duration_seconds": 14400.0, "idle_timeout_seconds": 900.0, "max_per_endpoint": 3.0, "max_per_tenant": 8.0, "program": "x"}
	if _, err := TerminalLimitsWording(before, extra); err == nil {
		t.Fatal("an unknown member was described")
	}
	payload, _ := json.Marshal(map[string]interface{}{"policy": "terminal_limits", "op": "raise", "before": before, "after": after})
	action, summary, err := describeApproval(ActionKindDetection, payload, []string{"terminal:limits"}, "admin")
	if err != nil || action != "Raise remote shell limits" || summary != got {
		t.Fatalf("approval %q %q %v", action, summary, err)
	}
	if _, _, err := describeApproval(ActionKindDetection, payload, []string{"detection:tuning"}, "admin"); err == nil {
		t.Fatal("a limits change under another target was described")
	}
}

// The owner reads control vs watch, the length, who for, and the consent
// cases; the payload is exactly the digested mode (and unattended).
func TestDescribeScreen(t *testing.T) {
	tg := []string{"win-01"}
	cases := []struct {
		payload  string
		seconds  int64
		askFirst bool
		action   string
		summary  string
	}{
		{`{"mode":"control"}`, 0, false, "Control screen", "See and control the screen on win-01, for alice"},
		{`{"mode":"control"}`, 4 * 3600, false, "Control screen", "See and control the screen on win-01, up to 4 hours, for alice"},
		{`{"mode":"view"}`, 1800, false, "Watch screen", "Watch the screen on win-01 (no control), up to 30 minutes, for alice"},
		{`{"mode":"control"}`, 3600, true, "Control screen", "See and control the screen on win-01, up to 1 hour, for alice; the person at the keyboard is asked to allow it first"},
		{`{"mode":"view","ask_first":true}`, 0, false, "Watch screen", "Watch the screen on win-01 (no control), for alice; the person at the keyboard is asked to allow it first"},
		{`{"mode":"control","unattended":true}`, 3600, true, "Control screen", "See and control the screen on win-01, up to 1 hour, for alice; the person at the keyboard is asked to allow it first; if nobody is signed in to allow it, it opens anyway with nobody at the keyboard"},
	}
	for _, tc := range cases {
		a, s, err := describeScreen([]byte(tc.payload), tg, "alice", tc.seconds, tc.askFirst)
		if err != nil || a != tc.action || s != tc.summary {
			t.Errorf("%s: %q %q %v", tc.payload, a, s, err)
		}
	}
	for _, tc := range []struct{ payload, summary string }{
		{`{"mode":"control"}`, "An agent (admin key) will see and control the screen on win-01, up to 1 hour"},
		{`{"mode":"view"}`, "An agent (admin key) will see the screen on win-01, up to 1 hour"},
	} {
		if _, s, err := describeScreen([]byte(tc.payload), tg, "admin (api-key)", 3600, false); err != nil || s != tc.summary {
			t.Errorf("agent %s: %q %v", tc.payload, s, err)
		}
	}
	for _, bad := range []string{`{"mode":"drive"}`, `{}`, `{"mode":"control","program":"cmd.exe"}`, `{"mode":"control","unattended":false}`, `[]`,
		`{"mode":"control","ask_first":false}`, `{"ask_first":true,"mode":"control"}`, `{"mode":"control","ask_first":true,"unattended":true}`,
		`{"mode": "control"}`, `{"Mode":"control"}`} {
		if _, _, err := describeScreen([]byte(bad), tg, "alice", 0, false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, _, err := describeScreen([]byte(`{"mode":"view"}`), []string{"a", "b"}, "alice", 0, false); err == nil {
		t.Error("two endpoints accepted")
	}
	// describeApproval routes the kind here.
	if a, _, err := describeApproval(response.ActionKindScreenSession, []byte(`{"mode":"view"}`), tg, "alice"); err != nil || a != "Watch screen" {
		t.Errorf("describeApproval: %q %v", a, err)
	}
}

func TestScreenAskFirstWording(t *testing.T) {
	off := map[string]interface{}{"scope": "win-01", "ask_first": false, "host": "Office PC"}
	on := map[string]interface{}{"scope": "win-01", "ask_first": true}
	got, err := ScreenAskFirstWording("screen:ask_first:win-01", on, off)
	if err != nil || got != "Screen sessions on endpoint win-01 (Office PC) open without asking the person at the keyboard first (was: asked first)" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = ScreenAskFirstWording("screen:ask_first", map[string]interface{}{"scope": "fleet", "ask_first": false}, map[string]interface{}{"scope": "fleet", "ask_first": true})
	if err != nil || !strings.HasPrefix(got, "Screen sessions on every machine without its own setting ask the person") {
		t.Fatalf("%q %v", got, err)
	}
	for _, tc := range []struct {
		target        string
		before, after map[string]interface{}
	}{
		{"screen:ask_first", on, off},         // endpoint scope, fleet target
		{"screen:ask_first:win-02", on, off},  // another endpoint
		{"screen:ask_first:win-01", on, on},   // no change
		{"screen:ask_first:win-01", nil, off}, // no before
		{"screen:ask_first:win-01", on, map[string]interface{}{"scope": "win-01", "ask_first": "no"}},
		{"screen:ask_first:win-01", on, map[string]interface{}{"scope": "win-02", "ask_first": false}},
		{"screen:ask_first:win-01", on, map[string]interface{}{"scope": "win-01", "ask_first": false, "extra": 1}},
	} {
		if _, err := ScreenAskFirstWording(tc.target, tc.before, tc.after); err == nil {
			t.Errorf("%s %v -> %v accepted", tc.target, tc.before, tc.after)
		}
	}
}
