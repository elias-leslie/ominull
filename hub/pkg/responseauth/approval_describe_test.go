package responseauth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
