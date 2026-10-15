package responseauth

import (
	"encoding/json"
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

	// Many changes fit the statement cap and say how many did not.
	before, after := map[string]interface{}{}, map[string]interface{}{}
	for i := 0; i < 40; i++ {
		k := strings.Repeat("x", 20) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		before[k], after[k] = 1, 2
	}
	raw, _ := json.Marshal(map[string]interface{}{"policy": "detection_tuning", "op": "save", "before": before, "after": after})
	_, summary, err = describeApproval(ActionKindDetection, raw, tuning, "admin")
	if err != nil || len([]rune(summary)) > approvalMaxSummary || !strings.Contains(summary, " more") {
		t.Fatalf("long summary (%d runes) %q err %v", len([]rune(summary)), summary, err)
	}

	exclusion := []byte(`{"after":{"active":true,"dst_ip_range":"172.18.0.0/16","expires_at":"2026-11-01T00:00:00Z","id":"","name":"bridge","port":7070,"process_path":"/usr/bin/docker-proxy","reason":"bridge","scope":"global","scope_value":"","tenant_id":"default"},"before":null,"op":"create","policy":"exclusion"}`)
	action, summary, err = describeApproval(ActionKindDetection, exclusion, []string{"exclusion:new"}, "admin")
	if err != nil || action != "Add a detection exclusion" ||
		summary != "name bridge; process_path /usr/bin/docker-proxy; dst_ip_range 172.18.0.0/16; port 7070; scope global; expires_at 2026-11-01T00:00:00Z; reason bridge" {
		t.Fatalf("exclusion action %q summary %q err %v", action, summary, err)
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
