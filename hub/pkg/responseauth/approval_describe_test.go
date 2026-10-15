package responseauth

import (
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
