package grants

import (
	"strings"
	"testing"

	"ominull/hub/pkg/response"
)

// A staged rollout reads as staged as staged, worked out from the payload.
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

// Remote shell limits and session lengths read the way the owner says them.
func TestTerminalLengthsAndLimitsInPlainWords(t *testing.T) {
	for secs, want := range map[int64]string{14400: "4 hours", 3600: "1 hour", 5400: "1 hour 30 minutes", 2700: "45 minutes", 60: "1 minute", 3599: "1 hour"} {
		if got := spanText(secs); got != want {
			t.Errorf("spanText(%d) = %q, want %q", secs, got, want)
		}
	}
	_, summary, err := describeTerminal([]byte(`{"program":"powershell.exe"}`), []string{"ep-1"}, "admin", 14400, "")
	if err != nil || summary != "Interactive powershell.exe on ep-1, recorded, up to 4 hours, for admin" {
		t.Fatalf("terminal summary %q err %v", summary, err)
	}
	_, summary, err = describeTerminal([]byte(`{"program":"bash"}`), []string{"ep-1"}, "admin (api-key)", 3600, "claude-ops")
	if err != nil || summary != `Interactive bash on ep-1, recorded, up to 1 hour, for admin (api-key), an agent calling itself "claude-ops"` {
		t.Fatalf("terminal summary with an agent label %q err %v", summary, err)
	}
	if _, _, err := describeTerminal([]byte(`{"program":"/bin/sh"}`), []string{"ep-1"}, "admin", 25*3600, ""); err == nil {
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
		{`{"mode":"control"}`, 0, false, "Control screen", "See and control the screen on win-01, for alice; it opens without asking the person at the keyboard"},
		{`{"mode":"control"}`, 4 * 3600, false, "Control screen", "See and control the screen on win-01, up to 4 hours, for alice; it opens without asking the person at the keyboard"},
		{`{"mode":"view"}`, 1800, false, "Watch screen", "Watch the screen on win-01 (no control), up to 30 minutes, for alice; it opens without asking the person at the keyboard"},
		{`{"mode":"control"}`, 3600, true, "Control screen", "See and control the screen on win-01, up to 1 hour, for alice; the person at the keyboard is asked to allow it first"},
		{`{"mode":"view","ask_first":true}`, 0, false, "Watch screen", "Watch the screen on win-01 (no control), for alice; the person at the keyboard is asked to allow it first"},
		{`{"mode":"control","unattended":true}`, 3600, true, "Control screen", "See and control the screen on win-01, up to 1 hour, for alice; the person at the keyboard is asked to allow it first; if nobody is signed in to allow it, it opens anyway with nobody at the keyboard"},
	}
	for _, tc := range cases {
		a, s, err := describeScreen([]byte(tc.payload), tg, "alice", tc.seconds, tc.askFirst, "")
		if err != nil || a != tc.action || s != tc.summary {
			t.Errorf("%s: %q %q %v", tc.payload, a, s, err)
		}
	}
	for _, tc := range []struct{ payload, label, summary string }{
		{`{"mode":"control"}`, "", "An agent (admin key) will see and control the screen on win-01, up to 1 hour; it opens without asking the person at the keyboard"},
		{`{"mode":"view"}`, "", "An agent (admin key) will see the screen on win-01, up to 1 hour; it opens without asking the person at the keyboard"},
		{`{"mode":"control"}`, "claude-ops", `An agent calling itself "claude-ops" (admin key) will see and control the screen on win-01, up to 1 hour; it opens without asking the person at the keyboard`},
	} {
		if _, s, err := describeScreen([]byte(tc.payload), tg, "admin (api-key)", 3600, false, tc.label); err != nil || s != tc.summary {
			t.Errorf("agent %s: %q %v", tc.payload, s, err)
		}
	}
	for _, bad := range []string{`{"mode":"drive"}`, `{}`, `{"mode":"control","program":"cmd.exe"}`, `{"mode":"control","unattended":false}`, `[]`,
		`{"mode":"control","ask_first":false}`, `{"ask_first":true,"mode":"control"}`, `{"mode":"control","ask_first":true,"unattended":true}`,
		`{"mode": "control"}`, `{"Mode":"control"}`} {
		if _, _, err := describeScreen([]byte(bad), tg, "alice", 0, false, ""); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, _, err := describeScreen([]byte(`{"mode":"view"}`), []string{"a", "b"}, "alice", 0, false, ""); err == nil {
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

func TestRemoteAccessWording(t *testing.T) {
	on := map[string]interface{}{"endpoint": "ws-1", "off": true}
	off := map[string]interface{}{"endpoint": "ws-1", "off": false, "host": "workstation"}
	got, err := RemoteAccessWording("remote_access:ws-1", on, off)
	if err != nil || got != "Remote terminal and screen allowed again on endpoint ws-1 (workstation), each session still with approval (was: switched off)" {
		t.Fatalf("%q %v", got, err)
	}
	for _, tc := range []struct {
		target        string
		before, after map[string]interface{}
	}{
		{"remote_access:other", on, off},
		{"remote_access:ws-1", on, on},
		{"remote_access:ws-1", nil, off},
		{"remote_access:ws-1", on, map[string]interface{}{"endpoint": "ws-1", "off": false, "extra": 1}},
		{"remote_access:ws-1", on, map[string]interface{}{"endpoint": "ws-2", "off": false}},
	} {
		if _, err := RemoteAccessWording(tc.target, tc.before, tc.after); err == nil {
			t.Errorf("accepted %+v", tc)
		}
	}
}
