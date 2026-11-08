package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testClaude = "/home/u/.local/share/claude/versions/2.1.296"

func egressEvent(at time.Time, path, session, dst string, port uint16) Event {
	ev := convEvent(at, path, "10.0.0.5", 50000, dst, int(port), "PERMIT")
	ev.AgentSession = session
	return ev
}

func saveEgressPolicy(t *testing.T, store *Store, p AgentEgressPolicy) {
	t.Helper()
	tuning := store.GetDetectionTuning()
	tuning.AgentEgressPolicy = p
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("SaveDetectionTuning: %v", err)
	}
}

// A flow keeps the session behind it, one row still holds a conversation
// whichever sessions held it, and the row can be narrowed to one session's part.
func TestConversationsShowWhichSessionMadeTheConnection(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC().Add(-2 * time.Minute)
	if _, err := store.RecordAgentSessions([]AgentSession{{Window: "aaaa1111", Name: "Lane one", Tool: "claude", Project: "ominull"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertEventsBatch([]Event{
		egressEvent(now, "/usr/bin/curl", "claude:aaaa1111", "203.0.113.9", 443),
		egressEvent(now, "/usr/bin/curl", "claude:aaaa1111", "203.0.113.9", 443),
		egressEvent(now, "/usr/bin/curl", "codex:bbbb2222", "203.0.113.9", 443),
		egressEvent(now, "/usr/bin/curl", "", "203.0.113.20", 443),
	}); err != nil {
		t.Fatal(err)
	}
	res, err := store.QueryTrafficConversations(TrafficFilter{Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conversations) != 2 {
		t.Fatalf("want one row per conversation, got %+v", res.Conversations)
	}
	c := findConversation(t, res.Conversations, "curl", "203.0.113.9")
	if c.Flows != 3 || len(c.Sessions) != 2 || c.Sessions[0].Key != "claude:aaaa1111" || c.Sessions[0].Name != "Lane one" || c.Sessions[0].Project != "ominull" {
		t.Fatalf("sessions not folded and named: %+v", c)
	}
	if c.Sessions[1].Tool != "codex" || c.Sessions[1].Name != "" {
		t.Fatalf("an unnamed session should still show: %+v", c.Sessions[1])
	}
	if len(res.Sessions) != 2 || res.Sessions[0].Flows != 2 {
		t.Fatalf("session totals: %+v", res.Sessions)
	}
	if res.Counts.Agent != 1 {
		t.Fatalf("agent rows: %+v", res.Counts)
	}

	one, err := store.QueryTrafficConversations(TrafficFilter{Range: "1h"}, ConversationQuery{Session: "codex:bbbb2222"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Conversations) != 1 || one.Conversations[0].Flows != 1 || len(one.Sessions) != 2 {
		t.Fatalf("one session's part, with the filter's choices kept: %+v", one)
	}
	named, err := store.QueryTrafficConversations(TrafficFilter{Range: "1h"}, ConversationQuery{Search: "lane one"})
	if err != nil {
		t.Fatal(err)
	}
	if len(named.Conversations) != 1 {
		t.Fatalf("search by session name: %+v", named.Conversations)
	}
}

// The older agents report the session only through the actor of what the
// session ran, and a bad value from an agent is no session at all.
func TestAgentSessionOf(t *testing.T) {
	for _, c := range []struct {
		ev   Event
		want string
	}{
		{Event{AgentSession: "claude:1b16ad8d"}, "claude:1b16ad8d"},
		{Event{Actor: "agent:codex:ab12"}, "codex:ab12"},
		{Event{Actor: "agent:claude:"}, "claude:"},
		{Event{Actor: "service:nightshift:x.service"}, ""},
		{Event{AgentSession: "claude:<script>"}, ""},
		{Event{AgentSession: "no-colon"}, ""},
	} {
		if got := AgentSessionOf(c.ev); got != c.want {
			t.Errorf("AgentSessionOf(%+v) = %q, want %q", c.ev, got, c.want)
		}
	}
}

// Rows answer what the saved policy says at once; observing, nothing is live.
func TestConversationsCarryThePolicyVerdict(t *testing.T) {
	store := conversationStore(t)
	now := time.Now().UTC().Add(-2 * time.Minute)
	// A session's process that answers a client is not the session reaching out.
	served := egressEvent(now, "/usr/bin/python3", "claude:aaaa1111", "203.0.113.50", 40000)
	served.SrcPort = 8080
	if err := store.InsertEventsBatch([]Event{
		egressEvent(now, testClaude, "claude:aaaa1111", "160.79.104.10", 443),
		egressEvent(now, "/usr/bin/curl", "claude:aaaa1111", "203.0.113.9", 443),
		egressEvent(now, "/usr/bin/curl", "", "203.0.113.9", 443),
		served,
	}); err != nil {
		t.Fatal(err)
	}
	saveEgressPolicy(t, store, AgentEgressPolicy{Rules: []AgentEgressRule{
		{ID: "model-api", Action: EgressAllow, CIDRs: []string{"160.79.104.0/24"}, Ports: []int{443}},
		{ID: "else", Action: EgressFlag},
	}})
	res, err := store.QueryTrafficConversations(TrafficFilter{Range: "1h"}, ConversationQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if res.EgressMode != EgressObserve {
		t.Fatalf("mode: %q", res.EgressMode)
	}
	api := findConversation(t, res.Conversations, "claude", "160.79.104.10")
	if api.Verdict == nil || api.Verdict.Action != EgressAllow || api.Runtime != "claude" {
		t.Fatalf("allowed row: %+v", api)
	}
	curl := findConversation(t, res.Conversations, "curl", "203.0.113.9")
	if curl.Verdict == nil || curl.Verdict.Action != EgressFlag || curl.Verdict.Rule != "else" || curl.Verdict.Live {
		t.Fatalf("flagged row should only show what it would do: %+v", curl.Verdict)
	}
	if res.Counts.Policy != 1 {
		t.Fatalf("policy count: %+v", res.Counts)
	}
	if in := findConversation(t, res.Conversations, "python3", "203.0.113.50"); in.Verdict != nil || in.Direction != "in" {
		t.Fatalf("served row has no verdict: %+v", in)
	}
	pol, err := store.QueryTrafficConversations(TrafficFilter{Range: "1h"}, ConversationQuery{Mark: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Conversations) != 1 {
		t.Fatalf("mark=policy: %+v", pol.Conversations)
	}
}

func TestEgressPolicyEvaluate(t *testing.T) {
	p := AgentEgressPolicy{Mode: EgressEnforce, BlockEndpoints: []string{"lab"}, Rules: []AgentEgressRule{
		{ID: "b", Action: EgressBlock, Session: "Lane*", CIDRs: []string{"203.0.113.0/24"}},
		{ID: "docs", Action: EgressAllow, Domains: []string{"example.com"}},
		{ID: "ssh", Action: EgressFlag, Runtime: "codex", Ports: []int{22}},
	}}
	for _, c := range []struct {
		s      EgressSubject
		action string
		rule   string
		live   bool
	}{
		{EgressSubject{EndpointID: "lab", Runtime: "claude", Session: "claude:ab12", Name: "Lane 3", IP: "203.0.113.4"}, EgressBlock, "b", true},
		{EgressSubject{EndpointID: "ws", Runtime: "claude", Session: "claude:ab12", Name: "lane 3", IP: "203.0.113.4"}, EgressBlock, "b", false},
		{EgressSubject{Runtime: "claude", Session: "claude:ab12", Name: "Other", IP: "203.0.113.4"}, "", "", false},
		{EgressSubject{Runtime: "claude", Domain: "API.example.com.", IP: "198.51.100.1"}, EgressAllow, "docs", true},
		{EgressSubject{Runtime: "claude", SNI: "example.com", IP: "198.51.100.1"}, EgressAllow, "docs", true},
		{EgressSubject{Runtime: "claude", Domain: "notexample.com", IP: "198.51.100.1"}, "", "", false},
		{EgressSubject{Runtime: "codex", IP: "198.51.100.1", Port: 22}, EgressFlag, "ssh", true},
		{EgressSubject{Runtime: "claude", IP: "198.51.100.1", Port: 22}, "", "", false},
		{EgressSubject{IP: "203.0.113.4", Domain: "example.com"}, "", "", false}, // no agent behind it
	} {
		v := p.Evaluate(c.s)
		if c.action == "" {
			if v != nil {
				t.Errorf("%+v: want no verdict, got %+v", c.s, v)
			}
			continue
		}
		if v == nil || v.Action != c.action || v.Rule != c.rule || v.Live != c.live {
			t.Errorf("%+v: got %+v, want %s %s live=%v", c.s, v, c.action, c.rule, c.live)
		}
	}
}

func TestEgressPolicyRefusesWhatAFirewallCannotHold(t *testing.T) {
	for want, rules := range map[string][]AgentEgressRule{
		"action must be":      {{ID: "a", Action: "deny"}},
		"used twice":          {{ID: "a", Action: EgressFlag}, {ID: "a", Action: EgressFlag}},
		"names addresses":     {{ID: "a", Action: EgressBlock, Domains: []string{"x.com"}}},
		"come before":         {{ID: "a", Action: EgressAllow}, {ID: "b", Action: EgressBlock, CIDRs: []string{"203.0.113.1"}}},
		"wider than":          {{ID: "a", Action: EgressBlock, CIDRs: []string{"12.0.0.0/7"}}},
		"public addresses":    {{ID: "a", Action: EgressBlock, CIDRs: []string{"192.168.1.0/24"}}},
		"not an address":      {{ID: "a", Action: EgressFlag, CIDRs: []string{"nope"}}},
		"not a domain":        {{ID: "a", Action: EgressFlag, Domains: []string{"a b"}}},
		"out of range":        {{ID: "a", Action: EgressFlag, Ports: []int{70000}}},
		"not a valid pattern": {{ID: "a", Action: EgressFlag, Session: "[x"}},
		"use lowercase":       {{ID: "A B", Action: EgressFlag}},
	} {
		err := AgentEgressPolicy{Rules: rules}.tidy().valid()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: got %v, want %q", rules, err, want)
		}
	}
	if err := (AgentEgressPolicy{Mode: "on"}).tidy().valid(); err == nil {
		t.Errorf("a bad mode should be refused")
	}
	if p := (AgentEgressPolicy{}).tidy(); p.Mode != EgressObserve || p.valid() != nil {
		t.Errorf("an empty policy observes: %+v", p)
	}
}

// Only the named endpoint, only while enforcing. A key's tool is the tool, so a
// rule is never wider on the wire than it reads.
func TestBlockEntries(t *testing.T) {
	p := AgentEgressPolicy{Mode: EgressEnforce, BlockEndpoints: []string{"lab"}, Rules: []AgentEgressRule{
		{ID: "key", Action: EgressBlock, Session: "claude:ab12", CIDRs: []string{"203.0.113.0/24"}, Ports: []int{443, 80}},
		{ID: "window", Action: EgressBlock, Session: "cd34", CIDRs: []string{"198.51.100.7/32"}},
		{ID: "runtime", Action: EgressBlock, Runtime: "codex", CIDRs: []string{"198.51.100.9/32"}},
		{ID: "all", Action: EgressBlock, CIDRs: []string{"198.51.100.10/32"}},
		{ID: "not-this", Action: EgressFlag, CIDRs: []string{"198.51.100.11/32"}},
	}}
	got := strings.Join(p.BlockEntries("lab"), " ")
	want := "claude|ab12|203.0.113.0/24|443 claude|ab12|203.0.113.0/24|80 *|cd34|198.51.100.7/32|0 codex|*|198.51.100.9/32|0 *|*|198.51.100.10/32|0"
	if got != want {
		t.Fatalf("entries:\n got %s\nwant %s", got, want)
	}
	if e := p.BlockEntries("workstation"); e != nil {
		t.Fatalf("an endpoint not named holds nothing: %v", e)
	}
	p.Mode = EgressObserve
	if e := p.BlockEntries("lab"); e != nil {
		t.Fatalf("observing holds nothing: %v", e)
	}
}

// What a block can't say, or an agent can't read whole, never gets saved.
func TestBlockRulesAnAgentCouldNotHold(t *testing.T) {
	block := func(r AgentEgressRule) AgentEgressPolicy {
		r.ID, r.Action = "r", EgressBlock
		if r.CIDRs == nil {
			r.CIDRs = []string{"198.51.100.7/32"}
		}
		return AgentEgressPolicy{Mode: EgressEnforce, Rules: []AgentEgressRule{r}}.tidy()
	}
	for name, p := range map[string]AgentEgressPolicy{
		"a session by name":        block(AgentEgressRule{Session: "Lane*"}),
		"a session with no window": block(AgentEgressRule{Session: "claude:"}),
		"a conflicting runtime":    block(AgentEgressRule{Runtime: "codex", Session: "claude:ab12"}),
		"too long for the parser":  block(AgentEgressRule{Session: "claude:0123456789abcdef0123456789abcdef", CIDRs: []string{"2001:4860:4860:1234:1234:1234:1234:1234/128"}}),
		"too many entries": block(AgentEgressRule{CIDRs: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5", "198.51.100.6"},
			Ports: []int{1, 2, 3, 4, 5, 6}}),
	} {
		if err := p.valid(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := block(AgentEgressRule{Session: "claude:ab12"}).valid(); err != nil {
		t.Errorf("a whole rule was refused: %v", err)
	}
}

// A session named with a slash is still covered by a pattern.
func TestSessionPatternCrossesASlash(t *testing.T) {
	r := AgentEgressRule{Session: "ominull*"}
	if !r.matchesSession("claude:ab12", "Ominull/fix") {
		t.Error("the pattern stopped at the slash")
	}
}

// Rules match each name a row's flows reached and each part of the row, as the
// detector does per flow, and the strictest answer is the row's.
func TestConversationVerdictReadsEveryName(t *testing.T) {
	tuning := DetectionTuning{AgentEgressPolicy: AgentEgressPolicy{Mode: EgressObserve, Rules: []AgentEgressRule{
		{ID: "ok", Action: EgressAllow, Domains: []string{"anthropic.com"}},
		{ID: "paste", Action: EgressFlag, Domains: []string{"paste.example"}},
	}}}
	row := func(session []string, plain []string) TrafficConversation {
		c := TrafficConversation{Direction: "out", PeerName: "zzz.cdn.example", PeerIP: "198.51.100.7", Port: 443, names: plain}
		if session != nil {
			c.Sessions = []ConversationSession{{Key: "claude:ab12", Tool: "claude", names: session}}
		}
		return c
	}
	if v := row([]string{"api.anthropic.com", "zzz.cdn.example"}, nil).judged(tuning).Verdict; v == nil || v.Rule != "ok" {
		t.Errorf("an allowed name hidden by a greater one: %+v", v)
	}
	if v := row([]string{"paste.example", "api.anthropic.com"}, nil).judged(tuning).Verdict; v == nil || v.Rule != "paste" {
		t.Errorf("a flagged name among others: %+v", v)
	}
	other := row([]string{"api.anthropic.com"}, nil)
	other.Sessions = append(other.Sessions, ConversationSession{Key: "codex:cd34", Tool: "codex", names: []string{"paste.example"}})
	narrowed, ok := other.onlySession("claude:ab12")
	if v := narrowed.judged(tuning).Verdict; !ok || v == nil || v.Rule != "ok" {
		t.Errorf("a session judged on what another session reached: %+v", v)
	}
}

// An older database has no column and a view with a fixed column list.
func TestOlderDatabaseGainsAgentSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER trg_events_view_insert; DROP VIEW events; DROP VIEW events_view_process;
		ALTER TABLE flow_processes DROP COLUMN agent_session;`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(strings.Replace(eventsViewSQL, ",\n\tp.agent_session AS agent_session", "", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(eventsViewProcessSQL); err != nil {
		t.Fatal(err)
	}
	store.Close()

	store, err = New(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	at := time.Now().UTC().Add(-time.Minute)
	if err := store.InsertEventsBatch([]Event{egressEvent(at, "/usr/bin/curl", "claude:ab12", "203.0.113.9", 443)}); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := store.db.QueryRow(`SELECT agent_session FROM events`).Scan(&got); err != nil || got != "claude:ab12" {
		t.Fatalf("view after upgrade: %q %v", got, err)
	}
	// The trigger is back too, for tools that insert into the view.
	if _, err := store.db.Exec(`INSERT INTO events (tenant_id, endpoint_id, timestamp, protocol, src_ip, dst_ip, src_port, dst_port) VALUES ('default', 'e', ?, 6, '10.0.0.1', '203.0.113.1', 1, 2)`, flowTime(at)); err != nil {
		t.Fatalf("insert through the view: %v", err)
	}
}

func TestAgentRowNamedOnlyForItsVersionShowsTheRuntime(t *testing.T) {
	tuning := DefaultDetectionTuning()
	row := TrafficConversation{Process: "2.1.319", ProcessPath: "/home/someone/.local/share/claude/versions/2.1.319"}.judged(tuning)
	if row.Runtime == "" || row.Process != row.Runtime {
		t.Fatalf("process %q runtime %q", row.Process, row.Runtime)
	}
	other := TrafficConversation{Process: "codex", ProcessPath: "/usr/local/bin/codex"}.judged(tuning)
	if other.Process != "codex" {
		t.Fatalf("a named program keeps its name, got %q", other.Process)
	}
	plain := TrafficConversation{Process: "7.2", ProcessPath: "/opt/app/7.2"}.judged(tuning)
	if plain.Process != "7.2" {
		t.Fatalf("not an agent keeps its name, got %q", plain.Process)
	}
}
