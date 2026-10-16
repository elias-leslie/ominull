package detector

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

const claudePath = "/home/u/.local/share/claude/versions/2.1.296"

func agentEvent(endpoint, path, domain, ip string, port uint16, out int64, at time.Time) storage.Event {
	return storage.Event{
		TenantID: "default", EndpointID: endpoint, Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: ip, DstPort: port, BytesOut: out, ProcessPath: path, Domain: domain,
	}
}

func TestAgentRuntimesAreRecognisedByTheirExecutable(t *testing.T) {
	tu := storage.DefaultDetectionTuning()
	for path, want := range map[string]string{
		claudePath: "claude",
		"/home/u/.local/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/bin/codex (deleted)": "codex",
		"/usr/local/bin/ollama":                      "ollama",
		"/home/u/.local/share/claude/versions/x/bin": "",
		"/usr/bin/python3.13":                        "",
	} {
		if got := tu.AgentRuntimeOf(path); got != want {
			t.Errorf("AgentRuntimeOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAgentDestinationIsTheRegistrableDomain(t *testing.T) {
	for _, c := range []struct{ domain, ip, want string }{
		// A suffix anyone can host under (run.app, a user-content domain) is
		// a separate party per name: that is where a rented sink would be.
		{"sdmntprcentralus.oaiusercontent.com", "", "sdmntprcentralus.oaiusercontent.com"},
		{"mpc2-prod-23.a.run.app", "", "mpc2-prod-23.a.run.app"},
		{"API.Anthropic.com.", "", "anthropic.com"},
		{"news.bbc.co.uk", "", "bbc.co.uk"},
		{"", "203.0.113.7", "net:203.0.113.0/24"},
	} {
		if got := agentDestination(c.domain, "", c.ip, threatintel.GeoRecord{}); got != c.want {
			t.Errorf("agentDestination(%q, %q) = %q, want %q", c.domain, c.ip, got, c.want)
		}
	}
	if got := agentDestination("", "", "203.0.113.7", threatintel.GeoRecord{Org: "Example Hosting"}); got != "owner:example hosting" {
		t.Errorf("an unnamed address with an owner should key on the owner, got %q", got)
	}
}

// A runtime's first week is its baseline; after it, somewhere new is a finding,
// once per destination, and somewhere it already goes is not.
func TestAnAgentReachingANewDestinationAfterItsBaselineIsReported(t *testing.T) {
	engine, store := noiseEngine(t)
	start := time.Now().UTC().Add(-10 * 24 * time.Hour)
	engine.Evaluate(agentEvent("linux-70", claudePath, "api.anthropic.com", "160.79.104.10", 443, 2000, start))
	engine.Evaluate(agentEvent("linux-70", claudePath, "paste.example.net", "203.0.113.9", 443, 2000, start.Add(time.Hour)))
	if got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION"); len(got) != 0 {
		t.Fatalf("destinations inside the baseline week raised %d findings", len(got))
	}
	now := time.Now().UTC()
	engine.Evaluate(agentEvent("linux-70", claudePath, "api.anthropic.com", "160.79.104.11", 443, 2000, now))
	engine.Evaluate(agentEvent("linux-70", claudePath, "drop.attacker.example", "198.51.100.40", 443, 4<<20, now))
	engine.Evaluate(agentEvent("linux-70", claudePath, "cdn.drop.attacker.example", "198.51.100.41", 443, 100, now.Add(time.Second)))
	got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION")
	if len(got) != 1 {
		t.Fatalf("one new registrable domain should raise one finding, got %d", len(got))
	}
	if got[0].Severity != "HIGH" {
		t.Fatalf("a first contact carrying 4 MB is HIGH, got %q", got[0].Severity)
	}
}

func TestAnAgentsUnusualHourOfUploadsIsReportedOnce(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	// Two weeks of ordinary hours: a few megabytes each.
	for h := 1; h <= 48; h++ {
		if _, err := store.AddAgentUpload("default", "linux-71", "codex", 3<<20, now.Add(-time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ { // 8 x 20 MB = 160 MB this hour, over the 100 MB floor and 5 x p95
		engine.Evaluate(agentEvent("linux-71", "/usr/bin/codex", "chatgpt.com", "104.18.32.47", 443, 20<<20, now.Add(time.Duration(i)*time.Second)))
	}
	if got := anomaliesOfType(t, store, "AGENT_UPLOAD_VOLUME"); len(got) != 1 {
		t.Fatalf("one unusual hour should raise one finding, got %d", len(got))
	}
}

func TestAToolResolvingNamesPastTheRouterIsReported(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	engine.Evaluate(agentEvent("linux-72", "/usr/bin/curl", "dns.google", "8.8.8.8", 443, 300, now))
	engine.Evaluate(agentEvent("linux-72", "/usr/bin/curl", "dns.google", "8.8.8.8", 443, 300, now.Add(time.Second)))
	engine.Evaluate(agentEvent("linux-72", claudePath, "", "1.1.1.1", 853, 300, now))
	// A browser's secure DNS and the host resolver are not agent tools.
	engine.Evaluate(agentEvent("linux-72", "/opt/google/chrome/chrome", "dns.google", "8.8.4.4", 443, 300, now))
	engine.Evaluate(agentEvent("linux-72", "/usr/sbin/dnsmasq", "", "1.0.0.1", 53, 300, now))
	if got := anomaliesOfType(t, store, "AGENT_DNS_BYPASS"); len(got) != 2 {
		t.Fatalf("expected one finding for curl and one for claude, got %d", len(got))
	}
}

// Resolver bypass is part of the floor: switching agent egress off silences
// the runtimes' baselines, never a tool resolving names past the router.
func TestResolverBypassIsReportedWithAgentEgressOff(t *testing.T) {
	engine, store := noiseEngine(t)
	tuning := storage.DefaultDetectionTuning()
	tuning.AgentEgressOn = false
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	engine.InvalidateTuning()
	now := time.Now().UTC()
	engine.Evaluate(agentEvent("linux-73", "/usr/bin/curl", "dns.google", "8.8.8.8", 443, 300, now))
	if got := anomaliesOfType(t, store, "AGENT_DNS_BYPASS"); len(got) != 1 {
		t.Fatalf("resolver bypass with agent egress off: %d findings, want 1", len(got))
	}
	engine.Evaluate(agentEvent("linux-73", claudePath, "drop.attacker.example", "198.51.100.40", 443, 4<<20, now.Add(time.Second)))
	if got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION"); len(got) != 0 {
		t.Fatalf("agent egress is off, yet its baseline finding fired %d times", len(got))
	}
}

func TestAgentBaselinesAreSeededFromProfilesOnce(t *testing.T) {
	engine, store := noiseEngine(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if err := store.RecordNetworkCommsBatch([]storage.Event{agentEvent("linux-73", claudePath, "api.anthropic.com", "160.79.104.10", 443, 100, old)}, "h73", ""); err != nil {
		t.Fatal(err)
	}
	engine.SeedAgentBaselines()
	list, err := store.ListAgentDestinations("", 10)
	if err != nil || len(list) != 1 || list[0].Destination != "anthropic.com" || list[0].Runtime != "claude" {
		t.Fatalf("seeded baseline = %+v %v", list, err)
	}
	// The seeded history means the baseline week is long over: a new domain now is reported.
	engine.Evaluate(agentEvent("linux-73", claudePath, "drop.attacker.example", "198.51.100.40", 443, 100, time.Now().UTC()))
	if got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION"); len(got) != 1 {
		t.Fatalf("after seeding, a new destination should be reported, got %d", len(got))
	}
}

// A runtime event landing before the seed must not cancel it, and the seed
// moves the baseline start back to when the profiles first saw the runtime.
func TestAFirstLiveEventDoesNotCancelTheSeed(t *testing.T) {
	engine, store := noiseEngine(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if err := store.RecordNetworkCommsBatch([]storage.Event{agentEvent("linux-74", claudePath, "api.anthropic.com", "160.79.104.10", 443, 100, old)}, "h74", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	engine.Evaluate(agentEvent("linux-74", claudePath, "statsig.anthropic.com", "160.79.104.12", 443, 100, now))
	engine.SeedAgentBaselines()
	engine.Evaluate(agentEvent("linux-74", claudePath, "drop.attacker.example", "198.51.100.40", 443, 100, now.Add(time.Second)))
	if got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION"); len(got) != 1 {
		t.Fatalf("after a seed that followed a live event, a new destination should be reported, got %d", len(got))
	}
}

// Retention forgets destinations, never when the baseline began: an idle
// runtime does not get a second silent learning week.
func TestRetentionDoesNotReopenTheLearningWeek(t *testing.T) {
	engine, store := noiseEngine(t)
	start := time.Now().UTC().Add(-40 * 24 * time.Hour)
	engine.Evaluate(agentEvent("linux-75", claudePath, "api.anthropic.com", "160.79.104.10", 443, 100, start))
	if _, err := store.AddAgentUpload("default", "linux-75", "claude", 100, start); err != nil {
		t.Fatal(err)
	}
	policy := storage.DefaultRetention()
	policy.CommProfiles = 30 * 24 * time.Hour
	removed, err := store.PruneOldData(policy)
	if err != nil {
		t.Fatal(err)
	}
	if removed["agent_egress_destinations"] != 1 || removed["agent_egress_hourly"] != 1 {
		t.Fatalf("retention removed %v", removed)
	}
	engine.Evaluate(agentEvent("linux-75", claudePath, "drop.attacker.example", "198.51.100.40", 443, 100, time.Now().UTC()))
	if got := anomaliesOfType(t, store, "AGENT_NEW_DESTINATION"); len(got) != 1 {
		t.Fatalf("a runtime whose destinations aged out is still past its baseline, got %d findings", len(got))
	}
}

// On a CDN one address serves many sites, so a borrowed name is keyed with
// its owner.
func TestANameOnSharedHostingIsKeyedWithItsOwner(t *testing.T) {
	got := agentDestination("api.example.com", "", "104.18.32.47", threatintel.GeoRecord{Org: "Cloudflare, Inc.", Tenancy: storage.TenancySharedCDN})
	if got != "example.com@cloudflare, inc." {
		t.Fatalf("got %q", got)
	}
}

// Claude Code sends each turn's whole context to api.anthropic.com, a few
// megabytes whenever a session is long, and its native build runs as its
// version number. Production raised seven CRITICAL "far more data than usual"
// pages in a day for exactly that. The runtime's own maker is judged by the
// runtime's hourly volume, not the per-connection spike; any other process,
// any other destination, and a path the agent could not match still are.
func TestAnAgentRuntimeTalkingToItsOwnMakerIsNotABandwidthSpike(t *testing.T) {
	const claude = "/home/kasadis/.local/share/claude/versions/2.1.301"
	spike := func(t *testing.T, ev storage.Event) []storage.AnomalyAlert {
		t.Helper()
		engine, store := noiseEngine(t)
		now := time.Now().UTC()
		for i := 0; i < 40; i++ {
			base := ev
			base.Timestamp, base.BytesOut = now.Add(time.Duration(i)*time.Second), 2000+int64(i)
			engine.Evaluate(base)
		}
		ev.Timestamp, ev.BytesOut = now.Add(time.Minute), 150*1024*1024
		engine.Evaluate(ev)
		return anomaliesOfType(t, store, "BANDWIDTH_SPIKE")
	}
	flow := func(path, ip, domain string) storage.Event {
		return storage.Event{TenantID: "default", EndpointID: "linux-ws", Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: ip, DstPort: 443, Domain: domain, ProcessPath: path}
	}

	own := flow(claude, "160.79.104.10", "api.anthropic.com")
	if got := spike(t, own); len(got) != 0 {
		t.Fatalf("claude uploading to its own API raised %d bandwidth alert(s): %q", len(got), got[0].Title)
	}
	if got := spike(t, flow(claude, "2607:6bc0::10", "api.anthropic.com")); len(got) != 0 {
		t.Fatalf("claude uploading to its own API over IPv6 raised %d bandwidth alert(s)", len(got))
	}
	// Its volume is still judged, against its own hours.
	engine, store := noiseEngine(t)
	own.Timestamp, own.BytesOut = time.Now().UTC(), 150*1024*1024
	engine.Evaluate(own)
	if got := anomaliesOfType(t, store, "AGENT_UPLOAD_VOLUME"); len(got) != 1 {
		t.Fatalf("150 MB in an hour from claude raised %d upload-volume alerts, want 1", len(got))
	}

	mismatch := flow(claude, "160.79.104.10", "api.anthropic.com")
	mismatch.AttributionStatus = pathMismatch
	spoofedSNI := flow(claude, "198.51.100.9", "")
	spoofedSNI.SNI = "api.anthropic.com"
	for name, ev := range map[string]storage.Event{
		"runtime to elsewhere":     flow(claude, "198.51.100.9", "paste.example.net"),
		"runtime with no name":     flow(claude, "198.51.100.9", ""),
		"other process to the API": flow("/usr/bin/curl", "160.79.104.10", "api.anthropic.com"),
		"unmatched path":           mismatch,
		"look-alike name":          flow(claude, "198.51.100.9", "anthropic.com.example.net"),
		// The SNI is the client's to choose: Anthropic's name on any other
		// address is not Anthropic's service.
		"own name, other address": flow(claude, "198.51.100.9", "api.anthropic.com"),
		"own SNI, other address":  spoofedSNI,
		"own name, next to range": flow(claude, "160.79.106.10", "api.anthropic.com"),
	} {
		t.Run(name, func(t *testing.T) {
			if got := spike(t, ev); len(got) != 1 {
				t.Fatalf("%s raised %d bandwidth alerts, want 1", name, len(got))
			}
		})
	}
}
