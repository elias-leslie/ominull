package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestSanitizeCommandRedactsSecretsAndShortens(t *testing.T) {
	for in, want := range map[string]string{
		"curl -H 'Authorization: Bearer abc.def' https://x":                  "curl -H 'Authorization: ***' https://x",
		"mysql --password=hunter2 -u root":                                   "mysql --password=*** -u root",
		"tool --api-key sk_live_1 run":                                       "tool --api-key *** run",
		"git clone https://user:s3cret@example.test/r.git":                   "git clone https://user:***@example.test/r.git",
		"ssh -o BatchMode=yes host qm status 112":                            "ssh -o BatchMode=yes host qm status 112",
		"echo " + strings.Repeat("A1b2", 10):                                 "echo ***",
		"env TOKEN=abc123 ./run":                                             "env TOKEN=*** ./run",
		"ssh -i /etc/nightshift/router-status.key root@10.0.0.1 status":      "ssh -i /etc/nightshift/router-status.key root@10.0.0.1 status",
		"ssh 10.0.0.234 ~/bin/st-browser-session stop c432df4a9ddc24b5a665":  "ssh 10.0.0.234 ~/bin/st-browser-session stop c432df4a9ddc24b5a665",
		"ssh 10.0.0.9 ~/.local/share/st-browser/bin/st-browser-session stop": "ssh 10.0.0.9 ~/.local/share/st-browser/bin/st-browser-session stop",
		"ls -la /etc/example-response-authority/":                            "ls -la /etc/example-response-authority/",
		"sha256sum 31430165113e51a046f3b9fa2a60ec98e073cc6c0411a081b3b1":     "sha256sum ***",
		"curl -u admin -H 'X-Api-Key: k1' --token tok1 -d password=p1":       "curl -u admin -H 'X-Api-Key: ***' --token *** -d password=***",
		"app --auth-token=\"a b\" ok":                                        "app --auth-token=*** ok",
	} {
		if got := sanitizeCommand(in); got != want {
			t.Errorf("sanitizeCommand(%q) = %q, want %q", in, got, want)
		}
	}
	long := sanitizeCommand(strings.Repeat("word ", 60))
	if n := len([]rune(long)); n > feedCommandMax || !strings.HasSuffix(long, "…") {
		t.Fatalf("long command not shortened: %d %q", n, long)
	}
}

// The v4 summary names each new paging alert in plain words with its facts;
// its severity is the worst alert's, and v1 keeps the counts-only summary.
func TestNightshiftFeedV4DescribesEachAlert(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	sweep, _ := json.Marshal(map[string]any{
		"command_line":  "ssh -o BatchMode=yes 10.0.0.9 uptime --token=abcdef",
		"sweep_targets": []map[string]any{{"ip": "10.0.0.1", "ports": []int{22}}, {"ip": "10.0.0.39", "ports": []int{22}}, {"ip": "10.0.0.9", "ports": []int{22}}},
		"admin_rule":    "10.0.0.9 was reached on port 23",
	})
	tuning := store.GetDetectionTuning()
	tuning.AdminFanoutSources = []string{"ws-01"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	alerts := []storage.AnomalyAlert{
		{ID: "a-sweep", EndpointID: "ws-01", Hostname: "ws-01", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "HIGH",
			Title: "Lateral Port Sweep / Internal Fan-Out (3 Hosts)", ProcessPath: "/usr/bin/ssh", DstIP: "10.0.0.9", DstPort: 22,
			Evidence: string(sweep), Timestamp: now.Add(-time.Hour)},
		{ID: "a-silent", EndpointID: "srv-01", Hostname: "srv-01", AnomalyType: "ENDPOINT_SILENT", Severity: "MEDIUM",
			Title: "Agent stopped reporting on srv-01", Timestamp: now.Add(-2 * time.Hour)},
	}
	for i := 0; i < 6; i++ {
		alerts = append(alerts, storage.AnomalyAlert{ID: fmt.Sprintf("a-bw-%d", i), EndpointID: "srv-01", Hostname: "srv-01",
			AnomalyType: "BANDWIDTH_SPIKE", Severity: "LOW", Title: "Bandwidth", ProcessPath: "/usr/bin/rclone",
			DstIP: "198.51.100.7", DstPort: 443, Timestamp: now.Add(-3 * time.Hour)})
	}
	for _, a := range alerts {
		a.TenantID, a.Description = "t-01", "d"
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	key := issueFeedKey(t, srv)

	summary := func(contract string) (int, string, map[string]any) {
		w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings"+contract, key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				return f.SeverityID, f.Message, f.Unmapped
			}
		}
		t.Fatal("no summary finding")
		return 0, "", nil
	}

	sev, msg, um := summary("?contract=v4")
	if sev != ocsfSevHigh {
		t.Errorf("severity = %d, want the worst alert's (HIGH = %d)", sev, ocsfSevHigh)
	}
	want := "ssh on ws-01 connected to 3 hosts on the local network within a minute, all on port 22 (+7 more)"
	if msg != want {
		t.Errorf("message = %q\nwant      %q", msg, want)
	}
	raw, _ := json.Marshal(um["alerts"])
	var got []feedAlert
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != feedAlertMax || um["more"] != float64(8-feedAlertMax) {
		t.Fatalf("listed %d alerts, more=%v", len(got), um["more"])
	}
	first := got[0]
	if first.ID != "a-sweep" || first.Process != "ssh" || strings.Contains(first.Command, "abcdef") ||
		first.Destinations != "10.0.0.1:22, 10.0.0.39:22, 10.0.0.9:22" ||
		!strings.Contains(first.Cause, "10.0.0.9 was reached on port 23") || first.Expected != "" || first.At == "" {
		t.Fatalf("sweep alert = %+v", first)
	}
	if got[1].What != "The OmniNull agent on srv-01 stopped reporting" {
		t.Errorf("silent alert = %q", got[1].What)
	}
	indented, _ := json.MarshalIndent(um, "", "  ")
	if len(indented) > 4096 {
		t.Errorf("summary details are %d bytes, over Nightshift's 4 KiB cap", len(indented))
	}

	sev, msg, um = summary("")
	if sev != ocsfSevInformational || !strings.Contains(msg, "8 new open anomalies") || um["alerts"] != nil {
		t.Errorf("v1 summary changed: %d %q %v", sev, msg, um["alerts"])
	}
}

// An alert the hub explains as the owner's own ssh is listed for the record
// and does not page; an alert that needs the owner still does, listed first.
func TestNightshiftFeedOwnAutomationDoesNotPage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	tuning := store.GetDetectionTuning()
	tuning.AdminFanoutSources = []string{"ws-01"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	own, _ := json.Marshal(map[string]any{
		"sweep_targets": []map[string]any{{"ip": "10.0.0.1", "ports": []int{22}}, {"ip": "10.0.0.39", "ports": []int{22}}, {"ip": "10.0.0.77", "ports": []int{22}}},
		"admin_rule":    "10.0.0.77 is not an inventoried host",
	})
	add := func(a storage.AnomalyAlert) {
		a.TenantID, a.Description, a.Hostname = "t-01", "d", a.EndpointID
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	add(storage.AnomalyAlert{ID: "a-own", EndpointID: "ws-01", AnomalyType: "LATERAL_PORT_SWEEP", Severity: "CRITICAL",
		Title: "Lateral Port Sweep / Internal Fan-Out (3 Hosts)", ProcessPath: "/usr/bin/ssh", Evidence: string(own), Timestamp: now.Add(-time.Minute)})
	key := issueFeedKey(t, srv)
	type sum struct {
		SeverityID int
		Message    string
		Unmapped   map[string]any
	}
	read := func() sum {
		w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v4", key)
		var doc feedDoc
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.anomalies.summary" {
				return sum{f.SeverityID, f.Message, f.Unmapped}
			}
		}
		t.Fatal("no summary finding")
		return sum{}
	}
	listed := func(f sum) []feedAlert {
		raw, _ := json.Marshal(f.Unmapped["alerts"])
		var got []feedAlert
		_ = json.Unmarshal(raw, &got)
		return got
	}
	f := read()
	got := listed(f)
	if f.SeverityID != ocsfSevInformational || len(got) != 1 || got[0].Expected != "own automation" || got[0].Cause == "" {
		t.Fatalf("own ssh paged or was not explained: sev=%d %+v", f.SeverityID, got)
	}

	add(storage.AnomalyAlert{ID: "a-real", EndpointID: "srv-01", AnomalyType: "THREAT_INTEL_MATCH", Severity: "HIGH",
		Title: "Threat intel", DstIP: "203.0.113.9", DstPort: 443, Timestamp: now.Add(-time.Hour)})
	f = read()
	got = listed(f)
	if f.SeverityID != ocsfSevHigh || len(got) != 2 || got[0].ID != "a-real" || got[1].ID != "a-own" ||
		!strings.HasPrefix(f.Message, "srv-01 contacted 203.0.113.9") {
		t.Fatalf("real alert not paging first: sev=%d msg=%q %+v", f.SeverityID, f.Message, got)
	}
}
