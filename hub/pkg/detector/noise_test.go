package detector

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The production fleet carried 2,549 open alerts, and the great majority of
// them were the detectors describing the platform rather than an intruder.
// These tests hold each of the specific causes shut.

func noiseEngine(t *testing.T) (*Engine, *storage.Store) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "noise.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Warm-up holds every behavioural finding for a day after an endpoint first
	// reports, which would mask everything these tests are checking.
	tuning := storage.DefaultDetectionTuning()
	tuning.WarmupHours = 0
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	return New(store, make(chan storage.Event, 64), func(string, string) error { return nil }), store
}

func anomaliesOfType(t *testing.T, store *storage.Store, kind string) []storage.AnomalyAlert {
	t.Helper()
	all, err := store.ListAnomalyAlerts("", 500)
	if err != nil {
		t.Fatalf("ListAnomalyAlerts failed: %v", err)
	}
	var out []storage.AnomalyAlert
	for _, a := range all {
		if a.AnomalyType == kind {
			out = append(out, a)
		}
	}
	return out
}

// The fleet's own Windows agent reported six CRITICAL "Bandwidth Exfiltration
// Spike" findings for its mTLS heartbeat to its own hub. The destination is on
// the LAN, and the process is the one this product installs.
func TestTheAgentsOwnHubTrafficIsNotExfiltration(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(2000)
		if i == 39 {
			bytes = 40 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "win-01", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "10.0.0.58", DstPort: 9443, BytesOut: bytes,
			ProcessPath: `C:\Program Files\Ominull\ominulld.exe`,
		})
	}
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Errorf("the agent reporting to its own hub raised %d exfiltration alert(s): %+v", len(got), got[0])
	}
}

// svchost.exe is the first name in the shipped quiet-process list and it still
// raised spikes, because the bandwidth detector never consulted the list.
func TestAQuietProcessDoesNotRaiseABandwidthSpike(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(1500)
		if i == 39 {
			bytes = 80 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "win-02", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "20.190.135.3", DstPort: 443, BytesOut: bytes,
			ProcessPath: `C:\Windows\System32\svchost.exe`,
		})
	}
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Errorf("a quiet process raised %d bandwidth alert(s)", len(got))
	}
}

// The detector still has to fire on a real one, against a real baseline, and
// say which it is.
func TestARealSpikeAgainstARealBaselineStillFires(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-01", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.9", DstPort: 443, BytesOut: 1000 + int64(i),
			ProcessPath: "/usr/bin/suspicious",
		})
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-01", Timestamp: now.Add(time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.9", DstPort: 443, BytesOut: 500 * 1024 * 1024,
		ProcessPath: "/usr/bin/suspicious",
	})
	got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE")
	if len(got) != 1 {
		t.Fatalf("expected one bandwidth alert for a genuine outlier, got %d", len(got))
	}
	if got[0].Severity != "CRITICAL" {
		t.Errorf("a transfer hundreds of deviations out is CRITICAL, got %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Details, "Samples:") {
		t.Errorf("the alert must carry the baseline it was judged against: %q", got[0].Details)
	}
}

// Chrome and the ChatGPT client holding Google's push channel open scored 1.00
// with zero payload variation. Google is in the shipped quiet-organisation
// list; the exemption applied only on port 443, and the push channel is 5228.
func TestAQuietOrganisationIsQuietOnEveryPort(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// 74.125.0.0/16 is Google. Thirty check-ins, thirty seconds apart, is the
	// shape that scored 1.00 on the fleet.
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-03", Timestamp: now.Add(time.Duration(i) * 30 * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "74.125.26.188", DstPort: 5228, BytesOut: 64,
			ProcessPath: "/opt/google/chrome/chrome",
		})
	}
	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 0 {
		t.Errorf("a keepalive to a trusted network owner raised %d beacon alert(s): %s", len(got), got[0].Title)
	}
}

// A metronomic conversation with a network nobody has vouched for is still the
// finding this detector exists for.
func TestBeaconingToAnUnvouchedNetworkStillFires(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-04", Timestamp: now.Add(time.Duration(i) * 30 * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.44", DstPort: 8443, BytesOut: 128,
			ProcessPath: "/tmp/implant",
		})
	}
	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) == 0 {
		t.Error("a metronomic conversation with an unattributed network raised nothing")
	}
}

// 1,584 of the fleet's alerts were first-seen destinations. The suppression key
// was the destination address, and a destination is first-seen exactly once, so
// the cooldown could never match and nothing bounded the rate.
func TestOneNewCounterpartyIsOneAlertNotOnePerEdgeAddress(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// Twelve different addresses inside one owner's network.
	for i := 0; i < 12; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-05", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "159.65.0." + itoa(i+1), DstPort: 443, BytesOut: 200,
			ProcessPath: "/usr/bin/firefox",
		})
	}
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) > 1 {
		t.Errorf("twelve edges of one network raised %d alerts; the counterparty is one relationship", len(got))
	}
	if len(got) == 1 && !strings.Contains(got[0].Title, "DigitalOcean") {
		t.Errorf("the alert must name the counterparty it is about, got %q", got[0].Title)
	}
}

// With the guessing removed, an address the table cannot attribute has no
// owner. The alert has to say that rather than print an empty pair of brackets.
func TestAnUnattributableDestinationSaysSoRatherThanNamingNothing(t *testing.T) {
	engine, store := noiseEngine(t)
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-06", Timestamp: time.Now().UTC(),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "203.0.113.77", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) != 1 {
		t.Fatalf("expected one alert for a genuinely new destination, got %d", len(got))
	}
	if strings.Contains(got[0].Details, "()") || strings.Contains(got[0].Description, "()") {
		t.Errorf("empty attribution was printed as if it were a value: %q / %q", got[0].Description, got[0].Details)
	}
	if !strings.Contains(got[0].Details, "not resolved") {
		t.Errorf("an unattributable address must be described as such: %q", got[0].Details)
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
