package detector

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestDetectorEngine(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_detector.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	eventsChan := make(chan storage.Event, 100)
	var isolatedCount int32

	engine := New(store, eventsChan, func(endpointID, reason string) error {
		atomic.AddInt32(&isolatedCount, 1)
		return nil
	})

	// 1. Test Blocked Threat Auto-Nullification
	engine.Evaluate(storage.Event{
		TenantID:   "default",
		EndpointID: "test-host-01",
		Timestamp:  time.Now().UTC(),
		Action:     "BLOCK",
		Direction:  "OUTBOUND",
		DstIP:      "185.220.101.5",
		DstPort:    443,
	})

	if atomic.LoadInt32(&isolatedCount) != 1 {
		t.Errorf("expected 1 auto-isolation trigger, got %d", isolatedCount)
	}

	// 2. Test Shell Egress Alert
	engine.Evaluate(storage.Event{
		TenantID:    "default",
		EndpointID:  "test-host-02",
		Timestamp:   time.Now().UTC(),
		Action:      "PERMIT",
		Direction:   "OUTBOUND",
		DstIP:       "203.0.113.50",
		DstPort:     4444,
		ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ProcessID:   1234,
	})

	// 3. Test Off-Hours Workstation Anomaly (02:00 UTC)
	offHoursTime := time.Date(2026, 8, 27, 2, 15, 0, 0, time.UTC)
	engine.Evaluate(storage.Event{
		TenantID:    "default",
		EndpointID:  "test-workstation-03",
		Timestamp:   offHoursTime,
		Action:      "PERMIT",
		Direction:   "OUTBOUND",
		DstIP:       "140.82.121.4",
		DstPort:     443,
		ProcessPath: "/usr/bin/curl",
		ProcessID:   5678,
	})

	// 4. Test Bandwidth Exfiltration Outlier (Z > 3.5)
	// Seed baseline
	for i := 0; i < 5; i++ {
		engine.Evaluate(storage.Event{
			TenantID:    "default",
			EndpointID:  "test-workstation-04",
			Timestamp:   time.Now().UTC(),
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			DstIP:       "104.244.42.1",
			DstPort:     443,
			BytesOut:    500 + int64(i*50),
			ProcessPath: "C:\\Program Files\\App\\app.exe",
			ProcessID:   999,
		})
	}
	// Massive burst (> 15MB)
	engine.Evaluate(storage.Event{
		TenantID:    "default",
		EndpointID:  "test-workstation-04",
		Timestamp:   time.Now().UTC(),
		Action:      "PERMIT",
		Direction:   "OUTBOUND",
		DstIP:       "104.244.42.1",
		DstPort:     443,
		BytesOut:    18 * 1024 * 1024,
		ProcessPath: "C:\\Program Files\\App\\app.exe",
		ProcessID:   999,
	})

	// 5. C2 beaconing. Twenty check-ins a minute apart, each carrying about the
	// same payload, over twenty minutes. Five connections two seconds apart used
	// to be enough, which is why a freshly installed workstation running nothing
	// but its own operating system reported command-and-control traffic.
	baseTime := time.Now().UTC().Add(-25 * time.Minute)
	for i := 0; i < 20; i++ {
		engine.Evaluate(storage.Event{
			TenantID:    "default",
			EndpointID:  "test-workstation-05",
			Timestamp:   baseTime.Add(time.Duration(i) * 60 * time.Second),
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			DstIP:       "194.26.29.114",
			DstPort:     8443,
			BytesOut:    int64(512 + i%3),
			ProcessPath: "/usr/bin/python3",
			ProcessID:   4444,
		})
	}

	// 6. Test Lateral Port Sweep / Internal Fan-Out (6 unique internal hosts in 10s)
	for i := 1; i <= 6; i++ {
		engine.Evaluate(storage.Event{
			TenantID:    "default",
			EndpointID:  "test-workstation-06",
			Timestamp:   time.Now().UTC(),
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			DstIP:       "10.0.0." + string(rune('0'+i)),
			DstPort:     445,
			ProcessPath: "C:\\Windows\\System32\\cmd.exe",
			ProcessID:   3333,
		})
	}

	// 7. Test Suspicious DGA Domain / High-Entropy SNI Anomaly
	engine.Evaluate(storage.Event{
		TenantID:    "default",
		EndpointID:  "test-workstation-07",
		Timestamp:   time.Now().UTC(),
		Action:      "PERMIT",
		Direction:   "OUTBOUND",
		DstIP:       "198.51.100.22",
		DstPort:     443,
		SNI:         "xj829vbnpqlmz019.xyz",
		ProcessPath: "/usr/bin/python3",
		ProcessID:   8888,
	})

	// Verify Anomaly Alerts created
	anomalies, err := store.ListAnomalyAlerts("default", 100)
	if err != nil {
		t.Fatalf("ListAnomalyAlerts failed: %v", err)
	}

	foundOffHours := false
	foundBwSpike := false
	foundBeacon := false
	foundLateral := false
	foundDGA := false
	for _, a := range anomalies {
		if a.AnomalyType == "OFF_HOURS_ACTIVITY" {
			foundOffHours = true
		}
		if a.AnomalyType == "BANDWIDTH_SPIKE" {
			foundBwSpike = true
		}
		if a.AnomalyType == "C2_BEACONING" {
			foundBeacon = true
		}
		if a.AnomalyType == "LATERAL_PORT_SWEEP" {
			foundLateral = true
		}
		if a.AnomalyType == "SUSPICIOUS_DGA_DOMAIN" {
			foundDGA = true
		}
	}

	if !foundOffHours {
		t.Errorf("expected OFF_HOURS_ACTIVITY anomaly to be recorded")
	}
	if !foundBwSpike {
		t.Errorf("expected BANDWIDTH_SPIKE anomaly to be recorded")
	}
	if !foundBeacon {
		t.Errorf("expected C2_BEACONING anomaly to be recorded")
	}
	if !foundLateral {
		t.Errorf("expected LATERAL_PORT_SWEEP anomaly to be recorded")
	}
	if !foundDGA {
		t.Errorf("expected SUSPICIOUS_DGA_DOMAIN anomaly to be recorded")
	}
}
