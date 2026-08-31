package scanner

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestScannerOUIVendorLookup(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"00:04:4B:11:22:33", "NVIDIA Corporation"},
		{"bc:24:11:95:31:52", "Proxmox QEMU / KVM Virtual"},
		{"f0-18-98-aa-bb-cc", "Apple, Inc."},
		{"b8:27:eb:12:34:56", "Raspberry Pi Foundation"},
		{"00:11:32:99:88:77", "Synology Inc."},
		{"99:99:99:11:22:33", "Generic / Unassigned Hardware"},
	}

	for _, tc := range tests {
		vendor := LookupVendor(tc.mac)
		if vendor != tc.expected {
			t.Errorf("LookupVendor(%s) = %s; want %s", tc.mac, vendor, tc.expected)
		}
	}
}

func TestDeviceSignatureMatching(t *testing.T) {
	// Test 1: NVIDIA Shield
	name, conf, cat := MatchDeviceSignature("00:04:4B:AA:BB:CC", 64, []int{8008, 8009, 8443}, []string{"Android/11", "NVIDIA Shield"}, 35.0, nil)
	if name != "NVIDIA Shield TV Pro (Android 11/12)" {
		t.Errorf("Expected NVIDIA Shield match, got: %s (confidence: %.2f)", name, conf)
	}
	if cat != "Smart TV / Media Streamer" {
		t.Errorf("Expected Smart TV category, got: %s", cat)
	}
	if conf < 0.80 {
		t.Errorf("Expected confidence >= 0.80, got: %.2f", conf)
	}

	// Test 2: Windows 11 on a Proxmox guest. The identification still lands,
	// but on the strength of the TTL, the ports and the banner - not the MAC.
	// BC:24:11 is Proxmox's prefix and every guest on that host wears it, so it
	// is not evidence of an operating system and no longer scores as any. The
	// confidence is lower than it used to be because it used to be wrong.
	wName, wConf, wCat := MatchDeviceSignature("BC:24:11:2E:DA:85", 128, []int{135, 445, 3389}, []string{"Microsoft Windows RPC", "MS-WBT-Server"}, 1.5, nil)
	if wName != "Windows 11 Enterprise / Pro (x86_64)" {
		t.Errorf("Expected Windows 11 match, got: %s (confidence: %.2f)", wName, wConf)
	}
	if wCat != "Workstation" {
		t.Errorf("Expected Workstation category, got: %s", wCat)
	}
	if wConf < 0.50 {
		t.Errorf("Expected confidence >= 0.50 from TTL, ports and banner alone, got: %.2f", wConf)
	}
	if p := VirtualPlatform("BC:24:11:2E:DA:85"); p == "" {
		t.Error("a Proxmox MAC was not recognised as a hypervisor address")
	}

	// Test 3: Synology NAS
	sName, sConf, sCat := MatchDeviceSignature("00:11:32:01:02:03", 64, []int{5000, 5001, 445}, []string{"Synology DSM 7.2 Web Server"}, 8.0, nil)
	if sName != "Synology DiskStation NAS (DSM 7.x)" {
		t.Errorf("Expected Synology NAS match, got: %s (confidence: %.2f)", sName, sConf)
	}
	if sCat != "Storage / NAS" {
		t.Errorf("Expected Storage category, got: %s", sCat)
	}
}

func TestTrainSignatureFeedbackLoop(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}
	defer store.Close()

	sc := New(store)
	testIP := "10.0.0.199"

	// Mock initial cached asset as generic
	sc.cachedAssets[testIP] = DiscoveredAsset{
		IP:         testIP,
		MAC:        "00:04:4B:99:88:77",
		Vendor:     "NVIDIA Corporation",
		Hostname:   "shield-living-room",
		OSGuess:    "Generic Network Asset",
		Category:   "Unclassified",
		Confidence: 0.35,
		OpenPorts: []PortInfo{
			{Port: 8008, Protocol: "TCP", Service: "Google Cast", Banner: "Chromecast CastV2 / Android 11", LatencyMs: 2.1},
			{Port: 5555, Protocol: "TCP", Service: "ADB", Banner: "Android Debug Bridge", LatencyMs: 1.8},
		},
		IsManaged:  false,
		RiskScore:  "MEDIUM",
		TTL:        64,
		AppDeltaMs: 42.0,
		LastSeen:   time.Now().UTC(),
	}

	// Train the engine with ground-truth override from analyst / user
	newSig, err := sc.TrainSignature(testIP, "NVIDIA Shield TV Pro (Living Room Edition)", "NVIDIA Corporation", "Smart TV / Media Streamer")
	if err != nil {
		t.Fatalf("TrainSignature failed: %v", err)
	}

	if newSig.Name != "NVIDIA Shield TV Pro (Living Room Edition)" {
		t.Errorf("Expected custom signature name, got: %s", newSig.Name)
	}

	// Verify updated asset in cache
	assets := sc.GetDiscoveredAssets()
	if len(assets) != 1 {
		t.Fatalf("Expected 1 asset in cache, got: %d", len(assets))
	}
	if assets[0].OSGuess != "NVIDIA Shield TV Pro (Living Room Edition)" {
		t.Errorf("Expected trained OS name in cache, got: %s", assets[0].OSGuess)
	}
	if assets[0].Confidence < 0.95 {
		t.Errorf("Expected confidence >= 0.95 after training, got: %.2f", assets[0].Confidence)
	}
}

func TestWeakpointEvaluation(t *testing.T) {
	ports := []PortInfo{
		{Port: 23, Protocol: "TCP", Service: "Telnet", RiskLevel: "CRITICAL"},
		{Port: 445, Protocol: "TCP", Service: "SMB", RiskLevel: "HIGH"},
		{Port: 6379, Protocol: "TCP", Service: "Redis", RiskLevel: "CRITICAL"},
	}

	weakpoints, riskScore := evaluateWeakpoints(ports, false, "Linux Server")
	if riskScore != "CRITICAL" {
		t.Errorf("Expected CRITICAL risk score, got: %s", riskScore)
	}
	if len(weakpoints) < 3 {
		t.Errorf("Expected at least 3 weakpoints identified, got: %d (%v)", len(weakpoints), weakpoints)
	}
}
