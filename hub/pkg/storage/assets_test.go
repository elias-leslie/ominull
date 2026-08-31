package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func claimFor(a Asset, field, source string) (AssetClaim, bool) {
	for _, c := range a.Claims {
		if c.Field == field && c.Source == source {
			return c, true
		}
	}
	return AssetClaim{}, false
}

func findAsset(assets []Asset, ip string) (Asset, bool) {
	for _, a := range assets {
		if a.IP == ip {
			return a, true
		}
	}
	return Asset{}, false
}

// A discovery must outlive the process that made it. Before the assets table
// the scanner kept results in an in-memory map, so a hub restart erased every
// host it had ever found.
func TestDiscoverySurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "assets.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seen := time.Now().UTC()
	err = store.UpsertAssetFromScan("10.0.4.55", "00:11:32:44:55:66", "Synology Inc.", "unmanaged-nas",
		"Synology DiskStation DSM 7.2", "Storage / NAS", "HIGH", 0.92,
		[]AssetPort{{Port: 445, Protocol: "tcp", Service: "smb", RiskLevel: "HIGH"}}, seen)
	if err != nil {
		t.Fatalf("UpsertAssetFromScan: %v", err)
	}
	store.Close()

	reopened, err := New(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	assets, err := reopened.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	a, ok := findAsset(assets, "10.0.4.55")
	if !ok {
		t.Fatalf("discovered asset did not survive the restart; got %d assets", len(assets))
	}
	if a.Vendor != "Synology Inc." || a.Category != "Storage / NAS" {
		t.Errorf("rehydrated asset lost its claims: vendor=%q category=%q", a.Vendor, a.Category)
	}
	if len(a.Ports) != 1 || a.Ports[0].Port != 445 {
		t.Errorf("rehydrated asset lost its ports: %+v", a.Ports)
	}
}

// Installing an agent on a host the scanner already found must enrich that
// row, not open a second record for the same machine.
func TestAgentEnrichesDiscoveredAsset(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	mac := "00:1A:2B:3C:4D:5E"

	if err := store.UpsertAssetFromScan("10.0.4.15", mac, "Dell Inc.", "", "Windows (generic)",
		"Workstation", "LOW", 0.62, nil, now); err != nil {
		t.Fatalf("scan upsert: %v", err)
	}

	before, _ := store.ListAssets("")
	if len(before) != 1 {
		t.Fatalf("expected one asset after the scan, got %d", len(before))
	}

	if err := store.UpsertEndpoint(Endpoint{
		ID: "win11-corp-exec", TenantID: "default", Hostname: "corp-win11-exec",
		OS: "Windows 11 Enterprise (x86_64)", IP: "10.0.4.15", MAC: mac,
		RoleTag: "workstation", DriverVersion: "1.1.0", Status: "online",
		LastSeenAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	after, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("agent install duplicated the host: %d assets", len(after))
	}
	a := after[0]
	if a.AgentEndpointID != "win11-corp-exec" {
		t.Errorf("asset did not adopt the endpoint: %q", a.AgentEndpointID)
	}
	if a.IdentityKind != "mac" {
		t.Errorf("identity was not promoted to the MAC: kind=%q value=%q", a.IdentityKind, a.IdentityValue)
	}

	// Merge is per field: the agent owns the OS it reports directly, the scan
	// still owns the vendor it read off the OUI, and the losing OS guess is
	// still on the record.
	if a.OS != "Windows 11 Enterprise (x86_64)" {
		t.Errorf("agent OS did not win the field: %q", a.OS)
	}
	if a.Vendor != "Dell Inc." {
		t.Errorf("scan vendor was lost when the agent arrived: %q", a.Vendor)
	}
	losing, ok := claimFor(a, FieldOS, SourceScan)
	if !ok {
		t.Fatal("the scan's OS claim was discarded; losing claims must stay visible")
	}
	if losing.Winner {
		t.Error("the scan's OS claim should have lost to the agent")
	}
}

// A correction outranks inference permanently, and withdrawing it hands the
// field back to the remaining evidence.
func TestOperatorCorrectionOutranksInference(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.UpsertInferredAsset("10.0.4.12", "domain-controller", 0.86,
		"5 agented endpoints, from lsass.exe, on 88/389/135; fan-in without any fan-out.", now); err != nil {
		t.Fatalf("UpsertInferredAsset: %v", err)
	}

	assets, _ := store.ListAssets("")
	a, ok := findAsset(assets, "10.0.4.12")
	if !ok {
		t.Fatal("inference did not create an asset for a host nothing else knows")
	}
	if a.Role != "domain-controller" || a.Rationale == "" {
		t.Fatalf("inferred role or rationale missing: role=%q rationale=%q", a.Role, a.Rationale)
	}

	if err := store.CorrectAsset(a.ID, FieldRole, "file-server", "operator rejected the flow inference"); err != nil {
		t.Fatalf("CorrectAsset: %v", err)
	}
	assets, _ = store.ListAssets("")
	a, _ = findAsset(assets, "10.0.4.12")
	if a.Role != "file-server" {
		t.Errorf("correction did not outrank the inference: %q", a.Role)
	}
	if inf, ok := claimFor(a, FieldRole, SourceInferred); !ok || inf.Winner {
		t.Error("the overruled inference must stay on the record, marked as losing")
	}

	if err := store.DropClaim(a.ID, FieldRole, SourceOperator); err != nil {
		t.Fatalf("DropClaim: %v", err)
	}
	assets, _ = store.ListAssets("")
	a, _ = findAsset(assets, "10.0.4.12")
	if a.Role != "domain-controller" {
		t.Errorf("withdrawing the correction did not return the field to the evidence: %q", a.Role)
	}
}

// An inference must never outrank ground truth, whichever order they arrive in.
func TestInferenceNeverOverwritesAgentTruth(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.UpsertEndpoint(Endpoint{
		ID: "linux-dmz-web-01", TenantID: "default", Hostname: "dmz-web-01", OS: "Debian 12",
		IP: "10.0.4.20", MAC: "00:50:56:A1:B2:C3", RoleTag: "web-server",
		DriverVersion: "1.1.0", Status: "online", LastSeenAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := store.UpsertInferredAsset("10.0.4.20", "file-server", 0.9, "445 fan-in.", now); err != nil {
		t.Fatalf("UpsertInferredAsset: %v", err)
	}

	assets, _ := store.ListAssets("")
	a, ok := findAsset(assets, "10.0.4.20")
	if !ok {
		t.Fatal("asset missing")
	}
	if a.Role != "web-server" {
		t.Errorf("inference at max confidence overwrote agent ground truth: %q", a.Role)
	}
	if _, ok := claimFor(a, FieldRole, SourceInferred); !ok {
		t.Error("the inference should still be recorded as a losing claim")
	}
}

// The graph must draw every known asset, including one that said nothing in
// the window. Absence is information on a security graph.
func TestTopologyDrawsQuietAssets(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.UpsertAssetFromScan("10.0.4.120", "50:02:91:AA:BB:CC", "Samsung Electronics",
		"lobby-display", "Tizen", "IoT / Display", "MEDIUM", 0.88, nil, now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("scan upsert: %v", err)
	}

	graph, err := store.GetTopologyGraph(24 * time.Hour)
	if err != nil {
		t.Fatalf("GetTopologyGraph: %v", err)
	}
	var found *TopologyNode
	for i := range graph.Nodes {
		if graph.Nodes[i].IP == "10.0.4.120" {
			found = &graph.Nodes[i]
		}
	}
	if found == nil {
		t.Fatal("a known asset that was quiet in the window was dropped from the graph")
	}
	if !found.Quiet {
		t.Error("a node with no traffic in the window should be marked quiet")
	}
	if found.Label != "lobby-display" {
		t.Errorf("node lost its identity: %q", found.Label)
	}
	if graph.Metrics.QuietNodesCount == 0 {
		t.Error("quiet nodes are not counted in the metrics")
	}
}

func TestAssetIdentityAndMACNormalisation(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e"},
		{"001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"},
		{"00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"},
		{"00:00:00:00:00:00", ""},
		{"ff:ff:ff:ff:ff:ff", ""},
		{"not-a-mac", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeMAC(c.in); got != c.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if kind, value := AssetIdentity("", "10.0.4.12", ""); kind != "ip" || value != "10.0.4.12|10.0.4.0/24" {
		t.Errorf("AssetIdentity without a MAC = %q/%q", kind, value)
	}
	if kind, _ := AssetIdentity("00:1A:2B:3C:4D:5E", "10.0.4.15", ""); kind != "mac" {
		t.Errorf("AssetIdentity with a MAC should key on it, got %q", kind)
	}
}

// A byte total is only worth as much as the share of flows it was taken from.
// Neither the Windows nor the macOS collector has a byte counter to read, so on
// a real fleet almost every flow contributes nothing to the sum; the graph has
// to carry that fraction or the console prints a volume that reads as a
// measurement of the whole link.
func TestTopologyReportsHowMuchTrafficCarriedByteCounts(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "measured.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	ev := func(bytesIn, bytesOut int64) Event {
		return Event{
			TenantID: "default", EndpointID: "ep-1", Timestamp: now,
			Layer: "TEST", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
			SrcIP: "10.0.4.15", DstIP: "10.0.4.10", SrcPort: 5000, DstPort: 389,
			BytesIn: bytesIn, BytesOut: bytesOut,
		}
	}
	batch := []Event{ev(600, 400)}
	for i := 0; i < 4; i++ {
		batch = append(batch, ev(0, 0))
	}
	if err := store.InsertEventsBatch(batch); err != nil {
		t.Fatalf("InsertEventsBatch: %v", err)
	}

	graph, err := store.GetTopologyGraph(time.Hour)
	if err != nil {
		t.Fatalf("GetTopologyGraph: %v", err)
	}
	if len(graph.Edges) != 1 {
		t.Fatalf("expected one edge, got %d", len(graph.Edges))
	}
	e := graph.Edges[0]
	if e.FlowCount != 5 {
		t.Errorf("FlowCount = %d, want 5", e.FlowCount)
	}
	if e.TotalBytes != 1000 {
		t.Errorf("TotalBytes = %d, want 1000", e.TotalBytes)
	}
	if e.MeasuredFlows != 1 {
		t.Errorf("MeasuredFlows = %d, want 1 - four of the five flows reported no byte count", e.MeasuredFlows)
	}
	if len(e.Ports) != 1 || e.Ports[0].MeasuredFlows != 1 {
		t.Errorf("the port breakdown lost the measured count: %+v", e.Ports)
	}
	if graph.Metrics.TotalFlowCount != 5 || graph.Metrics.MeasuredFlowCount != 1 {
		t.Errorf("metrics = %d measured of %d, want 1 of 5",
			graph.Metrics.MeasuredFlowCount, graph.Metrics.TotalFlowCount)
	}
}
