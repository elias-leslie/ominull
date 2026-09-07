package detector

import (
	"encoding/json"
	"ominull/hub/pkg/storage"
	"testing"
	"time"
)

func TestCoalescedOrLossyObservationsDoNotInventPacketCadence(t *testing.T) {
	for _, tc := range []struct {
		name, timing string
		count, lost  uint64
		incomplete   bool
	}{
		{"aggregate", "socket_io", 3, 0, false}, {"counter", "counter_sample", 1, 0, false}, {"loss", "socket_io", 1, 1, false}, {"buffer loss", "socket_io", 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, db := noiseEngine(t)
			base := time.Now().UTC().Add(-time.Hour)
			for i := 0; i < 40; i++ {
				at := base.Add(time.Duration(i) * time.Minute)
				first := at
				engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "observed-host", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND", Protocol: 17, DstIP: "198.51.100.77", DstPort: 443, BytesOut: 1024, ProcessPath: "/usr/bin/observer-demo", Observation: storage.FlowObservation{Source: "linux-bpf-udp", ByteBasis: "udp_payload", Timing: tc.timing, Count: tc.count, Lost: tc.lost, Incomplete: tc.incomplete, FirstAt: &first, LastAt: &at}})
			}
			if found := anomaliesOfType(t, db, "C2_BEACONING"); len(found) != 0 {
				t.Fatalf("%s observations invented cadence: %s", tc.name, found[0].Title)
			}
		})
	}
}

func TestBeaconWindowsDoNotMixTransportProtocols(t *testing.T) {
	engine, db := noiseEngine(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 22; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		protocol := uint8(6)
		if i%2 != 0 {
			protocol = 17
		}
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "protocol-host", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND", Protocol: protocol, DstIP: "198.51.100.77", DstPort: 443, BytesOut: 1024, ProcessPath: "/usr/bin/observer-demo"})
	}
	if found := anomaliesOfType(t, db, "C2_BEACONING"); len(found) != 0 {
		t.Fatalf("two subthreshold protocol windows merged into %s", found[0].Title)
	}
}

func TestObservedUDPBeaconRetainsProtocolAndByteBasisEvidence(t *testing.T) {
	engine, db := noiseEngine(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "udp-beacon", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND", Protocol: 17, DstIP: "198.51.100.77", DstPort: 443, BytesOut: 1024, ProcessPath: "/usr/bin/observer-demo", Observation: storage.FlowObservation{Source: "linux-bpf-udp", ByteBasis: "udp_payload", Timing: "socket_io", Count: 1, FirstAt: &at, LastAt: &at}})
	}
	found := anomaliesOfType(t, db, "C2_BEACONING")
	if len(found) == 0 {
		t.Fatal("real UDP cadence was missed")
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(found[0].Evidence), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["protocol"] != float64(17) || evidence["observation"] == nil {
		t.Fatalf("finding lost transport evidence: %v", evidence)
	}
}

func TestCollectorLossInvalidatesEarlierCadenceWindow(t *testing.T) {
	engine, db := noiseEngine(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		ev := storage.Event{TenantID: "default", EndpointID: "loss-window", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND", Protocol: 17, DstIP: "198.51.100.77", DstPort: 443, BytesOut: 1024, ProcessPath: "/usr/bin/observer-demo", Observation: storage.FlowObservation{Source: "linux-bpf-udp", ByteBasis: "udp_payload", Timing: "socket_io", Count: 1, FirstAt: &at, LastAt: &at}}
		if i%8 == 0 {
			lossy := ev
			lossy.Observation.Lost = 1
			engine.Evaluate(lossy)
		}
		engine.Evaluate(ev)
	}
	if found := anomaliesOfType(t, db, "C2_BEACONING"); len(found) != 0 {
		t.Fatalf("cadence survived known gaps: %s", found[0].Title)
	}
}

func TestBandwidthUsesObservedIntervalRatherThanBatchSize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		duration time.Duration
		want     bool
	}{{"deferred", time.Hour, false}, {"burst", time.Second, true}} {
		t.Run(tc.name, func(t *testing.T) {
			engine, db := noiseEngine(t)
			at := time.Now().UTC()
			first := at.Add(-tc.duration)
			engine.Evaluate(storage.Event{TenantID: "default", EndpointID: "rate-host", Timestamp: at, Action: "PERMIT", Direction: "OUTBOUND", Protocol: 17, DstIP: "198.51.100.77", DstPort: 443, BytesOut: 20 * 1024 * 1024, ProcessPath: "/usr/bin/observer-demo", Observation: storage.FlowObservation{Source: "linux-bpf-udp", ByteBasis: "udp_payload", Timing: "socket_io", Count: 1000, FirstAt: &first, LastAt: &at}})
			found := anomaliesOfType(t, db, "BANDWIDTH_SPIKE")
			if (len(found) > 0) != tc.want {
				t.Fatalf("%s interval produced %d bandwidth findings", tc.duration, len(found))
			}
		})
	}
}
