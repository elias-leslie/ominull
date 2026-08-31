package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

const perfSeedRows = 400000

// TestTelemetryPerformanceFeedback is an agent-runnable red-capable loop for
// the production telemetry seam. It keeps the database production-shaped,
// sends a real authenticated POST through the handler, and checks both the
// latency budget and persisted work. Set OMINULL_PERF_TEST=1 to run it so the
// ordinary unit suite stays fast.
func TestTelemetryPerformanceFeedback(t *testing.T) {
	if os.Getenv("OMINULL_PERF_TEST") != "1" {
		t.Skip("set OMINULL_PERF_TEST=1 to run the production-shaped feedback loop")
	}
	if testing.Short() {
		t.Skip("performance feedback loop is not a short test")
	}
	srv, store := newPerformanceServer(t)
	defer store.Close()

	for i := 0; i < 2; i++ {
		postPerformanceBatch(t, srv, performanceBatch(i))
	}

	const samples = 12
	latencies := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		started := time.Now()
		postPerformanceBatch(t, srv, performanceBatch(i+2))
		latencies = append(latencies, time.Since(started))
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[len(latencies)*95/100]
	if p95 > 100*time.Millisecond {
		t.Fatalf("telemetry POST p95=%s exceeds 100ms budget; samples=%s", p95, durations(latencies))
	}

	// The handler must not acknowledge a batch until all event rows are durable.
	// A second real request makes the expected count independent of any cached
	// analytics response.
	if got := countPerformanceEvents(store); got != 400000+14*64 {
		t.Fatalf("persisted event count=%d, want %d", got, 400000+14*64)
	}
	t.Logf("telemetry POST p95=%s p99=%s samples=%s", p95, latencies[len(latencies)-1], durations(latencies))
}

func newPerformanceServer(t *testing.T) (*Server, *storage.Store) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "performance.db"))
	if err != nil {
		t.Fatalf("opening performance store: %v", err)
	}
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "performance-endpoint", TenantID: "default", LocationID: "loc-home",
		Hostname: "performance-endpoint", OS: "Linux", IP: "10.0.4.20",
		DriverVersion: "1.7.16", UpdateCapability: "deb", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		store.Close()
		t.Fatalf("creating performance endpoint: %v", err)
	}
	seed := make([]storage.Event, 1000)
	for i := range seed {
		seed[i] = storage.Event{
			TenantID: "default", EndpointID: "performance-endpoint",
			Timestamp: time.Now().UTC().Add(-time.Duration(i%86400) * time.Second),
			Layer:     "linux-socket-v1", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
			SrcIP: "10.0.4.20", DstIP: "10.0.4.21", SrcPort: 4000, DstPort: 443,
			Country: "US", ProcessPath: "/usr/sbin/daemon",
		}
	}
	for rows := 0; rows < perfSeedRows; rows += len(seed) {
		if err := store.InsertEventsBatch(seed); err != nil {
			store.Close()
			t.Fatalf("seeding performance rows at %d: %v", rows, err)
		}
	}
	return New(store, "mock_admin_token", t.TempDir(), "http://10.0.0.57:9999", "1.7.16"), store
}

func performanceBatch(n int) []byte {
	events := make([]storage.Event, 64)
	for i := range events {
		events[i] = storage.Event{
			Layer: "linux-socket-v1", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
			SrcIP: "10.0.4.20", DstIP: "10.0.4.21", SrcPort: uint16(4000 + i), DstPort: 443,
			Country: "US", ProcessPath: "/usr/sbin/daemon", ProcessID: uint32(n*64 + i),
			Timestamp: time.Now().UTC(),
		}
	}
	body, _ := json.Marshal(TelemetryBatchMessage{
		Type: "telemetry", EndpointID: "performance-endpoint", TenantID: "default",
		LocationID: "loc-home", Role: "workstation", Hostname: "performance-endpoint",
		OS: "Linux", IP: "10.0.4.20", DriverVersion: "1.7.16", UpdateCapability: "deb",
		Events: events,
	})
	return body
}

func postPerformanceBatch(t *testing.T, srv *Server, body []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleEvents)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("telemetry POST status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func countPerformanceEvents(store *storage.Store) int64 {
	rows, err := store.ListEvents("default", 1000)
	if err != nil {
		return -1
	}
	// ListEvents is intentionally capped. Analytics reports the durable total,
	// and its cache is cold in this feedback loop.
	summary, err := store.GetAnalyticsSummary("default")
	if err != nil {
		return int64(len(rows))
	}
	return summary.TotalEvents
}

func durations(v []time.Duration) []string {
	out := make([]string, len(v))
	for i, d := range v {
		out[i] = d.String()
	}
	return out
}
