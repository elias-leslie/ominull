package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func postUpload(s *Server, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func uploadBatch(endpoint string, dropped int, at time.Time, port int) []byte {
	ts := at.Format(time.RFC3339Nano)
	return []byte(fmt.Sprintf(`{"type":"telemetry","endpoint_id":%q,"ip":"10.0.4.20","collector_health":[{"name":"linux-bpf-udp","state":"active","dropped":%d,"queued":0}],"events":[{"timestamp":%q,"protocol":17,"src_ip":"10.0.4.20","dst_ip":"10.0.4.21","src_port":40000,"dst_port":%d,"process_id":321,"bytes_out":10,"observation":{"source":"linux-bpf-udp","byte_basis":"udp_payload","timing":"socket_io","count":1,"first_at":%q,"last_at":%q}}]}`,
		endpoint, dropped, ts, port, ts, ts))
}

// A gzip batch is stored like a plain one, the reply tells the agent gzip is
// taken, and the upload ledger counts wire and decoded bytes separately.
func TestTelemetryGzipBodyIsDecodedAndCounted(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	at := time.Now().UTC().Add(-time.Second)

	plain := uploadBatch("gz-endpoint", 0, at, 9000)
	w := postUpload(s, plain, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"accept_encoding":"gzip"`) {
		t.Fatalf("plain batch: %d %s", w.Code, w.Body.String())
	}
	packed := gzipBytes(t, uploadBatch("gz-endpoint", 0, at, 9001))
	w = postUpload(s, packed, map[string]string{"Content-Encoding": "gzip"})
	if w.Code != 200 {
		t.Fatalf("gzip batch: %d %s", w.Code, w.Body.String())
	}
	events, err := db.ListEvents("default", 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events after gzip batch: %d %v", len(events), err)
	}

	uploads, err := db.UploadsSince(time.Now().UTC().Format("2006-01-02"))
	if err != nil || len(uploads) != 1 {
		t.Fatalf("uploads: %+v %v", uploads, err)
	}
	u := uploads[0]
	wantWire := int64(len(plain) + len(packed))
	wantRaw := int64(len(plain) + len(uploadBatch("gz-endpoint", 0, at, 9001)))
	if u.EndpointID != "gz-endpoint" || u.Batches != 2 || u.GzipBatches != 1 || u.WireBytes != wantWire || u.RawBytes != wantRaw {
		t.Errorf("upload ledger = %+v, want wire %d raw %d", u, wantWire, wantRaw)
	}
}

// Unknown encodings and bodies that expand past the limit are refused with a
// status that says so, never parsed as something else.
func TestTelemetryBodyEncodingRefusals(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()

	w := postUpload(s, []byte("x"), map[string]string{"Content-Encoding": "br"})
	if w.Code != 415 {
		t.Errorf("brotli body = %d, want 415", w.Code)
	}
	w = postUpload(s, []byte("not gzip"), map[string]string{"Content-Encoding": "gzip"})
	if w.Code != 400 {
		t.Errorf("corrupt gzip = %d, want 400", w.Code)
	}
	bomb := gzipBytes(t, bytes.Repeat([]byte(" "), maxTelemetryDecoded+1))
	w = postUpload(s, bomb, map[string]string{"Content-Encoding": "gzip"})
	if w.Code != 413 {
		t.Errorf("oversized decoded body = %d, want 413", w.Code)
	}
	if events, _ := db.ListEvents("default", 10); len(events) != 0 {
		t.Errorf("refused bodies stored %d events", len(events))
	}
}

// A replayed batch adds its events but leaves the endpoint as the live
// heartbeat left it: its older collector counters would otherwise read as a
// counter reset and mark the live window lost.
func TestTelemetryReplayStoresEventsOnly(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	now := time.Now().UTC()

	if w := postUpload(s, uploadBatch("replay-endpoint", 7, now.Add(-time.Second), 9000), nil); w.Code != 200 {
		t.Fatalf("live batch: %d %s", w.Code, w.Body.String())
	}
	before, err := db.GetEndpoint("replay-endpoint")
	if err != nil || before == nil {
		t.Fatal(err)
	}
	old := gzipBytes(t, uploadBatch("replay-endpoint", 2, now.Add(-2*time.Minute), 9001))
	w := postUpload(s, old, map[string]string{"Content-Encoding": "gzip", telemetryReplayHeader: "1"})
	if w.Code != 200 {
		t.Fatalf("replayed batch: %d %s", w.Code, w.Body.String())
	}
	var reply map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &reply)
	if reply["replayed"] != float64(1) || reply["is_isolated"] != nil {
		t.Errorf("replay reply carried control state or no count: %s", w.Body.String())
	}
	after, err := db.GetEndpoint("replay-endpoint")
	if err != nil || after == nil {
		t.Fatal(err)
	}
	if len(after.CollectorHealth) != 1 || after.CollectorHealth[0].Dropped != 7 {
		t.Errorf("replay moved collector health: %+v", after.CollectorHealth)
	}
	events, err := db.ListEvents("default", 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events after replay: %d %v", len(events), err)
	}
	for _, ev := range events {
		// The live batch's own loss (7, first report) stays; the replayed
		// event must not pick up a loss from its older counters.
		if ev.DstPort == 9001 && ev.Observation.Lost != 0 {
			t.Errorf("event marked lost after replay: %+v", ev.Observation)
		}
	}
	uploads, _ := db.UploadsSince(now.Format("2006-01-02"))
	if len(uploads) != 1 || uploads[0].ReplayedBatches != 1 || uploads[0].Batches != 2 {
		t.Errorf("replay not counted: %+v", uploads)
	}
}

// A batch replayed after its reply was lost is stored once; one replayed
// while its first send is still being written is turned back to be kept.
func TestTelemetryReplayOfStoredBatchIsNotStoredTwice(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	at := time.Now().UTC().Add(-time.Second)
	withID := func(b []byte, id string) []byte {
		return bytes.Replace(b, []byte(`{"type":"telemetry",`), []byte(`{"type":"telemetry","batch_id":"`+id+`",`), 1)
	}
	first := withID(uploadBatch("dedup-endpoint", 0, at, 9000), "a1b2-1")
	if w := postUpload(s, first, nil); w.Code != 200 {
		t.Fatalf("live batch: %d %s", w.Code, w.Body.String())
	}
	w := postUpload(s, gzipBytes(t, first), map[string]string{"Content-Encoding": "gzip", telemetryReplayHeader: "1"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"duplicate":true`) {
		t.Fatalf("replay of a stored batch: %d %s", w.Code, w.Body.String())
	}
	if events, _ := db.ListEvents("default", 10); len(events) != 1 {
		t.Errorf("stored %d events, want 1", len(events))
	}

	if st := s.batches.begin("dedup-endpoint", "a1b2-2"); st != batchNew {
		t.Fatalf("new id = %v", st)
	}
	w = postUpload(s, withID(uploadBatch("dedup-endpoint", 0, at, 9001), "a1b2-2"), map[string]string{telemetryReplayHeader: "1"})
	if w.Code != 503 {
		t.Errorf("replay while the first send is in flight = %d, want 503", w.Code)
	}
	s.batches.finish("dedup-endpoint", "a1b2-2", false)
	w = postUpload(s, withID(uploadBatch("dedup-endpoint", 0, at, 9001), "a1b2-2"), map[string]string{telemetryReplayHeader: "1"})
	if w.Code != 200 || strings.Contains(w.Body.String(), "duplicate") {
		t.Errorf("replay after a failed first send = %d %s", w.Code, w.Body.String())
	}
	if events, _ := db.ListEvents("default", 10); len(events) != 2 {
		t.Errorf("stored %d events, want 2", len(events))
	}
}
