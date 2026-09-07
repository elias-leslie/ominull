package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestAuthenticatedTelemetryCanonicalizesBeforeNaming(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "address-test", TenantID: "default", IP: "10.0.4.2", Status: "online"}); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.IssueDeviceCredential("address-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordDNSResolutions([]storage.DNSResolution{{IP: "2001:db8::9", Domain: "service.example.test", At: time.Now().UTC()}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(`{"type":"telemetry","endpoint_id":"address-test","ip":"::ffff:10.0.4.2","events":[{"src_ip":"::ffff:10.0.4.2","dst_ip":"2001:0DB8:0:0:0:0:0:9","protocol":6,"dst_port":443}]}`))
	r.Header.Set(deviceCredentialHeader, key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
	events, err := store.QueryEvents("default", "address-test", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want one accepted row, got %d", len(events))
	}
	ev := events[0]
	if ev.SrcIP != "10.0.4.2" || ev.DstIP != "2001:db8::9" || ev.Domain != "service.example.test" {
		t.Errorf("canonical naming failed: %s -> %s (%s)", ev.SrcIP, ev.DstIP, ev.Domain)
	}
	ep, err := store.GetEndpoint("address-test")
	if err != nil {
		t.Fatal(err)
	}
	if ep == nil || ep.IP != "10.0.4.2" {
		t.Errorf("noncanonical endpoint: %+v", ep)
	}
}

func TestOperatorWritesPreserveIPv6AuditPeer(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertAssetFromScan("10.0.4.2", "", "", "", "", "", "", 0, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body, action string }{
		{"/api/v1/exclusions", `{"name":"test exclusion","process_path":"/test/tool"}`, "CREATE_EXCLUSION"},
		{"/api/v1/assets/correct", `{"ip":"10.0.4.2","field":"hostname","value":"test-host","reason":"test"}`, "CORRECT_ASSET"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			r.RemoteAddr = "[2001:db8::2]:45678"
			r.Header.Set("X-API-Key", "mock_admin_token")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code < 200 || w.Code >= 300 {
				t.Fatalf("write: %d %s", w.Code, w.Body.String())
			}
			entries, err := store.ListAuditLogs("", 100)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, entry := range entries {
				if entry.Action == tc.action {
					found = true
					if entry.IPAddress != "2001:db8::2" {
						t.Errorf("audit peer = %q", entry.IPAddress)
					}
				}
			}
			if !found {
				t.Fatal("audit row missing")
			}
		})
	}
}

func TestMalformedTelemetryAddressesRejectBeforeAnyWrite(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "invalid-address-test", TenantID: "default", IP: "10.0.4.2"}); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.IssueDeviceCredential("invalid-address-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"endpoint_id":"invalid-address-test","ip":"not-an-address","events":[]}`,
		`{"endpoint_id":"invalid-address-test","ip":"10.0.4.3","events":[{"src_ip":"10.0.4.3","dst_ip":"2001:db8::2"},{"src_ip":"10.0.4.3","dst_ip":"2001::db8::2"}]}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(body))
		r.Header.Set(deviceCredentialHeader, key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("invalid address status=%d", w.Code)
		}
	}
	events, err := store.QueryEvents("default", "invalid-address-test", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("partially persisted invalid batch: %d", len(events))
	}
	ep, err := store.GetEndpoint("invalid-address-test")
	if err != nil {
		t.Fatal(err)
	}
	if ep.IP != "10.0.4.2" {
		t.Errorf("invalid batch changed endpoint IP: %s", ep.IP)
	}
}
