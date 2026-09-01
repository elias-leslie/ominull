package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ominull/hub/pkg/dns"
	"ominull/hub/pkg/storage"
)

func TestDNSAPIEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dns_api_test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	srv := New(store, "mock_admin_token", tmpDir, "http://localhost:9999", "1.8.1")
	dnsServer := dns.NewServer("127.0.0.1:53556", []string{"1.1.1.1:53"}, store, nil)
	srv.SetDNSServer(dnsServer)

	// 1. GET /api/v1/dns/status
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/status", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleDNSStatus).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleDNSStatus returned code %d, want 200: %s", w.Code, w.Body.String())
	}
	var status map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &status)
	if status["state"] != "starting" && status["state"] != "forwarding" && status["state"] != "protecting" {
		t.Errorf("unexpected status state: %v", status["state"])
	}

	// 2. PUT /api/v1/dns/policy (Add a block rule)
	ruleBody, _ := json.Marshal(map[string]string{
		"domain":  "phishing.bad.test",
		"action":  "BLOCK",
		"comment": "Test block rule",
	})
	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/dns/policy", bytes.NewReader(ruleBody))
	reqPut.Header.Set("X-API-Key", "mock_admin_token")
	wPut := httptest.NewRecorder()
	srv.authMiddleware(srv.handleDNSPolicy).ServeHTTP(wPut, reqPut)

	if wPut.Code != http.StatusOK {
		t.Fatalf("handleDNSPolicy PUT returned code %d, want 200: %s", wPut.Code, wPut.Body.String())
	}

	// 3. GET /api/v1/dns/policy (List rules)
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/dns/policy", nil)
	reqGet.Header.Set("X-API-Key", "mock_admin_token")
	wGet := httptest.NewRecorder()
	srv.authMiddleware(srv.handleDNSPolicy).ServeHTTP(wGet, reqGet)

	if wGet.Code != http.StatusOK {
		t.Fatalf("handleDNSPolicy GET returned code %d, want 200", wGet.Code)
	}
	var polRes map[string]interface{}
	_ = json.Unmarshal(wGet.Body.Bytes(), &polRes)
	if polRes["total"] != float64(1) {
		t.Fatalf("expected 1 policy rule, got %v", polRes["total"])
	}

	// 4. POST /api/v1/dns/policy/test (Test domain against policy)
	testBody, _ := json.Marshal(map[string]string{
		"domain": "sub.phishing.bad.test",
	})
	reqTest := httptest.NewRequest(http.MethodPost, "/api/v1/dns/policy/test", bytes.NewReader(testBody))
	reqTest.Header.Set("X-API-Key", "mock_admin_token")
	wTest := httptest.NewRecorder()
	srv.authMiddleware(srv.handleDNSPolicyTest).ServeHTTP(wTest, reqTest)

	if wTest.Code != http.StatusOK {
		t.Fatalf("handleDNSPolicyTest returned code %d, want 200", wTest.Code)
	}
	var testRes map[string]interface{}
	_ = json.Unmarshal(wTest.Body.Bytes(), &testRes)
	if testRes["verdict"] != "BLOCK" {
		t.Errorf("expected verdict BLOCK for sub.phishing.bad.test, got: %v", testRes["verdict"])
	}

	// 5. GET /api/v1/dns/events
	_ = store.RecordDNSEvent(storage.DNSEvent{
		ClientIP:     "127.0.0.1",
		Domain:       "phishing.bad.test",
		QType:        "A",
		Action:       "BLOCK",
		Status:       "BLOCKED",
		ResponseCode: "NOERROR",
		LatencyUs:    120,
	})
	reqEv := httptest.NewRequest(http.MethodGet, "/api/v1/dns/events", nil)
	reqEv.Header.Set("X-API-Key", "mock_admin_token")
	wEv := httptest.NewRecorder()
	srv.authMiddleware(srv.handleDNSEvents).ServeHTTP(wEv, reqEv)

	if wEv.Code != http.StatusOK {
		t.Fatalf("handleDNSEvents returned code %d, want 200", wEv.Code)
	}
	var evRes map[string]interface{}
	_ = json.Unmarshal(wEv.Body.Bytes(), &evRes)
	if evRes["total"] != float64(1) {
		t.Errorf("expected 1 DNS event, got %v", evRes["total"])
	}
}
