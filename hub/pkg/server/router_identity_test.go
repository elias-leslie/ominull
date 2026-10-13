package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func issueRouterIdentity(t *testing.T, srv *Server, key, id string) (*httptest.ResponseRecorder, *x509.Certificate) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/router/identity", strings.NewReader(`{"router_id":"`+id+`"}`))
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return w, nil
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["key_pem"] == "" || body["ca_pem"] == "" {
		t.Fatalf("identity response lacks key or CA: %v", body)
	}
	block, _ := pem.Decode([]byte(body["cert_pem"]))
	if block == nil {
		t.Fatal("no certificate in identity response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return w, cert
}

// postAsRouter sends telemetry over a TLS connection whose verified client
// certificate is leaf, with no API key.
func postAsRouter(srv *Server, leaf *x509.Certificate, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/router/telemetry", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Router-ID", "spoofed")
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestRouterIdentityAuthenticatesOnlyItsOwnRouterAndIsRevokedOnReissue(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	if w, _ := issueRouterIdentity(t, srv, "mock_tenant_token", "gw"); w.Code != http.StatusForbidden {
		t.Fatalf("tenant key issued a router identity: %d", w.Code)
	}
	_, first := issueRouterIdentity(t, srv, "mock_admin_token", "gw")
	if first == nil || first.Subject.CommonName != "router:gw" {
		t.Fatalf("unexpected router certificate: %+v", first)
	}

	if w := postAsRouter(srv, first, `{"router_id":"gw","leases":[]}`); w.Code != http.StatusOK {
		t.Fatalf("registered router certificate refused: %d %s", w.Code, w.Body.String())
	}
	if w := postAsRouter(srv, first, `{"router_id":"other","leases":[]}`); w.Code != http.StatusForbidden {
		t.Fatalf("router certificate reported as another router: %d", w.Code)
	}

	_, second := issueRouterIdentity(t, srv, "mock_admin_token", "gw")
	if w := postAsRouter(srv, first, `{"router_id":"gw","leases":[]}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked router certificate still accepted: %d", w.Code)
	}
	if w := postAsRouter(srv, second, `{"router_id":"gw","leases":[]}`); w.Code != http.StatusOK {
		t.Fatalf("reissued router certificate refused: %d", w.Code)
	}

	// A router certificate is not a credential for anything else.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/flows", nil)
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{second}}}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("router certificate opened another route: %d", w.Code)
	}
}

func TestRouterClientCountersBecomeDailyDeltas(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	poll := func(rx, tx int) {
		t.Helper()
		body := `{"router_id":"gw","gl_clients":{"clients":{"aa:bb:cc:dd:ee:01":{"mac":"AA:BB:CC:DD:EE:01","ip":"10.0.0.36","name":"laptop","online":true,"total_rx":` +
			strconv.Itoa(rx) + `,"total_tx":` + strconv.Itoa(tx) + `,"iface":"5G"}}}}`
		if w := postTelemetry(t, srv, body); w.Code != http.StatusOK {
			t.Fatalf("poll refused: %d %s", w.Code, w.Body.String())
		}
	}
	poll(1000, 500) // first sighting: lifetime totals are not today's traffic
	poll(1600, 700) // +600 / +200
	poll(100, 50)   // counter reset: +100 / +50
	days, err := store.ListRouterClientDays(time.Now().UTC(), "", 0)
	if err != nil || len(days) != 1 {
		t.Fatalf("daily rows = %v, %v", days, err)
	}
	if days[0].RxBytes != 700 || days[0].TxBytes != 250 || days[0].MAC != "aa:bb:cc:dd:ee:01" || days[0].Name != "laptop" {
		t.Fatalf("daily delta = %+v, want rx 700 tx 250", days[0])
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/clients?days=1", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"rx_bytes":700`) {
		t.Fatalf("clients API = %d %s", w.Code, w.Body.String())
	}
}

func TestRouterDNSIsAggregatedPerClientPerDay(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	body := `{"router_id":"gw","dns":[
		{"client_ip":"10.0.0.36","domain":"Example.COM","qtype":"A","at":"` + at + `"},
		{"client_ip":"10.0.0.36","domain":"example.com","qtype":"AAAA","at":"` + at + `"},
		{"client_ip":"10.0.0.37","domain":"example.com","qtype":"A","at":"` + at + `"}]}`
	if w := postTelemetry(t, srv, body); w.Code != http.StatusOK {
		t.Fatalf("poll refused: %d", w.Code)
	}
	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if n, _ := store.DNSDomainQueries(day, "gw", "10.0.0.36", "example.com"); n != 2 {
		t.Fatalf("10.0.0.36 example.com queries = %d, want 2", n)
	}
	if n, _ := store.DNSDomainQueries(day, "gw", "10.0.0.37", "example.com"); n != 1 {
		t.Fatalf("10.0.0.37 example.com queries = %d, want 1", n)
	}
}
