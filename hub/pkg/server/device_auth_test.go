package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/storage"
)

func redeemForTest(t *testing.T, srv *Server, code, platform, hostname string) map[string]interface{} {
	t.Helper()
	body := `{"code":"` + code + `","platform":"` + platform + `","hostname":"` + hostname + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("enrollment redeem returned %d: %s", w.Code, w.Body.String())
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode enrollment bundle: %v", err)
	}
	return bundle
}

func TestDeviceCredentialBindsAgentRoutesAndRevocation(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	_, code, err := store.CreateEnrollmentProfile(storage.EnrollmentProfile{
		Kind: "invitation", Platform: "linux", TenantID: "default", MaxUses: 1,
	}, storage.EnrollmentProfileTTL)
	if err != nil {
		t.Fatalf("create enrollment profile: %v", err)
	}
	bundle := redeemForTest(t, srv, code, "linux", "linux-device")
	endpointID := bundle["endpoint_id"].(string)
	credential := bundle["device_credential"].(string)
	if !strings.HasPrefix(credential, "omd_") {
		t.Fatalf("unexpected device credential format: %q", credential)
	}

	batch := `{"type":"telemetry","endpoint_id":"` + endpointID + `","tenant_id":"default","hostname":"linux-device","os":"Linux","events":[]}`
	request := func(endpoint string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(strings.Replace(batch, endpointID, endpoint, 1)))
		req.Header.Set(deviceCredentialHeader, credential)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := request(endpointID); w.Code != http.StatusOK {
		t.Fatalf("valid device credential was refused: %d %s", w.Code, w.Body.String())
	}
	if w := request(endpointID + "-other"); w.Code != http.StatusForbidden {
		t.Fatalf("device credential acted as another endpoint: %d %s", w.Code, w.Body.String())
	}

	if err := store.RevokeDeviceCredentials(endpointID); err != nil {
		t.Fatalf("revoke device credential: %v", err)
	}
	if w := request(endpointID); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device credential was accepted: %d %s", w.Code, w.Body.String())
	}

	// A fresh package install must not silently fall back to the shared tenant
	// key once migration mode has been closed.
	if err := store.SetSetting("legacy_agent_auth", "disabled"); err != nil {
		t.Fatal(err)
	}
	legacy := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(batch))
	legacy.Header.Set("X-API-Key", "mock_tenant_token")
	legacyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(legacyRec, legacy)
	if legacyRec.Code != http.StatusUnauthorized {
		t.Fatalf("shared tenant credential remained active after disable: %d %s", legacyRec.Code, legacyRec.Body.String())
	}
}

func TestDeviceCredentialCannotReadAnotherEndpointConfiguration(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	_, code, err := store.CreateEnrollmentProfile(storage.EnrollmentProfile{Platform: "linux", TenantID: "default"}, storage.EnrollmentProfileTTL)
	if err != nil {
		t.Fatal(err)
	}
	bundle := redeemForTest(t, srv, code, "linux", "linux-config")
	credential := bundle["device_credential"].(string)
	other := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config?endpoint_id=some-other&version=1.0.0", nil)
	other.Header.Set(deviceCredentialHeader, credential)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, other)
	if w.Code != http.StatusForbidden {
		t.Fatalf("device credential read another endpoint config: %d %s", w.Code, w.Body.String())
	}
}

func TestLegacyHeartbeatDeliversAndRetriesUniqueCredentialMigration(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	body := `{"type":"telemetry","endpoint_id":"legacy-linux","tenant_id":"t-01","hostname":"legacy-linux","os":"Linux","events":[]}`
	legacyHeartbeat := func() map[string]interface{} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(body))
		req.Header.Set("X-API-Key", "mock_tenant_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("legacy heartbeat was refused: %d %s", w.Code, w.Body.String())
		}
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode migration response: %v", err)
		}
		return response
	}

	first := legacyHeartbeat()
	firstCredential, ok := first["device_credential"].(string)
	if !ok || !strings.HasPrefix(firstCredential, "omd_") {
		t.Fatalf("legacy heartbeat did not deliver a unique credential: %#v", first)
	}
	second := legacyHeartbeat()
	secondCredential, ok := second["device_credential"].(string)
	if !ok || secondCredential == firstCredential {
		t.Fatalf("lost-response migration did not rotate an unused credential: %#v", second)
	}

	device := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(body))
	device.Header.Set(deviceCredentialHeader, secondCredential)
	deviceResponse := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deviceResponse, device)
	if deviceResponse.Code != http.StatusOK {
		t.Fatalf("migrated device credential was refused: %d %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	if strings.Contains(deviceResponse.Body.String(), "device_credential") {
		t.Fatal("device-authenticated heartbeat kept returning migration material")
	}

	items, err := store.ListDeviceCredentials()
	if err != nil || len(items) != 2 {
		t.Fatalf("expected two historical migration records, got %d (%v)", len(items), err)
	}
}
