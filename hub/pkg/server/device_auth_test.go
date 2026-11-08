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
	t.Parallel()
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

	// The shared tenant key never stands in for a device credential.
	legacy := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(batch))
	legacy.Header.Set("X-API-Key", "mock_tenant_token")
	legacyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(legacyRec, legacy)
	if legacyRec.Code != http.StatusUnauthorized {
		t.Fatalf("shared tenant credential was accepted on an agent route: %d %s", legacyRec.Code, legacyRec.Body.String())
	}
}

func TestDeviceCredentialCannotReadAnotherEndpointConfiguration(t *testing.T) {
	t.Parallel()
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

func TestOperatorCanReadEventsViaAdminAuth(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	// 1. Admin JWT Bearer token
	w := call(srv, srv.handleEvents, http.MethodGet, "/api/v1/events", "mock_admin_token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("operator events read via admin token returned status %d: %s", w.Code, w.Body.String())
	}

	// 2. Admin API key via router
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	wKey := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wKey, req)
	if wKey.Code != http.StatusOK {
		t.Fatalf("operator events read via X-API-Key returned status %d: %s", wKey.Code, wKey.Body.String())
	}
}

// A supervised run's heartbeat comes from the agent on its own credential,
// like the job ack and result; the device-route list must let it through.
func TestDeviceCredentialMayPostResponseProgress(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, path := range []string{"/api/v1/response/jobs/ack", "/api/v1/response/jobs/result", "/api/v1/response/jobs/progress"} {
		if !isAllowedDeviceRoute(http.MethodPost, path) {
			t.Errorf("%s is not a device route", path)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs/progress", strings.NewReader(`{}`))
	req.Header.Set(deviceCredentialHeader, issueTestCredential(t, store, "linux-progress"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "permitted agent endpoints") {
		t.Fatalf("a device credential was refused on the progress route: %d %s", w.Code, w.Body.String())
	}
}
