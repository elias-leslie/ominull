package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"ominull/hub/pkg/storage"
	"strings"
	"testing"
)

func TestEstateNetworkConfigurationRoute(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	send := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/topology/networks", strings.NewReader(body))
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	w := send(http.MethodPut, `[{"cidr":"2001:db8:4::9/64","label":"Lab segment"}]`)
	if w.Code != http.StatusOK {
		t.Fatalf("configure: %d %s", w.Code, w.Body.String())
	}
	w = send(http.MethodGet, "")
	var got []storage.TopologyNetwork
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CIDR != "2001:db8:4::/64" || got[0].Label != "Lab segment" {
		t.Fatalf("configuration: %+v", got)
	}
	for _, bad := range []string{`[{"cidr":"::/0"}]`, `[{"cidr":"garbage"}]`, `[{"cidr":"ff00::/8"}]`, `[{"cidr":"10.0.4.1/24"},{"cidr":"10.0.4.2/24"}]`} {
		if w = send(http.MethodPut, bad); w.Code != http.StatusBadRequest {
			t.Errorf("bad network accepted: %d", w.Code)
		}
	}
	saved, err := store.TopologyNetworks()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || saved[0].Label != "Lab segment" {
		t.Fatal("invalid input overwrote configuration")
	}
}

func TestContainerNetworkConfigurationRejectsBroadOrPublicExemptions(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, cidr := range []string{"172.16.0.0/8", "192.168.0.0/15", "fd00::/6", "::/0", "2001:db8::/64"} {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/detection/tuning", strings.NewReader(`{"container_cidrs":["`+cidr+`"]}`))
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("invalid container prefix %s returned %d", cidr, w.Code)
		}
	}
	if len(store.GetDetectionTuning().ContainerCIDRs) != 0 {
		t.Fatal("invalid exemption persisted")
	}
}
