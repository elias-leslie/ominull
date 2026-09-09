package server

import (
	"net/http/httptest"
	"ominull/hub/pkg/ipv6guard"
	"ominull/hub/pkg/storage"
	"testing"
	"time"
)

func TestIPv6ObservationPersistsAndFindingHonorsLearning(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if _, err := store.CreateLearningWindow(storage.LearningWindow{TenantID: "t-01", ScopeType: storage.LearningScopeTenant, ScopeID: "t-01", StartedBy: "fixture"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cfg := ipv6guard.Config{TenantID: "t-01", Routers: []ipv6guard.Peer{{IP: "fe80::b", MAC: "02:00:00:00:00:02"}}}
	packet := ipv6guard.Observation{Kind: "router_advertisement", Interface: "fixture", Source: "fe80::a%fixture", MAC: "02:00:00:00:00:01", FirstSeen: now, LastSeen: now, Count: 1}
	srv.persistIPv6Observations([]ipv6guard.Observation{packet}, cfg)
	srv.persistIPv6Observations([]ipv6guard.Observation{packet}, cfg)
	if err := srv.ipv6Monitor.Status().PersistenceError; err != "" {
		t.Fatal(err)
	}
	rows, err := store.IPv6Observations("t-01")
	if err != nil || len(rows) != 1 || rows[0].Count != 2 {
		t.Fatalf("bad aggregation: %+v %v", rows, err)
	}
	alerts, total, err := store.QueryAnomalyAlerts("t-01", 100, 0, true, "", "IPV6_INFRASTRUCTURE", "", storage.HeldAny)
	if err != nil || total != 1 || alerts[0].HeldReason != storage.HeldLearning {
		t.Fatalf("learning/cooldown: %+v %d %v", alerts, total, err)
	}
}
func TestIPv6MonitorRequiresAdministrator(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, tc := range []struct {
		key  string
		want int
	}{{"mock_tenant_token", 403}, {"mock_admin_token", 200}} {
		req := httptest.NewRequest("GET", "/api/v1/ipv6/monitor", nil)
		req.Header.Set("X-API-Key", tc.key)
		req.Header.Set("X-Role", "admin")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d: %s", w.Code, tc.want, w.Body.String())
		}
	}
}
