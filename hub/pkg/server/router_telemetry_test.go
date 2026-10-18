package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/scanner"
	"ominull/hub/pkg/storage"
)

// postTelemetry sends one poll body and returns the recorder.
func postTelemetry(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/router/telemetry", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTelemetry).ServeHTTP(w, req)
	return w
}

// One poll carrying all three observation kinds must be folded and counted.
func TestRouterTelemetryIngestsAllThreeSources(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postTelemetry(t, srv, `{
		"router_id":"gw","label":"living room",
		"leases":[{"mac":"64:16:66:3b:b5:81","ip":"10.0.0.36","hostname":"thermostat"}],
		"flows":[{"src_ip":"10.0.0.36","dst_ip":"10.9.9.9","dst_port":443,"protocol":"tcp","orig_bytes":100,"reply_bytes":50}],
		"dns":[{"client_ip":"10.0.0.36","domain":"firmware.nest.com","qtype":"A"}]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest returned %d: %s", w.Code, w.Body.String())
	}

	var out storage.RouterIngestResult
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable reply: %v", err)
	}
	if out.LeasesAccepted != 1 || out.FlowsAccepted != 1 || out.DNSAccepted != 1 {
		t.Fatalf("expected one of each accepted, got %+v", out)
	}

	// The lease has to have become an asset; that is the whole point.
	assets, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("listing assets: %v", err)
	}
	found := false
	for _, a := range assets {
		if a.IP == "10.0.0.36" && a.Hostname == "thermostat" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the lease did not reach the asset store: %+v", assets)
	}
}

// A compromised gateway must not be able to ask the hub what to do next. The
// reply is a count and nothing else.
func TestRouterTelemetryReplyCarriesNoInstructions(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postTelemetry(t, srv, `{"router_id":"gw","leases":[{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.9"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest returned %d", w.Code)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unreadable reply: %v", err)
	}
	allowed := map[string]bool{
		"leases_accepted": true, "leases_rejected": true,
		"flows_accepted": true, "flows_rejected": true,
		"dns_accepted": true, "dns_rejected": true,
		"resolutions_accepted": true, "resolutions_rejected": true,
		"clients_accepted": true, "clients_rejected": true,
		"assets_touched":  true,
		"health_accepted": true, "health_rejected": true,
	}
	for k := range raw {
		if !allowed[k] {
			t.Fatalf("the reply carried a field the gateway could act on: %q in %v", k, raw)
		}
	}
}

// A gateway whose conntrack parser has broken should still be able to tell us
// who holds which lease. One bad section must not cost the others.
func TestRouterTelemetrySectionsFoldIndependently(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postTelemetry(t, srv, `{
		"router_id":"gw",
		"leases":[{"mac":"64:16:66:3b:b5:81","ip":"10.0.0.36","hostname":"thermostat"}],
		"flows":[{"src_ip":"not-an-ip","dst_ip":"also-not","dst_port":443,"protocol":"tcp"}],
		"dns":[{"client_ip":"","domain":"","qtype":"A"}]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a malformed section must not fail the poll, got %d: %s", w.Code, w.Body.String())
	}
	var out storage.RouterIngestResult
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.LeasesAccepted != 1 {
		t.Fatalf("the good lease was lost with the bad flow: %+v", out)
	}
	if out.FlowsAccepted != 0 || out.FlowsRejected != 1 {
		t.Fatalf("the malformed flow should be rejected and counted: %+v", out)
	}
	if out.DNSAccepted != 0 || out.DNSRejected != 1 {
		t.Fatalf("the malformed dns line should be rejected and counted: %+v", out)
	}
}

// The router must name itself, and only POST may write.
func TestRouterTelemetryRejectsUnnamedAndWrongMethod(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	if w := postTelemetry(t, srv, `{"router_id":"  ","leases":[]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unnamed router should be refused, got %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/telemetry", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTelemetry).ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the ingest route should be 405, got %d", w.Code)
	}
}

// Ingest is authenticated like every other route.
func TestRouterTelemetryRequiresAuth(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/router/telemetry",
		strings.NewReader(`{"router_id":"gw"}`))
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTelemetry).ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("an unauthenticated poll was accepted")
	}
}

// A body past the cap is refused before it is parsed, not after.
func TestRouterTelemetryBodyIsCapped(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	var b bytes.Buffer
	b.WriteString(`{"router_id":"gw","leases":[`)
	for i := 0; i < 200000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.5","hostname":"%s"}`, strings.Repeat("A", 60))
	}
	b.WriteString(`]}`)
	if b.Len() <= routerIngestLimit {
		t.Fatalf("test body is not larger than the cap (%d bytes)", b.Len())
	}

	w := postTelemetry(t, srv, b.String())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an oversized poll should be refused, got %d", w.Code)
	}
}

// The read side answers the question the ingest exists for, and names the
// devices the hub already knows.
func TestRouterTalkersAreRankedAndNamed(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	now := time.Now().UTC()
	if _, _, err := store.RecordRouterLeases("gw", []storage.RouterLease{
		{MAC: "64:16:66:3b:b5:81", IP: "10.0.0.36", Hostname: "thermostat"},
	}, nil, now); err != nil {
		t.Fatalf("seeding lease: %v", err)
	}
	if _, _, err := store.RecordRouterFlows("gw", []storage.RouterFlow{
		{SrcIP: "10.0.0.36", DstIP: "198.51.100.1", DstPort: 443, Protocol: "tcp", OrigBytes: 10},
		{SrcIP: "10.0.0.99", DstIP: "198.51.100.2", DstPort: 443, Protocol: "tcp", OrigBytes: 900000},
	}, now); err != nil {
		t.Fatalf("seeding flows: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/talkers?hours=24", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTalkers).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("talkers returned %d: %s", w.Code, w.Body.String())
	}

	var out struct {
		Talkers []map[string]interface{} `json:"talkers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable talkers reply: %v", err)
	}
	if len(out.Talkers) != 2 {
		t.Fatalf("expected two talkers, got %d: %v", len(out.Talkers), out.Talkers)
	}
	if out.Talkers[0]["ip"] != "10.0.0.99" {
		t.Fatalf("the loudest device should rank first, got %v", out.Talkers[0]["ip"])
	}
	// The device we hold a lease for must come back named, not as a bare address.
	named := false
	for _, tk := range out.Talkers {
		if tk["ip"] == "10.0.0.36" && tk["hostname"] == "thermostat" {
			named = true
		}
	}
	if !named {
		t.Fatalf("a device the hub has a lease for came back unnamed: %v", out.Talkers)
	}
}

// Flow reads are filterable, because an unfiltered flow table is not an answer.
func TestRouterFlowsFilterBySource(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	now := time.Now().UTC()
	if _, _, err := store.RecordRouterFlows("gw", []storage.RouterFlow{
		{SrcIP: "10.0.0.36", DstIP: "10.9.9.1", DstPort: 443, Protocol: "tcp", OrigBytes: 10},
		{SrcIP: "10.0.0.99", DstIP: "10.9.9.2", DstPort: 443, Protocol: "tcp", OrigBytes: 20},
	}, now); err != nil {
		t.Fatalf("seeding flows: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/flows?src=10.0.0.36", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterFlows).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("flows returned %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Flows []storage.RouterFlowRow `json:"flows"`
		Count int                     `json:"count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Count != 1 || len(out.Flows) != 1 || out.Flows[0].SrcIP != "10.0.0.36" {
		t.Fatalf("the src filter did not hold: %+v", out)
	}
}

// The payoff: a talker's destinations come back as names, not bare addresses.
func TestRouterTalkersNameDestinations(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()

	if _, _, err := store.RecordRouterFlows("gw", []storage.RouterFlow{
		{SrcIP: "10.0.0.36", DstIP: "198.51.100.9", DstPort: 443, Protocol: "tcp", OrigBytes: 100},
	}, now); err != nil {
		t.Fatalf("seeding flow: %v", err)
	}
	if _, _, err := store.RecordDNSResolutions([]storage.DNSResolution{
		{Domain: "firmware.nest.com", IP: "198.51.100.9", At: now},
	}, now); err != nil {
		t.Fatalf("seeding resolution: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/talkers?hours=24", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTalkers).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("talkers returned %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "firmware.nest.com") {
		t.Fatalf("the destination was not named: %s", w.Body.String())
	}
}

// Resolutions fold independently, like every other section.
func TestRouterTelemetryIngestsResolutions(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postTelemetry(t, srv, `{
		"router_id":"gw",
		"resolutions":[
			{"domain":"firmware.nest.com","ip":"10.9.9.9"},
			{"domain":"NXDOMAIN","ip":"10.9.9.8"}
		]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest returned %d: %s", w.Code, w.Body.String())
	}
	var out storage.RouterIngestResult
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.ResolutionsAccepted != 1 || out.ResolutionsRejected != 1 {
		t.Fatalf("expected one kept and one refused, got %+v", out)
	}
	if store.NameForIP("10.9.9.9") != "firmware.nest.com" {
		t.Fatalf("the resolution did not reach the store")
	}
}

// A lease is often the only evidence an unagented device ever produces, and it
// carries the hardware address. Recording one without resolving the vendor
// left the inventory blank for exactly the devices it exists to cover.
func TestRouterLeaseNamesTheManufacturer(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	body := `{"router_id":"gw","leases":[
		{"mac":"F4:03:2A:3F:FC:71","ip":"10.0.0.41","hostname":"echo"},
		{"mac":"64:16:66:3B:B5:81","ip":"10.0.0.36","hostname":"thermostat"},
		{"mac":"F6:55:AD:29:6C:93","ip":"10.0.0.44","hostname":"phone"}
	]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/router/telemetry", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleRouterTelemetry).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest returned %d: %s", w.Code, w.Body.String())
	}

	assets, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("listing assets: %v", err)
	}
	got := map[string]string{}
	for _, a := range assets {
		got[a.IP] = a.Vendor
	}
	for ip, want := range map[string]string{
		"10.0.0.41": "Amazon Technologies Inc.",
		"10.0.0.36": "Nest Labs Inc.",
		// Randomised, so there is no manufacturer - but saying so is the
		// useful answer, and blank is not.
		"10.0.0.44": scanner.VendorRandomised,
	} {
		if got[ip] != want {
			t.Errorf("lease %s recorded vendor %q; want %q", ip, got[ip], want)
		}
	}
}

func TestRouterDHCPFingerprintRemainsObservedEvidence(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	w := postTelemetry(t, srv, `{"router_id":"gw","leases":[{"mac":"da:bb:cc:dd:ee:01","ip":"10.0.0.9","dhcp":{"vendor_class":"android-dhcp-14","requested_options":"1,3,6,15,26,28,51,58,59","observed_at":"2026-09-01T12:00:00Z"}}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
	a, err := store.GetAsset("10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, c := range a.Claims {
		if strings.HasPrefix(c.Field, "dhcp_") {
			if c.Source != "router" || c.ObservedAt.Format(time.RFC3339) != "2026-09-01T12:00:00Z" {
				t.Fatalf("false observation provenance: %+v", c)
			}
			found[c.Field] = c.Value
		}
	}
	if found["dhcp_vendor_class"] != "android-dhcp-14" || found["dhcp_requested_options"] != "1,3,6,15,26,28,51,58,59" {
		t.Fatalf("missing fingerprint: %v", found)
	}
	if a.OS != "" {
		t.Fatalf("self-reported fingerprint invented OS: %q", a.OS)
	}
}

const healthPoll = `{"router_id":"gw","label":"living room","health":{
	"uptime_s":86400,"mem_total_kb":524288,"mem_avail_kb":262144,"overlay_kb":1000,"overlay_used_kb":400,
	"conntrack_count":100,"conntrack_max":1000,"wan_up":true,"wan_ipv4":true,"load1":0.4,
	"firmware":{"glversion":"4.8.3","openwrt":"23.05.4","kernel":"5.4.0"},
	"auth_pw":[1792000001,-5],"auth_pre":[],"upnp":[1,1],"upnp_n":2,"upnp_maps":["tcp:51413:deadbeef","evil;rm -rf /"]}}`

func getRouterHealth(t *testing.T, srv *Server, path, key string) []storage.RouterHealthRecord {
	t.Helper()
	w := feedRequest(srv, http.MethodGet, path, key)
	if w.Code != http.StatusOK {
		t.Fatalf("%s returned %d: %s", path, w.Code, w.Body.String())
	}
	var doc struct {
		Schema  string                       `json:"schema"`
		Routers []storage.RouterHealthRecord `json:"routers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Schema != "ominull.router-health/v1" {
		t.Fatalf("unreadable health document: %v %s", err, w.Body.String())
	}
	return doc.Routers
}

// The gateway's own condition rides in the poll, is bounded on the way in and
// is readable by operators and by Nightshift's feed key (and nobody else).
func TestRouterHealthIsStoredBoundedAndReadable(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	if got := getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token"); len(got) != 0 {
		t.Fatalf("health before any poll = %+v", got)
	}
	if w := postTelemetry(t, srv, healthPoll); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"health_accepted":true`) {
		t.Fatalf("poll with health = %d %s", w.Code, w.Body.String())
	}
	got := getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token")
	if len(got) != 1 || got[0].RouterID != "gw" || got[0].Label != "living room" {
		t.Fatalf("health rows = %+v", got)
	}
	h := got[0].Health
	if !h.WANUp || h.UptimeS != 86400 || h.MemAvailKB != 262144 || h.ConntrackMax != 1000 {
		t.Fatalf("health values lost: %+v", h)
	}
	if len(h.AuthPW) != 1 || h.AuthPW[0] != 1792000001 {
		t.Fatalf("a negative stamp was kept: %v", h.AuthPW)
	}
	if len(h.UPnPMaps) != 1 || h.UPnPMaps[0] != "tcp:51413:deadbeef" {
		t.Fatalf("an unhashed or malformed UPnP mapping was kept: %v", h.UPnPMaps)
	}
	if got[0].Firmware != "GL 4.8.3 / OpenWrt 23.05.4 / kernel 5.4.0" || got[0].FirmwareChangedAt != nil {
		t.Fatalf("first reading must not read as a firmware change: %+v", got[0])
	}

	key := issueFeedKey(t, srv)
	if len(getRouterHealth(t, srv, "/api/v1/integrations/nightshift/router-health", key)) != 1 {
		t.Fatal("Nightshift's feed key cannot read router health")
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/router/health", key); w.Code == http.StatusOK {
		t.Fatal("the feed key opened the operator route")
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/router-health", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous read = %d", w.Code)
	}
}

// A new firmware string is recorded once, with the one it replaced; a reading
// that cannot say what it runs changes nothing.
func TestRouterHealthRecordsFirmwareChange(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	postTelemetry(t, srv, healthPoll)
	postTelemetry(t, srv, `{"router_id":"gw","health":{"uptime_s":5,"firmware":{"glversion":"","openwrt":"","kernel":""}}}`)
	got := getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token")
	if got[0].FirmwareChangedAt != nil || got[0].Firmware == "" || got[0].Health.UptimeS != 5 {
		t.Fatalf("an unreadable firmware must keep the last known one: %+v", got[0])
	}
	postTelemetry(t, srv, strings.Replace(healthPoll, "4.8.3", "4.8.4", 1))
	got = getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token")
	if got[0].FirmwareChangedAt == nil || got[0].FirmwarePrevious != "GL 4.8.3 / OpenWrt 23.05.4 / kernel 5.4.0" ||
		!strings.Contains(got[0].Firmware, "4.8.4") {
		t.Fatalf("firmware change not recorded: %+v", got[0])
	}
	changed := *got[0].FirmwareChangedAt
	postTelemetry(t, srv, strings.Replace(healthPoll, "4.8.3", "4.8.4", 1))
	got = getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token")
	if !got[0].FirmwareChangedAt.Equal(changed) {
		t.Fatalf("a repeat of the same firmware moved the change time: %v -> %v", changed, got[0].FirmwareChangedAt)
	}
}

// A health block the hub cannot read must not cost the leases beside it.
func TestRouterHealthGarbageDoesNotCostTheOtherSections(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postTelemetry(t, srv, `{"router_id":"gw","leases":[{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.9"}],"health":"nonsense"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"leases_accepted":1`) || !strings.Contains(w.Body.String(), `"health_rejected":true`) {
		t.Fatalf("garbage health = %d %s", w.Code, w.Body.String())
	}
	if got := getRouterHealth(t, srv, "/api/v1/router/health", "mock_admin_token"); len(got) != 0 {
		t.Fatalf("garbage was stored: %+v", got)
	}
}
