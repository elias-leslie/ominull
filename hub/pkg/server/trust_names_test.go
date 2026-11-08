package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/trustfabric"
)

// fakeNames is a resolver a test can change under the hub.
type fakeNames struct {
	mu  sync.Mutex
	ans map[string][]string
	err error
}

func (f *fakeNames) set(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ans[name] = addrs
}

func (f *fakeNames) lookup(_ context.Context, name string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []netip.Addr
	for _, a := range f.ans[name] {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func allowList(t *testing.T, store *storage.Store, id string) string {
	t.Helper()
	iso, allow, err := store.GetEndpointIsolation(id)
	if err != nil || !iso {
		t.Fatalf("%s not isolated: %v", id, err)
	}
	return strings.Join(allow, ",")
}

// lastGrantPayload is the newest grant the agent would be handed, as it sees it.
func lastGrantBody(t *testing.T, store *storage.Store, id string) (allow []string, grantID string) {
	t.Helper()
	newest, err := store.LatestIsolationGrant(id, 0, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if newest == nil {
		t.Fatalf("no grant for %s", id)
	}
	var p struct {
		Route string `json:"route"`
		Body  struct {
			AllowIPs   []string `json:"allow_ips"`
			EndpointID string   `json:"endpoint_id"`
		} `json:"body"`
	}
	if err := json.Unmarshal(newest.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Route != "/api/v1/endpoints/isolate" || p.Body.EndpointID != id {
		t.Fatalf("grant over %s for %s", p.Route, p.Body.EndpointID)
	}
	return p.Body.AllowIPs, newest.GrantID
}

// A refresh that read the isolation before it was released must not undo the
// release, nor widen one that replaced it: a grant the agent sees last wins.
func TestStaleRefreshCannotReviveOrWidenAnIsolation(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	names := &fakeNames{ans: map[string][]string{"api.example.com": {"198.51.100.1"}}}
	srv.trustNameLookup = names.lookup
	seedEndpointRow(t, store, storage.Endpoint{ID: "r-1", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "r-1")
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "r-1", Kind: "fqdn", Value: "api.example.com", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	isolate := func() (*storage.Endpoint, storage.IsolationRecord, isolationFabric) {
		t.Helper()
		if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"r-1","mode":"selective"}`); w.Code != http.StatusOK {
			t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
		}
		recs, _ := store.IsolatedEndpoints()
		var f isolationFabric
		if err := json.Unmarshal([]byte(recs[0].Fabric), &f); err != nil {
			t.Fatal(err)
		}
		ep, _ := store.GetEndpoint("r-1")
		return ep, recs[0], f
	}
	moved := []string{"198.51.100.1", "198.51.100.2"}

	ep, rec, f := isolate()
	if w := postJSON(t, srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"r-1"}`); w.Code != http.StatusOK {
		t.Fatalf("release: %d", w.Code)
	}
	newest := func() string {
		t.Helper()
		g, err := store.LatestIsolationGrant("r-1", 0, time.Now().Unix())
		if err != nil || g == nil {
			t.Fatalf("grant: %v", err)
		}
		return g.GrantID
	}
	released := newest()
	if err := srv.regrantIsolation(context.Background(), ep, rec, f, moved, nil); err != nil {
		t.Fatal(err)
	}
	if iso, _, _ := store.GetEndpointIsolation("r-1"); iso {
		t.Fatal("a stale refresh isolated a released endpoint")
	}
	if newest() != released {
		t.Fatal("a stale refresh left a newer grant for the agent than the release")
	}

	// A new isolation under the same fabric is not the one the refresh read.
	ep, rec, f = isolate()
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"r-1","mode":"full"}`); w.Code != http.StatusOK {
		t.Fatalf("full: %d", w.Code)
	}
	if err := srv.regrantIsolation(context.Background(), ep, rec, f, moved, nil); err != nil {
		t.Fatal(err)
	}
	if got := allowList(t, store, "r-1"); got != "" {
		t.Fatalf("a stale refresh widened a full isolation: %q", got)
	}
	if allow, _ := lastGrantBody(t, store, "r-1"); len(allow) != 0 {
		t.Fatalf("the newest grant opens %v", allow)
	}
}

// A release that lands while the detector's goroutine is on its way to signing
// is not undone by a grant newer than the release.
func TestDetectorGrantDoesNotUndoARelease(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "r-2", ResponseCapabilities: `{"isolate":true}`})
	srv.signDetectorIsolation("r-2", "lateral sweep")
	if g, err := store.LatestIsolationGrant("r-2", 0, time.Now().Unix()); err != nil || g != nil {
		t.Fatalf("a released endpoint was handed an isolation grant: %+v %v", g, err)
	}
}

// Following a name changes the name's addresses and nothing else, whatever the
// contained host reports about itself and whatever the operator's baseline
// has become since.
func TestFollowingANameChangesOnlyItsAddresses(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	names := &fakeNames{ans: map[string][]string{"api.example.com": {"198.51.100.1"}}}
	srv.trustNameLookup = names.lookup
	seedEndpointRow(t, store, storage.Endpoint{ID: "f-1", RoleTag: "pos", DriverVersion: "1.8.40", ResponseCapabilities: `{"isolate":true}`})
	reportReady(t, store, "f-1")
	for _, r := range []trustfabric.Rule{
		{ScopeType: "provider", Kind: "fqdn", Value: "api.example.com", Action: "allow"},
		{ScopeType: "provider", Kind: "cidr", Value: "203.0.113.0/30", Action: "allow"},
		{ScopeType: "group", ScopeID: "pos", Kind: "ip", Value: "203.0.113.1", Action: "deny"},
		{ScopeType: "provider", Kind: "cidr", Value: "192.0.2.0/24", Action: "allow"},
	} {
		if _, err := store.CreateTrustRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"f-1","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	before := allowList(t, store, "f-1")
	if strings.Contains(before, "203.0.113.1,") || strings.Contains(before, "192.0.2.0/24") {
		t.Fatalf("allow list %q", before)
	}

	// The host claims another role and a newer agent; the operator adds a
	// baseline rule. None of it may reach the next grant.
	seedEndpointRow(t, store, storage.Endpoint{ID: "f-1", RoleTag: "other", DriverVersion: "1.8.92", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	savePolicy(t, store, "added later", storage.BaselineRule{Service: "dns", Destination: "198.51.100.200", Protocol: "udp", Port: 53})
	srv.refreshTrustNames(context.Background(), time.Now().UTC())
	if got := allowList(t, store, "f-1"); got != before {
		t.Fatalf("nothing about the name moved, yet %q became %q", before, got)
	}

	names.set("api.example.com", "198.51.100.2")
	srv.refreshTrustNames(context.Background(), time.Now().UTC().Add(time.Second))
	got := allowList(t, store, "f-1")
	if !strings.Contains(got, "198.51.100.2") {
		t.Fatalf("the name did not move: %q", got)
	}
	if strings.Contains(got, "203.0.113.1,") || strings.Contains(got, "/") {
		t.Fatalf("a contained host's own report changed what it may reach: %q", got)
	}
	g, err := store.LatestIsolationGrant("f-1", 0, time.Now().Unix())
	if err != nil || g == nil {
		t.Fatalf("grant: %v", err)
	}
	if strings.Contains(string(g.Payload), "198.51.100.200") {
		t.Fatalf("a baseline added after the isolation reached its grant: %s", g.Payload)
	}
}

// One name's old addresses cannot starve another name's current one, nor push a
// rule's own range off the list.
func TestAllowListKeepsRulesAndEachNamesNewestAnswer(t *testing.T) {
	t.Parallel()
	ep := trustfabric.Endpoint{ID: "c-1"}
	now := time.Now().UTC()
	var rules []trustfabric.Rule
	add := func(kind, value string) {
		n, err := trustfabric.Normalize(trustfabric.Rule{ID: value, ScopeType: "provider", Kind: kind, Value: value, Action: "allow"})
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, n)
	}
	add("cidr", "203.0.113.0/24")
	add("ip", "192.0.2.200")
	answers := map[string]storage.TrustNameAnswer{}
	for i, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		add("fqdn", name)
		a := storage.TrustNameAnswer{Name: name}
		for j := 0; j < 16; j++ {
			a.Addrs = append(a.Addrs, storage.TrustNameAddr{Addr: netip.AddrFrom4([4]byte{198, 51, byte(i), byte(255 - 2*j)}).String()})
		}
		answers[name] = a
	}
	// Neighbouring old answers merge into a range; it ranks as those answers.
	add("fqdn", "pairs.example.com")
	pairs := storage.TrustNameAnswer{Name: "pairs.example.com"}
	for j := 0; j < 16; j++ {
		pairs.Addrs = append(pairs.Addrs, storage.TrustNameAddr{Addr: netip.AddrFrom4([4]byte{198, 51, 9, byte(j)}).String()})
	}
	answers["pairs.example.com"] = pairs
	p := compileFabricFor(ep, true, rules, answers, now)
	if len(p.Enforced) != maxAllowEntries {
		t.Fatalf("%d entries", len(p.Enforced))
	}
	got := strings.Join(p.Enforced, ",") + ","
	for _, want := range []string{"192.0.2.200", "203.0.113.0/24", "198.51.0.255", "198.51.1.255", "198.51.2.255", "198.51.9.0/28"} {
		if !strings.Contains(got, want+",") {
			t.Fatalf("%s lost its place: %s", want, got)
		}
	}
	if len(p.NotEnforced) == 0 {
		t.Fatal("what did not fit is not reported")
	}
}

// Containment does not wait on DNS, however many names are dead.
func TestIsolationDoesNotWaitOnDeadNames(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.trustNameLookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	seedEndpointRow(t, store, storage.Endpoint{ID: "d-1", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "d-1")
	for i := 0; i < 20; i++ {
		if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "d-1", Kind: "fqdn", Value: "n" + strconv.Itoa(i) + ".example.com", Action: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"d-1","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	if took := time.Since(start); took > trustNameIsolateBudget+2*time.Second {
		t.Fatalf("isolating took %s", took)
	}
	if got := allowList(t, store, "d-1"); got != "" {
		t.Fatalf("allow list %q", got)
	}
}

// A name rule opens what the hub resolved it to, in the signed grant; when the
// name moves, the isolation in force follows with a new grant, keeping its id.
func TestNameRuleFollowsItsAddressesThroughAGrant(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	names := &fakeNames{ans: map[string][]string{}}
	srv.trustNameLookup = names.lookup
	names.set("api.example.com", "198.51.100.1", "0.0.0.0", "127.0.0.1", "ff02::1", "fe80::1")
	seedEndpointRow(t, store, storage.Endpoint{ID: "n-1", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "n-1")
	if w := trustRequest(t, srv, http.MethodPost, "/api/v1/trust/rules", `{"scope_type":"endpoint","scope_id":"n-1","kind":"fqdn","value":"API.example.com","action":"allow"}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if w := trustRequest(t, srv, http.MethodPost, "/api/v1/trust/rules", `{"scope_type":"endpoint","scope_id":"n-1","kind":"ip","value":"192.0.2.9","action":"allow"}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"n-1","mode":"selective","allow_ips":["203.0.113.5"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	if got := allowList(t, store, "n-1"); got != "203.0.113.5,192.0.2.9,198.51.100.1" {
		t.Fatalf("allow list %q: 0.0.0.0, loopback, multicast and link-local answers must never open", got)
	}
	recs, _ := store.IsolatedEndpoints()
	id := recs[0].ID

	// Nothing moved: no new grant.
	_, before := lastGrantBody(t, store, "n-1")
	srv.refreshTrustNames(context.Background(), time.Now().UTC())
	if _, n := lastGrantBody(t, store, "n-1"); n != before {
		t.Fatalf("re-signed with nothing changed: grant %s, was %s", n, before)
	}

	// The name moves: the old address stays for the retention window and the
	// new one opens, in a grant the agent can verify; the rule set stays frozen.
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "provider", Kind: "ip", Value: "192.0.2.77", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	names.set("api.example.com", "198.51.100.2")
	now := time.Now().UTC().Add(time.Second)
	srv.refreshTrustNames(context.Background(), now)
	want := "203.0.113.5,192.0.2.9,198.51.100.2,198.51.100.1"
	if got := allowList(t, store, "n-1"); got != want {
		t.Fatalf("allow list after the move %q, want %q", got, want)
	}
	signed, _ := lastGrantBody(t, store, "n-1")
	if strings.Join(signed, ",") != want {
		t.Fatalf("signed %v, enforced %q", signed, want)
	}
	recs, _ = store.IsolatedEndpoints()
	if recs[0].ID != id || recs[0].Mode != isolationModeSelective || recs[0].Fabric == "" {
		t.Fatalf("record after the grant %+v (id was %s)", recs[0], id)
	}
	if n := len(auditActions(t, store, "TRUST_NAME_REGRANTED")); n != 1 {
		t.Fatalf("audit rows %d", n)
	}

	// Past the retention window the old address closes.
	later := now.Add(time.Duration(trustNameRetainDefault+1) * time.Minute)
	srv.refreshTrustNames(context.Background(), later)
	if got, want := allowList(t, store, "n-1"), "203.0.113.5,192.0.2.9,198.51.100.2"; got != want {
		t.Fatalf("after retention %q, want %q", got, want)
	}

	// A resolver outage closes nothing and signs nothing.
	names.mu.Lock()
	names.err = errors.New("resolver down")
	names.mu.Unlock()
	_, grantsBefore := lastGrantBody(t, store, "n-1")
	srv.refreshTrustNames(context.Background(), later.Add(time.Hour*5))
	if got, want := allowList(t, store, "n-1"), "203.0.113.5,192.0.2.9,198.51.100.2"; got != want {
		t.Fatalf("after an outage %q, want %q", got, want)
	}
	if _, n := lastGrantBody(t, store, "n-1"); n != grantsBefore {
		t.Fatal("an outage signed a new grant")
	}
	answers, _ := store.TrustNameAnswers()
	if answers["api.example.com"].Error == "" {
		t.Fatalf("the outage is not visible: %+v", answers["api.example.com"])
	}

	// Release ends it: no more grants, no isolation left to follow.
	if w := postJSON(t, srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"n-1"}`); w.Code != http.StatusOK {
		t.Fatalf("release: %d %s", w.Code, w.Body.String())
	}
	names.mu.Lock()
	names.err = nil
	names.mu.Unlock()
	names.set("api.example.com", "198.51.100.3")
	srv.refreshTrustNames(context.Background(), later.Add(time.Hour*6))
	if iso, _, _ := store.GetEndpointIsolation("n-1"); iso {
		t.Fatal("a name refresh isolated a released endpoint")
	}
}

// A name with no answer opens nothing and says so; containment still goes ahead.
func TestUnresolvableNameStaysClosedAndIsReported(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	names := &fakeNames{ans: map[string][]string{}, err: errors.New("no such host")}
	srv.trustNameLookup = names.lookup
	seedEndpointRow(t, store, storage.Endpoint{ID: "n-2", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "n-2")
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "n-2", Kind: "fqdn", Value: "gone.example.com", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"n-2","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	if got := allowList(t, store, "n-2"); got != "" {
		t.Fatalf("allow list %q", got)
	}
	if !authorizedAuditHas(t, store, "n-2", "gone.example.com") {
		t.Fatalf("the audit does not say the name stayed closed: %+v", authorizedAudit(t, store))
	}
	// It opens when the name starts answering.
	names.mu.Lock()
	names.err = nil
	names.mu.Unlock()
	names.set("gone.example.com", "198.51.100.8")
	srv.refreshTrustNames(context.Background(), time.Now().UTC())
	if got := allowList(t, store, "n-2"); got != "198.51.100.8" {
		t.Fatalf("allow list %q", got)
	}
}

// A hand-run isolation drops the frozen fabric: a later refresh must not put
// back what the operator just took away.
func TestFullIsolationStopsFollowingNames(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	names := &fakeNames{ans: map[string][]string{"api.example.com": {"198.51.100.1"}}}
	srv.trustNameLookup = names.lookup
	seedEndpointRow(t, store, storage.Endpoint{ID: "n-3", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "n-3")
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "n-3", Kind: "fqdn", Value: "api.example.com", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"n-3","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"n-3","mode":"full"}`); w.Code != http.StatusOK {
		t.Fatalf("full: %d %s", w.Code, w.Body.String())
	}
	names.set("api.example.com", "198.51.100.2")
	srv.refreshTrustNames(context.Background(), time.Now().UTC())
	if got := allowList(t, store, "n-3"); got != "" {
		t.Fatalf("a refresh reopened a full isolation: %q", got)
	}
}

// Live 2026-11-08: a VM restored to agent 1.8.40 kept the allow_prefixes it had
// reported from a later agent, was handed a range, and applied no isolation at
// all. An agent's own version outranks a capability it no longer reports.
func TestOldAgentWithStaleCapabilityGetsAddressesNotRanges(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	stale := normalizeResponseCapabilities([]byte(`{"isolate":true,"allow_prefixes":true}`))
	seedEndpointRow(t, store, storage.Endpoint{ID: "old-1", DriverVersion: "1.8.40", ResponseCapabilities: stale})
	reportReady(t, store, "old-1")
	for _, r := range []trustfabric.Rule{
		{ScopeType: "endpoint", ScopeID: "old-1", Kind: "cidr", Value: "203.0.113.0/30", Action: "allow"},
		{ScopeType: "endpoint", ScopeID: "old-1", Kind: "cidr", Value: "198.51.100.0/24", Action: "allow"},
		{ScopeType: "endpoint", ScopeID: "old-1", Kind: "ip", Value: "192.0.2.9", Action: "allow"},
	} {
		if _, err := store.CreateTrustRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"old-1","allow_ips":["10.0.0.0/24"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a named range on an old agent: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"old-1","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	want := "192.0.2.9,203.0.113.0,203.0.113.1,203.0.113.2,203.0.113.3"
	if got := allowList(t, store, "old-1"); got != want {
		t.Fatalf("allow list %q, want %q (the /24 stays closed)", got, want)
	}
	if !authorizedAuditHas(t, store, "old-1", "198.51.100.0/24") {
		t.Fatalf("the audit does not name the closed range: %+v", authorizedAudit(t, store))
	}
}

// An agent refuses a grant listing more than it holds, and then does not
// isolate at all; so the hub never signs one.
func TestAllowListNeverExceedsWhatAnAgentHolds(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "cap-1", ResponseCapabilities: `{"isolate":true,"allow_prefixes":true}`})
	reportReady(t, store, "cap-1")
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "cap-1", Kind: "cidr", Value: "10.0.0.0/8", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	// Three denies split the /8 into more pieces than a list holds.
	for _, v := range []string{"10.1.2.3", "10.200.3.4", "10.77.5.6"} {
		if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "cap-1", Kind: "ip", Value: v, Action: "deny"}); err != nil {
			t.Fatal(err)
		}
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"cap-1","mode":"selective","allow_ips":["192.0.2.1"]}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	_, allow, _ := store.GetEndpointIsolation("cap-1")
	if len(allow) != maxAllowEntries || allow[0] != "192.0.2.1" {
		t.Fatalf("%d entries, first %q", len(allow), allow[0])
	}
	for _, a := range allow {
		if strings.HasPrefix(a, "10.1.2.3") {
			t.Fatalf("the denied address opened: %v", allow)
		}
	}
	var over []string
	for i := 0; i <= maxAllowEntries; i++ {
		over = append(over, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String())
	}
	body, _ := json.Marshal(map[string]any{"endpoint_id": "cap-1", "allow_ips": over})
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", string(body)); w.Code != http.StatusBadRequest {
		t.Fatalf("too long a request: %d %s", w.Code, w.Body.String())
	}
}

// An agent going back a version drops the capabilities its successor reported.
func TestCapabilitiesDoNotOutliveTheAgentThatReportedThem(t *testing.T) {
	t.Parallel()
	_, store := setupTestServer(t)
	defer store.Close()
	caps := normalizeResponseCapabilities([]byte(`{"isolate":true,"allow_prefixes":true}`))
	seedEndpointRow(t, store, storage.Endpoint{ID: "v-1", DriverVersion: "1.8.92", ResponseCapabilities: caps})
	ep, _ := store.GetEndpoint("v-1")
	ep.ResponseCapabilities = ""
	if err := store.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetEndpoint("v-1"); got.ResponseCapabilities != caps {
		t.Fatalf("a batch without capabilities from the same agent cleared them: %q", got.ResponseCapabilities)
	}
	ep.DriverVersion = "1.8.40"
	if err := store.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetEndpoint("v-1"); got.ResponseCapabilities != "" {
		t.Fatalf("capabilities outlived their agent: %q", got.ResponseCapabilities)
	}
}
