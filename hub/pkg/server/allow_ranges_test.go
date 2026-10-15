package server

import (
	"net/http"
	"strings"
	"testing"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/trustfabric"
)

func TestValidateAllowEntry(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"10.0.0.9": "10.0.0.9", " 10.0.8.5/22 ": "10.0.8.0/22", "10.0.0.0/8": "10.0.0.0/8", "10.0.0.9/32": "10.0.0.9",
		"fd00:10::1/48": "fd00:10::/48", "fd00::1/128": "fd00::1", "2001:db8::/32": "2001:db8::/32",
	} {
		if got, err := validateAllowEntry(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"0.0.0.0/0", "10.0.0.0/7", "fd00::/31", "::/0", "10.0.0.0/33", "host.example/24", "::ffff:10.0.0.0/104", "10.0.0.0/",
		"fe80::/64", "64:ff9b::/96", "2001::/32", "2001:0:1::/48", "2002::/16", "2002:a00::/32", "ff02::/32"} {
		if got, err := validateAllowEntry(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

// Ranges reach only agents that report allow_prefixes; an older agent would
// refuse the whole grant, so it keeps getting single addresses.
func TestAllowRangesNeedAnAgentThatEnforcesThem(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	old := `{"isolate":true}`
	ranges := normalizeResponseCapabilities([]byte(`{"isolate":true,"allow_prefixes":true,"collect":true}`))
	if !strings.Contains(ranges, `"allow_prefixes":true`) {
		t.Fatalf("capability not kept: %s", ranges)
	}
	seedEndpointRow(t, store, storage.Endpoint{ID: "pos-old", ResponseCapabilities: old})
	seedEndpointRow(t, store, storage.Endpoint{ID: "pos-new", ResponseCapabilities: ranges})
	for _, id := range []string{"pos-old", "pos-new"} {
		reportReady(t, store, id)
	}
	for _, r := range []trustfabric.Rule{
		{ScopeType: "provider", Kind: "cidr", Value: "203.0.113.0/28", Action: "allow"},
		{ScopeType: "provider", Kind: "ip", Value: "198.51.100.25", Action: "allow"},
		{ScopeType: "provider", Kind: "cidr", Value: "100.64.0.0/10", Action: "allow"},
	} {
		if _, err := store.CreateTrustRule(r); err != nil {
			t.Fatal(err)
		}
	}
	allowOf := func(id string) string {
		t.Helper()
		iso, allow, err := store.GetEndpointIsolation(id)
		if err != nil || !iso {
			t.Fatalf("%s not isolated: %v", id, err)
		}
		return strings.Join(allow, ",")
	}

	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-old","allow_ips":["10.0.8.0/22"]}`); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "single addresses only") {
		t.Fatalf("range for an old agent: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-old","mode":"selective"}`); w.Code != http.StatusOK {
		t.Fatalf("selective old: %d %s", w.Code, w.Body.String())
	}
	if got := allowOf("pos-old"); got != "198.51.100.25" {
		t.Fatalf("old agent got %s", got)
	}

	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-new","allow_ips":["10.0.0.0/7"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("too wide a range: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-new","mode":"selective","allow_ips":["10.0.8.5/22"]}`); w.Code != http.StatusOK {
		t.Fatalf("selective new: %d %s", w.Code, w.Body.String())
	}
	if got := allowOf("pos-new"); got != "10.0.8.0/22,100.64.0.0/10,198.51.100.25,203.0.113.0/28" {
		t.Fatalf("new agent got %s", got)
	}
	// Bulk isolation names addresses only.
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate-bulk", `{"scope":"ids","ids":["pos-new"],"allow_ips":["10.0.8.0/22"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bulk range: %d %s", w.Code, w.Body.String())
	}
}
