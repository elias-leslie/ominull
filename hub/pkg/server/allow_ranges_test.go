package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
// refuse the whole grant, so it gets single addresses.
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
	// The /28 is spelled out as addresses; the /10 is too big and stays closed.
	got := allowOf("pos-old")
	if !strings.HasPrefix(got, "198.51.100.25,203.0.113.0,203.0.113.1,") || !strings.HasSuffix(got, ",203.0.113.15") || strings.Contains(got, "/") || strings.Contains(got, "100.64") {
		t.Fatalf("old agent got %s", got)
	}

	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-new","allow_ips":["10.0.0.0/7"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("too wide a range: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-new","mode":"selective","allow_ips":["10.0.8.5/22"]}`); w.Code != http.StatusOK {
		t.Fatalf("selective new: %d %s", w.Code, w.Body.String())
	}
	if got := allowOf("pos-new"); got != "10.0.8.0/22,198.51.100.25,100.64.0.0/10,203.0.113.0/28" {
		t.Fatalf("new agent got %s", got)
	}
	// Bulk isolation names addresses only.
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate-bulk", `{"scope":"ids","ids":["pos-new"],"allow_ips":["10.0.8.0/22"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bulk range: %d %s", w.Code, w.Body.String())
	}
}

// Windows agents before 1.8.120 report allow_prefixes and drop every range, so
// the hub spells ranges out for them; from 1.8.120 they take the range.
func TestWindowsAgentsTakeRangesFrom1_8_120(t *testing.T) {
	t.Parallel()
	caps := `{"isolate":true,"allow_prefixes":true}`
	for _, c := range []struct {
		ep   storage.Endpoint
		want bool
	}{
		{storage.Endpoint{UpdateCapability: "msi", DriverVersion: "1.8.119", ResponseCapabilities: caps}, false},
		{storage.Endpoint{UpdateCapability: "msi", DriverVersion: "1.8.120", ResponseCapabilities: caps}, true},
		{storage.Endpoint{OS: "Windows 11", DriverVersion: "1.8.65", ResponseCapabilities: caps}, false},
		{storage.Endpoint{OS: "Linux", UpdateCapability: "deb", DriverVersion: "1.8.65", ResponseCapabilities: caps}, true},
		{storage.Endpoint{OS: "Linux", DriverVersion: "1.8.64", ResponseCapabilities: caps}, false},
	} {
		if got := agentTakesAllowRanges(&c.ep); got != c.want {
			t.Errorf("%s %s: got %v", c.ep.OS+c.ep.UpdateCapability, c.ep.DriverVersion, got)
		}
	}
}

// What an agent says it could not apply is audited once per change, through the
// real telemetry path, and shown next to the policy the hub would sign.
func TestAgentApplyReportIsAuditedAndShown(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "rep-1", TenantID: "t-rep", ResponseCapabilities: `{"isolate":true}`})
	report := func(note string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"type": "telemetry", "endpoint_id": "rep-1", "hostname": "host-rep-1", "os": "Linux", "events": []any{},
			"isolation_readiness": map[string]any{"enforcement_engine": "ok", "hub_literal": "10.0.0.2", "last_applied": note}})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
		r.Header.Set(deviceCredentialHeader, issueTestCredential(t, store, "rep-1"))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("telemetry: %d %s", w.Code, w.Body.String())
		}
	}
	rows := func() (out []storage.AuditEntry) {
		t.Helper()
		entries, err := store.ListAuditLogs("", 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Action == "AGENT_APPLY_REPORT" && e.Resource == "rep-1" {
				out = append(out, e)
			}
		}
		return out
	}
	report("")
	if n := len(rows()); n != 0 {
		t.Fatalf("nothing to say was audited: %d", n)
	}
	note := "policy not applied: WFP error 0x00000005"
	report(note)
	report(note)
	got := rows()
	if len(got) != 1 || got[0].Details != note || got[0].TenantID != "t-rep" {
		t.Fatalf("one report wanted: %+v", got)
	}
	for _, id := range []string{"rep-1", "host-rep-1"} {
		w := httptest.NewRecorder()
		srv.handleTrustEffective(w, httptest.NewRequest("GET", "/api/v1/trust/effective?endpoint_id="+id, nil))
		if !strings.Contains(w.Body.String(), note) {
			t.Fatalf("effective by %s: %s", id, w.Body.String())
		}
	}
	report("")
	if got := rows(); len(got) != 2 || !strings.HasPrefix(firstRow(got, note), "no longer reporting") {
		t.Fatalf("the end of a report is a change too: %+v", got)
	}
	long := strings.Repeat("x\n", 400)
	report(long)
	report(long)
	if got := rows(); len(got) != 3 {
		t.Fatalf("a long note must compare equal once stored: %d rows", len(got))
	}
	if stored, _ := store.LastAppliedReport("rep-1"); len(stored) != 240 || strings.Contains(stored, "\n") {
		t.Fatalf("note not bounded: %d bytes", len(stored))
	}
}

func firstRow(rows []storage.AuditEntry, not string) string {
	for _, e := range rows {
		if e.Details != not {
			return e.Details
		}
	}
	return ""
}
