package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func dataReq(srv *Server, method, path, header, cred, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set(header, cred)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func dataSetup(t *testing.T) (*Server, *storage.Store, string) {
	t.Helper()
	srv, store := setupTestServer(t)
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()
	for _, id := range []string{"ws", "other"} {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: id, RoleTag: "workstation", Status: "online", LastSeenAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	key, _, err := store.IssueDeviceCredential("ws")
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, key
}

func policyText(t *testing.T, srv *Server, key, body string) string {
	t.Helper()
	w := dataReq(srv, http.MethodPost, "/api/v1/data/policy", deviceCredentialHeader, key, body)
	if w.Code != http.StatusOK {
		t.Fatalf("policy: %d %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

func TestDataPolicyStaysOffUntilCanariesAreSynced(t *testing.T) {
	t.Parallel()
	srv, _, key := dataSetup(t)
	p := policyText(t, srv, key, `{"endpoint_id":"ws"}`)
	if !strings.HasPrefix(p, "ominull-data-policy/1\nversion ") || !strings.Contains(p, "\nenabled 0\n") || !strings.HasSuffix(p, "\nend\n") {
		t.Fatalf("default policy:\n%s", p)
	}
	if w := dataReq(srv, http.MethodPost, "/api/v1/data/policy", deviceCredentialHeader, key, `{"endpoint_id":"other"}`); w.Code != http.StatusForbidden {
		t.Fatalf("another endpoint's policy: %d", w.Code)
	}
	// A layer needs a reason and must be in the agent's ranges.
	for body, want := range map[string]int{
		`{"scope":"default","policy":{"enabled":true}}`:                                    http.StatusBadRequest,
		`{"scope":"default","policy":{"max_seconds":5},"reason":"x"}`:                      http.StatusBadRequest,
		`{"scope":"default","policy":{"roots":["/srv/../etc"]},"reason":"x"}`:              http.StatusBadRequest,
		`{"scope":"nowhere","policy":{"enabled":true},"reason":"x"}`:                       http.StatusBadRequest,
		`{"scope":"role:workstation","policy":{"enabled":true},"reason":"workstations"}`:   http.StatusOK,
		`{"scope":"endpoint:ws","policy":{"roots":["/srv/workspaces"]},"reason":"narrow"}`: http.StatusOK,
	} {
		if w := dataReq(srv, http.MethodPost, "/api/v1/data/policies", "X-API-Key", "mock_admin_token", body); w.Code != want {
			t.Fatalf("%s = %d %s, want %d", body, w.Code, w.Body.String(), want)
		}
	}
	p = policyText(t, srv, key, `{"endpoint_id":"ws"}`)
	if !strings.Contains(p, "\nenabled 0\n") || !strings.Contains(p, "\nreason canaries_not_synced\n") {
		t.Fatalf("enabled before canaries were synced:\n%s", p)
	}
	if w := dataReq(srv, http.MethodPost, "/api/v1/data/canaries", "X-API-Key", "mock_admin_token",
		`{"source":"test","endpoints":[{"endpoint_id":"ws","paths":["/home/u/.aws/credentials","/srv/x/../y"]}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unnormalised canary accepted: %d", w.Code)
	}
	if w := dataReq(srv, http.MethodPost, "/api/v1/data/canaries", "X-API-Key", "mock_admin_token",
		`{"source":"test","endpoints":[{"endpoint_id":"ws","paths":["/home/u/.aws/credentials"]}]}`); w.Code != http.StatusOK {
		t.Fatalf("canary sync: %d %s", w.Code, w.Body.String())
	}
	p2 := policyText(t, srv, key, `{}`)
	if !strings.Contains(p2, "\nenabled 1\n") || !strings.Contains(p2, "\nroot /srv/workspaces\n") ||
		strings.Contains(p2, "root /home\n") || !strings.Contains(p2, "\ncanary /home/u/.aws/credentials\n") {
		t.Fatalf("effective policy:\n%s", p2)
	}
	if strings.SplitN(p, "\n", 3)[1] == strings.SplitN(p2, "\n", 3)[1] {
		t.Fatal("policy version did not change with the policy")
	}
	if p3 := policyText(t, srv, key, `{}`); p3 != p2 {
		t.Fatal("policy rendering is not stable")
	}
	// The read side reports counts, never the canary paths.
	w := dataReq(srv, http.MethodGet, "/api/v1/data/canaries?endpoint_id=ws", "X-API-Key", "mock_admin_token", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), ".aws") || !strings.Contains(w.Body.String(), `"count":1`) {
		t.Fatalf("canary read: %d %s", w.Code, w.Body.String())
	}
	if w := dataReq(srv, http.MethodPost, "/api/v1/data/policies", deviceCredentialHeader, key, `{"scope":"default","policy":{"enabled":false},"reason":"x"}`); w.Code == http.StatusOK {
		t.Fatal("a device changed the data policy")
	}
}

func dataDoc(cycle string, started int64, complete bool, stores []string, items [][2]string, partial string) string {
	var st, it []string
	for _, s := range stores {
		st = append(st, fmt.Sprintf(`{"path":%q,"root":"/srv","shallow":false,"partial":%v,"files":3,"bytes":100,"items":1,"hints":["git"]}`, s, s == partial))
	}
	for _, i := range items {
		it = append(it, fmt.Sprintf(`{"path":%q,"store":%q,"kind":"secret_candidate","rules":["aws_access_key","env_file"],"mode":420,"uid":1000,"size":40,"mtime":1}`, i[0], i[1]))
	}
	return fmt.Sprintf(`{"schema":"ominull.data-inventory/1","endpoint_id":"ws","platform":"linux","run":{"cycle_id":%q,"mode":"full","started_at":%d,"finished_at":%d,"cycle_started_at":%d,"cycle_complete":%v,"budget_hit":"none","files":9,"items_dropped":0,"policy_version":7,"rules_version":1,"sandboxed":true},"host":{"roots":[{"path":"/srv","encryption":"luks"}],"ufw":"active"},"stores":[%s],"items":[%s]}`,
		cycle, started, started+10, started, complete, strings.Join(st, ","), strings.Join(it, ","))
}

func TestDataInventoryUploadReplacesWhatACycleNoLongerSees(t *testing.T) {
	t.Parallel()
	srv, store, key := dataSetup(t)
	if err := store.SetDataCanaries(storage.DataCanaries{EndpointID: "ws", Paths: []string{"/srv/c/trap.env"}, SyncedAt: time.Now(), Source: "t"}); err != nil {
		t.Fatal(err)
	}
	post := func(doc string) *httptest.ResponseRecorder {
		return dataReq(srv, http.MethodPost, "/api/v1/data/inventory", deviceCredentialHeader, key, doc)
	}
	// Cycle a, run 1 of 2: stores a and b (b cut by the budget).
	if w := post(dataDoc("00000000000000a1", 1000, false, []string{"/srv/a", "/srv/b"},
		[][2]string{{"/srv/a/.env", "/srv/a"}, {"/srv/b/one.env", "/srv/b"}}, "/srv/b")); w.Code != http.StatusOK {
		t.Fatalf("upload 1: %d %s", w.Code, w.Body.String())
	}
	// Cycle a, run 2: store c, which holds a canary the agent should never
	// have reported: dropped.
	if w := post(dataDoc("00000000000000a1", 2000, true, []string{"/srv/c"},
		[][2]string{{"/srv/c/trap.env", "/srv/c"}, {"/srv/c/real.env", "/srv/c"}}, "")); w.Code != http.StatusOK {
		t.Fatalf("upload 2: %d %s", w.Code, w.Body.String())
	}
	snap, ok, err := store.DataSnapshotFor("ws", 100, 100)
	if err != nil || !ok || len(snap.Stores) != 3 || len(snap.Items) != 3 || snap.LastCompleteAt != 2010 {
		t.Fatalf("after cycle a: %v %v stores=%d items=%d complete=%d", ok, err, len(snap.Stores), len(snap.Items), snap.LastCompleteAt)
	}
	for _, it := range snap.Items {
		if strings.Contains(it.Path, "trap") {
			t.Fatal("canary item stored")
		}
	}
	// Cycle b, one run: store a is gone, c lost its item, b (partial before)
	// is now fully walked without items.
	if w := post(dataDoc("00000000000000b2", 3000, true, []string{"/srv/b", "/srv/c"}, nil, "")); w.Code != http.StatusOK {
		t.Fatalf("upload 3: %d %s", w.Code, w.Body.String())
	}
	snap, _, _ = store.DataSnapshotFor("ws", 100, 100)
	if len(snap.Stores) != 2 || len(snap.Items) != 0 {
		t.Fatalf("after cycle b: stores=%d items=%d", len(snap.Stores), len(snap.Items))
	}
	// An older run than the latest is acknowledged and ignored.
	w := post(dataDoc("00000000000000c3", 2500, true, []string{"/srv/z"}, nil, ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"stale"`) {
		t.Fatalf("stale run: %d %s", w.Code, w.Body.String())
	}
	// Malformed documents are refused whole.
	for name, doc := range map[string]string{
		"item outside stores": dataDoc("00000000000000d4", 4000, true, []string{"/srv/a"}, [][2]string{{"/etc/shadow", "/srv/a"}}, ""),
		"relative path":       dataDoc("00000000000000d4", 4000, true, []string{"srv/a"}, nil, ""),
		"bad cycle":           dataDoc("XYZ", 4000, true, []string{"/srv/a"}, nil, ""),
		"other endpoint":      strings.Replace(dataDoc("00000000000000d4", 4000, true, nil, nil, ""), `"endpoint_id":"ws"`, `"endpoint_id":"other"`, 1),
	} {
		if w := post(doc); w.Code == http.StatusOK {
			t.Fatalf("%s accepted", name)
		}
	}
	// The admin read shows the picture; a device cannot read it.
	if w := dataReq(srv, http.MethodGet, "/api/v1/data/inventory?endpoint_id=ws", "X-API-Key", "mock_admin_token", ""); w.Code != http.StatusOK {
		t.Fatalf("admin read: %d", w.Code)
	}
	if w := dataReq(srv, http.MethodGet, "/api/v1/data/inventory?endpoint_id=ws", deviceCredentialHeader, key, ""); w.Code == http.StatusOK {
		t.Fatal("device read the data inventory")
	}
}

func TestNightshiftFeedV3CarriesBoundedDataInventory(t *testing.T) {
	t.Parallel()
	srv, store, key := dataSetup(t)
	if err := store.SetDataCanaries(storage.DataCanaries{EndpointID: "ws", Paths: []string{}, SyncedAt: time.Now(), Source: "t"}); err != nil {
		t.Fatal(err)
	}
	var stores []string
	var items [][2]string
	for i := 0; i < 3000; i++ {
		s := fmt.Sprintf("/srv/p%04d", i)
		stores = append(stores, s)
		if i < 600 {
			items = append(items, [2]string{s + "/.env", s})
		}
	}
	if w := dataReq(srv, http.MethodPost, "/api/v1/data/inventory", deviceCredentialHeader, key,
		dataDoc("00000000000000a1", 1000, true, stores, items, "")); w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	get := func(contract string) map[string]json.RawMessage {
		w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings?contract="+contract, "mock_admin_token")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", contract, w.Code, w.Body.String())
		}
		if w.Body.Len() > feedDocumentBytesV3 {
			t.Fatalf("%s document is %d bytes", contract, w.Body.Len())
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if v2 := get("v2"); v2["data_inventory"] != nil {
		t.Fatal("v2 carries data_inventory")
	}
	v3 := get("v3")
	if string(v3["schema"]) != `"nightshift.findings/v3"` {
		t.Fatalf("schema %s", v3["schema"])
	}
	var blocks []feedDataBlock
	if err := json.Unmarshal(v3["data_inventory"], &blocks); err != nil || len(blocks) != 1 {
		t.Fatalf("blocks: %v %d", err, len(blocks))
	}
	b := blocks[0]
	if b.EndpointID != "ws" || !strings.HasPrefix(b.DeviceID, "dev_") || len(b.Items) != feedDataItemsPerHost || !b.ItemsTruncated ||
		len(b.Stores) == 0 || len(b.Stores) > feedDataStoresPerHost || !b.StoresTruncated {
		t.Fatalf("block: id=%s dev=%s items=%d/%v stores=%d/%v", b.EndpointID, b.DeviceID, len(b.Items), b.ItemsTruncated, len(b.Stores), b.StoresTruncated)
	}
	if b.Scan["sandboxed"] != true || b.Scan["last_complete_at"] != float64(1010) {
		t.Fatalf("scan summary: %v", b.Scan)
	}
}
