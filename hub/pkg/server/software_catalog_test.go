package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

func catalogCall(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "test-admin-key-12345")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

type catalogResp struct {
	Entries    scripts.Catalog `json:"entries"`
	Saved      bool            `json:"saved"`
	Changed    bool            `json:"changed"`
	ApprovalID string          `json:"approval_id"`
}

func mustCatalog(t *testing.T, w *httptest.ResponseRecorder) catalogResp {
	t.Helper()
	var v catalogResp
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	return v
}

// The catalog starts as the shipped seed; adding or widening what an entry
// removes is signed at once and audited with the entry; a name change or a
// delete goes straight through; settings never fill the catalog param.
func TestSoftwareCatalogChanges(t *testing.T) {
	t.Parallel()
	srv, store, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	const path = "/api/v1/maintenance/catalog"
	v := mustCatalog(t, catalogCall(srv, http.MethodGet, path, ""))
	seed, _ := scripts.SeedCatalog()
	if v.Saved || len(v.Entries) != len(seed) || v.Entries.Find("xsplit") == nil {
		t.Fatalf("seed view: %+v", v)
	}
	add := `{"entry":{"id":"bloat-tool","name":"Bloat Tool","kind":"program","match":"Bloat Tool*","category":"adware","method":"registry","flag":"/S","risk":"safe"}}`
	v = mustCatalog(t, catalogCall(srv, http.MethodPut, path, add))
	if !v.Saved || !v.Changed || v.ApprovalID == "" || v.Entries.Find("bloat-tool") == nil {
		t.Fatalf("first request: %+v", v)
	}
	if !authorizedAuditHas(t, store, "Software removal catalog: add Bloat Tool (adware; matches 'Bloat Tool*'; the program's own uninstaller /S)", v.ApprovalID) {
		t.Fatalf("no ACTION_AUTHORIZED row for the added entry: %+v", authorizedAudit(t, store))
	}
	// Renaming is not a loosening; widening the match is signed at once too.
	if v := mustCatalog(t, catalogCall(srv, http.MethodPut, path, strings.Replace(add, `"Bloat Tool",`, `"Bloat Tool Suite",`, 1))); v.Entries.Find("bloat-tool").Name != "Bloat Tool Suite" || v.ApprovalID != "" {
		t.Fatalf("a rename did not apply plainly: %+v", v)
	}
	wide := strings.Replace(strings.Replace(add, `"Bloat Tool",`, `"Bloat Tool Suite",`, 1), `"Bloat Tool*"`, `"Bloat*"`, 1)
	v = mustCatalog(t, catalogCall(srv, http.MethodPut, path, wide))
	if v.Entries.Find("bloat-tool").Match != "Bloat*" || !authorizedAuditHas(t, store, "match Bloat Tool* -> Bloat*") {
		t.Fatalf("widened match: %+v", v)
	}
	// Invalid entries are refused before anything is signed.
	n := len(authorizedAudit(t, store))
	if w := catalogCall(srv, http.MethodPut, path, strings.Replace(add, `"Bloat Tool*"`, `"**"`, 1)); w.Code != http.StatusBadRequest {
		t.Fatalf("a match-everything entry: %d", w.Code)
	}
	if got := len(authorizedAudit(t, store)); got != n {
		t.Fatalf("a refused entry was authorized: %d -> %d rows", n, got)
	}
	// Deleting tightens.
	if v := mustCatalog(t, catalogCall(srv, http.MethodDelete, path+"?id=xsplit", "")); v.Entries.Find("xsplit") != nil {
		t.Fatal("delete did not apply")
	}
	if w := catalogCall(srv, http.MethodPut, "/api/v1/maintenance/settings", `{"package":"windows-software-removal","params":{"catalog":"[]"}}`); w.Code == http.StatusOK {
		t.Fatal("a setting set the catalog")
	}
}

// A run of the removal package carries the catalog in force.
func TestSoftwareRemovalRunCarriesTheCatalog(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "software-removal.ps1")
	// Even an audit of a careful package is authorized and dispatched on the
	// first request.
	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-software-removal"],"mode":"audit"}`
	if w := adminPost(srv, "/api/v1/maintenance/run", audit, ""); w.Code != http.StatusCreated {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
	if !authorizedAuditHas(t, store, "windows-software-removal (audit)") {
		t.Fatalf("audit authorization: %+v", authorizedAudit(t, store))
	}
	offers, err := srv.responseStore.OfferPendingJobs("default", "ep-lap", 4, time.Minute)
	if err != nil || len(offers) != 1 {
		t.Fatalf("offers: %v %d", err, len(offers))
	}
	var p response.ScriptExecPayload
	if err := json.Unmarshal([]byte(offers[0].PayloadJSON), &p); err != nil {
		t.Fatal(err)
	}
	c, err := scripts.ParseCatalogWire(p.Parameters["catalog"])
	seed, _ := scripts.SeedCatalog()
	if err != nil || len(c) != len(seed) || p.Parameters["categories"] != "adware,oem_bloat,trialware" {
		t.Fatalf("payload params: %v %v", err, p.Parameters)
	}
	// Enforce is signed at once too.
	if w := adminPost(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["ep-lap"],"packages":["windows-software-removal"],"mode":"enforce"}`, ""); w.Code != http.StatusCreated {
		t.Fatalf("enforce: %d %s", w.Code, w.Body.String())
	}
	if !authorizedAuditHas(t, store, "windows-software-removal (enforce)") {
		t.Fatalf("enforce authorization: %+v", authorizedAudit(t, store))
	}
}
