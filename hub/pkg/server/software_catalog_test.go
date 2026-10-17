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

func catalogCall(srv *Server, method, path, body, approval string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "test-admin-key-12345")
	if approval != "" {
		r.Header.Set(approvalHeader, approval)
	}
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

// The catalog starts as the shipped seed; adding or changing what an entry
// removes waits for the owner, who sees the entry; a name change or a
// delete goes straight through; settings never fill the catalog param.
func TestSoftwareCatalogChanges(t *testing.T) {
	t.Parallel()
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	const path = "/api/v1/maintenance/catalog"
	v := mustCatalog(t, catalogCall(srv, http.MethodGet, path, "", ""))
	seed, _ := scripts.SeedCatalog()
	if v.Saved || len(v.Entries) != len(seed) || v.Entries.Find("xsplit") == nil {
		t.Fatalf("seed view: %+v", v)
	}
	add := `{"entry":{"id":"bloat-tool","name":"Bloat Tool","kind":"program","match":"Bloat Tool*","category":"adware","method":"registry","flag":"/S","risk":"safe"}}`
	p := mustPend(t, catalogCall(srv, http.MethodPut, path, add, ""))
	if p.Action != "Add to the software removal catalog" ||
		p.Summary != "Software removal catalog: add Bloat Tool (adware; matches 'Bloat Tool*'; the program's own uninstaller /S)" {
		t.Fatalf("the owner would see %+v", p)
	}
	if mustCatalog(t, catalogCall(srv, http.MethodGet, path, "", "")).Entries.Find("bloat-tool") != nil {
		t.Fatal("an entry was added before the owner approved it")
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	v = mustCatalog(t, catalogCall(srv, http.MethodPut, path, add, p.ApprovalID))
	if !v.Saved || !v.Changed || v.Entries.Find("bloat-tool") == nil {
		t.Fatalf("after approval: %+v", v)
	}
	// Renaming asks nobody; widening the match asks again.
	if v := mustCatalog(t, catalogCall(srv, http.MethodPut, path, strings.Replace(add, `"Bloat Tool",`, `"Bloat Tool Suite",`, 1), "")); v.Entries.Find("bloat-tool").Name != "Bloat Tool Suite" {
		t.Fatal("a rename did not apply")
	}
	wide := strings.Replace(strings.Replace(add, `"Bloat Tool",`, `"Bloat Tool Suite",`, 1), `"Bloat Tool*"`, `"Bloat*"`, 1)
	p = mustPend(t, catalogCall(srv, http.MethodPut, path, wide, ""))
	if !strings.Contains(p.Summary, "match Bloat Tool* -> Bloat*") {
		t.Fatalf("change wording: %s", p.Summary)
	}
	// Invalid entries are refused before any ask.
	if w := catalogCall(srv, http.MethodPut, path, strings.Replace(add, `"Bloat Tool*"`, `"**"`, 1), ""); w.Code != http.StatusBadRequest {
		t.Fatalf("a match-everything entry: %d", w.Code)
	}
	// Deleting tightens.
	if v := mustCatalog(t, catalogCall(srv, http.MethodDelete, path+"?id=xsplit", "", "")); v.Entries.Find("xsplit") != nil {
		t.Fatal("delete did not apply")
	}
	if w := catalogCall(srv, http.MethodPut, "/api/v1/maintenance/settings", `{"package":"windows-software-removal","params":{"catalog":"[]"}}`, ""); w.Code == http.StatusOK {
		t.Fatal("a setting set the catalog")
	}
}

// A run of the removal package carries the catalog in force.
func TestSoftwareRemovalRunCarriesTheCatalog(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	ownerOf(t, srv)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "software-removal.ps1")
	// A careful package asks even for an audit (as debloat does); the owner
	// sees the catalog's size, never its bytes.
	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-software-removal"],"mode":"audit"}`
	aid := pendingID(t, adminPost(srv, "/api/v1/maintenance/run", audit, ""))
	if a, err := ownerOf(t, srv).auth.GetApproval(aid, ""); err != nil || !strings.Contains(a.Summary, "settings catalog of 19 entries") {
		t.Fatalf("audit ask: %v %+v", err, a)
	}
	ownerOf(t, srv).approve(t, aid)
	if w := adminPost(srv, "/api/v1/maintenance/run", audit, aid); w.Code != http.StatusCreated {
		t.Fatalf("approved audit: %d %s", w.Code, w.Body.String())
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
	// Enforce is a careful package: it asks, naming the catalog's size.
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["ep-lap"],"packages":["windows-software-removal"],"mode":"enforce"}`, ""))
	v, err := ownerOf(t, srv).auth.GetApproval(id, "")
	if err != nil || !strings.Contains(v.Summary, "windows-software-removal (enforce)") || !strings.Contains(v.Summary, "catalog of ") {
		t.Fatalf("enforce ask: %v %+v", err, v)
	}
}
