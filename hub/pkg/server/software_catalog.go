package server

// The software removal catalog: GET/PUT/DELETE /api/v1/maintenance/catalog.
// One settings row holds the catalog (scripts.Catalog); a hub that never
// saved one uses the seed shipped with it. Adding or changing an entry widens
// what a removal package may uninstall, so the authority authorizes it
// through the same hub-policy path as a detection loosening (the
// authority writes the statement from the entry itself); a change to name or
// note only, and deleting an entry, go straight through. Every run of a
// package with a catalog parameter carries the catalog as it is at that
// moment, so the run's own approval covers the exact entries it uses.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

const (
	softwareCatalogSetting = "maintenance.software_catalog"
	softwareCatalogAudit   = "SOFTWARE_CATALOG_CHANGED"
)

// softwareCatalog is the catalog in force and whether it was saved here.
func (s *Server) softwareCatalog() (scripts.Catalog, bool) {
	if raw, err := s.store.GetSetting(softwareCatalogSetting); err == nil && raw != "" {
		var c scripts.Catalog
		if err := json.Unmarshal([]byte(raw), &c); err == nil && c.Validate() == nil {
			return c.Sorted(), true
		}
		log.Printf("[!] Ignoring an unreadable or invalid saved software catalog; using the shipped one.")
	}
	c, err := scripts.SeedCatalog()
	if err != nil {
		log.Printf("[!] The shipped software catalog is invalid: %v", err)
		return nil, false
	}
	return c, false
}

// fillCatalogParams puts the catalog in force into a run's catalog params.
func (s *Server) fillCatalogParams(h *scripts.PackageHeader, params map[string]string) error {
	names := h.CatalogParams()
	if len(names) == 0 {
		return nil
	}
	c, _ := s.softwareCatalog()
	w, err := c.Wire()
	if err != nil {
		return err
	}
	for _, n := range names {
		params[n] = w
	}
	// Agents take at most 16 KiB of parameters (SCRIPT_EXEC_MAX_PARAMS_BYTES).
	if raw, _ := json.Marshal(params); len(raw) > agentMaxParamsBytes {
		return fmt.Errorf("%s with this catalog is %d bytes of parameters; agents take at most %d, so shorten the catalog", h.Name, len(raw), agentMaxParamsBytes)
	}
	return nil
}

const agentMaxParamsBytes = 15 * 1024 // 16 KiB in the agents, less room for the JSON around it

func (s *Server) catalogView() map[string]interface{} {
	c, saved := s.softwareCatalog()
	if c == nil {
		c = scripts.Catalog{}
	}
	return map[string]interface{}{
		"entries": c, "saved": saved,
		"categories": scripts.CatalogCategories, "methods": scripts.CatalogMethods, "flags": scripts.CatalogFlags,
	}
}

func (s *Server) handleSoftwareCatalog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.catalogView())
		return
	case http.MethodPut, http.MethodDelete:
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin credential required to change the software catalog")
		return
	}
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	cur, _ := s.softwareCatalog()
	if r.Method == http.MethodDelete {
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if cur.Find(id) == nil {
			writeJSONError(w, http.StatusNotFound, "no catalog entry "+id)
			return
		}
		next := scripts.Catalog{}
		for _, e := range cur {
			if e.ID != id {
				next = append(next, e)
			}
		}
		if !s.saveCatalog(w, next) {
			return
		}
		s.audit(r, softwareCatalogAudit, "catalog:"+id, "removed "+id+"; credential "+credentialOf(r)+" (unverified)")
		writeJSON(w, http.StatusOK, s.catalogView())
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 16 KiB")
		return
	}
	var req struct {
		Entry scripts.CatalogEntry `json:"entry"`
	}
	if !decodeInto(w, body, &req) {
		return
	}
	e := req.Entry
	if err := e.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	before := cur.Find(e.ID)
	next := scripts.Catalog{}
	for _, x := range cur {
		if x.ID != e.ID {
			next = append(next, x)
		}
	}
	next = append(next, e).Sorted()
	if err := next.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	op, how := "add", "added"
	var loosens []string
	var beforeMap map[string]interface{}
	if before != nil {
		op, how = "change", "changed"
		if *before == e {
			view := s.catalogView()
			view["changed"] = false
			writeJSON(w, http.StatusOK, view)
			return
		}
		b, a := *before, e
		b.Name, b.Note, a.Name, a.Note = "", "", "", ""
		if b != a {
			loosens = []string{"what " + e.ID + " removes or how"}
		}
		beforeMap = catalogEntryMap(*before)
	} else {
		loosens = []string{"a new entry " + e.ID}
	}
	wording := "name or note of " + e.ID
	if len(loosens) > 0 {
		if wording, err = responseauth.SoftwareCatalogWording("catalog:"+e.ID, beforeMap, catalogEntryMap(e)); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	c := policyChange{policy: "software_catalog", op: op, target: "catalog:" + e.ID, after: e,
		loosens: loosens, wording: wording, subject: "the software removal catalog"}
	if before != nil {
		c.before = *before
	}
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
	if !s.saveCatalog(w, next) {
		return
	}
	if approvalID != "" {
		how += ", authorization " + approvalID
	}
	s.audit(r, softwareCatalogAudit, "catalog:"+e.ID, how+": "+wording+"; credential "+credentialOf(r)+" (unverified)")
	view := s.catalogView()
	view["changed"] = true
	if approvalID != "" {
		view["approval_id"] = approvalID
	}
	writeJSON(w, http.StatusOK, view)
}

func catalogEntryMap(e scripts.CatalogEntry) map[string]interface{} {
	raw, _ := json.Marshal(e)
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func (s *Server) saveCatalog(w http.ResponseWriter, c scripts.Catalog) bool {
	raw, err := json.Marshal(c.Sorted())
	if err == nil {
		err = s.store.SetSetting(softwareCatalogSetting, string(raw))
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the catalog could not be saved: "+err.Error())
		return false
	}
	return true
}
