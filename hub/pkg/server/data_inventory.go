package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Data inventory.
//
// Each agent runs a read-only, sandboxed scan of the roots its policy names
// and reports metadata: stores (directories at a fixed depth, with counts,
// sizes, times and hints), flagged items (secret candidates, private keys,
// encrypted containers, key files - by rule name, never by content) and a
// few host facts. Secret detection runs on the endpoint; nothing it matched
// leaves the host. The hub keeps the latest picture and a run log, and hands
// a bounded copy to Nightshift (contract v3), which classifies and decides.
//
// The hub owns the policy. It is served as text to the agent
// (ominull-data-policy/1) and is disabled for any endpoint whose canary list
// has not been synced: canary files trip when opened, so the agent must know
// them before it walks anything.

const (
	dataPolicyHeader      = "ominull-data-policy/1"
	dataInventorySchema   = "ominull.data-inventory/1"
	dataInventoryMaxBody  = 16 << 20
	dataMaxRoots          = 16
	dataMaxExcludes       = 64
	dataMaxCanaries       = 256
	dataPathMax           = 1023
	dataMaxStoresAccepted = 20000
	dataMaxItemsAccepted  = 5000
)

// dataPolicyDefaults are the hub's built-in values; every layer overrides
// them field by field. Scanning is off until an administrator enables it.
func dataPolicyDefaults() storage.DataPolicy {
	f, t := false, true
	i := func(v int) *int { return &v }
	i64 := func(v int64) *int64 { return &v }
	return storage.DataPolicy{
		Enabled:            &f,
		Roots:              []string{"/home", "/root", "/etc", "/srv", "/opt"},
		Excludes:           []string{},
		StoreDepth:         i(2),
		MaxFiles:           i(300000),
		MaxSeconds:         i(900),
		ContentMaxBytes:    i64(256 << 10),
		ContentBudgetBytes: i64(256 << 20),
		IntervalHours:      i(24),
		ResumeMinutes:      i(60),
		FullEveryDays:      i(7),
		OneFilesystem:      &t,
		MaxStores:          i(3000),
		MaxItems:           i(1000),
	}
}

func mergeDataPolicy(base storage.DataPolicy, layer storage.DataPolicy) storage.DataPolicy {
	if layer.Enabled != nil {
		base.Enabled = layer.Enabled
	}
	if layer.Roots != nil {
		base.Roots = layer.Roots
	}
	if layer.Excludes != nil {
		base.Excludes = layer.Excludes
	}
	if layer.StoreDepth != nil {
		base.StoreDepth = layer.StoreDepth
	}
	if layer.MaxFiles != nil {
		base.MaxFiles = layer.MaxFiles
	}
	if layer.MaxSeconds != nil {
		base.MaxSeconds = layer.MaxSeconds
	}
	if layer.ContentMaxBytes != nil {
		base.ContentMaxBytes = layer.ContentMaxBytes
	}
	if layer.ContentBudgetBytes != nil {
		base.ContentBudgetBytes = layer.ContentBudgetBytes
	}
	if layer.IntervalHours != nil {
		base.IntervalHours = layer.IntervalHours
	}
	if layer.ResumeMinutes != nil {
		base.ResumeMinutes = layer.ResumeMinutes
	}
	if layer.FullEveryDays != nil {
		base.FullEveryDays = layer.FullEveryDays
	}
	if layer.OneFilesystem != nil {
		base.OneFilesystem = layer.OneFilesystem
	}
	if layer.MaxStores != nil {
		base.MaxStores = layer.MaxStores
	}
	if layer.MaxItems != nil {
		base.MaxItems = layer.MaxItems
	}
	return base
}

// dataPathOK mirrors the agent's DataInv_AbsPathOK: absolute, normalised, no
// control bytes, short enough.
func dataPathOK(p string) bool {
	if p == "" || len(p) > dataPathMax || p[0] != '/' {
		return false
	}
	if p != "/" && strings.HasSuffix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return false
		}
	}
	return path.Clean(p) == p
}

func rangeErr(name string, v, lo, hi int64) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
	}
	return nil
}

// validateDataPolicy checks one layer against the agent's accepted ranges, so
// a layer the agent would reject is refused when it is set, not discovered on
// every endpoint later.
func validateDataPolicy(p storage.DataPolicy) error {
	if len(p.Roots) > dataMaxRoots {
		return fmt.Errorf("at most %d roots", dataMaxRoots)
	}
	for _, r := range p.Roots {
		if !dataPathOK(r) {
			return fmt.Errorf("root %q is not an absolute normalised path", r)
		}
	}
	if len(p.Excludes) > dataMaxExcludes {
		return fmt.Errorf("at most %d excludes", dataMaxExcludes)
	}
	for _, e := range p.Excludes {
		if e == "" || len(e) >= 256 || strings.ContainsAny(e, "\n\r\x00") {
			return fmt.Errorf("exclude %q is empty, too long or has a line break", e)
		}
	}
	checks := []struct {
		name   string
		v      *int
		lo, hi int64
	}{
		{"store_depth", p.StoreDepth, 1, 6}, {"max_files", p.MaxFiles, 1000, 5000000}, {"max_seconds", p.MaxSeconds, 30, 14400},
		{"interval_hours", p.IntervalHours, 1, 720}, {"resume_minutes", p.ResumeMinutes, 5, 1440},
		{"full_every_days", p.FullEveryDays, 1, 90}, {"max_stores", p.MaxStores, 10, 20000}, {"max_items", p.MaxItems, 10, 5000},
	}
	for _, c := range checks {
		if c.v != nil {
			if err := rangeErr(c.name, int64(*c.v), c.lo, c.hi); err != nil {
				return err
			}
		}
	}
	if p.ContentMaxBytes != nil {
		if err := rangeErr("content_max_bytes", *p.ContentMaxBytes, 0, 4<<20); err != nil {
			return err
		}
	}
	if p.ContentBudgetBytes != nil {
		if err := rangeErr("content_budget_bytes", *p.ContentBudgetBytes, 0, 8<<30); err != nil {
			return err
		}
	}
	return nil
}

// effectiveDataPolicy is the merged policy for one endpoint and the canary
// paths it must avoid. It is disabled, with a reason, when the canary list was
// never synced.
func (s *Server) effectiveDataPolicy(ep *storage.Endpoint) (storage.DataPolicy, []string, string, error) {
	pol := dataPolicyDefaults()
	layers, err := s.store.DataPolicyLayers(ep.ID, ep.RoleTag)
	if err != nil {
		return pol, nil, "", err
	}
	for _, l := range layers {
		pol = mergeDataPolicy(pol, l.Policy)
	}
	can, synced, err := s.store.GetDataCanaries(ep.ID)
	if err != nil {
		return pol, nil, "", err
	}
	reason := ""
	if *pol.Enabled && !synced {
		f := false
		pol.Enabled = &f
		reason = "canaries_not_synced"
	}
	if *pol.Enabled && len(pol.Roots) == 0 {
		f := false
		pol.Enabled = &f
		reason = "no_roots"
	}
	return pol, can.Paths, reason, nil
}

// renderDataPolicy writes the agent's text form. The version is a hash of
// everything else, so any change - including a canary list change - starts a
// fresh full cycle on the agent.
func renderDataPolicy(p storage.DataPolicy, canaries []string, reason string) string {
	var b strings.Builder
	b01 := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	fmt.Fprintf(&b, "enabled %s\n", b01(*p.Enabled))
	for _, r := range p.Roots {
		fmt.Fprintf(&b, "root %s\n", r)
	}
	for _, e := range p.Excludes {
		fmt.Fprintf(&b, "exclude %s\n", e)
	}
	can := append([]string(nil), canaries...)
	sort.Strings(can)
	for _, c := range can {
		fmt.Fprintf(&b, "canary %s\n", c)
	}
	fmt.Fprintf(&b, "store_depth %d\nmax_files %d\nmax_seconds %d\ncontent_max_bytes %d\ncontent_budget_bytes %d\n",
		*p.StoreDepth, *p.MaxFiles, *p.MaxSeconds, *p.ContentMaxBytes, *p.ContentBudgetBytes)
	fmt.Fprintf(&b, "interval_hours %d\nresume_minutes %d\nfull_every_days %d\none_filesystem %s\nmax_stores %d\nmax_items %d\n",
		*p.IntervalHours, *p.ResumeMinutes, *p.FullEveryDays, b01(*p.OneFilesystem), *p.MaxStores, *p.MaxItems)
	if reason != "" {
		fmt.Fprintf(&b, "reason %s\n", reason) // ignored by the agent; read by people
	}
	body := b.String()
	sum := sha256.Sum256([]byte(body))
	version := binary.BigEndian.Uint32(sum[:4]) % 2000000000
	return fmt.Sprintf("%s\nversion %d\n%send\n", dataPolicyHeader, version, body)
}

// callerEndpoint is the endpoint a device request speaks for: the enrolled
// identity when a device credential was used, else the body's claim (legacy
// tenant key, migration mode only).
func callerEndpoint(r *http.Request, claimed string) (string, bool) {
	if id := r.Header.Get("X-Device-Endpoint-ID"); id != "" {
		return id, claimed == "" || claimed == id
	}
	return claimed, claimed != ""
}

// handleDataPolicy serves an agent its scan policy.
func (s *Server) handleDataPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable policy request")
		return
	}
	id, ok := callerEndpoint(r, req.EndpointID)
	if !ok {
		writeJSONError(w, http.StatusForbidden, "a device may only ask for its own policy")
		return
	}
	ep, err := s.store.GetEndpoint(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "endpoint could not be read")
		return
	}
	if ep == nil || ep.ID != id {
		writeJSONError(w, http.StatusNotFound, "endpoint not registered")
		return
	}
	pol, canaries, reason, err := s.effectiveDataPolicy(ep)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "data policy could not be read")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, renderDataPolicy(pol, canaries, reason))
}

// Agent document, as data_inventory_linux.h writes it.
type dataInvDoc struct {
	Schema     string                     `json:"schema"`
	EndpointID string                     `json:"endpoint_id"`
	Platform   string                     `json:"platform"`
	Run        map[string]json.RawMessage `json:"run"`
	Host       json.RawMessage            `json:"host"`
	Stores     []json.RawMessage          `json:"stores"`
	Items      []json.RawMessage          `json:"items"`
}

type dataInvRun struct {
	CycleID       string `json:"cycle_id"`
	Mode          string `json:"mode"`
	StartedAt     int64  `json:"started_at"`
	FinishedAt    int64  `json:"finished_at"`
	CycleStarted  int64  `json:"cycle_started_at"`
	CycleComplete bool   `json:"cycle_complete"`
	BudgetHit     string `json:"budget_hit"`
	ItemsDropped  int64  `json:"items_dropped"`
	StoresDropped int64  `json:"stores_dropped"`
	PolicyVersion int64  `json:"policy_version"`
	RulesVersion  int64  `json:"rules_version"`
	Sandboxed     bool   `json:"sandboxed"`
}

type dataInvStore struct {
	Path    string `json:"path"`
	Root    string `json:"root"`
	Partial bool   `json:"partial"`
	Files   int64  `json:"files"`
	Bytes   int64  `json:"bytes"`
}

type dataInvItem struct {
	Path  string   `json:"path"`
	Store string   `json:"store"`
	Kind  string   `json:"kind"`
	Rules []string `json:"rules"`
	Mode  int64    `json:"mode"`
	Size  int64    `json:"size"`
	Mtime int64    `json:"mtime"`
}

var dataItemKinds = map[string]bool{"private_key": true, "secret_candidate": true, "encrypted_container": true, "key_file": true}

func ruleNameOK(r string) bool {
	if r == "" || len(r) > 40 {
		return false
	}
	for _, c := range r {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func cycleIDOK(c string) bool {
	if len(c) < 8 || len(c) > 32 {
		return false
	}
	for _, ch := range c {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

// underCanary reports a path that is, or is inside, one of the canary paths.
func underCanary(p string, canaries []string) bool {
	for _, c := range canaries {
		if p == c || strings.HasPrefix(p, c+"/") {
			return true
		}
	}
	return false
}

// parseDataInventory validates an agent document into a store upload. Any
// malformed part rejects the whole document; records naming a canary path are
// dropped (the agent must never report one, so this is a second line) and
// counted.
func parseDataInventory(body []byte, endpointID string, canaries []string, now time.Time) (storage.DataRunUpload, int, error) {
	var u storage.DataRunUpload
	var doc dataInvDoc
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&doc); err != nil {
		return u, 0, fmt.Errorf("unreadable document: %w", err)
	}
	if doc.Schema != dataInventorySchema {
		return u, 0, fmt.Errorf("schema must be %s", dataInventorySchema)
	}
	if doc.EndpointID != endpointID {
		return u, 0, errors.New("endpoint_id does not match the caller")
	}
	if doc.Platform != "linux" && doc.Platform != "windows" {
		return u, 0, errors.New("platform must be linux or windows")
	}
	if len(doc.Stores) > dataMaxStoresAccepted || len(doc.Items) > dataMaxItemsAccepted {
		return u, 0, errors.New("too many stores or items")
	}
	runRaw, err := json.Marshal(doc.Run)
	if err != nil {
		return u, 0, err
	}
	var run dataInvRun
	if err := json.Unmarshal(runRaw, &run); err != nil {
		return u, 0, fmt.Errorf("unreadable run: %w", err)
	}
	if !cycleIDOK(run.CycleID) || (run.Mode != "full" && run.Mode != "incremental") || run.StartedAt <= 0 ||
		run.FinishedAt < 0 || len(run.BudgetHit) > 16 {
		return u, 0, errors.New("run fields out of range")
	}
	u.Run = storage.DataRun{
		EndpointID: endpointID, CycleID: run.CycleID, Mode: run.Mode, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
		CycleStarted: run.CycleStarted, CycleComplete: run.CycleComplete, BudgetHit: run.BudgetHit,
		PolicyVersion: run.PolicyVersion, RulesVersion: run.RulesVersion, Sandboxed: run.Sandboxed,
		Summary: runRaw, ReceivedAt: now,
	}
	u.Complete = run.CycleComplete
	u.Truncated = run.ItemsDropped > 0
	if len(doc.Host) > 0 && !bytes.Equal(doc.Host, []byte("null")) {
		if len(doc.Host) > 256<<10 || !json.Valid(doc.Host) || doc.Host[0] != '{' {
			return u, 0, errors.New("host facts malformed")
		}
		u.Host = doc.Host
	}
	dropped := 0
	u.Partial = map[string]bool{}
	seen := map[string]bool{}
	for _, raw := range doc.Stores {
		var st dataInvStore
		if err := json.Unmarshal(raw, &st); err != nil || !dataPathOK(st.Path) || !dataPathOK(st.Root) || len(raw) > 16<<10 {
			return u, 0, errors.New("store record malformed")
		}
		if seen[st.Path] {
			return u, 0, errors.New("store reported twice")
		}
		seen[st.Path] = true
		if underCanary(st.Path, canaries) {
			dropped++
			continue
		}
		u.Partial[st.Path] = st.Partial
		u.Stores = append(u.Stores, storage.DataStore{Path: st.Path, Doc: raw})
	}
	for _, raw := range doc.Items {
		var it dataInvItem
		if err := json.Unmarshal(raw, &it); err != nil || !dataPathOK(it.Path) || !dataPathOK(it.Store) ||
			!dataItemKinds[it.Kind] || len(it.Rules) == 0 || len(it.Rules) > 40 || len(raw) > 8<<10 {
			return u, 0, errors.New("item record malformed")
		}
		for _, r := range it.Rules {
			if !ruleNameOK(r) {
				return u, 0, errors.New("item rule malformed")
			}
		}
		if !seen[it.Store] || !strings.HasPrefix(it.Path, strings.TrimSuffix(it.Store, "/")+"/") {
			return u, 0, errors.New("item outside the stores reported")
		}
		if underCanary(it.Path, canaries) {
			dropped++
			continue
		}
		u.Items = append(u.Items, storage.DataItem{Path: it.Path, Store: it.Store, Kind: it.Kind, Doc: raw})
	}
	return u, dropped, nil
}

// handleDataInventory accepts one scan run from an agent.
func (s *Server) handleDataInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleDataInventoryRead(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, dataInventoryMaxBody))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "data inventory document too large or unreadable")
		return
	}
	var head struct {
		EndpointID string `json:"endpoint_id"`
	}
	_ = json.Unmarshal(body, &head)
	id, ok := callerEndpoint(r, head.EndpointID)
	if !ok {
		writeJSONError(w, http.StatusForbidden, "a device may only report its own data inventory")
		return
	}
	ep, err := s.store.GetEndpoint(id)
	if err != nil || ep == nil || ep.ID != id {
		writeJSONError(w, http.StatusNotFound, "endpoint not registered")
		return
	}
	can, _, err := s.store.GetDataCanaries(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "canary list could not be read")
		return
	}
	u, dropped, err := parseDataInventory(body, id, can.Paths, time.Now().UTC())
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "data inventory rejected: "+err.Error())
		return
	}
	if dropped > 0 {
		s.audit(r, "DATA_INVENTORY_CANARY_DROPPED", id, fmt.Sprintf("Dropped %d records naming canary paths", dropped))
	}
	err = s.store.RecordDataRun(u)
	if errors.Is(err, storage.ErrDataStaleRun) {
		// Accepted and ignored: refusing would make the agent resend it forever.
		writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "reason": "stale"})
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "data inventory could not be saved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "stores": len(u.Stores), "items": len(u.Items),
		"cycle_complete": u.Complete})
}

// handleDataInventoryRead returns one endpoint's latest picture (admin).
func (s *Server) handleDataInventoryRead(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "only a fleet administrator can read data inventories")
		return
	}
	id := r.URL.Query().Get("endpoint_id")
	if id == "" {
		ids, err := s.store.DataInventoryEndpoints()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "data inventory could not be read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": ids})
		return
	}
	limit := 2000
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v < limit {
		limit = v
	}
	snap, ok, err := s.store.DataSnapshotFor(id, limit, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "data inventory could not be read")
		return
	}
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no data inventory for this endpoint")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, snap)
}

// handleDataPolicies lists or sets policy layers (admin, audited).
func (s *Server) handleDataPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "data policy is fleet-wide; a tenant administrator cannot change it")
		return
	}
	switch r.Method {
	case http.MethodGet:
		layers, err := s.store.ListDataPolicies()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "data policies could not be read")
			return
		}
		resp := map[string]any{"defaults": dataPolicyDefaults(), "layers": layers}
		if id := r.URL.Query().Get("endpoint_id"); id != "" {
			ep, err := s.store.GetEndpoint(id)
			if err != nil || ep == nil {
				writeJSONError(w, http.StatusNotFound, "endpoint not registered")
				return
			}
			pol, canaries, reason, err := s.effectiveDataPolicy(ep)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "data policy could not be read")
				return
			}
			resp["effective"] = pol
			resp["canaries"] = len(canaries)
			resp["disabled_reason"] = reason
			resp["rendered_version"] = strings.SplitN(strings.SplitN(renderDataPolicy(pol, canaries, reason), "\nversion ", 2)[1], "\n", 2)[0]
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req struct {
			Scope  string              `json:"scope"`
			Policy *storage.DataPolicy `json:"policy"`
			Reason string              `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable policy body")
			return
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			writeJSONError(w, http.StatusBadRequest, "say why the scan scope changes")
			return
		}
		if !storage.ValidDataPolicyScope(req.Scope) {
			writeJSONError(w, http.StatusBadRequest, "scope is default, role:<tag> or endpoint:<id>")
			return
		}
		if req.Policy != nil {
			if err := validateDataPolicy(*req.Policy); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.SetDataPolicy(req.Scope, req.Policy, r.Header.Get("X-Username")); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		desc := "removed"
		if req.Policy != nil {
			raw, _ := json.Marshal(req.Policy)
			desc = string(raw)
		}
		s.audit(r, "DATA_POLICY_SET", req.Scope, desc+": "+reason)
		writeJSON(w, http.StatusOK, map[string]any{"scope": req.Scope, "policy": req.Policy})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleDataCanaries records the canary paths of endpoints, as synced from
// Nightshift's canary registry (admin, audited). An empty list is a valid
// sync: it says the endpoint was checked and holds none.
func (s *Server) handleDataCanaries(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "canary lists are fleet-wide")
		return
	}
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("endpoint_id")
		c, ok, err := s.store.GetDataCanaries(id)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "canary list could not be read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoint_id": id, "synced": ok, "count": len(c.Paths),
			"synced_at": c.SyncedAt, "source": c.Source})
	case http.MethodPost:
		var req struct {
			Endpoints []struct {
				EndpointID string   `json:"endpoint_id"`
				Paths      []string `json:"paths"`
			} `json:"endpoints"`
			Source string `json:"source"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable canary body")
			return
		}
		source := strings.TrimSpace(req.Source)
		if source == "" || len(source) > 64 || len(req.Endpoints) == 0 {
			writeJSONError(w, http.StatusBadRequest, "source and at least one endpoint are required")
			return
		}
		now := time.Now().UTC()
		total := 0
		for _, e := range req.Endpoints {
			if len(e.Paths) > dataMaxCanaries {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("at most %d canary paths per endpoint", dataMaxCanaries))
				return
			}
			for i, p := range e.Paths {
				if !dataPathOK(p) {
					// The index, not the path: an error body can end up in a log.
					writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("canary path %d of %s is not absolute and normalised", i, e.EndpointID))
					return
				}
			}
			ep, err := s.store.GetEndpoint(e.EndpointID)
			if err != nil || ep == nil || ep.ID != e.EndpointID {
				writeJSONError(w, http.StatusNotFound, "endpoint not registered: "+e.EndpointID)
				return
			}
		}
		for _, e := range req.Endpoints {
			if err := s.store.SetDataCanaries(storage.DataCanaries{EndpointID: e.EndpointID, Paths: e.Paths, SyncedAt: now, Source: source}); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "canary list could not be saved")
				return
			}
			total += len(e.Paths)
		}
		// Counts only: the paths themselves are what an intruder would want.
		s.audit(r, "DATA_CANARIES_SYNCED", "data-inventory", fmt.Sprintf("Synced %d canary paths for %d endpoints from %s",
			total, len(req.Endpoints), source))
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": len(req.Endpoints), "paths": total})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
