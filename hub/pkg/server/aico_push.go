package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ominull/hub/pkg/storage"
)

// Aico push.
//
// The hub pushes its paging alerts (as notices) and its health (as Status
// rows) to Aico's OmniNull door, POST /api/ominull/push, every minute. Aico
// holds only the SHA-256 of the hub's push key (its ominull-keys.json), so the
// key is made here, kept here and sent as X-API-Key; no answer ever returns or
// logs it. Notices ask the owner once per incident (and once more for its
// first escalation); "That was me" comes back through the alerts/verdict
// route. Rows are re-sent every pass and carry a next_run, so a hub that
// stops pushing shows late in Aico.

const (
	aicoURLSetting     = "aico_push_url"
	aicoKeySetting     = "aico_push_key"
	aicoSinceSetting   = "aico_push_since"
	aicoLastAtSetting  = "aico_push_last_at"
	aicoLastOKSetting  = "aico_push_last_ok_at"
	aicoLastErrSetting = "aico_push_last_error"
	// aicoRowsSetting is JSON {"<row id>": "<what>"}: the rows Aico last
	// accepted with a next_run. A row the hub stops producing is resolved
	// once (aicoResolvedRows), so it never shows late in Aico.
	aicoRowsSetting = "aico_push_rows"
	// retiredKeysSetting is JSON [{"id","clean_from"}]: release keys that
	// agents older than clean_from still trust.
	retiredKeysSetting = "retired_release_keys"

	aicoKeyName      = "ominull-hub"
	aicoPushPath     = "/api/ominull/push"
	aicoPushInterval = time.Minute
	aicoPushTimeout  = 15 * time.Second
	aicoLookback     = 7 * 24 * time.Hour
	aicoSentKeep     = 30 * 24 * time.Hour
	aicoRowsDue      = 5 * time.Minute
	aicoListMax      = 50
	aicoKeyMax       = 200
	aicoRowMachine   = "ominull-hub"
	aicoRowProject   = "ominull"
	escalationSuffix = "+escalation"
)

const defaultRetiredKeys = `[{"id":"1932669bb5871af4","clean_from":"1.8.71"}]`

// consoleOnlyTypes are closed in the OmniNull console, never by one answer.
var consoleOnlyTypes = map[string]bool{"THREAT_INTEL_MATCH": true, "C2_BEACONING": true}

var (
	aicoKeyID     = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	aicoAlertID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@+=-]*$`)
	aicoRowIDBad  = regexp.MustCompile(`[^A-Za-z0-9._:/@-]`)
	aicoVersionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})$`)
)

// ---- configuration route ----

// aicoPushURL validates the receiver URL: http, a loopback or private IPv4
// literal with a port, and exactly the push path.
func aicoPushURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("the Aico URL must look like http://192.168.1.10:8090%s", aicoPushPath)
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() || !(ip.IsLoopback() || ip.IsPrivate()) {
		return "", fmt.Errorf("the Aico host must be a private or loopback IPv4 address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("the Aico URL needs a port")
	}
	if u.Path != aicoPushPath {
		return "", fmt.Errorf("the Aico URL path must be %s", aicoPushPath)
	}
	return fmt.Sprintf("http://%s:%d%s", ip, port, aicoPushPath), nil
}

func (s *Server) newAicoKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := "onp_" + hex.EncodeToString(raw)
	if err := s.store.SetSetting(aicoKeySetting, key); err != nil {
		return "", err
	}
	return key, nil
}

type aicoPushState struct {
	URL       string `json:"url"`
	KeyName   string `json:"key_name"`
	KeySHA256 string `json:"key_sha256"`
	Since     string `json:"since"`
	LastPush  string `json:"last_push_at"`
	LastOK    string `json:"last_ok_at"`
	LastError string `json:"last_error"`
}

func (s *Server) aicoPushState() aicoPushState {
	get := func(k string) string { v, _ := s.store.GetSetting(k); return v }
	st := aicoPushState{URL: get(aicoURLSetting), KeyName: aicoKeyName, Since: get(aicoSinceSetting),
		LastPush: get(aicoLastAtSetting), LastOK: get(aicoLastOKSetting), LastError: get(aicoLastErrSetting)}
	if key := get(aicoKeySetting); key != "" {
		st.KeySHA256 = hashFeedKey(key)
	}
	return st
}

// handleAicoPush: GET/POST /api/v1/integrations/aico (fleet administrator).
func (s *Server) handleAicoPush(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.aicoPushState())
	case http.MethodPost:
		var body struct {
			URL    string `json:"url"`
			Rotate bool   `json:"rotate"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "send {\"url\": \"http://<private IPv4>:<port>"+aicoPushPath+"\"} or {\"rotate\": true}")
			return
		}
		if body.URL == "" && !body.Rotate {
			writeJSONError(w, http.StatusBadRequest, "send a url, or rotate: true")
			return
		}
		now := time.Now().UTC()
		if body.URL != "" {
			clean, err := aicoPushURL(body.URL)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := s.store.SetSetting(aicoURLSetting, clean); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "the URL could not be saved")
				return
			}
			s.audit(r, "AICO_PUSH_URL_SET", "aico", "Set the Aico push URL to "+clean)
		}
		existing, _ := s.store.GetSetting(aicoKeySetting)
		if existing == "" || body.Rotate {
			if _, err := s.newAicoKey(); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "the push key could not be made")
				return
			}
			if body.Rotate && existing != "" {
				s.audit(r, "AICO_PUSH_KEY_ROTATED", "aico", "Made a new Aico push key; the old one stops working once Aico's key list changes")
			} else {
				s.audit(r, "AICO_PUSH_KEY_MADE", "aico", "Made the Aico push key")
			}
		}
		if since, _ := s.store.GetSetting(aicoSinceSetting); since == "" {
			_ = s.store.SetSetting(aicoSinceSetting, now.Format(time.RFC3339))
		}
		writeJSON(w, http.StatusOK, s.aicoPushState())
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ---- push loop ----

func (s *Server) aicoPushLoop() {
	client := &http.Client{Timeout: aicoPushTimeout}
	ticker := time.NewTicker(aicoPushInterval)
	defer ticker.Stop()
	for {
		s.aicoPushPass(time.Now().UTC(), client)
		<-ticker.C
	}
}

type aicoField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type aicoNotice struct {
	V        int         `json:"v"`
	Source   string      `json:"source"`
	Kind     string      `json:"kind"`
	Severity string      `json:"severity"`
	Title    string      `json:"title"`
	Body     string      `json:"body"`
	Detail   string      `json:"detail,omitempty"`
	Key      string      `json:"key"`
	Open     string      `json:"open,omitempty"`
	Fields   []aicoField `json:"fields,omitempty"`
	Actions  []string    `json:"actions"`
	Primary  string      `json:"primary"`
	Push     string      `json:"push"`
}

type aicoRow struct {
	ID      string `json:"id"`
	What    string `json:"what"`
	Kind    string `json:"kind"`
	Machine string `json:"machine"`
	Project string `json:"project"`
	State   string `json:"state"`
	Meaning string `json:"meaning"`
	LastRun string `json:"last_run"`
	NextRun string `json:"next_run,omitempty"`
}

// aicoPushPass sends one push: the unsent notices (at most 50) and every
// row. With no URL or key it does nothing. A non-2xx answer or a failed
// connection keeps the notices for the next pass.
func (s *Server) aicoPushPass(now time.Time, client *http.Client) {
	target, _ := s.store.GetSetting(aicoURLSetting)
	key, _ := s.store.GetSetting(aicoKeySetting)
	if target == "" || key == "" {
		return
	}
	_ = s.store.PruneAicoPushSent(now.Add(-aicoSentKeep))
	notices, tokens, noticeErr := s.aicoNotices(now)
	if noticeErr != nil {
		log.Printf("[!] Aico push: reading alerts failed: %v", noticeErr)
	}
	rows := s.aicoAllRows(now)
	shown := s.aicoShownRows()
	// A row cut by the 50 limit is still produced, so it is never resolved.
	resolved := aicoResolvedRows(shown, rows, now, aicoListMax-min(len(rows), aicoListMax))
	if len(rows) > aicoListMax {
		rows = rows[:aicoListMax]
	}
	err := aicoPost(client, target, key, notices, append(append([]aicoRow{}, rows...), resolved...))
	_ = s.store.SetSetting(aicoLastAtSetting, now.Format(time.RFC3339))
	switch {
	case err != nil:
		_ = s.store.SetSetting(aicoLastErrSetting, err.Error())
		log.Printf("[!] Aico push failed: %v", err)
	default:
		_ = s.store.SetSetting(aicoLastOKSetting, now.Format(time.RFC3339))
		if noticeErr != nil {
			_ = s.store.SetSetting(aicoLastErrSetting, "the alerts could not be read; health was sent")
		} else {
			_ = s.store.SetSetting(aicoLastErrSetting, "")
		}
		s.saveAicoShownRows(shown, rows, resolved)
		if len(tokens) > 0 {
			if err := s.store.MarkAicoPushSent(tokens, now); err != nil {
				log.Printf("[!] Aico push: recording sent notices failed: %v", err)
			}
		}
	}
}

func aicoPost(client *http.Client, target, key string, notices []aicoNotice, rows []aicoRow) error {
	if notices == nil {
		notices = []aicoNotice{}
	}
	if rows == nil {
		rows = []aicoRow{}
	}
	payload, err := json.Marshal(map[string]any{"notices": notices, "rows": rows})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		// The error text carries the URL, never the key (a header).
		return fmt.Errorf("Aico not reached: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Aico answered %d", resp.StatusCode)
	}
	return nil
}

// aicoShownRows reads the rows Aico last accepted with a next_run (id -> what).
func (s *Server) aicoShownRows() map[string]string {
	shown := map[string]string{}
	if raw, _ := s.store.GetSetting(aicoRowsSetting); raw != "" {
		_ = json.Unmarshal([]byte(raw), &shown)
	}
	return shown
}

// aicoResolvedRows resolves the rows Aico shows that the hub no longer
// produces (a section that recovered, a finding that went away): one ok row
// with no next_run, so Aico shows it settled instead of late. At most room.
func aicoResolvedRows(shown map[string]string, rows []aicoRow, now time.Time, room int) []aicoRow {
	live := map[string]bool{}
	for _, r := range rows {
		live[r.ID] = true
	}
	var gone []string
	for id := range shown {
		if !live[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	var out []aicoRow
	for _, id := range gone {
		if len(out) >= room {
			break
		}
		what := shown[id]
		if what == "" {
			what = id
		}
		out = append(out, aicoRow{ID: id, What: cutRunes(what, 120), Kind: "check", Machine: aicoRowMachine, Project: aicoRowProject,
			State: "ok", Meaning: "Resolved: the OmniNull hub no longer reports this", LastRun: now.UTC().Format(time.RFC3339)})
	}
	return out
}

// saveAicoShownRows records, after Aico accepted a push, the rows it now
// shows with a next_run: this pass's rows, plus earlier ones not yet resolved.
func (s *Server) saveAicoShownRows(shown map[string]string, rows, resolved []aicoRow) {
	next := map[string]string{}
	for id, what := range shown {
		next[id] = what
	}
	for _, r := range resolved {
		delete(next, r.ID)
	}
	for _, r := range rows {
		if r.NextRun != "" {
			next[r.ID] = r.What
		}
	}
	raw, err := json.Marshal(next)
	if err == nil {
		err = s.store.SetSetting(aicoRowsSetting, string(raw))
	}
	if err != nil {
		log.Printf("[!] Aico push: recording the shown rows failed: %v", err)
	}
}

// ---- notices ----

func cutRunes(text string, max int) string {
	if utf8.RuneCountInString(text) <= max {
		return text
	}
	return strings.TrimSpace(string([]rune(text)[:max-1])) + "…"
}

func oneLine(text string) string { return strings.Join(strings.Fields(text), " ") }

// aicoWhen words an RFC 3339 time in UTC: 19:16 UTC today, else Wed 14 Oct 19:16 UTC.
func aicoWhen(at string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return ""
	}
	t, now = t.UTC(), now.UTC()
	if t.Format("2006-01-02") == now.Format("2006-01-02") {
		return t.Format("15:04") + " UTC"
	}
	return t.Format("Mon 02 Jan 15:04") + " UTC"
}

type aicoGroup struct {
	token  string
	alerts []feedAlert // oldest first; the last one leads
}

// aicoTokens are the asks a paging alert makes: its incident, plus the
// incident's escalation; an alert with no incident asks by its own id.
func aicoTokens(d feedAlert) []string {
	if d.Incident == "" {
		return []string{d.ID}
	}
	if d.Escalation {
		return []string{d.Incident, d.Incident + escalationSuffix}
	}
	return []string{d.Incident}
}

// aicoNotices builds the notices not yet sent, with their tokens (same order).
func (s *Server) aicoNotices(now time.Time) ([]aicoNotice, []string, error) {
	since := now.Add(-aicoLookback)
	if raw, _ := s.store.GetSetting(aicoSinceSetting); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil && t.After(since) {
			since = t
		}
	}
	list, err := s.store.NewOpenAlerts(since, feedAlertScan)
	if err != nil {
		return nil, nil, err
	}
	tuning := s.store.GetDetectionTuning()
	var described []feedAlert
	for _, a := range list {
		if d := describeAlert(a, tuning); d.pages() && d.ID != "" {
			described = append(described, d)
		}
	}
	sort.SliceStable(described, func(i, j int) bool { return described[i].At < described[j].At })
	var groups []*aicoGroup
	byToken := map[string]*aicoGroup{}
	for _, d := range described {
		for _, tok := range aicoTokens(d) {
			g := byToken[tok]
			if g == nil {
				g = &aicoGroup{token: tok}
				byToken[tok] = g
				groups = append(groups, g)
			}
			g.alerts = append(g.alerts, d)
		}
	}
	all := make([]string, len(groups))
	for i, g := range groups {
		all[i] = g.token
	}
	sent, err := s.store.AicoPushSent(all)
	if err != nil {
		return nil, nil, err
	}
	var notices []aicoNotice
	var tokens []string
	for _, g := range groups {
		if sent[g.token] {
			continue
		}
		if len(notices) == aicoListMax {
			break
		}
		if n, ok := s.aicoNotice(g, now); ok {
			notices = append(notices, n)
			tokens = append(tokens, g.token)
		}
	}
	return notices, tokens, nil
}

func (s *Server) aicoNotice(g *aicoGroup, now time.Time) (aicoNotice, bool) {
	lead := g.alerts[len(g.alerts)-1]
	// The ids the owner's "That was me" confirms: newest first, as many as fit.
	prefix, key, seen := "alerts:", "", map[string]bool{}
	var ids []string
	for i := len(g.alerts) - 1; i >= 0 && len(ids) < verdictMaxIDs; i-- {
		id := g.alerts[i].ID
		if seen[id] || !aicoAlertID.MatchString(id) || len(prefix)+len(strings.Join(append(ids, id), ",")) > aicoKeyMax {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return aicoNotice{}, false
	}
	key = prefix + strings.Join(ids, ",")
	when := aicoWhen(lead.At, now)
	sentence := strings.TrimRight(oneLine(lead.What), ".!? ")
	body := sentence
	if when != "" {
		body += " at " + when
	}
	body = cutRunes(body+".", 1000)
	var detail []string
	add := func(label, v string) {
		if v = oneLine(v); v != "" {
			detail = append(detail, label+v)
		}
	}
	add("Seen ", when)
	add("Program: ", lead.Process)
	add("Command: ", lead.Command)
	add("Connected to: ", lead.Destinations)
	add("Likely cause: ", lead.Cause)
	add("Actor: ", lead.Actor)
	var fields []aicoField
	field := func(label, v string) {
		if v = oneLine(v); v != "" {
			fields = append(fields, aicoField{label, cutRunes(v, 300)})
		}
	}
	field("Host", lead.Host)
	field("Rule", ruleName(lead.Type))
	field("Program", lead.Process)
	field("Seen", when)
	console := false
	for _, a := range g.alerts {
		console = console || consoleOnlyTypes[a.Type]
	}
	actions := []string{"not-expected", "expected", "look-into"}
	if console {
		actions = []string{"not-expected", "look-into"}
	}
	n := aicoNotice{V: 1, Source: "ominull", Kind: "alert", Severity: "critical",
		Title:  cutRunes("Security alert on "+oneLine(lead.Host), 200),
		Body:   body,
		Detail: cutRunes(strings.Join(detail, "\n"), 4000),
		Key:    key, Fields: fields, Actions: actions, Primary: "not-expected", Push: "phone"}
	if base := strings.TrimSuffix(s.hubURL, "/"); strings.HasPrefix(base, "https://") && len(base) <= 300 {
		n.Open = base
		n.Actions = append(n.Actions, "open")
	}
	return n, true
}

// ---- rows ----

// foldedRows are findings whose uid carries a per-item id; they fold into one
// row per prefix so rows never pile up.
var foldedRows = []string{"ominull.run.", "ominull.decisions.", "ominull.compliance."}

func foldRowID(uid string) string {
	for _, p := range foldedRows {
		if strings.HasPrefix(uid, p) {
			return strings.TrimSuffix(p, ".")
		}
	}
	return aicoRowIDBad.ReplaceAllString(uid, "-")
}

// aicoRowState is warn for a finding that is open and not merely a note. A finding that only waits on a
// machine that is off is off: nothing can be done until the machine is back, so it is not a problem.
func aicoRowState(f feedFinding) string {
	if f.StatusID == ocsfStatusResolved || f.SeverityID <= ocsfSevInformational {
		return "ok"
	}
	if pending, _ := f.Unmapped[pendingHostKey].(bool); pending {
		return "off"
	}
	return "warn"
}

// aicoFindingRows maps findings to rows, one per row id, the worst state
// leading its row.
func aicoFindingRows(findings []feedFinding, now time.Time) []aicoRow {
	type acc struct {
		row   aicoRow
		count int
		warn  int
	}
	byID := map[string]*acc{}
	var order []string
	for _, f := range findings {
		uid, _ := f.FindingInfo["uid"].(string)
		title, _ := f.FindingInfo["title"].(string)
		if uid == "" {
			continue
		}
		id := foldRowID(uid)
		state := aicoRowState(f)
		meaning := oneLine(f.Message)
		if meaning == "" {
			meaning = title
		}
		kind := "check"
		if id == "ominull.hub" {
			kind = "service"
		}
		row := aicoRow{ID: cutRunes(id, 200), What: cutRunes(title, 120), Kind: kind, Machine: aicoRowMachine, Project: aicoRowProject,
			State: state, Meaning: cutRunes(meaning, 300)}
		a := byID[id]
		if a == nil {
			byID[id] = &acc{row: row, count: 1, warn: btoi(state == "warn")}
			order = append(order, id)
			continue
		}
		a.count++
		a.warn += btoi(state == "warn")
		if state == "warn" && a.row.State != "warn" {
			a.row = row
		}
	}
	rows := make([]aicoRow, 0, len(order))
	for _, id := range order {
		a := byID[id]
		switch {
		case a.count > 1 && a.warn > 1:
			a.row.Meaning = cutRunes(fmt.Sprintf("%s (and %d more need a look)", a.row.Meaning, a.warn-1), 300)
		case a.count > 1 && a.warn == 0:
			a.row.Meaning = cutRunes(fmt.Sprintf("%s: %d records, none needing you", a.row.What, a.count), 300)
		}
		a.row.LastRun = now.UTC().Format(time.RFC3339)
		a.row.NextRun = now.Add(aicoRowsDue).UTC().Format(time.RFC3339)
		rows = append(rows, a.row)
	}
	return rows
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// aicoRows is every health row plus the retired-build rows, at most 50 with
// the ones needing a look first.
func (s *Server) aicoRows(now time.Time) []aicoRow {
	rows := s.aicoAllRows(now)
	if len(rows) > aicoListMax {
		rows = rows[:aicoListMax]
	}
	return rows
}

// aicoAllRows is every row the hub produces this pass: the hub's own machine row first, then the
// rest with the ones needing a look first. Uncut.
func (s *Server) aicoAllRows(now time.Time) []aicoRow {
	rows := append(aicoFindingRows(s.healthFindings(now), now), s.retiredBuildRows(now)...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].State == "warn" && rows[j].State != "warn" })
	return append([]aicoRow{aicoMachineRow(now)}, rows...)
}

// aicoMachineRow is the hub's own liveness row. Aico shows every other row of a machine as
// unknown ("no word from ominull-hub") unless the machine itself reports a kind=machine row with
// a next_run, so the hub pushes one every pass, ahead of the cut at aicoListMax.
func aicoMachineRow(now time.Time) aicoRow {
	return aicoRow{ID: "ominull.machine", What: aicoRowMachine, Kind: "machine", Machine: aicoRowMachine, Project: aicoRowProject,
		State: "ok", Meaning: "The OmniNull hub is up and pushing its checks",
		LastRun: now.UTC().Format(time.RFC3339), NextRun: now.Add(aicoRowsDue).UTC().Format(time.RFC3339)}
}

type retiredKey struct {
	ID        string `json:"id"`
	CleanFrom string `json:"clean_from"`
}

func parseAgentVersion(v string) ([]int, bool) {
	m := aicoVersionRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(m[1], ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out, true
}

func versionLess(a, b []int) bool {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func (s *Server) retiredKeys() []retiredKey {
	raw, _ := s.store.GetSetting(retiredKeysSetting)
	if strings.TrimSpace(raw) == "" {
		raw = defaultRetiredKeys
	}
	var in []retiredKey
	if json.Unmarshal([]byte(raw), &in) != nil {
		return nil
	}
	var out []retiredKey
	for _, k := range in {
		k.CleanFrom = strings.TrimPrefix(strings.TrimSpace(k.CleanFrom), "v")
		if _, ok := parseAgentVersion(k.CleanFrom); ok && aicoKeyID.MatchString(k.ID) {
			out = append(out, k)
		}
	}
	return out
}

// retiredBuildRows is one row per retired release key: warn while an enrolled
// agent (offline ones too: an old build that is off still trusts the old key
// when it wakes) runs a build older than clean_from or one that cannot be read.
func (s *Server) retiredBuildRows(now time.Time) []aicoRow {
	keys := s.retiredKeys()
	if len(keys) == 0 {
		return nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		log.Printf("[!] Aico push: retired-build row: %v", err)
		return nil
	}
	var live []storage.Endpoint
	for _, ep := range eps {
		if ep.Status != "retired" {
			live = append(live, ep)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].Hostname+live[i].ID < live[j].Hostname+live[j].ID })
	var rows []aicoRow
	for _, k := range keys {
		need, _ := parseAgentVersion(k.CleanFrom)
		var old []string
		for _, ep := range live {
			if v, ok := parseAgentVersion(ep.DriverVersion); ok && !versionLess(v, need) {
				continue
			}
			name := ep.Hostname
			if name == "" {
				name = ep.ID
			}
			version := ep.DriverVersion
			if version == "" {
				version = "version unknown"
			}
			seen := ""
			if !ep.LastSeenAt.IsZero() {
				seen = ", last seen " + ep.LastSeenAt.UTC().Format("2006-01-02")
			}
			old = append(old, fmt.Sprintf("%s (%s%s)", name, version, seen))
		}
		short := k.ID[:8]
		row := aicoRow{ID: "ominull.builds." + k.ID, What: "Old release key " + short, Kind: "check", Machine: aicoRowMachine, Project: aicoRowProject,
			LastRun: now.UTC().Format(time.RFC3339), NextRun: now.Add(aicoRowsDue).UTC().Format(time.RFC3339)}
		if len(old) == 0 {
			row.State = "ok"
			row.Meaning = fmt.Sprintf("All %d agents run %s or newer, so none trusts the old release key %s", len(live), k.CleanFrom, short)
		} else {
			row.State = "warn"
			named := strings.Join(old[:min(len(old), 6)], "; ")
			if len(old) > 6 {
				named += fmt.Sprintf("; +%d more", len(old)-6)
			}
			noun, verb := "agents", "run"
			if len(old) == 1 {
				noun, verb = "agent", "runs"
			}
			row.Meaning = fmt.Sprintf("%d %s still %s a build that trusts the old release key %s (need %s or newer): %s",
				len(old), noun, verb, short, k.CleanFrom, named)
		}
		row.Meaning = cutRunes(row.Meaning, 300)
		rows = append(rows, row)
	}
	return rows
}
