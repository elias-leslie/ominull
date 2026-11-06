package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/storage"
)

func TestAicoPushURLValidation(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"http://10.0.0.57:8090/api/ominull/push":     "http://10.0.0.57:8090/api/ominull/push",
		"http://127.0.0.1:1/api/ominull/push":        "http://127.0.0.1:1/api/ominull/push",
		" http://192.168.1.5:80/api/ominull/push ":   "http://192.168.1.5:80/api/ominull/push",
		"http://172.16.0.9:9/api/ominull/push":       "http://172.16.0.9:9/api/ominull/push",
		"https://10.0.0.57:8090/api/ominull/push":    "",
		"http://8.8.8.8:8090/api/ominull/push":       "",
		"http://aico.lan:8090/api/ominull/push":      "",
		"http://[::1]:8090/api/ominull/push":         "",
		"http://10.0.0.57/api/ominull/push":          "",
		"http://10.0.0.57:0/api/ominull/push":        "",
		"http://10.0.0.57:99999/api/ominull/push":    "",
		"http://10.0.0.57:8090/other":                "",
		"http://10.0.0.57:8090/api/ominull/push?x=1": "",
		"http://u:p@10.0.0.57:8090/api/ominull/push": "",
		"http://169.254.1.1:8090/api/ominull/push":   "",
		"": "",
	} {
		got, err := aicoPushURL(in)
		if (want == "") != (err != nil) || got != want {
			t.Errorf("aicoPushURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func aicoConfigPost(t *testing.T, srv *Server, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/aico", strings.NewReader(body))
	req.Header.Set("X-API-Key", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if strings.Contains(w.Body.String(), "onp_") {
		t.Fatalf("an answer carried the key: %s", w.Body.String())
	}
	return w.Code, out
}

func TestAicoPushRouteSavesURLMakesKeyAndNeverShowsIt(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()

	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/aico", "mock_tenant_token"); w.Code != http.StatusForbidden {
		t.Fatalf("tenant key read the Aico push config: %d", w.Code)
	}
	tenantAdmin, _ := auth.GenerateJWT(auth.Claims{UserID: "u", Username: "ta", Role: auth.RoleAdmin, TenantID: "t-01"}, "mock_admin_token", time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/aico", nil)
	req.Header.Set("Authorization", "Bearer "+tenantAdmin)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped administrator reached the fleet-wide route: %d", w.Code)
	}

	g := feedRequest(srv, http.MethodGet, "/api/v1/integrations/aico", "mock_admin_token")
	var empty map[string]any
	_ = json.Unmarshal(g.Body.Bytes(), &empty)
	if g.Code != http.StatusOK || empty["url"] != "" || empty["key_sha256"] != "" || empty["key_name"] != "ominull-hub" {
		t.Fatalf("empty config = %d %v", g.Code, empty)
	}

	if code, _ := aicoConfigPost(t, srv, "mock_admin_token", `{"url":"http://8.8.8.8:80/api/ominull/push"}`); code != http.StatusBadRequest {
		t.Fatalf("a public URL was saved: %d", code)
	}
	if code, _ := aicoConfigPost(t, srv, "mock_admin_token", `{}`); code != http.StatusBadRequest {
		t.Fatalf("an empty change was accepted: %d", code)
	}
	code, first := aicoConfigPost(t, srv, "mock_admin_token", `{"url":"http://10.0.0.57:8090/api/ominull/push"}`)
	if code != http.StatusOK || first["url"] != "http://10.0.0.57:8090/api/ominull/push" {
		t.Fatalf("save = %d %v", code, first)
	}
	key, _ := store.GetSetting(aicoKeySetting)
	if !regexp.MustCompile(`^onp_[0-9a-f]{64}$`).MatchString(key) {
		t.Fatalf("key shape %q", key[:min(len(key), 8)])
	}
	if first["key_sha256"] != hashFeedKey(key) || first["since"] == "" {
		t.Fatalf("answer = %v", first)
	}
	// Saving the URL again keeps the key and the cutoff.
	_, again := aicoConfigPost(t, srv, "mock_admin_token", `{"url":"http://10.0.0.58:8090/api/ominull/push"}`)
	if again["key_sha256"] != first["key_sha256"] || again["since"] != first["since"] {
		t.Fatalf("re-saving the URL changed the key or cutoff: %v", again)
	}
	_, rotated := aicoConfigPost(t, srv, "mock_admin_token", `{"rotate":true}`)
	if rotated["key_sha256"] == first["key_sha256"] || rotated["url"] != "http://10.0.0.58:8090/api/ominull/push" {
		t.Fatalf("rotate = %v", rotated)
	}
	if now, _ := store.GetSetting(aicoKeySetting); now == key || rotated["key_sha256"] != hashFeedKey(now) {
		t.Fatal("rotate did not replace the key")
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/aico", "mock_admin_token"); strings.Contains(w.Body.String(), "onp_") {
		t.Fatal("GET carried the key")
	}
}

// ---- notices ----

type aicoReceiver struct {
	mu      sync.Mutex
	status  int
	keys    []string
	notices []map[string]any
	rows    []map[string]any
	server  *httptest.Server
}

func newAicoReceiver(t *testing.T) *aicoReceiver {
	t.Helper()
	r := &aicoReceiver{status: 200}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var body struct {
			Notices []map[string]any `json:"notices"`
			Rows    []map[string]any `json:"rows"`
		}
		_ = json.Unmarshal(raw, &body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.keys = append(r.keys, req.Header.Get("X-API-Key"))
		r.notices, r.rows = body.Notices, body.Rows
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *aicoReceiver) set(status int) { r.mu.Lock(); r.status = status; r.mu.Unlock() }

func aicoConfigure(t *testing.T, srv *Server, store *storage.Store, r *aicoReceiver, since time.Time) {
	t.Helper()
	for k, v := range map[string]string{aicoURLSetting: r.server.URL + aicoPushPath, aicoKeySetting: "onp_" + strings.Repeat("ab", 32),
		aicoSinceSetting: since.UTC().Format(time.RFC3339)} {
		if err := store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
}

func aicoAlert(t *testing.T, store *storage.Store, id, typ, sev, host, incident string, escalation bool, at time.Time) {
	t.Helper()
	ev := map[string]any{"command_line": "ssh -o BatchMode=yes 10.0.0.9 --token=abcdef", "sweep_targets": []map[string]any{{"ip": "10.0.0.9", "ports": []int{22}}}}
	if incident != "" {
		ev["class"], ev["incident"] = "page", incident
		if escalation {
			ev["escalation"] = true
		}
	}
	raw, _ := json.Marshal(ev)
	if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: host, Hostname: host, AnomalyType: typ,
		Severity: sev, Title: "t", Description: "d", ProcessPath: "/usr/bin/ssh", Timestamp: at, Evidence: string(raw)}); err != nil {
		t.Fatal(err)
	}
}

// checkNotice holds a notice to contracts/notice.schema.json.
func checkNotice(t *testing.T, n map[string]any) {
	t.Helper()
	allowed := map[string]bool{"v": true, "source": true, "kind": true, "severity": true, "title": true, "body": true, "detail": true,
		"key": true, "open": true, "command": true, "fields": true, "actions": true, "primary": true, "push": true,
		"cooldown": true, "expires": true, "if_ignored": true}
	for k := range n {
		if !allowed[k] {
			t.Errorf("notice has field %q the schema does not", k)
		}
	}
	str := func(k string, min, max int) string {
		s, _ := n[k].(string)
		if c := utf8.RuneCountInString(s); c < min || c > max {
			t.Errorf("%s has %d characters, schema allows %d-%d", k, c, min, max)
		}
		return s
	}
	if n["v"] != 1.0 || n["source"] != "ominull" || n["kind"] != "alert" || n["severity"] != "critical" || n["push"] != "phone" || n["primary"] != "not-expected" {
		t.Errorf("notice header = %v", n)
	}
	str("title", 1, 200)
	str("body", 1, 1000)
	if _, ok := n["detail"]; ok {
		str("detail", 0, 4000)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@+=,-]{0,199}$`).MatchString(str("key", 1, 200)) || !strings.HasPrefix(n["key"].(string), "alerts:") {
		t.Errorf("key %q", n["key"])
	}
	if o, ok := n["open"].(string); ok && (!strings.HasPrefix(o, "https://") || len(o) > 300) {
		t.Errorf("open %q", o)
	}
	fields, _ := n["fields"].([]any)
	if len(fields) > 8 {
		t.Errorf("%d fields", len(fields))
	}
	for _, f := range fields {
		fm := f.(map[string]any)
		if l, v := fm["label"].(string), fm["value"].(string); l == "" || utf8.RuneCountInString(l) > 40 || v == "" || utf8.RuneCountInString(v) > 300 || len(fm) != 2 {
			t.Errorf("field %v", fm)
		}
	}
	enum := map[string]bool{"expected": true, "not-expected": true, "mute": true, "look-into": true, "answer": true, "open": true, "done": true, "mark-read": true}
	seen := map[string]bool{}
	for _, a := range n["actions"].([]any) {
		if !enum[a.(string)] || seen[a.(string)] {
			t.Errorf("action %v", a)
		}
		seen[a.(string)] = true
	}
}

func TestAicoPushOneNoticePerIncidentAndEscalationThenNoRepeats(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.hubURL = "https://hub.example.test"
	rcv := newAicoReceiver(t)
	now := time.Now().UTC()
	aicoConfigure(t, srv, store, rcv, now.Add(-24*time.Hour))

	// inc-1: a first page and a repeat. inc-2: a page and its escalation.
	aicoAlert(t, store, "a1", "LATERAL_PORT_SWEEP", "HIGH", "ws-01", "inc-1", false, now.Add(-50*time.Minute))
	aicoAlert(t, store, "a2", "LATERAL_PORT_SWEEP", "HIGH", "ws-01", "inc-1", false, now.Add(-40*time.Minute))
	aicoAlert(t, store, "b1", "LATERAL_PORT_SWEEP", "MEDIUM", "srv-01", "inc-2", false, now.Add(-30*time.Minute))
	aicoAlert(t, store, "b2", "LATERAL_PORT_SWEEP", "CRITICAL", "srv-01", "inc-2", true, now.Add(-20*time.Minute))
	// Console-only type: no "expected".
	aicoAlert(t, store, "c1", "C2_BEACONING", "CRITICAL", "lap-01", "inc-3", false, now.Add(-10*time.Minute))
	// Unclassed alert that pages by severity asks by its own id; a LOW one does not page.
	aicoAlert(t, store, "u1", "ENDPOINT_SILENT", "HIGH", "srv-02", "", false, now.Add(-5*time.Minute))
	aicoAlert(t, store, "u2", "ENDPOINT_SILENT", "LOW", "srv-03", "", false, now.Add(-5*time.Minute))

	srv.aicoPushPass(now, rcv.server.Client())
	if len(rcv.notices) != 5 {
		t.Fatalf("notices = %d, want 5 (inc-1, inc-2, inc-2 escalation, inc-3, u1): %v", len(rcv.notices), rcv.notices)
	}
	if rcv.keys[0] != "onp_"+strings.Repeat("ab", 32) {
		t.Fatalf("X-API-Key = %q", rcv.keys[0])
	}
	byKey := map[string]map[string]any{}
	for _, n := range rcv.notices {
		checkNotice(t, n)
		byKey[n["key"].(string)] = n
	}
	for _, k := range []string{"alerts:a2,a1", "alerts:b2,b1", "alerts:b2", "alerts:c1", "alerts:u1"} {
		if byKey[k] == nil {
			t.Fatalf("no notice with key %s; have %v", k, noticeKeys(byKey))
		}
	}
	n := byKey["alerts:b2,b1"]
	if n["title"] != "Security alert on srv-01" || !strings.Contains(n["body"].(string), " at ") || n["open"] != "https://hub.example.test" {
		t.Fatalf("notice = %v", n)
	}
	acts := fmt.Sprint(n["actions"])
	if acts != "[not-expected expected look-into open]" {
		t.Fatalf("actions = %s", acts)
	}
	if got := fmt.Sprint(byKey["alerts:c1"]["actions"]); got != "[not-expected look-into open]" {
		t.Fatalf("console-only actions = %s", got)
	}
	if d := n["detail"].(string); strings.Contains(d, "abcdef") || !strings.Contains(d, "Program: ssh") {
		t.Fatalf("detail = %q", d)
	}
	labels := ""
	for _, f := range n["fields"].([]any) {
		labels += f.(map[string]any)["label"].(string) + ","
	}
	if labels != "Host,Rule,Program,Seen," {
		t.Fatalf("fields = %s", labels)
	}
	if st := srv.aicoPushState(); st.LastOK == "" || st.LastError != "" {
		t.Fatalf("state = %+v", st)
	}

	// Sent tokens are not sent again; a new repeat of inc-1 makes no notice.
	aicoAlert(t, store, "a3", "LATERAL_PORT_SWEEP", "HIGH", "ws-01", "inc-1", false, now.Add(-time.Minute))
	srv.aicoPushPass(now.Add(time.Minute), rcv.server.Client())
	if len(rcv.notices) != 0 {
		t.Fatalf("repeat notices = %v", rcv.notices)
	}
	if len(rcv.rows) == 0 {
		t.Fatal("rows are sent on every pass")
	}
}

func noticeKeys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAicoPushRetriesUntilAccepted(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	rcv := newAicoReceiver(t)
	now := time.Now().UTC()
	aicoConfigure(t, srv, store, rcv, now.Add(-24*time.Hour))
	aicoAlert(t, store, "a1", "LATERAL_PORT_SWEEP", "HIGH", "ws-01", "inc-1", false, now.Add(-time.Hour))

	rcv.set(http.StatusInternalServerError)
	srv.aicoPushPass(now, rcv.server.Client())
	if st := srv.aicoPushState(); st.LastError != "Aico answered 500" || st.LastOK != "" || st.LastPush == "" {
		t.Fatalf("state after a failure = %+v", st)
	}
	rcv.set(http.StatusUnauthorized)
	srv.aicoPushPass(now.Add(time.Minute), rcv.server.Client())
	if len(rcv.notices) != 1 {
		t.Fatalf("the notice was not kept for the retry: %v", rcv.notices)
	}
	rcv.set(http.StatusOK)
	srv.aicoPushPass(now.Add(2*time.Minute), rcv.server.Client())
	if len(rcv.notices) != 1 {
		t.Fatalf("the notice was not retried: %v", rcv.notices)
	}
	if st := srv.aicoPushState(); st.LastError != "" || st.LastOK == "" {
		t.Fatalf("state after success = %+v", st)
	}
	srv.aicoPushPass(now.Add(3*time.Minute), rcv.server.Client())
	if len(rcv.notices) != 0 {
		t.Fatal("the notice was sent after it was accepted")
	}

	// A receiver that cannot be reached keeps notices too and says why, without the key.
	aicoAlert(t, store, "z1", "LATERAL_PORT_SWEEP", "HIGH", "ws-09", "inc-9", false, now.Add(-time.Minute))
	rcv.server.Close()
	srv.aicoPushPass(now.Add(4*time.Minute), &http.Client{Timeout: time.Second})
	st := srv.aicoPushState()
	if st.LastError == "" || strings.Contains(st.LastError, "onp_") {
		t.Fatalf("unreachable state = %+v", st)
	}
	if sent, _ := store.AicoPushSent([]string{"inc-9"}); sent["inc-9"] {
		t.Fatal("a notice was marked sent though nothing was delivered")
	}
}

func TestAicoPushSinceCutoffAndNoURL(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	rcv := newAicoReceiver(t)
	now := time.Now().UTC()
	aicoAlert(t, store, "old", "LATERAL_PORT_SWEEP", "HIGH", "ws-01", "inc-old", false, now.Add(-3*time.Hour))
	aicoAlert(t, store, "new", "LATERAL_PORT_SWEEP", "HIGH", "ws-02", "inc-new", false, now.Add(-30*time.Minute))

	srv.aicoPushPass(now, rcv.server.Client())
	if len(rcv.keys) != 0 {
		t.Fatal("pushed with no URL configured")
	}
	aicoConfigure(t, srv, store, rcv, now.Add(-time.Hour))
	srv.aicoPushPass(now, rcv.server.Client())
	if len(rcv.notices) != 1 || rcv.notices[0]["key"] != "alerts:new" {
		t.Fatalf("notices before the cutoff were sent: %v", rcv.notices)
	}

	// With no cutoff of its own, the lookback is a week.
	if err := store.SetSetting(aicoSinceSetting, ""); err != nil {
		t.Fatal(err)
	}
	aicoAlert(t, store, "week", "LATERAL_PORT_SWEEP", "HIGH", "ws-03", "inc-week", false, now.Add(-6*24*time.Hour))
	aicoAlert(t, store, "ancient", "LATERAL_PORT_SWEEP", "HIGH", "ws-04", "inc-ancient", false, now.Add(-8*24*time.Hour))
	srv.aicoPushPass(now.Add(time.Minute), rcv.server.Client())
	if len(rcv.notices) != 2 {
		t.Fatalf("lookback notices = %v", rcv.notices)
	}
	for _, n := range rcv.notices {
		if n["key"] == "alerts:ancient" || n["key"] == "alerts:new" {
			t.Fatalf("unexpected notice %v", n["key"])
		}
	}
}

func TestAicoNoticeFitsTheLimits(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	g := &aicoGroup{token: "inc"}
	long := strings.Repeat("é", 2000)
	for i := 0; i < 30; i++ {
		g.alerts = append(g.alerts, feedAlert{ID: fmt.Sprintf("%036d", i), Type: "X", Host: long, At: now.Format(time.RFC3339), What: long,
			Process: long, Command: long, Destinations: long, Cause: long, Actor: long})
	}
	g.alerts = append(g.alerts, feedAlert{ID: "bad id,with comma", Host: "h", What: "w", At: now.Format(time.RFC3339)})
	n, ok := srv.aicoNotice(g, now)
	if !ok {
		t.Fatal("no notice")
	}
	raw, _ := json.Marshal(n)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	checkNotice(t, m)
	if ids := strings.Split(strings.TrimPrefix(n.Key, "alerts:"), ","); len(ids) > verdictMaxIDs {
		t.Fatalf("%d ids in the key", len(ids))
	}
}

// ---- rows ----

func finding(uid, title string, sev, status int, msg string) feedFinding {
	return feedFinding{SeverityID: sev, StatusID: status, Message: msg, FindingInfo: map[string]any{"uid": uid, "title": title}}
}

func TestAicoRowsMapStatesFoldAndFitLimits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	rows := aicoFindingRows([]feedFinding{
		finding("ominull.hub", "Hub", ocsfSevInformational, ocsfStatusResolved, "OmniNull hub 1.0 answering"),
		finding("ominull.agents.offline", "Quiet agents", ocsfSevMedium, ocsfStatusNew, "2 server agents offline"),
		finding("ominull.hunt.x", "Note", ocsfSevInformational, ocsfStatusNew, "a note is not a warning"),
		finding("ominull.hub.router_unavailable", "Hub section unavailable", ocsfSevMedium, ocsfStatusNew, "The hub could not read its router"),
		finding("ominull.run.ws-1.pkg-a", "Maintenance run needs attention", ocsfSevMedium, ocsfStatusNew, "run one stalled"),
		finding("ominull.run.ws-2.pkg-b", "Maintenance run needs attention", ocsfSevInformational, ocsfStatusResolved, "Resolved: run two"),
		finding("ominull.run.ws-3.pkg-c", "Maintenance run needs attention", ocsfSevMedium, ocsfStatusNew, "run three stalled"),
		finding("ominull.decisions.r1", "Maintenance decisions", ocsfSevInformational, ocsfStatusResolved, "r1: every item answered"),
		finding("ominull.decisions.r2", "Maintenance decisions", ocsfSevInformational, ocsfStatusResolved, "r2: every item answered"),
		finding("ominull.compliance.ep-1", "Machine compliance", ocsfSevInformational, ocsfStatusResolved, "ws-1: 4 controls pass"),
		finding("ominull.anomalies.digest", strings.Repeat("t", 200), ocsfSevInformational, ocsfStatusNew, strings.Repeat("m", 500)),
	}, now)
	got := map[string]aicoRow{}
	for _, r := range rows {
		if _, dup := got[r.ID]; dup {
			t.Fatalf("duplicate row %s", r.ID)
		}
		got[r.ID] = r
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`).MatchString(r.ID) || !strings.HasPrefix(r.ID, "ominull") || len(r.ID) > 200 ||
			utf8.RuneCountInString(r.What) > 120 || r.What == "" || utf8.RuneCountInString(r.Meaning) > 300 || r.Meaning == "" ||
			r.Machine != "ominull-hub" || r.Project != "ominull" || (r.State != "ok" && r.State != "warn") {
			t.Errorf("row breaks the contract: %+v", r)
		}
		if r.LastRun != "2026-11-06T12:00:00Z" || r.NextRun != "2026-11-06T12:05:00Z" {
			t.Errorf("times %s %s", r.LastRun, r.NextRun)
		}
	}
	if len(rows) != 8 {
		t.Fatalf("rows = %d: %+v", len(rows), rows)
	}
	for id, want := range map[string]string{"ominull.hub": "ok", "ominull.agents.offline": "warn", "ominull.hunt.x": "ok",
		"ominull.hub.router_unavailable": "warn", "ominull.run": "warn", "ominull.decisions": "ok", "ominull.compliance": "ok", "ominull.anomalies.digest": "ok"} {
		if got[id].State != want {
			t.Errorf("%s state = %q, want %q", id, got[id].State, want)
		}
	}
	if got["ominull.hub"].Kind != "service" || got["ominull.agents.offline"].Kind != "check" {
		t.Errorf("kinds: %s %s", got["ominull.hub"].Kind, got["ominull.agents.offline"].Kind)
	}
	if !strings.Contains(got["ominull.run"].Meaning, "and 1 more") || !strings.Contains(got["ominull.decisions"].Meaning, "2 records") {
		t.Errorf("folded meanings: %q / %q", got["ominull.run"].Meaning, got["ominull.decisions"].Meaning)
	}
}

func TestAicoPushSendsHealthRowsFromTheLiveHub(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	rcv := newAicoReceiver(t)
	now := time.Now().UTC()
	aicoConfigure(t, srv, store, rcv, now)
	srv.aicoPushPass(now, rcv.server.Client())
	ids := map[string]string{}
	for _, r := range rcv.rows {
		ids[r["id"].(string)] = r["state"].(string)
		if !strings.HasPrefix(r["id"].(string), "ominull") || (r["state"] != "ok" && r["state"] != "warn") {
			t.Errorf("row %v", r)
		}
	}
	for _, id := range []string{"ominull.hub", "ominull.anomalies.summary", "ominull.agents.offline", "ominull.builds.1932669bb5871af4"} {
		if ids[id] == "" {
			t.Errorf("no row %s; have %v", id, ids)
		}
	}
	if len(rcv.rows) > aicoListMax {
		t.Errorf("%d rows", len(rcv.rows))
	}
}

func TestRetiredBuildRow(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	add := func(id, host, version, status string, seen time.Time) {
		t.Helper()
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "t-01", Hostname: host, DriverVersion: version, Status: status, LastSeenAt: seen}); err != nil {
			t.Fatal(err)
		}
	}
	add("e1", "new-1", "1.8.71", "online", now)
	add("e2", "new-2", "1.9.0", "online", now)
	add("e3", "retired-old", "1.0.0", "retired", now)
	rows := srv.retiredBuildRows(now)
	if len(rows) != 1 || rows[0].ID != "ominull.builds.1932669bb5871af4" || rows[0].State != "ok" ||
		rows[0].Meaning != "All 2 agents run 1.8.71 or newer, so none trusts the old release key 1932669b" {
		t.Fatalf("clean row = %+v", rows)
	}
	add("e4", "old-1", "1.8.70", "offline", now.Add(-72*time.Hour))
	add("e5", "odd", "", "online", now)
	add("e6", "weird", "dev-build", "online", now)
	rows = srv.retiredBuildRows(now)
	m := rows[0].Meaning
	if rows[0].State != "warn" || !strings.Contains(m, "3 agents still run a build that trusts the old release key 1932669b (need 1.8.71 or newer)") ||
		!strings.Contains(m, "old-1 (1.8.70, last seen 2026-11-03)") || !strings.Contains(m, "odd (version unknown, last seen 2026-11-06)") ||
		!strings.Contains(m, "weird (dev-build") || strings.Contains(m, "retired-old") || strings.Contains(m, "new-1") {
		t.Fatalf("warn row = %+v", rows[0])
	}

	// Many old agents: six named, the rest counted, inside 300 characters.
	for i := 0; i < 8; i++ {
		add(fmt.Sprintf("o%d", i), fmt.Sprintf("old-host-%d", i), "1.0.0", "online", now)
	}
	m = srv.retiredBuildRows(now)[0].Meaning
	if utf8.RuneCountInString(m) > 300 || !strings.Contains(m, "11 agents") {
		t.Fatalf("long row = %q", m)
	}

	// The setting overrides the default: two keys, one row each.
	if err := store.SetSetting(retiredKeysSetting, `[{"id":"aaaaaaaabbbbbbbb","clean_from":"1.9.0"},{"id":"bad","clean_from":"1"},{"id":"1932669bb5871af4","clean_from":"v1.8.71"}]`); err != nil {
		t.Fatal(err)
	}
	rows = srv.retiredBuildRows(now)
	if len(rows) != 2 || rows[0].ID != "ominull.builds.aaaaaaaabbbbbbbb" || rows[1].ID != "ominull.builds.1932669bb5871af4" {
		t.Fatalf("configured rows = %+v", rows)
	}
}

func TestPullFeedIsGoneAndDiagnosticsStayAdminOnly(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/integrations/nightshift/findings"},
		{http.MethodGet, "/api/v1/integrations/nightshift/findings?contract=v4"},
		{http.MethodPost, "/api/v1/integrations/nightshift/key"},
	} {
		if w := feedRequest(srv, c.method, c.path, "mock_admin_token"); w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, w.Code)
		}
	}
	if w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_tenant_token"); w.Code != http.StatusForbidden {
		t.Errorf("tenant key read the findings: %d", w.Code)
	}
	w := feedRequest(srv, http.MethodGet, "/api/v1/health/findings", "mock_admin_token")
	var doc map[string]json.RawMessage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &doc) != nil || doc["generated_at"] == nil || doc["findings"] == nil || len(doc) != 2 {
		t.Fatalf("findings = %d %s", w.Code, w.Body.String())
	}
	if w := feedRequest(srv, http.MethodPost, "/api/v1/health/findings", "mock_admin_token"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST findings = %d", w.Code)
	}
}
