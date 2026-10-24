package server

// The steward: Nightshift's maintenance agent, with its own key.
//
// The steward key (POST /api/v1/integrations/steward/key, admin, issued
// once; reissue revokes) is a credential of its own, not the admin key with
// a self-declared label: the hub names it "steward (steward-key)" to the
// response authority. It reaches only the routes in stewardRoutes: reading
// and waiting on maintenance runs, escalating one (a console row and a
// Nightshift feed finding), and taking a remote screen for a stuck run
// (open, attach, close).
//
// A steward screen request names the run it is for (steward_run). The hub
// opens it only while that run is a supervised maintenance run on that
// machine waiting on a dialog (needs_hands) or stalled, inside the
// machine's maintenance window, never unattended, for no longer than
// stewardDefaultSeconds, and never on a host-locked machine. Otherwise the
// request is refused and the steward escalates the run instead. The session
// is bound to the run and ends when the run moves on (stewardSessionSweep).

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

const (
	stewardKeySetting = "steward.key_hash"
	stewardAuthMethod = "steward-key"
	stewardUsername   = "steward"
	stewardKeyAudit   = "STEWARD_KEY_ISSUED"
	stewardSweepTick  = 15 * time.Second
	// stewardDefaultSeconds is a steward session's length.
	stewardDefaultSeconds = 30 * 60
)

// stewardRoutes is everything the steward key reaches, by path and method.
var stewardRoutes = map[string][]string{
	"/api/v1/maintenance/wait":       {http.MethodGet},
	"/api/v1/maintenance/escalate":   {http.MethodPost},
	"/api/v1/maintenance":            {http.MethodGet},
	"/api/v1/screen/sessions":        {http.MethodPost, http.MethodDelete},
	"/api/v1/screen/sessions/attach": {http.MethodPost},
	"/api/v1/screen/sessions/close":  {http.MethodPost},
}

func stewardAllowed(r *http.Request) bool {
	for _, m := range stewardRoutes[r.URL.Path] {
		if m == r.Method {
			return true
		}
	}
	return false
}

func isSteward(r *http.Request) bool {
	return r.Header.Get("X-Auth-Method") == stewardAuthMethod
}

// stewardKeyMatches says whether key is the live steward key.
func (s *Server) stewardKeyMatches(key string) bool {
	want, _ := s.store.GetSetting(stewardKeySetting)
	return key != "" && want != "" && secretEqual(hashFeedKey(key), want)
}

// handleStewardKey issues (POST) or revokes (DELETE) the steward key.
func (s *Server) handleStewardKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" || isSteward(r) {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the steward key")
		return
	}
	switch r.Method {
	case http.MethodPost:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "generating the key failed")
			return
		}
		key := "nss_" + hex.EncodeToString(raw)
		if err := s.store.SetSetting(stewardKeySetting, hashFeedKey(key)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the key could not be saved")
			return
		}
		s.audit(r, stewardKeyAudit, "steward", "Issued the steward key; any earlier steward key is revoked; credential "+credentialOf(r))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]interface{}{"key": key, "routes": stewardRouteList()})
	case http.MethodDelete:
		if err := s.store.SetSetting(stewardKeySetting, ""); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the key could not be revoked")
			return
		}
		s.audit(r, stewardKeyAudit, "steward", "Revoked the steward key; credential "+credentialOf(r))
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func stewardRouteList() []string {
	out := []string{}
	for p, methods := range stewardRoutes {
		for _, m := range methods {
			out = append(out, m+" "+p)
		}
	}
	sort.Strings(out)
	return out
}

// stewardRun checks the run a steward screen request names: a supervised
// maintenance job on that machine, waiting on a dialog or stalled. It
// returns why not, or "".
func (s *Server) stewardRunRefusal(tenantID, endpointID, jobID string) string {
	if s.responseStore == nil {
		return "the response store is not available"
	}
	job, err := s.responseStore.GetJob(tenantID, jobID)
	if err != nil || job == nil || job.Kind != response.ActionKindScriptExec {
		return "no such maintenance run: " + jobID
	}
	if job.EndpointID != endpointID {
		return "run " + jobID + " is on another machine"
	}
	run := s.liveRun(job, time.Now())
	if run == nil || (run.State != "needs_hands" && run.State != "stalled") {
		state := "unknown"
		if run != nil {
			state = run.State
		}
		return fmt.Sprintf("run %s is not waiting on a dialog or stalled (it is %s); the steward takes the screen only for a stuck run", jobID, state)
	}
	return ""
}

// hostLocked says the machine carries a host authority file (the owner's
// own infrastructure, locked on the host).
func (s *Server) hostLocked(endpointID string) bool {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	s.trust.init()
	seen, ok := s.trust.reports[endpointID]
	return ok && seen.report.HostAuthority
}

// stewardSessions binds open steward screen sessions to their runs.
var stewardSessions = struct {
	sync.Mutex
	byID map[string]stewardBinding
}{byID: map[string]stewardBinding{}}

type stewardBinding struct {
	Tenant, Endpoint, Run string
}

func bindStewardSession(sessionID string, b stewardBinding) {
	stewardSessions.Lock()
	stewardSessions.byID[sessionID] = b
	stewardSessions.Unlock()
}

// StewardRunOf is the run a screen session was opened for ("" when none).
func stewardRunOf(sessionID string) string {
	stewardSessions.Lock()
	defer stewardSessions.Unlock()
	return stewardSessions.byID[sessionID].Run
}

func (s *Server) stewardSessionLoop() {
	t := time.NewTicker(stewardSweepTick)
	defer t.Stop()
	for range t.C {
		s.stewardSessionSweep()
	}
}

// stewardSessionSweep ends steward sessions whose run is no longer stuck
// (finished, cancelled, or moving again) and forgets ended sessions.
func (s *Server) stewardSessionSweep() int {
	if s.terminalMgr == nil {
		return 0
	}
	stewardSessions.Lock()
	list := make(map[string]stewardBinding, len(stewardSessions.byID))
	for id, b := range stewardSessions.byID {
		list[id] = b
	}
	stewardSessions.Unlock()
	closed := 0
	for id, b := range list {
		sess, err := s.terminalMgr.GetSession(id)
		if err != nil || sess == nil || !sess.IsLive() {
			stewardSessions.Lock()
			delete(stewardSessions.byID, id)
			stewardSessions.Unlock()
			continue
		}
		why := s.stewardRunRefusal(b.Tenant, b.Endpoint, b.Run)
		if why == "" {
			continue
		}
		if s.terminalMgr.CloseSession(id, "steward_run_resolved") == nil {
			screenCreds.Forget(id)
			closed++
			s.recordHubAudit(b.Tenant, "SCREEN_SESSION_CLOSED", id, fmt.Sprintf("Closed the steward's screen session on %s: maintenance run %s no longer needs it (%s)", b.Endpoint, b.Run, why))
		}
		stewardSessions.Lock()
		delete(stewardSessions.byID, id)
		stewardSessions.Unlock()
	}
	return closed
}

// stewardScreenPlan applies the steward's limits to a screen request: the
// run must be stuck, the machine's maintenance window open, never
// unattended, and the length is stewardDefaultSeconds at most. It returns the
// session length and ask-first to use, or false after writing the refusal.
func (s *Server) stewardScreenPlan(w http.ResponseWriter, r *http.Request, req *screenOpenRequest) (time.Duration, bool, bool) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	run := strings.TrimSpace(req.StewardRun)
	if run == "" {
		writeJSONError(w, http.StatusBadRequest, "the steward names the stuck run it takes the screen for (steward_run)")
		return 0, false, false
	}
	if req.Unattended {
		writeJSONError(w, http.StatusBadRequest, "the steward never opens a screen with nobody at the keyboard")
		return 0, false, false
	}
	if why := s.stewardRunRefusal(tenantID, req.EndpointID, run); why != "" {
		writeJSONError(w, http.StatusConflict, why)
		return 0, false, false
	}
	if s.hostLocked(req.EndpointID) {
		writeJSONError(w, http.StatusConflict, "this machine is locked on the host (the owner's own infrastructure); the steward does not take its screen")
		return 0, false, false
	}
	maintenanceWindowsMu.Lock()
	win, _ := s.windowFor(s.loadMaintenanceWindows(), req.EndpointID)
	maintenanceWindowsMu.Unlock()
	if in, known := win.Contains(time.Now(), s.endpointUTCOffset(req.EndpointID)); !known || !in {
		writeJSONError(w, http.StatusConflict, "the steward takes this machine's screen only inside its maintenance window ("+win.Param()+"), and it is closed or its clock is unknown; escalate the run instead")
		return 0, false, false
	}
	d := time.Duration(stewardDefaultSeconds) * time.Second
	if req.MaxDurationSeconds > 0 && time.Duration(req.MaxDurationSeconds)*time.Second < d {
		d = time.Duration(req.MaxDurationSeconds) * time.Second
	}
	return d, s.screenAskFirst(req.EndpointID), true
}

// recordHubAudit leaves an audit row for something the hub did on its own.
func (s *Server) recordHubAudit(tenantID, action, resource, details string) {
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID: uuid.New().String(), TenantID: tenantID, Username: "hub", Action: action,
		Resource: resource, Details: details, Timestamp: time.Now().UTC(),
	})
}
