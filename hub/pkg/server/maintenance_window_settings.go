package server

// Maintenance windows per machine: GET/PUT /api/v1/maintenance/windows
// [?endpoint_id=]. Inside its window an enforce or revert run does not wait
// for people (battery and Windows Update still count), and the schedule only
// starts enforce runs there. One fleet default plus per-machine windows, each
// 1-4 daily ranges in the machine's own time or in UTC, kept as data in one
// settings row. Unset, the fleet default is 01:00-05:00 machine time (or the
// older single fleet window, maintenance.window, when one was saved).

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/scripts"
)

const maintenanceWindowsSetting = "maintenance.windows"

var shippedMaintenanceWindow = scripts.Window{Ranges: []string{"01:00-05:00"}}

var maintenanceWindowsMu sync.Mutex

type maintenanceWindows struct {
	Default   *scripts.Window           `json:"default,omitempty"`
	Endpoints map[string]scripts.Window `json:"endpoints,omitempty"`
}

func (s *Server) loadMaintenanceWindows() maintenanceWindows {
	var st maintenanceWindows
	if raw, err := s.store.GetSetting(maintenanceWindowsSetting); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			log.Printf("[!] Ignoring unreadable maintenance windows: %v", err)
			st = maintenanceWindows{}
		}
	}
	if st.Default != nil && st.Default.Check() != nil {
		st.Default = nil
	}
	for id, w := range st.Endpoints {
		if w.Check() != nil {
			delete(st.Endpoints, id)
		}
	}
	return st
}

// fleet is the fleet default and where it comes from ("fleet" or "default").
func (s *Server) fleetWindow(st maintenanceWindows) (scripts.Window, string) {
	if st.Default != nil {
		return *st.Default, "fleet"
	}
	if v, err := s.store.GetSetting(maintenanceWindowSetting); err == nil && v != "" {
		if w, err := scripts.ParseWindow(v); err == nil {
			return w, "fleet"
		}
	}
	return shippedMaintenanceWindow, "default"
}

// windowFor is a machine's effective window and where it comes from
// ("endpoint", "fleet" or "default").
func (s *Server) windowFor(st maintenanceWindows, endpointID string) (scripts.Window, string) {
	if w, ok := st.Endpoints[endpointID]; ok && endpointID != "" {
		return w, "endpoint"
	}
	return s.fleetWindow(st)
}

// windowParams is each machine's window run parameter.
func (s *Server) windowParams(endpointIDs []string) map[string]string {
	maintenanceWindowsMu.Lock()
	st := s.loadMaintenanceWindows()
	maintenanceWindowsMu.Unlock()
	out := make(map[string]string, len(endpointIDs))
	for _, id := range endpointIDs {
		w, _ := s.windowFor(st, id)
		out[id] = w.Param()
	}
	return out
}

// endpointUTCOffset is the machine's UTC offset in minutes from its latest
// trust report (agents from 1.8.82), or nil.
func (s *Server) endpointUTCOffset(endpointID string) *int {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	s.trust.init()
	seen, ok := s.trust.reports[endpointID]
	if !ok || seen.report.UTCOffset == nil || time.Since(seen.at) > 24*time.Hour {
		return nil
	}
	v := *seen.report.UTCOffset
	return &v
}

func windowClock(w scripts.Window) string {
	if w.UTC {
		return "utc"
	}
	return "machine"
}

// windowView is one machine's window as the console and ominullctl show it.
func (s *Server) windowView(w scripts.Window, source, endpointID string, now time.Time) map[string]interface{} {
	v := map[string]interface{}{"ranges": w.Ranges, "clock": windowClock(w), "source": source}
	if endpointID == "" {
		return v
	}
	v["endpoint_id"] = endpointID
	off := s.endpointUTCOffset(endpointID)
	if off != nil {
		v["utc_offset_minutes"] = *off
	}
	if in, known := w.Contains(now, off); known {
		v["open_now"] = in
		ns, _ := w.NextStart(now, off)
		v["next_start"] = ns.UTC().Format(time.RFC3339)
	}
	return v
}

func (s *Server) maintenanceWindowsView(st maintenanceWindows, endpointID string, now time.Time) map[string]interface{} {
	if endpointID != "" {
		w, src := s.windowFor(st, endpointID)
		return s.windowView(w, src, endpointID, now)
	}
	fw, fsrc := s.fleetWindow(st)
	eps := map[string]interface{}{}
	ids := make([]string, 0, len(st.Endpoints))
	for id := range st.Endpoints {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		eps[id] = s.windowView(st.Endpoints[id], "endpoint", id, now)
	}
	return map[string]interface{}{"default": s.windowView(fw, fsrc, "", now), "endpoints": eps}
}

func (s *Server) handleMaintenanceWindows(w http.ResponseWriter, r *http.Request) {
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	switch r.Method {
	case http.MethodGet:
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for maintenance windows")
			return
		}
		if endpointID != "" && !s.endpointInScope(w, r, endpointID) {
			return
		}
		maintenanceWindowsMu.Lock()
		view := s.maintenanceWindowsView(s.loadMaintenanceWindows(), endpointID, time.Now())
		maintenanceWindowsMu.Unlock()
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to change maintenance windows")
			return
		}
		s.putMaintenanceWindows(w, r, endpointID)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// putMaintenanceWindows: {"ranges":["01:00-05:00"],"clock":"machine"|"utc"}
// for the fleet default, or with endpoint_id (query or body) for one
// machine; {"reset":true} drops a machine's own window, or the fleet default
// (back to 01:00-05:00 machine time).
func (s *Server) putMaintenanceWindows(w http.ResponseWriter, r *http.Request, endpointID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024+1))
	if err != nil || len(body) > 4*1024 {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 4 KiB")
		return
	}
	var req struct {
		EndpointID string   `json:"endpoint_id"`
		Ranges     []string `json:"ranges"`
		Clock      string   `json:"clock"`
		Reset      bool     `json:"reset"`
	}
	if !decodeInto(w, body, &req) {
		return
	}
	if endpointID == "" {
		endpointID = strings.TrimSpace(req.EndpointID)
	}
	if endpointID != "" {
		if ep, err := s.store.GetEndpoint(endpointID); err != nil || ep == nil || ep.Status == "retired" {
			writeJSONError(w, http.StatusBadRequest, "endpoint not found")
			return
		}
		if !s.endpointInScope(w, r, endpointID) {
			return
		}
	}
	var win scripts.Window
	if req.Reset == (len(req.Ranges) > 0) {
		writeJSONError(w, http.StatusBadRequest, `send "ranges" (and "clock"), or "reset": true`)
		return
	}
	if !req.Reset {
		switch req.Clock {
		case "", "machine":
		case "utc":
			win.UTC = true
		default:
			writeJSONError(w, http.StatusBadRequest, `clock is "machine" or "utc"`)
			return
		}
		for _, rg := range req.Ranges {
			win.Ranges = append(win.Ranges, strings.TrimSpace(rg))
		}
		if err := win.Check(); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	maintenanceWindowsMu.Lock()
	defer maintenanceWindowsMu.Unlock()
	st := s.loadMaintenanceWindows()
	if st.Endpoints == nil {
		st.Endpoints = map[string]scripts.Window{}
	}
	target, what := "fleet", ""
	switch {
	case endpointID != "" && req.Reset:
		delete(st.Endpoints, endpointID)
		target, what = endpointID, "reset (follows the fleet default)"
	case endpointID != "":
		st.Endpoints[endpointID] = win
		target, what = endpointID, "set to "+win.Param()
	case req.Reset:
		st.Default = nil
		_ = s.store.SetSetting(maintenanceWindowSetting, "") // the older single window goes too
		what = "reset to 01:00-05:00 machine time"
	default:
		st.Default = &win
		what = "set to " + win.Param()
	}
	raw, _ := json.Marshal(st)
	if st.Default == nil && len(st.Endpoints) == 0 {
		raw = nil
	}
	if err := s.store.SetSetting(maintenanceWindowsSetting, string(raw)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the maintenance windows could not be saved: "+err.Error())
		return
	}
	s.audit(r, "MAINTENANCE_WINDOWS_SET", "maintenance_window:"+target, "maintenance window for "+target+" "+what+" (Z = UTC, otherwise machine time)")
	view := s.maintenanceWindowsView(st, endpointID, time.Now())
	view["changed"] = true
	writeJSON(w, http.StatusOK, view)
}

// windowOpenOrUnknown says whether the schedule may start an enforce run
// now: inside the machine's window, or when the hub cannot tell (machine
// time, offset not reported), where the package's own check holds it.
func (s *Server) windowOpenOrUnknown(param, endpointID string, now time.Time) bool {
	w, err := scripts.ParseWindow(param)
	if err != nil {
		return true
	}
	in, known := w.Contains(now, s.endpointUTCOffset(endpointID))
	return in || !known
}
