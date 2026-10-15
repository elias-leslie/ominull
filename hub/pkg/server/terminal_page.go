package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/terminal"
)

// /console/terminal is the remote terminal as its own page: the running
// sessions and the form that asks the owner to open one, or, with ?session=,
// one full-height terminal. The hub renders the page; web/terminal.js (built
// from web-src/terminal.ts) runs the approval wait and the xterm pane.

// The hub's caps, which the page states: three live shells per host, eight
// per tenant. Detached sessions count; they are still running.
const (
	terminalHostCap   = 3
	terminalTenantCap = 8
)

type terminalHostOption struct {
	ID, Name, OS, Identity string
	// Programs is the JSON list the program picker offers for this host.
	Programs string
	Live     int
	// Problem says why a terminal cannot be opened here, if it cannot.
	Problem  string
	Selected bool
}

type terminalSessionRow struct {
	ID, HostID, Host, Program, Started string
	// Label and Tone say the state in words: whether someone is attached.
	Label, Tone string
	at          time.Time
}

func terminalStateLabel(state terminal.SessionState) (string, string) {
	switch state {
	case terminal.StateActive:
		return "In use", "ok"
	case terminal.StateDetached:
		return "Detached, still running", "warn"
	case terminal.StateConnecting:
		return "Connecting", "info"
	}
	return "Starting", "idle"
}

type terminalSessionView struct {
	ID, HostID, Host, Identity, Program string
	// Summary is the session as GET /api/v1/terminal/sessions?id= returns it.
	Summary string
	// Fresh marks a session this browser has just created: its connect
	// cookie is already set, so the first connect skips the attach.
	Fresh bool
}

type terminalPageBody struct {
	CanOpen   bool
	Hosts     []terminalHostOption
	Sessions  []terminalSessionRow
	LiveCount int
	HostCap   int
	TenantCap int
	Zone      string
	View      *terminalSessionView
	// Gone explains a ?session= that cannot be shown.
	Gone string
	// Off is set when the hub runs without remote response.
	Off bool
}

func terminalSessionLive(state terminal.SessionState) bool {
	switch state {
	case terminal.StateActive, terminal.StateDetached, terminal.StateConnecting, terminal.StateWaiting:
		return true
	}
	return false
}

func terminalIdentity(os string) string {
	if strings.Contains(strings.ToLower(os), "windows") {
		return "LocalSystem"
	}
	return "root"
}

// terminalHostPrograms is what the program picker offers: what the agent
// reports, or the platform's defaults for an agent too old to report it.
func terminalHostPrograms(os, rawCaps string) ([]string, string) {
	caps := parseResponseCapabilities(rawCaps)
	if caps.reported {
		if caps.NoResponseKey {
			return nil, "Can't open a terminal here yet: this host's agent hasn't been given the hub's response key."
		}
		if len(caps.TerminalPrograms) == 0 {
			return nil, "This host reports no terminal support."
		}
		return caps.TerminalPrograms, ""
	}
	if terminalIdentity(os) == "LocalSystem" {
		return []string{"powershell.exe", "cmd.exe", "pwsh.exe"}, ""
	}
	return []string{"/bin/bash", "/bin/sh"}, ""
}

func (s *Server) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.requirePageViewer(w, r)
	if !ok {
		return
	}
	body := s.buildTerminalPage(viewer, r.URL.Query())
	title := "Terminal"
	if body.View != nil && body.View.Host != "" {
		title = body.View.Host + " terminal"
	}
	data := pageData{Title: title, Operator: viewer.Email, Role: viewer.Role, Back: "response", Body: body}
	if body.CanOpen {
		data.Script = "terminal.js"
	}
	s.servePage(w, r, "terminal", data)
}

func (s *Server) buildTerminalPage(viewer accessOperator, q map[string][]string) terminalPageBody {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	body := terminalPageBody{
		CanOpen:   s.responseEnabled && (viewer.Role == "admin" || viewer.Role == "operator"),
		HostCap:   terminalHostCap,
		TenantCap: terminalTenantCap,
		Off:       !s.responseEnabled,
	}
	if body.Off {
		return body
	}
	loc := s.store.GetDetectionTuning().Location()
	body.Zone = loc.String()
	if body.Zone == "Local" {
		body.Zone = time.Now().In(loc).Format("MST")
	}

	endpoints, _ := s.store.ListEndpoints("")
	names := map[string]string{}
	oses := map[string]string{}
	for _, ep := range endpoints {
		names[ep.ID] = ep.Hostname
		oses[ep.ID] = ep.OS
	}

	var sessions []*terminal.TerminalSession
	if s.terminalMgr != nil {
		sessions = s.terminalMgr.ListSessions("default")
	}
	live := map[string]int{}
	for _, ts := range sessions {
		sum := ts.Summary()
		st, _ := sum["state"].(string)
		if !terminalSessionLive(terminal.SessionState(st)) {
			continue
		}
		id, _ := sum["session_id"].(string)
		ep, _ := sum["endpoint_id"].(string)
		prog, _ := sum["program"].(string)
		row := terminalSessionRow{ID: id, HostID: ep, Host: names[ep], Program: prog}
		row.Label, row.Tone = terminalStateLabel(terminal.SessionState(st))
		if row.Host == "" {
			row.Host = ep
		}
		row.at = ts.CreatedAt
		row.Started = ts.CreatedAt.In(loc).Format("Jan 2 15:04")
		live[ep]++
		body.Sessions = append(body.Sessions, row)
	}
	sort.Slice(body.Sessions, func(i, j int) bool { return body.Sessions[i].at.After(body.Sessions[j].at) })
	body.LiveCount = len(body.Sessions)

	if id := get("session"); id != "" {
		body.View = &terminalSessionView{ID: id, Fresh: get("new") == "1"}
		var sess *terminal.TerminalSession
		if s.terminalMgr != nil {
			sess, _ = s.terminalMgr.GetSession(id)
		}
		switch {
		case sess == nil || sess.TenantID != "default":
			body.Gone = "That terminal isn't running anymore. Its recording, if it made one, is in evidence."
		case !body.CanOpen:
			body.Gone = "Your role can see terminals but can't open or join them."
		default:
			sum := sess.Summary()
			st, _ := sum["state"].(string)
			ep, _ := sum["endpoint_id"].(string)
			body.View.HostID = ep
			body.View.Host = names[ep]
			if body.View.Host == "" {
				body.View.Host = ep
			}
			body.View.Program, _ = sum["program"].(string)
			body.View.Identity = terminalIdentity(oses[ep])
			if !terminalSessionLive(terminal.SessionState(st)) {
				body.Gone = "This terminal has ended. Its recording is sealed into evidence."
				break
			}
			raw, _ := json.Marshal(sum)
			body.View.Summary = string(raw)
		}
		if body.Gone != "" {
			body.View.Summary = ""
		}
		return body
	}

	selected := get("endpoint")
	for _, ep := range endpoints {
		if ep.Status == "retired" {
			continue
		}
		programs, problem := terminalHostPrograms(ep.OS, ep.ResponseCapabilities)
		if problem == "" && live[ep.ID] >= terminalHostCap {
			problem = fmt.Sprintf("Already has %d terminals open. End one first.", terminalHostCap)
		}
		raw, _ := json.Marshal(programs)
		os := ep.OS
		if os == "" {
			os = "Linux"
		}
		body.Hosts = append(body.Hosts, terminalHostOption{
			ID: ep.ID, Name: ep.Hostname, OS: os, Identity: terminalIdentity(ep.OS),
			Programs: string(raw), Live: live[ep.ID], Problem: problem, Selected: ep.ID == selected,
		})
	}
	sort.Slice(body.Hosts, func(i, j int) bool { return strings.ToLower(body.Hosts[i].Name) < strings.ToLower(body.Hosts[j].Name) })
	// Without a host in the link, start on the first one that can open.
	if selected == "" {
		for i := range body.Hosts {
			if body.Hosts[i].Problem == "" {
				body.Hosts[i].Selected = true
				break
			}
		}
	}
	return body
}
