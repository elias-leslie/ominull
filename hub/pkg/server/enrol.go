package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/storage"
)

// Getting an agent onto a host that has none.
//
// The hub has always been able to generate an enrolment script for each
// platform. The console could not: the three routes that serve them authenticate
// with the admin key in the query string, and the console has no business
// building a URL with the fleet's most privileged credential in it - that URL
// lands in shell history, in proxy logs, and on the screen of whoever is looking
// over the operator's shoulder. So the capability existed and had no door, and
// the only way to add an endpoint was to already know the API.
//
// Two doors, then. The console fetches the rendered script over an ordinary
// authenticated POST, which is how it copies and downloads it. For the case the
// operator wants a one-line command, the command fetches only a generic script;
// the one-use enrollment code is entered in the script's request body.

type enrolmentPlatform struct {
	key      string
	label    string
	route    string
	filename string
	generate func(bootstrap.Options) string
	// oneLiner downloads a generic script. The code is entered through the
	// script's terminal or a protected code file, never placed in this command.
	oneLiner func(base string, ignored ...string) string
}

func enrolmentPlatforms() []enrolmentPlatform {
	return []enrolmentPlatform{
		{
			key: "linux", label: "Linux", route: "/bootstrap.sh", filename: "ominull-install.sh",
			generate: bootstrap.GenerateBash,
			oneLiner: func(base string, _ ...string) string {
				return fmt.Sprintf("curl -fsSL %q | sudo bash", base+"/bootstrap.sh")
			},
		},
		{
			key: "windows", label: "Windows", route: "/bootstrap.ps1", filename: "ominull-install.ps1",
			generate: bootstrap.GeneratePowerShell,
			// -UseBasicParsing so it runs on a host where Internet Explorer's
			// engine was never initialised, which is every Server Core box and
			// any account that has not logged in interactively.
			oneLiner: func(base string, _ ...string) string {
				return fmt.Sprintf("iwr -UseBasicParsing '%s/bootstrap.ps1' | iex", base)
			},
		},
	}
}

func enrolmentPlatform_(key string) (enrolmentPlatform, bool) {
	for _, p := range enrolmentPlatforms() {
		if p.key == key {
			return p, true
		}
	}
	return enrolmentPlatform{}, false
}

// handleEnrolmentPlatforms lists what can be installed and where the scripts
// live, so the console does not hard-code three route names.
func (s *Server) handleEnrolmentPlatforms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := []map[string]string{}
	for _, p := range enrolmentPlatforms() {
		out = append(out, map[string]string{
			"platform": p.key, "label": p.label, "route": p.route, "filename": p.filename,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"platforms":      out,
		"enrollment_ttl": humanDuration(storage.EnrollmentProfileTTL),
		"download_base":  s.downloadBase(r),
	})
}

// handleEnrolmentScript creates a short-lived profile and renders a script that
// redeems it through a request body. The returned code is never put in the
// one-line command or a URL.
func (s *Server) handleEnrolmentScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Platform   string  `json:"platform"`
		Kind       string  `json:"kind"`
		TenantID   string  `json:"tenant_id"`
		LocationID string  `json:"location_id"`
		Role       string  `json:"role"`
		EndpointID string  `json:"endpoint_id"`
		Hours      float64 `json:"hours"`
		MaxUses    int     `json:"max_uses"`
		Persistent bool    `json:"persistent"`
		// OneLiner asks the hub to also return a generic command. The enrollment
		// code remains in the protected response body, never in the command.
		OneLiner bool `json:"one_liner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	plat, ok := enrolmentPlatform_(strings.TrimSpace(strings.ToLower(req.Platform)))
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "platform: must be linux or windows")
		return
	}

	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if req.Persistent {
		kind = "deployment"
	}
	if kind == "" {
		kind = "invitation"
	}
	if kind != "invitation" && kind != "campaign" && kind != "deployment" {
		writeJSONError(w, http.StatusBadRequest, "kind must be invitation, campaign, or deployment")
		return
	}
	maxUses := req.MaxUses
	if kind == "invitation" && maxUses == 0 {
		maxUses = 1
	}
	ttl := storage.EnrollmentProfileTTL
	if kind == "campaign" {
		if req.Hours <= 0 {
			req.Hours = 8
		}
		ttl = time.Duration(req.Hours * float64(time.Hour))
	} else if kind == "deployment" {
		ttl = 0
		maxUses = 0
	}
	profile, code, err := s.store.CreateEnrollmentProfile(storage.EnrollmentProfile{
		Kind: kind, Platform: plat.key, TenantID: req.TenantID,
		LocationID: req.LocationID, Role: req.Role, EndpointID: req.EndpointID,
		MaxUses: maxUses, CreatedBy: r.Header.Get("X-Username"),
	}, ttl)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	opts := bootstrap.Options{HubURL: s.downloadBase(r), AgentHubURL: s.agentHubURL,
		LocationID: req.LocationID, RoleTag: req.Role, EndpointID: req.EndpointID,
		AgentVersion: s.agentVersion, EnrollmentCode: code, UseSystemCA: s.agentUsesSystemCA()}

	body := map[string]interface{}{
		"platform":        plat.key,
		"label":           plat.label,
		"filename":        plat.filename,
		"script":          plat.generate(opts),
		"profile_id":      profile.ID,
		"enrollment_code": code,
		"note":            enrollmentProfileNote(profile),
	}

	s.audit(r, "BOOTSTRAP_GENERATED", profile.ID,
		"Rendered a "+plat.label+" installer backed by a body-only one-use enrollment profile")

	if req.OneLiner {
		base := s.downloadBase(r)
		body["one_liner"] = plat.oneLiner(base)
		body["one_liner_expires_in"] = enrollmentExpiresIn(profile)
		body["one_liner_origin"] = base
		// The operator is about to paste this onto a host. If the hub has any
		// reason to doubt the URL it just built, that belongs on the screen
		// next to the command, not only in a log nobody has open.
		if problem := s.publicURLProblem(); problem != "" {
			body["one_liner_warning"] = problem
			if alt := requestOrigin(r); alt != base {
				body["one_liner_alternate"] = plat.oneLiner(alt)
				body["one_liner_alternate_origin"] = alt
			}
		}
		s.audit(r, "INSTALL_COMMAND_RENDERED", profile.ID,
			"Rendered a generic "+plat.label+" install command; enrollment code remains in the protected response body")
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

/* ------------------------------------------------- enrolment windows */

// handleEnrolmentWindows is the console's door onto self-service enrolment:
// list what is open, open one, close one. Admin only - a window is a standing
// authorisation to join the fleet, which is the same weight of decision as
// minting an install link, made once for a network instead of once per host.
func (s *Server) handleEnrolmentWindows(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listEnrolmentWindows(w, r)
	case http.MethodPost:
		s.createEnrolmentWindow(w, r)
	case http.MethodDelete:
		s.revokeEnrolmentWindow(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listEnrolmentWindows(w http.ResponseWriter, r *http.Request) {
	windows, err := s.store.ListEnrolmentWindows()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Decorated with what the console would otherwise have to derive: the state
	// of each window in one word, and the address to hand to whoever is standing
	// at the endpoint.
	out := make([]map[string]interface{}, 0, len(windows))
	for _, win := range windows {
		out = append(out, map[string]interface{}{
			"id": win.ID, "label": win.Label, "cidrs": win.CIDRs,
			"tenant_id": win.TenantID, "location_id": win.LocationID, "role": win.Role,
			"max_uses": win.MaxUses, "used": win.Used, "has_passcode": win.HasPasscode,
			"created_at": win.CreatedAt, "expires_at": win.ExpiresAt,
			"created_by": win.CreatedBy, "revoked_at": win.RevokedAt,
			"last_used_at": win.LastUsedAt, "state": win.State(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"windows":    out,
		"portal_url": s.downloadBase(r) + "/install",
		// What to prefill the network box with. An operator opening a window for
		// "this LAN" should not have to work out its CIDR from memory.
		"suggested_cidrs": suggestedEnrolmentCIDRs(),
		"enrollment_ttl":  storage.EnrollmentProfileTTL.String(),
	})
}

func enrollmentExpiresIn(profile storage.EnrollmentProfile) string {
	if profile.Kind == "deployment" {
		return "until revoked"
	}
	remaining := time.Until(profile.ExpiresAt)
	if remaining <= 0 {
		return "expired"
	}
	return humanDuration(remaining)
}

func enrollmentProfileNote(profile storage.EnrollmentProfile) string {
	switch profile.Kind {
	case "deployment":
		return "This persistent deployment code is scoped to its tenant/site and remains valid until revoked. Each successful install receives a unique device credential and matching client certificate. Keep the code out of URLs, service arguments, and logs."
	case "campaign":
		if profile.MaxUses == 0 {
			return "This campaign code is reusable until its expiry. Each successful install receives a unique device credential and matching client certificate. Keep the code out of URLs, service arguments, and logs."
		}
		return "This campaign code is limited to its configured use count and expires at the displayed time. Each successful install receives a unique device credential and matching client certificate. Keep the code out of URLs, service arguments, and logs."
	default:
		return "This invitation code works once and expires at the displayed time. Each successful install receives a unique device credential and matching client certificate. Keep the code out of URLs, service arguments, and logs."
	}
}

func (s *Server) createEnrolmentWindow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label      string   `json:"label"`
		CIDRs      []string `json:"cidrs"`
		TenantID   string   `json:"tenant_id"`
		LocationID string   `json:"location_id"`
		Role       string   `json:"role"`
		MaxUses    int      `json:"max_uses"`
		Hours      float64  `json:"hours"`
		Passcode   string   `json:"passcode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	if req.Hours <= 0 {
		req.Hours = 8
	}
	// A window that outlives the memory of opening it is the failure mode this
	// whole feature has to avoid, so the ceiling is a week and it is not a
	// preference.
	if req.Hours > 168 {
		writeJSONError(w, http.StatusBadRequest, "an enrolment window may stay open for at most a week (168 hours)")
		return
	}

	window, err := s.store.CreateEnrolmentWindow(storage.EnrolmentWindow{
		Label: req.Label, CIDRs: req.CIDRs, TenantID: req.TenantID,
		LocationID: req.LocationID, Role: req.Role, MaxUses: req.MaxUses,
		ExpiresAt: time.Now().UTC().Add(time.Duration(req.Hours * float64(time.Hour))),
		CreatedBy: strings.TrimSpace(r.Header.Get("X-Username")),
	}, req.Passcode)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	budget := "no limit on how many"
	if window.MaxUses > 0 {
		budget = fmt.Sprintf("at most %d", window.MaxUses)
	}
	s.audit(r, "ENROLMENT_WINDOW_OPENED", window.ID,
		fmt.Sprintf("Opened self-service enrolment for %s until %s (%s enrolments, passcode: %v)",
			strings.Join(window.CIDRs, ", "), window.ExpiresAt.Format(time.RFC3339), budget, window.HasPasscode))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"window":     window,
		"portal_url": s.downloadBase(r) + "/install",
	})
}

func (s *Server) revokeEnrolmentWindow(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := s.store.RevokeEnrolmentWindow(id); err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	s.audit(r, "ENROLMENT_WINDOW_REVOKED", id, "Closed a self-service enrolment window")
	writeJSON(w, http.StatusOK, map[string]interface{}{"revoked": id})
}

// suggestedEnrolmentCIDRs is the hub's own networks, as the /24 (or /64) an
// operator most likely means by "this LAN". Best effort: an empty list just
// means the console shows an empty box.
func suggestedEnrolmentCIDRs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || !ipnet.IP.IsPrivate() {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil {
			continue
		}
		entry := net.IP{v4[0], v4[1], v4[2], 0}.String() + "/24"
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out
}
