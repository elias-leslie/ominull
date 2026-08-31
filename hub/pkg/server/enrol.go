package server

import (
	"encoding/json"
	"fmt"
	"log"
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
// authenticated POST, which is how it copies and downloads it. And for the case
// the operator actually wants - paste one line on the host - the hub mints a
// single-use install ticket that authorises fetching exactly that script and
// nothing else, for half an hour.

type enrolmentPlatform struct {
	key      string
	label    string
	route    string
	filename string
	generate func(bootstrap.Options) string
	// oneLiner renders the paste-on-the-host command for this platform.
	oneLiner func(base, ticket string) string
}

func enrolmentPlatforms() []enrolmentPlatform {
	return []enrolmentPlatform{
		{
			key: "linux", label: "Linux", route: "/bootstrap.sh", filename: "ominull-install.sh",
			generate: bootstrap.GenerateBash,
			// Quote the URL. The ticket query marker is a shell glob character.
			oneLiner: func(base, ticket string) string {
				return fmt.Sprintf("curl -fsSL \"%s/bootstrap.sh?t=%s\" | sudo bash", base, ticket)
			},
		},
		{
			key: "windows", label: "Windows", route: "/bootstrap.ps1", filename: "ominull-install.ps1",
			generate: bootstrap.GeneratePowerShell,
			// -UseBasicParsing so it runs on a host where Internet Explorer's
			// engine was never initialised, which is every Server Core box and
			// any account that has not logged in interactively.
			oneLiner: func(base, ticket string) string {
				return fmt.Sprintf("iwr -UseBasicParsing '%s/bootstrap.ps1?t=%s' | iex", base, ticket)
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
		"platforms":     out,
		"ticket_ttl":    storage.InstallTicketTTL.String(),
		"download_base": s.downloadBase(r),
	})
}

// handleEnrolmentScript renders one enrolment script and mints the ticket that
// makes its one-line form usable. Admin only: the body carries the tenant key.
func (s *Server) handleEnrolmentScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Platform   string `json:"platform"`
		TenantID   string `json:"tenant_id"`
		LocationID string `json:"location_id"`
		Role       string `json:"role"`
		EndpointID string `json:"endpoint_id"`
		// OneLiner asks the hub to also mint an install ticket. It is a
		// separate credential with its own audit line, so it is opt-in rather
		// than minted on every look at the screen.
		OneLiner bool `json:"one_liner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	plat, ok := enrolmentPlatform_(strings.TrimSpace(strings.ToLower(req.Platform)))
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "platform: must be linux, macos or windows")
		return
	}

	ticket := storage.InstallTicket{
		Platform: plat.key, TenantID: req.TenantID, LocationID: req.LocationID,
		Role: req.Role, EndpointID: req.EndpointID,
	}
	opts, ok := s.buildEnrolmentOptions(w, r, ticket)
	if !ok {
		return
	}

	body := map[string]interface{}{
		"platform": plat.key,
		"label":    plat.label,
		"filename": plat.filename,
		"script":   plat.generate(opts),
		// Said plainly, because an operator who generates three of these and
		// runs the oldest one gets a failure that looks like a broken installer.
		"note": "This script carries the tenant key and an enrolment token that works once and expires in " +
			storage.EnrollmentTokenTTL.String() + ". Generate a fresh one for each host.",
	}

	s.audit(r, "BOOTSTRAP_GENERATED", opts.EndpointID,
		"Rendered a "+plat.label+" installer in the console, carrying the tenant key and a single-use enrolment token")

	if req.OneLiner {
		tok, err := s.store.CreateInstallTicket(ticket, storage.InstallTicketTTL)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not mint an install link: "+err.Error())
			return
		}
		base := s.downloadBase(r)
		body["one_liner"] = plat.oneLiner(base, tok)
		body["one_liner_expires_in"] = storage.InstallTicketTTL.String()
		body["one_liner_origin"] = base
		// The operator is about to paste this onto a host. If the hub has any
		// reason to doubt the URL it just built, that belongs on the screen
		// next to the command, not only in a log nobody has open.
		if problem := s.publicURLProblem(); problem != "" {
			body["one_liner_warning"] = problem
			if alt := requestOrigin(r); alt != base {
				body["one_liner_alternate"] = plat.oneLiner(alt, tok)
				body["one_liner_alternate_origin"] = alt
			}
		}
		s.audit(r, "INSTALL_TICKET_MINTED", opts.EndpointID,
			"Minted a single-use "+plat.label+" install link, valid for "+storage.InstallTicketTTL.String())
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

// installTicketOptions redeems the ?t= on a bootstrap route. It returns false
// having written the response when there is no ticket to redeem, so the caller
// can fall through to the admin-key path.
func (s *Server) installTicketOptions(w http.ResponseWriter, r *http.Request, want string) (bootstrap.Options, bool, bool) {
	tok := strings.TrimSpace(r.URL.Query().Get("t"))
	if tok == "" {
		return bootstrap.Options{}, false, false
	}

	// A ticket is a bearer credential in a URL, so a wrong one is a guess and
	// guesses get the same throttle a wrong admin key does.
	addr := clientIP(r)
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many failed attempts; try again shortly")
		return bootstrap.Options{}, true, false
	}

	t, err := s.store.ConsumeInstallTicket(tok)
	if err != nil {
		if s.throttle.fail(addr) {
			log.Printf("[!] %s has presented %d bad install links in a minute; refusing it for the next minute.", addr, s.throttle.limit)
		}
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return bootstrap.Options{}, true, false
	}
	s.throttle.succeed(addr)

	if t.Platform != "" && t.Platform != want {
		writeJSONError(w, http.StatusBadRequest,
			"this install link was issued for "+t.Platform+", not "+want)
		return bootstrap.Options{}, true, false
	}

	// A redeemed ticket is an authorisation decision made earlier by an
	// administrator, so the audit identity is theirs, not the anonymous
	// fetcher's - but nothing the fetcher sent may name them.
	for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID"} {
		r.Header.Del(h)
	}
	r.Header.Set("X-Role", "admin")
	r.Header.Set("X-Username", "install-link")

	opts, ok := s.buildEnrolmentOptions(w, r, t)
	if !ok {
		return bootstrap.Options{}, true, false
	}
	s.audit(r, "INSTALL_TICKET_REDEEMED", opts.EndpointID,
		"A single-use "+want+" install link was redeemed from "+addr+" at "+time.Now().UTC().Format(time.RFC3339))
	return opts, true, true
}
