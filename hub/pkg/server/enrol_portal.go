package server

import (
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// The self-service enrolment portal.
//
// An administrator opens an enrolment window for a network; from then until it
// expires, anyone standing at a machine on that network can browse here and be
// handed the exact one-line command for the operating system they are on. That
// is the whole of it. What it replaces is an operator minting install links one
// at a time in the console while somebody else walks between desks.
//
// The portal mints a one-use enrollment profile. The window only decides who is
// allowed to cause one to be minted, and it is bounded by source network,
// expiry, a use budget and optionally a passcode.
//
// The page is deliberately not the console. It shares no script, no stylesheet
// and no session with it: it is served to whatever is on the LAN, so it renders
// from one self-contained template with its own strict policy, and the only
// thing it can do is ask for an install command for itself.

// portalOSFromAgent guesses which command to offer first. It is a convenience
// and never an authorisation - the visitor can pick either retained platform.
func portalOSFromAgent(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "cros"):
		return "linux"
	default:
		return "linux"
	}
}

type portalView struct {
	Nonce       string
	HubVersion  string
	ClientIP    string
	Covered     bool
	NeedsPass   bool
	Platform    string
	PlatformLbl string
	Platforms   []portalPlatform
	Command     string
	Code        string
	ProfileID   string
	ExpiresIn   string
	Error       string
	WindowLabel string
}

type portalPlatform struct {
	Key      string
	Label    string
	Selected bool
}

// handleEnrolPortal serves the portal and mints against it.
//
// GET renders the choice. POST is what spends a use, so a page that is merely
// loaded - by a link preview, a scanner, a browser prefetching - costs nothing.
func (s *Server) handleEnrolPortal(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	addr := clientIP(r)
	guess := portalOSFromAgent(r.Header.Get("User-Agent"))

	view := portalView{
		HubVersion: s.agentVersion,
		ClientIP:   addr,
		Platform:   guess,
	}
	_, view.Covered = s.store.CoveringWindow(addr)

	if r.Method == http.MethodPost {
		s.portalMint(w, r, addr, &view)
	} else if covering, ok := s.store.CoveringWindow(addr); ok {
		view.NeedsPass = covering.HasPasscode
		view.WindowLabel = covering.Label
	}

	if view.Platform == "" {
		view.Platform = guess
	}
	for _, p := range enrolmentPlatforms() {
		view.Platforms = append(view.Platforms, portalPlatform{
			Key: p.key, Label: p.label, Selected: p.key == view.Platform,
		})
		if p.key == view.Platform {
			view.PlatformLbl = p.label
		}
	}

	// The rendered command carries a live credential. Nothing on the path may
	// keep a copy of this page, and no navigation away from it may carry the
	// URL onward.
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	view.Nonce = newCSPNonce()
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+view.Nonce+"'; script-src 'nonce-"+view.Nonce+"'; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

	if err := portalTemplate.Execute(w, view); err != nil {
		log.Printf("[!] Could not render the enrolment portal for %s: %v", addr, err)
	}
}

// portalMint is the POST half: spend one use of a window that covers this
// address, mint a body-only enrollment profile, and render the command.
func (s *Server) portalMint(w http.ResponseWriter, r *http.Request, addr string, view *portalView) {
	if err := r.ParseForm(); err != nil {
		view.Error = "That request could not be read. Reload the page and try again."
		return
	}
	if want := strings.TrimSpace(r.FormValue("platform")); want != "" {
		view.Platform = want
	}
	plat, ok := enrolmentPlatform_(strings.ToLower(view.Platform))
	if !ok {
		view.Error = "Pick Linux or Windows."
		return
	}

	// A passcode is guessable in a way a 256-bit ticket is not, so it gets the
	// same throttle a wrong admin key does.
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		view.Error = "Too many attempts from this address. Wait a minute and try again."
		view.NeedsPass = true
		return
	}

	window, err := s.store.ClaimEnrolment(addr, r.FormValue("passcode"))
	if err != nil {
		var unavailable *storage.EnrolmentWindowUnavailable
		if ok := asEnrolmentUnavailable(err, &unavailable); ok && unavailable.NeedsPasscode {
			if s.throttle.fail(addr) {
				log.Printf("[!] %s has failed the enrolment passcode %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
			}
			view.NeedsPass = true
			view.Covered = true
			if strings.TrimSpace(r.FormValue("passcode")) != "" {
				view.Error = "That passcode is not right."
			}
			return
		}
		view.Covered = false
		if ok := asEnrolmentUnavailable(err, &unavailable); ok && unavailable.Closed != "" {
			// Covered by a window that has stopped authorising. Say which,
			// because "not authorised" would send whoever is standing here
			// looking for the wrong problem.
			view.Error = "The enrolment window for this network is " + unavailable.Closed +
				". Ask an administrator to open another one."
			return
		}
		view.Error = "This machine is not authorised to enrol itself. Ask an administrator to open an enrolment window for " + addr + "."
		return
	}
	s.throttle.succeed(addr)

	profile, code, err := s.store.CreateEnrollmentProfile(storage.EnrollmentProfile{
		Kind: "campaign", Platform: plat.key, TenantID: window.TenantID,
		LocationID: window.LocationID, Role: window.Role, MaxUses: 1,
		CreatedBy: "self-service",
	}, storage.EnrollmentProfileTTL)
	if err != nil {
		view.Error = "The hub could not mint an enrollment profile: " + err.Error()
		return
	}

	view.Covered = true
	view.NeedsPass = false
	view.WindowLabel = window.Label
	view.Command = plat.oneLiner(s.downloadBase(r))
	view.Code = code
	view.ProfileID = profile.ID
	view.ExpiresIn = enrollmentExpiresIn(profile)

	// Self-service is exactly the case where the record has to say where the
	// request came from: nobody was watching when it happened.
	for _, hdr := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID"} {
		r.Header.Del(hdr)
	}
	r.Header.Set("X-Role", "admin")
	r.Header.Set("X-Username", "self-service")
	s.audit(r, "ENROLLMENT_PROFILE_CREATED", profile.ID,
		"Self-service: "+addr+" received a one-use "+plat.label+" enrollment code from window "+
			window.ID+" ("+window.Label+") at "+time.Now().UTC().Format(time.RFC3339))
}

// humanDuration is for the one place a duration is read by somebody who is not
// an operator. "30m0s" is what Go prints and is not what a person standing at a
// laptop should be asked to parse.
func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		if h := int(d / time.Hour); h == 1 {
			return "an hour"
		} else {
			return strconv.Itoa(h) + " hours"
		}
	case d >= time.Minute && d%time.Minute == 0:
		if m := int(d / time.Minute); m == 1 {
			return "a minute"
		} else {
			return strconv.Itoa(m) + " minutes"
		}
	case d >= time.Minute:
		// A profile is normally rendered a few microseconds after it was
		// created. Round up so a fresh 30-minute code is not shown as an
		// unexplained duration string such as 29m59.9s.
		m := int((d + time.Minute - 1) / time.Minute)
		if m == 1 {
			return "a minute"
		}
		return strconv.Itoa(m) + " minutes"
	default:
		return d.String()
	}
}

// asEnrolmentUnavailable is errors.As without importing errors for one call.
func asEnrolmentUnavailable(err error, target **storage.EnrolmentWindowUnavailable) bool {
	if u, ok := err.(*storage.EnrolmentWindowUnavailable); ok {
		*target = u
		return true
	}
	return false
}

var portalTemplate = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Install the Ominull agent</title>
<style nonce="{{.Nonce}}">
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--ink:#14181f;--dim:#5c6673;--line:#dfe3e9;--brand:#1f6feb;--warn:#8a5a00;--warnbg:#fff6e0;--crit:#a11;--critbg:#fdecec;--code:#0f1319;--codeink:#e6edf3}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--dim:#9aa5b1;--line:#2b313a;--brand:#58a6ff;--warn:#e3b341;--warnbg:#2a2312;--crit:#f85149;--critbg:#2a1416;--code:#010409;--codeink:#e6edf3}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:44rem;margin:0 auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.5rem;margin-bottom:1rem}
h1{font-size:1.35rem;margin:0 0 .35rem}
p.sub{color:var(--dim);margin:0 0 1.25rem}
fieldset{border:0;padding:0;margin:0 0 1rem}
legend{font-weight:600;margin-bottom:.5rem;padding:0}
.picks{display:flex;gap:.5rem;flex-wrap:wrap}
.pick{flex:1 1 8rem}
.pick input{position:absolute;opacity:0;pointer-events:none}
.pick span{display:block;text-align:center;padding:.7rem .5rem;border:1px solid var(--line);border-radius:8px;cursor:pointer;background:var(--bg)}
.pick input:checked+span{border-color:var(--brand);box-shadow:inset 0 0 0 1px var(--brand);font-weight:600}
.pick input:focus-visible+span{outline:2px solid var(--brand);outline-offset:2px}
label.field{display:block;margin-bottom:1rem}
label.field span{display:block;font-weight:600;margin-bottom:.35rem}
input[type=password]{width:100%;padding:.6rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
button{font:inherit;font-weight:600;padding:.7rem 1.1rem;border-radius:8px;border:1px solid var(--brand);background:var(--brand);color:#fff;cursor:pointer}
button.ghost{background:transparent;color:var(--brand)}
pre{background:var(--code);color:var(--codeink);padding:1rem;border-radius:8px;overflow-x:auto;margin:0 0 .75rem;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.note{padding:.75rem 1rem;border-radius:8px;margin:0 0 1rem}
.note-warn{background:var(--warnbg);color:var(--warn)}
.note-crit{background:var(--critbg);color:var(--crit)}
ol{margin:0;padding-left:1.25rem}
ol li{margin-bottom:.4rem}
footer{color:var(--dim);font-size:.8rem;text-align:center;margin-top:1.5rem}
code.inline{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:.1rem .3rem;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
/* The page's policy allows only this nonced block, so every rule lives here -
   a style attribute is refused silently and the layout quietly drifts. */
ol.steps{margin-top:1.25rem}
p.flush{margin:0}
a{color:var(--brand)}
</style>
</head>
<body>
<main>
{{if .Command}}
  <div class="card">
    <h1>Run this on this machine</h1>
    <p class="sub">{{.PlatformLbl}} &middot; code expires in {{.ExpiresIn}}.</p>
    <p>Run the command below on this host. When it asks, enter this code:</p>
    <pre id="code">{{.Code}}</pre>
    <pre id="cmd">{{.Command}}</pre>
    <button type="button" id="copy" class="ghost">Copy command</button>
    <ol class="steps">
      {{if eq .Platform "windows"}}
      <li>Open <strong>PowerShell as Administrator</strong> — right-click Start, then &ldquo;Terminal (Admin)&rdquo;.</li>
      {{else}}
      <li>Open a <strong>Terminal</strong>.</li>
      {{end}}
      <li>Paste the command and press Enter.</li>
      <li>Enter the code when prompted. It installs the native package and enrolls this machine.</li>
    </ol>
  </div>
  <div class="card">
    <p class="flush"><a href="/install">Get a command for a different operating system</a></p>
  </div>
{{else}}
  <div class="card">
    <h1>Install the Ominull agent</h1>
    <p class="sub">This machine ({{.ClientIP}}) can enrol itself. Pick its operating system.</p>
    {{if .Error}}<p class="note note-crit">{{.Error}}</p>{{end}}
    {{if .Covered}}
    <form method="POST" action="/install">
      <fieldset>
        <legend>Operating system</legend>
        <div class="picks">
          {{range .Platforms}}
          <label class="pick"><input type="radio" name="platform" value="{{.Key}}"{{if .Selected}} checked{{end}}><span>{{.Label}}</span></label>
          {{end}}
        </div>
      </fieldset>
      {{if .NeedsPass}}
      <label class="field"><span>Enrolment passcode</span>
        <input type="password" name="passcode" autocomplete="off" autofocus></label>
      {{end}}
      <button type="submit">Get my install command</button>
    </form>
    {{else}}
    <p class="note note-warn">This machine is not authorised to enrol itself. An administrator has to open an enrolment window covering <code class="inline">{{.ClientIP}}</code> in the Ominull console.</p>
    {{end}}
  </div>
{{end}}
<footer>Ominull {{.HubVersion}}</footer>
</main>
<script nonce="{{.Nonce}}">
(function () {
  var btn = document.getElementById("copy"), cmd = document.getElementById("cmd");
  if (!btn || !cmd) return;
  btn.addEventListener("click", function () {
    var text = cmd.textContent;
    var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy command"; }, 1600); };
    /* clipboard.writeText is unavailable on a plain-HTTP origin, which is
       exactly how this page is usually reached, so the selection fallback is
       the path that actually runs rather than a nicety. */
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, select);
    } else { select(); }
    function select() {
      var range = document.createRange();
      range.selectNodeContents(cmd);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      try { document.execCommand("copy"); done(); } catch (e) { btn.textContent = "Press Ctrl+C"; }
    }
  });
})();
</script>
</body>
</html>
`))
