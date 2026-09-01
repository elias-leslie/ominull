package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/configuration"
	"ominull/hub/pkg/diagnostics"
	"ominull/hub/pkg/setup"
)

const setupSessionCookie = "ominull_setup"
const setupSessionTTL = 30 * time.Minute

type setupSession struct {
	CSRF      string
	ExpiresAt time.Time
}

type setupApplyRequest struct {
	Configuration    configuration.Config `json:"configuration"`
	LocalAdminEmail  string               `json:"local_admin_email"`
	OIDCClientSecret string               `json:"oidc_client_secret,omitempty"`
}

func (s *Server) SetSetupPaths(tokenPath, configPath, dbPath, adminPath, binaryDir string) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if strings.TrimSpace(tokenPath) != "" {
		s.setupTokenPath = tokenPath
	}
	s.setupConfigPath = configPath
	s.setupDBPath = dbPath
	if strings.TrimSpace(adminPath) == "" {
		adminPath = "/etc/ominull/admin.key"
	}
	s.setupAdminPath = adminPath
	s.setupBinaryDir = binaryDir
}

func (s *Server) setupIsComplete() bool {
	value, err := s.store.GetSetting("setup.complete")
	return err == nil && strings.EqualFold(strings.TrimSpace(value), "true")
}

func (s *Server) setupSessionFromRequest(r *http.Request) (setupSession, bool) {
	cookie, err := r.Cookie(setupSessionCookie)
	if err != nil || cookie.Value == "" {
		return setupSession{}, false
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	session, ok := s.setupSessions[cookie.Value]
	if !ok || time.Now().UTC().After(session.ExpiresAt) {
		delete(s.setupSessions, cookie.Value)
		return setupSession{}, false
	}
	return session, true
}

func setupRandomString(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Server) createSetupSession(w http.ResponseWriter, r *http.Request) error {
	id, err := setupRandomString(32)
	if err != nil {
		return err
	}
	csrf, err := setupRandomString(24)
	if err != nil {
		return err
	}
	s.setupMu.Lock()
	s.setupSessions[id] = setupSession{CSRF: csrf, ExpiresAt: time.Now().UTC().Add(setupSessionTTL)}
	s.setupMu.Unlock()
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: setupSessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(setupSessionTTL / time.Second),
	})
	return nil
}

func (s *Server) invalidateSetupSessions(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	s.setupSessions = map[string]setupSession{}
	s.setupMu.Unlock()
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: setupSessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func (s *Server) setupCSRF(r *http.Request) (setupSession, bool) {
	session, ok := s.setupSessionFromRequest(r)
	if !ok {
		return setupSession{}, false
	}
	presented := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if presented == "" && r.Method == http.MethodPost {
		presented = strings.TrimSpace(r.PostFormValue("csrf_token"))
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !secureStringEqual(presented, session.CSRF) {
		return setupSession{}, false
	}
	return session, true
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/setup" && r.URL.Path != "/setup/" {
		http.NotFound(w, r)
		return
	}
	setConsoleSecurityHeaders(w, "")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if session, ok := s.setupSessionFromRequest(r); ok {
		doc, nonce := setupWizardDocument(session.CSRF, s.setupIsComplete())
		setConsoleSecurityHeaders(w, nonce)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(doc)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(setupGateDocument()))
}

func (s *Server) handleSetupSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var token string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable setup token body")
			return
		}
		token = body.Token
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable setup token body")
			return
		}
		token = r.PostFormValue("token")
	}
	s.setupMu.Lock()
	tokenPath := s.setupTokenPath
	s.setupMu.Unlock()
	ok, err := setup.Consume(tokenPath, token)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "setup token could not be checked")
		return
	}
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid or already used setup token")
		return
	}
	if err := s.createSetupSession(w, r); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "setup session could not be created")
		return
	}
	if s.setupIsComplete() {
		s.auditAs(r, "local-recovery", "SETUP_REOPENED", "setup", "Opened a recovery setup session with a fresh local token")
	} else {
		s.auditAs(r, "local-setup", "SETUP_STARTED", "setup", "Started first-run setup with the local one-time token")
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") || !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated", "redirect": "/setup"})
}

func (s *Server) setupOrAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.setupCSRF(r); ok {
			r.Header.Set("X-Role", "admin")
			r.Header.Set("X-Username", "local-setup")
			next(w, r)
			return
		}
		if _, ok := s.setupSessionFromRequest(r); ok && r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		s.authMiddleware(next)(w, r)
	}
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	results := s.runDiagnostics(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"setup_complete": s.setupIsComplete(),
		"configuration":  s.setupConfiguration(),
		"results":        results,
		"has_failures":   diagnostics.HasFailure(results),
	})
}

func (s *Server) setupConfiguration() configuration.Config {
	raw, err := s.store.GetSetting("setup.configuration")
	if err != nil || strings.TrimSpace(raw) == "" {
		return configuration.Config{}
	}
	var cfg configuration.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return configuration.Config{}
	}
	return cfg
}

func (s *Server) handleSetupApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req setupApplyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable setup body")
		return
	}
	req.Configuration = req.Configuration.Normalized()
	if err := req.Configuration.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	previousConfiguration := s.setupConfiguration()
	email := strings.ToLower(strings.TrimSpace(req.LocalAdminEmail))
	if email == "" || !strings.Contains(email, "@") {
		writeJSONError(w, http.StatusBadRequest, "local_admin_email is required")
		return
	}
	if err := s.store.UpsertOperator(email, "admin", "local-setup"); err != nil {
		writeJSONError(w, http.StatusBadRequest, "local administrator could not be saved: "+err.Error())
		return
	}
	encoded, err := json.Marshal(req.Configuration)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "configuration could not be encoded")
		return
	}
	if err := s.store.SetSetting("setup.configuration", string(encoded)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "configuration could not be saved")
		return
	}
	if err := s.store.SetSetting("setup.network_mode", req.Configuration.NetworkMode); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "network mode could not be saved")
		return
	}
	if req.Configuration.OIDCIssuer != "" {
		if err := s.store.SetSetting("oidc.issuer", req.Configuration.OIDCIssuer); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "OIDC configuration could not be saved")
			return
		}
		if err := s.store.SetSetting("oidc.client_id", req.Configuration.OIDCClientID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "OIDC client could not be saved")
			return
		}
		if err := s.store.SetSetting("oidc.redirect_url", req.Configuration.OIDCRedirectURL); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "OIDC redirect URL could not be saved")
			return
		}
	} else {
		for _, key := range []string{"oidc.issuer", "oidc.client_id", "oidc.redirect_url"} {
			if err := s.store.SetSetting(key, ""); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "OIDC configuration could not be cleared")
				return
			}
		}
	}
	if req.Configuration.Cloudflare {
		_ = s.store.SetSetting("cloudflare.adapter", "tunnel-access-guided")
	} else if err := s.store.SetSetting("cloudflare.adapter", ""); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Cloudflare adapter state could not be cleared")
		return
	}
	s.setupMu.Lock()
	configPath, dbPath, adminPath, binaryDir := s.setupConfigPath, s.setupDBPath, s.setupAdminPath, s.setupBinaryDir
	s.setupMu.Unlock()
	restartRequired := configPath != "" && (!s.setupRuntimeMatches(req.Configuration) ||
		!strings.EqualFold(previousConfiguration.TLSMode, req.Configuration.TLSMode))
	if configPath != "" {
		contents := req.Configuration.Environment(dbPath, adminPath, binaryDir, s.setupTokenPath)
		if err := configuration.WriteEnvironmentAtomic(configPath, contents); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "package configuration could not be written")
			return
		}
		if strings.TrimSpace(req.OIDCClientSecret) != "" {
			secretPath := filepath.Join(filepath.Dir(configPath), "oidc-client.secret")
			if err := configuration.WriteEnvironmentAtomic(secretPath, req.OIDCClientSecret+"\n"); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "OIDC secret could not be stored")
				return
			}
		} else if req.Configuration.OIDCIssuer == "" {
			secretPath := filepath.Join(filepath.Dir(configPath), "oidc-client.secret")
			if err := removeOIDCSecret(secretPath); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "OIDC secret could not be removed safely")
				return
			}
		}
	}
	s.audit(r, "SETUP_APPLIED", "setup", "Saved first-run network, TLS, identity, and optional Cloudflare adapter configuration")
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "saved", "restart_required": restartRequired})
}

func (s *Server) setupRuntimeMatches(cfg configuration.Config) bool {
	if strings.TrimRight(strings.TrimSpace(s.hubURL), "/") != cfg.ConsoleURL ||
		strings.TrimRight(strings.TrimSpace(s.agentHubURL), "/") != cfg.AgentURL ||
		strings.TrimSpace(s.tlsOpts.CertFile) != cfg.TLSCertFile ||
		strings.TrimSpace(s.tlsOpts.KeyFile) != cfg.TLSKeyFile ||
		!strings.EqualFold(strings.TrimSpace(string(s.tlsOpts.ClientCerts)), cfg.ClientCerts) {
		return false
	}
	activeHosts := append([]string(nil), s.tlsOpts.Hosts...)
	configuredHosts := append([]string(nil), cfg.TLSHosts...)
	sort.Strings(activeHosts)
	sort.Strings(configuredHosts)
	if !slices.Equal(activeHosts, configuredHosts) {
		return false
	}
	if cfg.AccessTeam == "" && cfg.AccessAudience == "" {
		return s.access == nil
	}
	return s.access != nil && s.access.team == cfg.AccessTeam && s.access.aud == cfg.AccessAudience
}

func removeOIDCSecret(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("OIDC secret path is not a regular file")
	}
	return os.Remove(path)
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	results := s.runDiagnostics(r.Context())
	if diagnostics.HasFailure(results) {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "resolve failed diagnostics before completing setup", "results": results})
		return
	}
	if err := s.store.SetSetting("setup.complete", "true"); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "setup state could not be saved")
		return
	}
	cfg := s.setupConfiguration()
	cfg.SetupComplete = true
	if encoded, err := json.Marshal(cfg); err == nil {
		_ = s.store.SetSetting("setup.configuration", string(encoded))
	}
	s.audit(r, "SETUP_COMPLETED", "setup", "Completed first-run setup after diagnostics passed")
	s.invalidateSetupSessions(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "complete"})
}

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/status" {
		http.NotFound(w, r)
		return
	}
	_, session := s.consoleSession(r)
	_, setupSession := s.setupSessionFromRequest(r)
	authorized := session || setupSession || secureStringEqual(strings.TrimSpace(r.Header.Get("X-API-Key")), s.adminKey)
	if !authorized {
		if _, ok := s.access.Verify(r); ok {
			authorized = true
		}
	}
	if !authorized {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	nonce := newCSPNonce()
	setConsoleSecurityHeaders(w, nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ominull status</title><link rel="stylesheet" href="/app.css"></head>
<body class="setup-page">
<main class="setup-shell">
  <header class="setup-head"><div><h1>Ominull status</h1><p class="sub">Live checks for host, packages, network, certificates, agent transport, identity, and fleet proof.</p></div><a class="btn" href="/">Open console</a></header>
  <section class="setup-step"><div class="setup-actions"><div><h2>System checks</h2></div><div><button id="rerun" class="btn btn-primary" type="button">Run checks again</button></div></div><div id="checks"><p class="empty">Running diagnostics…</p></div></section>
</main>
<script nonce="` + nonce + `">
(function(){
  "use strict";
  var checks=document.querySelector("#checks"), rerun=document.querySelector("#rerun");
  function el(tag,cls,text){var node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node;}
  function render(body){
    checks.textContent="";
    var results=body.results||[], counts={pass:0,fail:0,warn:0,not_configured:0};
    results.forEach(function(item){counts[item.state]=(counts[item.state]||0)+1;});
    var summary=el("div","diag-summary");
    [["pass","Pass"],["fail","Fail"],["warn","Warning"],["not_configured","Not configured"]].forEach(function(pair){summary.appendChild(el("span","st",""+counts[pair[0]]+" "+pair[1]));});
    var grid=el("div","diag-grid");
    results.forEach(function(item){
      var card=el("article","diag");card.dataset.state=item.state||"not_configured";
      card.appendChild(el("span","diag-mark",item.state==="pass"?"✓":item.state==="fail"?"×":item.state==="warn"?"!":"–"));
      var copy=el("div");copy.appendChild(el("h3","",item.title||"Check"));copy.appendChild(el("p","",item.summary||"No result"));
      if(item.remediation)copy.appendChild(el("p","remediation",item.remediation));card.appendChild(copy);grid.appendChild(card);
    });
    checks.append(summary,grid);
  }
  function load(){rerun.disabled=true;rerun.textContent="Running…";return fetch("/api/v1/setup/status",{credentials:"same-origin"}).then(function(response){if(!response.ok)throw new Error("diagnostics request failed");return response.json();}).then(render).catch(function(error){checks.textContent=error.message;}).finally(function(){rerun.disabled=false;rerun.textContent="Run checks again";});}
  rerun.addEventListener("click",load);load();
})();
</script>
</body></html>`
	_, _ = w.Write([]byte(page))
}

func (s *Server) runDiagnostics(ctx context.Context) []diagnostics.Result {
	return diagnostics.Runner{Timeout: 8 * time.Second, Limit: 4, Checks: s.diagnosticChecks()}.Run(ctx)
}

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return "configured"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func secureStringEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

var setupGateTemplate = template.Must(template.New("setup-gate").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ominull setup</title><link rel="stylesheet" href="/app.css"></head><body><main class="gate"><form method="post" action="/api/v1/setup/session"><h1>Ominull first-run setup</h1><p>Run <code>ominullctl setup-token</code> on the hub host. Token is one-use and never appears in a URL.</p><input type="password" name="token" autocomplete="off" required autofocus placeholder="Local setup token"><button class="btn btn-primary" type="submit">Open setup</button></form></main></body></html>`))

func setupGateDocument() []byte {
	var b strings.Builder
	_ = setupGateTemplate.Execute(&b, nil)
	return []byte(b.String())
}
