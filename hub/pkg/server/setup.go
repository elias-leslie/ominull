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
		doc, nonce := setupDocument(session.CSRF, s.setupIsComplete())
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
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "saved", "restart_required": configPath != ""})
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
	authorized := session || secureStringEqual(strings.TrimSpace(r.Header.Get("X-API-Key")), s.adminKey)
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
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ominull status</title><link rel="stylesheet" href="/app.css"></head><body><main class="setup-shell"><h1>Ominull status</h1><p class="sub">Same bounded diagnostics used by first-run setup.</p><button id="rerun" class="btn btn-primary" type="button">Run checks again</button><section id="checks"><p>Loading…</p></section><p><a href="/">Open console</a></p></main><script nonce="` + nonce + `">const checks=document.querySelector('#checks');const render=b=>{checks.replaceChildren(...(b.results||[]).map(x=>{const p=document.createElement('p');const strong=document.createElement('strong');strong.textContent=x.state||'unknown';p.append(strong,document.createTextNode(' '+(x.title||'')+': '+(x.summary||'')+(x.remediation?' — '+x.remediation:'')));return p}))};const load=()=>fetch('/api/v1/diagnostics',{credentials:'same-origin'}).then(r=>r.json()).then(render).catch(e=>{checks.textContent=e.message});document.querySelector('#rerun').addEventListener('click',load);load();</script></body></html>`
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

func setupDocument(csrf string, complete bool) ([]byte, string) {
	nonce := newCSPNonce()
	state, _ := json.Marshal(map[string]interface{}{"csrf": csrf, "complete": complete})
	html := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ominull setup wizard</title><link rel="stylesheet" href="/app.css"></head><body><main class="setup-shell"><h1>Ominull setup wizard</h1><p class="sub">Resumable package-owned setup. Direct native access works without Cloudflare.</p><section class="setup-step"><h2>Step 1 · Host preflight</h2><p>Checks cover the hub package, one service, storage, PKI, signed agent packages, URLs, optional identity providers, and a real agent heartbeat.</p><section id="checks"><p>Loading diagnostics…</p></section></section><form id="setup-form"><fieldset class="setup-step"><legend>Step 2 · Local administrator and recovery</legend><label>Administrator email<input name="email" type="email" required placeholder="operator@example.invalid"></label><p class="pending">The local admin key stays in its root-only package file. Keep <code>sudo ominullctl setup-token --rotate</code> as break-glass recovery if OIDC or Cloudflare is unavailable.</p></fieldset><fieldset class="setup-step"><legend>Step 3 · Network mode and addresses</legend><label>Network mode<select name="network"><option value="lan">LAN-only / direct local</option><option value="direct">Direct WAN</option><option value="cloudflare">Optional Cloudflare Tunnel + Access</option></select></label><label>Console URL<input name="console_url" type="url" placeholder="https://console.example.invalid"></label><label>Agent URL<input name="agent_url" type="url" placeholder="https://agent.example.invalid"></label><p class="pending">Keep console and agent hostnames separate. Direct WAN requires public TLS and upstream TCP 443 forwarding. Cloudflare uses an outbound Tunnel; this hub does not change DNS, router forwarding, or provider policy.</p></fieldset><fieldset class="setup-step"><legend>Step 4 · DNS and certificates</legend><label>TLS mode<select name="tls_mode"><option value="self-issued">Self-issued native CA (LAN)</option><option value="acme">ACME certificate prepared by operator</option><option value="custom">Operator certificate</option></select></label><label>Client certificate proof<select name="client_certs"><option value="optional">Optional during migration; verify when offered</option><option value="required">Required after every agent is proven</option><option value="off">Do not request client certificates (recovery only)</option></select></label><label>Server certificate path<input name="tls_cert_file" placeholder="/etc/ominull/server.crt"></label><label>Server key path<input name="tls_key_file" placeholder="/etc/ominull/server.key"></label><label>Additional certificate names<input name="tls_hosts" placeholder="hub.local,agent.example.invalid"></label><p class="pending">Keep native mTLS optional while enrolling or recovering a fleet, then require it after every agent presents its matching hub-issued certificate. The hub device CA stays separate from the public server certificate. Private keys are read by the package service and never returned by diagnostics.</p></fieldset><fieldset class="setup-step"><legend>Step 5 · Human authentication</legend><h3>Optional native OIDC</h3><label>HTTPS issuer<input name="oidc_issuer" type="url" placeholder="https://issuer.example.invalid"></label><label>Client ID<input name="oidc_client_id"></label><label>Redirect URL<input name="oidc_redirect_url" type="url" placeholder="https://console.example.invalid/oidc/callback"></label><label>Client secret<input name="oidc_client_secret" type="password" autocomplete="off" placeholder="stored root-only"></label><h3>Optional Cloudflare Access console</h3><label>Access team<input name="access_team" placeholder="team-name"></label><label>Access application audience<input name="access_audience" placeholder="application audience tag"></label><p class="pending">OIDC uses discovery, authorization code, PKCE, state, nonce, issuer, audience, and stable subject binding. Cloudflare Access uses its signed JWT and explicit Ominull operator membership. Neither provider grants an Ominull role by itself.</p></fieldset><section class="setup-step"><h2>Step 6 · WAN agent access</h2><p>Use the separate agent URL for native device credentials. An unauthenticated agent request must return bounded JSON, never a browser login page. In Cloudflare mode create the separate agent Tunnel route without an interactive Access redirect; no shared service token, Access mTLS, BYOCA, Workers, Spectrum, paid load balancing, or Enterprise feature is required.</p></section><section class="setup-step"><h2>Step 7 · Install agents</h2><p>Open <a href="/install">/install</a> for Linux or Windows native package enrollment. Choose the platform, redeem the one-use invitation, campaign, or persistent deployment profile, and run the protected stdin/file installer.</p></section><section class="setup-step"><h2>Step 8 · Prove and finish</h2><p>Each successful redemption receives a unique device credential and matching client certificate. The proof gate requires current heartbeats and native package provenance. Re-run checks after each install, then complete setup.</p><button id="complete" class="btn btn-primary" type="button">Complete after proof</button><button id="rerun" class="btn" type="button">Run checks again</button><pre id="output"></pre></section><button class="btn btn-primary" type="submit">Save validated configuration</button></form><p><a href="/status">Open permanent status page</a></p></main><script nonce="` + nonce + `">const SETUP=` + string(state) + `;const q=s=>document.querySelector(s);const field=n=>q('[name="'+n+'"]');async function api(url,opt={}){opt.headers=Object.assign({'Content-Type':'application/json','X-CSRF-Token':SETUP.csrf},opt.headers||{});const r=await fetch(url,opt);const b=await r.json().catch(()=>({}));if(!r.ok)throw new Error(b.error||'request failed');return b}function renderChecks(b){const box=q('#checks');box.replaceChildren(document.createElement('h2'));box.firstChild.textContent='Diagnostics';(b.results||[]).forEach(x=>{const p=document.createElement('p');const strong=document.createElement('strong');strong.textContent=x.state||'unknown';p.append(strong,document.createTextNode(' '+(x.title||'')+': '+(x.summary||'')+(x.remediation?' — '+x.remediation:'')+(x.checked_at?' · '+new Date(x.checked_at).toLocaleString():'')));box.append(p)});q('#complete').disabled=!!b.has_failures;const c=b.configuration||{};[['network','network_mode'],['console_url','console_url'],['agent_url','agent_url'],['tls_mode','tls_mode'],['client_certs','client_certs'],['tls_cert_file','tls_cert_file'],['tls_key_file','tls_key_file'],['tls_hosts','tls_hosts'],['oidc_issuer','oidc_issuer'],['oidc_client_id','oidc_client_id'],['oidc_redirect_url','oidc_redirect_url'],['access_team','access_team'],['access_audience','access_audience']].forEach(pair=>{if(c[pair[1]]!==undefined&&field(pair[0]))field(pair[0]).value=Array.isArray(c[pair[1]])?c[pair[1]].join(','):c[pair[1]]})}function load(){return api('/api/v1/setup/status',{headers:{}}).then(renderChecks).catch(e=>{q('#checks').textContent=e.message})}q('#setup-form').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target);const b={configuration:{network_mode:f.get('network'),console_url:f.get('console_url'),agent_url:f.get('agent_url'),tls_mode:f.get('tls_mode'),client_certs:f.get('client_certs'),tls_cert_file:f.get('tls_cert_file'),tls_key_file:f.get('tls_key_file'),tls_hosts:String(f.get('tls_hosts')||'').split(',').map(x=>x.trim()).filter(Boolean),oidc_issuer:f.get('oidc_issuer'),oidc_client_id:f.get('oidc_client_id'),oidc_redirect_url:f.get('oidc_redirect_url'),access_team:f.get('access_team'),access_audience:f.get('access_audience'),cloudflare:f.get('network')==='cloudflare'},local_admin_email:f.get('email'),oidc_client_secret:f.get('oidc_client_secret')};try{q('#output').textContent=JSON.stringify(await api('/api/v1/setup/apply',{method:'POST',body:JSON.stringify(b)}),null,2);await load()}catch(e){q('#output').textContent=e.message}});q('#complete').addEventListener('click',async()=>{try{q('#output').textContent=JSON.stringify(await api('/api/v1/setup/complete',{method:'POST',body:'{}'}),null,2);q('#complete').disabled=true}catch(e){q('#output').textContent=e.message}});q('#rerun').addEventListener('click',load);load();</script></body></html>`
	return []byte(html), nonce
}
