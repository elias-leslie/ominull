package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/scanner"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

type Server struct {
	store     *storage.Store
	ti        *threatintel.Manager
	detector  *detector.Engine
	pki       *pki.Manager
	scanner   *scanner.Scanner
	adminKey  string
	binaryDir string
	hubURL    string
	// Whether hubURL actually serves this hub, and when that was last checked.
	// A configured public URL is a claim, not a fact: see downloadBaseWithNote.
	publicURLMu  sync.Mutex
	publicURLOK  bool
	publicURLAt  time.Time
	agentHubURL  string
	agentVersion string
	httpServer   *http.Server
	tlsServer    *http.Server
	tlsOpts      TLSOptions
	// access verifies Cloudflare Access assertions when the hub sits behind
	// Access. nil means it is not configured, which is the default.
	access *accessVerifier

	// throttle bounds online credential guessing across every route that
	// accepts a key.
	throttle *authThrottle
	// topology holds the rendered graph briefly; see responsecache.go.
	topology responseCache
}

type TelemetryBatchMessage struct {
	Type       string `json:"type"` // "telemetry"
	EndpointID string `json:"endpoint_id"`
	TenantID   string `json:"tenant_id"`
	LocationID string `json:"location_id"`
	Role       string `json:"role"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	IP         string `json:"ip"`
	// MAC is the endpoint's primary hardware address. Asset identity keys on
	// it, so an agented host that changes DHCP lease stays one record instead
	// of forking a second one. The retained Linux and Windows agents send
	// this field; until 1.2.0 the hub had nowhere to put it and encoding/json
	// discarded it, which left every agented asset keyed on address alone.
	MAC           string `json:"mac"`
	DriverVersion string `json:"driver_version"`
	// UpdateCapability is the package format the agent can install for
	// itself. Deciding that from the reported OS string was always fragile -
	// that string is a display label, and v1.2.0 changed the Windows one from
	// a hardcoded literal to a detected value - so the agent states it
	// outright. Absent means "none", which is what a pre-1.3.0 agent sends.
	UpdateCapability         string          `json:"update_capability"`
	InstallType              string          `json:"install_type"`
	PackageIdentifier        string          `json:"package_identifier"`
	RegisteredPackageVersion string          `json:"registered_package_version"`
	ProvenanceStatus         string          `json:"provenance_status"`
	Events                   []storage.Event `json:"events"`
	// ObservedServices is what this host actually uses the network for at the
	// infrastructure layer - its resolvers, its DHCP server, its time sources -
	// so the baseline isolation policy can be checked against reality instead
	// of against an assumption. The agent reports; it never authors.
	ObservedServices []storage.ObservedService `json:"observed_services"`
	// Readiness is the endpoint's own answer to "can I still be released after
	// this?". Absent from agents that predate the check, which is a state the
	// gate distinguishes from a failing answer.
	Readiness *storage.Readiness `json:"isolation_readiness"`
}

// TLSOptions configures the hub's HTTPS listener. Agents carry the API key in
// a header and take isolation commands from the response body, so the listener
// they talk to has to be this one; the plain-HTTP listener stays available for
// a reverse proxy terminating on loopback and for an operator CLI, and can be
// switched off entirely once a fleet has converged onto TLS.
type TLSOptions struct {
	// Listen is the HTTPS bind address. Empty disables the listener.
	Listen string
	// CertFile and KeyFile override the hub's own PKI with an operator-supplied
	// certificate - a public one, for a hub reachable under a real domain.
	CertFile string
	KeyFile  string
	// Hosts are extra SANs to put in the self-issued certificate. The hub always
	// includes localhost, its own interface addresses and the host in --hub-url;
	// this covers the cases it cannot see, such as a floating VIP.
	Hosts []string
	// ClientCerts is how far the listener goes in asking agents to identify
	// themselves: ClientCertsOff, ClientCertsOptional (the default) or
	// ClientCertsRequired.
	//
	// The three exist because the middle setting is not as harmless as it
	// looks. "Verify if given" still makes the listener *ask*, and an agent
	// that has no certificate has to answer the request with an empty one.
	// curl does. WinHTTP does not: it fails the handshake with
	// ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED unless the caller explicitly says
	// there is no certificate, so turning this on took every Windows endpoint
	// off the fleet at once - and off a hub they then could not reach to be
	// given a certificate by. Agents from v1.5.1 answer correctly; Off is what
	// gets a fleet with older ones back, and what an operator reaches for if
	// this ever happens again.
	//
	// Required is the end state, and only after every endpoint is confirmed to
	// be presenting a certificate: past that point the listener stops answering
	// the ones that are not.
	ClientCerts ClientCertMode
}

// ClientCertMode is how the TLS listener treats agent certificates.
type ClientCertMode string

const (
	// ClientCertsOff does not ask for one. No endpoint can be told apart from
	// another holding the same tenant key; it exists to recover a fleet whose
	// agents cannot survive being asked.
	ClientCertsOff ClientCertMode = "off"
	// ClientCertsOptional asks, verifies whatever is presented against the
	// hub's own CA, and lets an endpoint that has none through. This is what
	// makes a migration possible.
	ClientCertsOptional ClientCertMode = "optional"
	// ClientCertsRequired refuses the handshake without one.
	ClientCertsRequired ClientCertMode = "required"
)

// ParseClientCertMode maps the flag value, defaulting an empty one to optional.
func ParseClientCertMode(v string) (ClientCertMode, error) {
	switch ClientCertMode(strings.TrimSpace(strings.ToLower(v))) {
	case "":
		return ClientCertsOptional, nil
	case ClientCertsOff:
		return ClientCertsOff, nil
	case ClientCertsOptional:
		return ClientCertsOptional, nil
	case ClientCertsRequired:
		return ClientCertsRequired, nil
	default:
		return "", fmt.Errorf("--client-certs must be off, optional or required (got %q)", v)
	}
}

// SetTLS installs the HTTPS configuration. Call it before Start.
func (s *Server) SetTLS(opts TLSOptions) {
	s.tlsOpts = opts
}

// SetAgentHubURL sets the transport enrolment writes into an agent's config.
// It is deliberately separate from --hub-url: the hub is published to operators
// and installers at one address, typically through a reverse proxy, and reached
// by agents at another - the TLS listener whose certificate they pin. Left
// empty, enrolment falls back to the published URL and the deployment behaves
// exactly as it did before there was a TLS listener at all.
// SetAccess turns on Cloudflare Access verification for the console. Passing a
// zero AccessOptions leaves it off.
func (s *Server) SetAccess(opts AccessOptions) error {
	v, err := newAccessVerifier(opts, s.store.GetOperatorRole)
	if err != nil {
		return err
	}
	if v != nil {
		if err := s.store.EnsureBootstrapAdmin(opts.BootstrapAdmin); err != nil {
			return fmt.Errorf("seeding the bootstrap administrator: %w", err)
		}
	}
	s.access = v
	return nil
}

// AccessConfigured reports whether Access identity is in use, so startup can say
// so plainly rather than leaving an operator guessing why the key is or is not
// being asked for.
func (s *Server) AccessConfigured() bool { return s.access != nil }

func (s *Server) SetAgentHubURL(u string) {
	s.agentHubURL = u
}

func New(store *storage.Store, adminKey, binaryDir, hubURL, agentVersion string) *Server {
	pkiMgr, err := pki.New(filepath.Join(binaryDir, "certs"))
	if err != nil {
		log.Printf("[-] Warning: Failed to initialize Autonomous PKI Manager: %v", err)
	}

	// Project every existing endpoint into the asset graph before anything
	// reads it. A hub upgrading into this schema then shows its whole fleet
	// at once instead of one host per agent check-in, and the scanner's cache
	// hydrates from a populated table.
	if err := store.BackfillAssetsFromEndpoints(); err != nil {
		log.Printf("[-] Warning: Failed to backfill the asset graph from endpoints: %v", err)
	}

	s := &Server{
		store:        store,
		ti:           threatintel.New(store),
		pki:          pkiMgr,
		scanner:      scanner.New(store),
		adminKey:     adminKey,
		binaryDir:    binaryDir,
		hubURL:       hubURL,
		agentVersion: agentVersion,
		throttle:     newAuthThrottle(),
	}
	s.detector = detector.New(store, nil, func(endpointID, reason string) error {
		if err := s.store.SetEndpointIsolation(endpointID, true, nil); err != nil {
			return fmt.Errorf("persist detector isolation for %s (%s): %w", endpointID, reason, err)
		}
		return nil
	})
	return s
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Zero-Trust Least Privilege: Reject Cloudflare Service Tokens on the Web Console
	if r.Header.Get("CF-Access-Client-Id") != "" || r.Header.Get("Cf-Access-Client-Id") != "" || r.Header.Get("Cf-Access-Service-Token-Id") != "" {
		http.Error(w, "Access Denied: Service Tokens are restricted to agent telemetry and API endpoints only.", http.StatusForbidden)
		return
	}
	setConsoleSecurityHeaders(w, "")

	// The gate hands out the admin key to anyone who can present it, so it is
	// the one page worth guessing at. Throttle it by source address.
	addr := clientIP(r)
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write(consoleGate())
		return
	}

	// The console embeds the admin API key at serve-time, so it is only rendered
	// for callers who can already present a valid admin credential.
	//
	// A session cookie is checked first, because the other two ways of arriving
	// here both put the credential somewhere it outlives the request. The gate
	// form used to be a GET, so unlocking the console wrote the admin key into
	// the address bar, and from there into browser history, into the request log
	// of every proxy on the path, and into whatever the CDN in front records.
	// Purging a CDN cache does not reach any of those. The key is now accepted
	// from a POST body, exchanged for a short-lived signed cookie, and a request
	// that still arrives with ?key= is redirected to a clean URL so it stops
	// being part of the address.
	fromQuery := strings.TrimSpace(r.URL.Query().Get("key"))
	provided := fromQuery
	if provided == "" && r.Method == http.MethodPost {
		provided = strings.TrimSpace(r.PostFormValue("key"))
	}
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	// heldAdminKey is tracked separately from "may see the console", because it
	// decides whether the served document carries the admin key. Only a caller
	// who already has that key is handed it back; an operator identified by
	// Access gets a session cookie scoped to their own role instead. Otherwise
	// granting someone the auditor role would still post them the credential
	// that runs the entire fleet.
	heldAdminKey := secretEqual(provided, s.adminKey)
	ok := heldAdminKey
	viewer := accessOperator{Email: "admin", Role: auth.RoleAdmin}

	// An operator who already signed in through Cloudflare Access does not have
	// to present the admin key as well. The signed assertion is checked, never
	// the plaintext identity header, because this hub also answers directly on
	// the LAN where any caller could assert whatever address it liked.
	var operator accessOperator
	if !ok {
		if op, viaAccess := s.access.Verify(r); viaAccess {
			ok = true
			operator = op
			viewer = op
		}
	}
	// Resolved up front rather than only as a fallback, because whether there
	// was already a session decides whether this load is a sign-in worth
	// recording or the same person reloading the page.
	prior, hadSession := s.consoleSession(r)
	if !ok && hadSession {
		ok = true
		viewer = prior
	}
	if !ok {
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			if claims, err := auth.ValidateJWT(strings.TrimPrefix(authHeader, "Bearer "), s.adminKey); err == nil && claims != nil {
				ok = true
				viewer = accessOperator{Email: claims.Username, Role: claims.Role}
			}
		}
	}
	if !ok {
		if provided != "" && s.throttle.fail(addr) {
			log.Printf("[!] %s has failed the console gate %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(consoleGate())
		return
	}
	s.throttle.succeed(addr)

	// Whoever just proved who they are gets a cookie, so the next request does
	// not have to carry a credential at all.
	if heldAdminKey || operator.Email != "" {
		s.setConsoleSession(w, r, operator)
	}

	// A sign-in is a thing that happened, and until now nothing recorded it:
	// the hub logged an assertion it refused but said nothing about one it
	// accepted, so "did my Google login actually work, or am I still on an old
	// session?" had no answer anywhere. Recorded once per sign-in rather than
	// once per page load - a reload carrying a live session is the same person
	// still being there, not a new event.
	if !hadSession || prior.Email != viewer.Email {
		how := "the admin key"
		if operator.Email != "" {
			how = "Cloudflare Access"
		}
		log.Printf("[+] %s opened the console via %s as %s.", viewer.Email, how, viewer.Role)
		s.auditAs(r, viewer.Email, "CONSOLE_SIGNIN", viewer.Email, "Opened the console via "+how+" with the "+viewer.Role+" role")
	}
	// The credential is in this URL. Send the browser to a clean one before
	// rendering anything, so the address that ends up in history, in a bookmark
	// and in every access log upstream has no key in it.
	if fromQuery != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// The key is embedded only for the caller who already presented it. Everyone
	// else authenticates their API calls with the session cookie, which carries
	// their role and stops working the moment an admin revokes them.
	embeddedKey := ""
	if heldAdminKey {
		embeddedKey = s.adminKey
	}
	doc, nonce := consoleDocument(embeddedKey, s.agentVersion, viewer)
	setConsoleSecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(doc)
}

// consoleSessionCookie carries a short-lived signed assertion that this browser
// already presented the admin key, so the key itself does not have to travel on
// every console request.
const consoleSessionCookie = "ominull_console"

// consoleSessionTTL is deliberately short. The cookie is a convenience for one
// working session, not a second credential with a long life of its own.
const consoleSessionTTL = 12 * time.Hour

// consoleSession resolves the signed session cookie back to the operator it was
// issued to.
//
// The role is re-read from the operator list on every request rather than taken
// from the token. A token is valid for twelve hours, and "you are an admin for
// the rest of the day" is the wrong answer to someone being demoted or removed
// at ten in the morning. The cookie proves who you are; the table decides what
// that is currently worth.
//
// The cookie is SameSite=Strict, so it does not accompany a request another site
// caused the browser to make: it authenticates the console's own calls without
// becoming a way for a page elsewhere to act as the operator.
func (s *Server) consoleSession(r *http.Request) (accessOperator, bool) {
	c, err := r.Cookie(consoleSessionCookie)
	if err != nil || c.Value == "" {
		return accessOperator{}, false
	}
	claims, err := auth.ValidateJWT(c.Value, s.adminKey)
	if err != nil || claims == nil {
		return accessOperator{}, false
	}
	// A session minted for the admin key itself names no person. It carries the
	// authority of the key that was presented, which cannot be revoked from the
	// console, only rotated.
	if !strings.Contains(claims.Username, "@") {
		return accessOperator{Email: claims.Username, Role: claims.Role}, true
	}
	role, listed := s.store.GetOperatorRole(claims.Username)
	if !listed {
		return accessOperator{}, false
	}
	return accessOperator{Email: claims.Username, Role: role}, true
}

func (s *Server) setConsoleSession(w http.ResponseWriter, r *http.Request, operator accessOperator) {
	// An operator identified by Access is named in the session, so the audit log
	// records the person rather than the role. Presenting the admin key directly
	// is anonymous by construction - it says what was held, not who held it.
	username, role := "admin", auth.RoleAdmin
	if operator.Email != "" {
		username, role = operator.Email, operator.Role
	}
	token, err := auth.GenerateJWT(auth.Claims{
		Username: username,
		Role:     role,
	}, s.adminKey, consoleSessionTTL)
	if err != nil {
		return
	}
	// Secure is set only when this request actually arrived over TLS. The hub is
	// reached over https through the public hostname and over plain http on the
	// LAN, and a Secure cookie on the second would simply never be stored,
	// leaving the operator stuck retyping the key into the URL.
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     consoleSessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(consoleSessionTTL / time.Second),
	})
}

func (s *Server) Start(addr string) error {
	// Start Threat Intelligence feed scheduler and behavioral detector.
	s.ti.Start(context.Background(), 1*time.Hour)
	s.detector.Start(context.Background())

	mux := s.routes()

	// Both listeners share one mux. Which port a request arrived on decides
	// whether it was encrypted, never what it is allowed to do - an endpoint
	// that behaved differently per listener would be a second policy surface
	// to keep in step with the first.
	errs := make(chan error, 2)
	listeners := 0

	if s.tlsOpts.Listen != "" {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			return fmt.Errorf("TLS listener on %s: %w", s.tlsOpts.Listen, err)
		}
		s.tlsServer = &http.Server{
			Addr:         s.tlsOpts.Listen,
			Handler:      limitRequestBodies(mux),
			TLSConfig:    tlsCfg,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		listeners++
		log.Printf("[+] Ominull Hub listening on %s over TLS (agent transport)", s.tlsOpts.Listen)
		go func() { errs <- s.tlsServer.ListenAndServeTLS("", "") }()
	}

	if addr != "" {
		s.httpServer = &http.Server{
			Addr:         addr,
			Handler:      limitRequestBodies(mux),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		listeners++
		log.Printf("[+] Ominull Hub listening on %s in the clear (Admin Key configured)", addr)
		go func() { errs <- s.httpServer.ListenAndServe() }()
	}

	if listeners == 0 {
		return fmt.Errorf("no listener configured: --listen and --tls-listen are both empty")
	}

	// Whichever listener fails first ends Start. A shutdown closes both, and
	// the close of the one we are not reporting on is not an error worth
	// drowning the real one in.
	if err := <-errs; err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// tlsConfig resolves the certificate the HTTPS listener presents: an
// operator-supplied pair when one is configured, and otherwise a leaf the hub
// signs with its own CA - the same CA it already serves at
// /api/v1/pki/ca.crt and that enrolment pins on every agent.
//
// The SAN set is fixed at start rather than recomputed per handshake, so a hub
// whose address changes needs a restart to reissue. That is a deliberate trade:
// enumerating interfaces on every connection to catch a rare DHCP move would
// cost more than the restart it saves.
func (s *Server) tlsConfig() (*tls.Config, error) {
	base := &tls.Config{MinVersion: tls.VersionTLS12}

	// How far the listener goes in asking an agent to name itself. "Optional"
	// is not a weaker setting than "required" for the thing that matters: a
	// presented certificate is verified against the hub's own CA either way, so
	// a forged one is refused at the handshake. What it buys is a fleet that can
	// be migrated - an endpoint without a certificate yet keeps reporting, and
	// endpointIdentityOK can tell the two apart. "Off" does not ask at all, and
	// exists because asking is not free: see ClientCerts.
	mode := s.tlsOpts.ClientCerts
	if mode == "" {
		mode = ClientCertsOptional
	}
	if s.pki != nil {
		switch mode {
		case ClientCertsOff:
			base.ClientAuth = tls.NoClientCert
			log.Printf("[!] TLS client certificates: not requested. Every agent holding the tenant key can report as any endpoint.")
		case ClientCertsRequired:
			base.ClientCAs = s.pki.ClientCAPool()
			base.ClientAuth = tls.RequireAndVerifyClientCert
			log.Printf("[+] TLS client certificates: required (agents without one are refused at the handshake)")
		default:
			base.ClientCAs = s.pki.ClientCAPool()
			base.ClientAuth = tls.VerifyClientCertIfGiven
			log.Printf("[+] TLS client certificates: verified when offered; agents without one still report")
		}
	} else if mode == ClientCertsRequired {
		return nil, fmt.Errorf("--client-certs required needs the hub PKI, which failed to initialize")
	}

	if s.tlsOpts.CertFile != "" || s.tlsOpts.KeyFile != "" {
		if s.tlsOpts.CertFile == "" || s.tlsOpts.KeyFile == "" {
			return nil, fmt.Errorf("--tls-cert and --tls-key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(s.tlsOpts.CertFile, s.tlsOpts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load the supplied certificate: %w", err)
		}
		base.Certificates = []tls.Certificate{cert}
		log.Printf("[+] TLS certificate: operator-supplied (%s)", s.tlsOpts.CertFile)
		return base, nil
	}

	if s.pki == nil {
		return nil, fmt.Errorf("the PKI manager failed to initialize, so no certificate can be issued; pass --tls-cert/--tls-key or fix the certs directory")
	}

	hosts := hubSANs(s.hubURL, s.tlsOpts.Hosts)
	cert, err := s.pki.ServerCertificate(hosts)
	if err != nil {
		return nil, err
	}
	base.Certificates = []tls.Certificate{*cert}
	log.Printf("[+] TLS certificate: issued by the hub CA for %s (expires %s)",
		strings.Join(hosts, ", "), cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return base, nil
}

// hubSANs collects every name an agent could plausibly dial this hub by. The
// interface addresses matter most: on the LAN an agent connects to the hub by
// IP, and a certificate without that IP in a SAN is rejected by curl, WinHTTP
// and Go alike - correctly, and with an error that reads like a CA problem.
func hubSANs(hubURL string, extra []string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hosts = append(hosts, hostname)
	}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			hosts = append(hosts, ipNet.IP.String())
		}
	}

	if hubURL != "" {
		trimmed := hubURL
		for _, scheme := range []string{"https://", "http://"} {
			trimmed = strings.TrimPrefix(trimmed, scheme)
		}
		if slash := strings.IndexByte(trimmed, '/'); slash >= 0 {
			trimmed = trimmed[:slash]
		}
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			trimmed = host
		}
		if trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}

	return append(hosts, extra...)
}

// hubOwnsAddress reports why an address belongs to this hub, or "" when it does
// not. Used to refuse orders that would sever the fleet from its controller.
func (s *Server) hubOwnsAddress(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	if addr.IsLoopback() {
		return "loopback"
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(addr) {
				return "a local interface"
			}
		}
	}
	for label, raw := range map[string]string{"--hub-url": s.hubURL, "--agent-hub-url": s.agentHubURL} {
		if raw == "" {
			continue
		}
		host := raw
		for _, scheme := range []string{"https://", "http://"} {
			host = strings.TrimPrefix(host, scheme)
		}
		if slash := strings.IndexByte(host, '/'); slash >= 0 {
			host = host[:slash]
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil && parsed.Equal(addr) {
			return label
		}
	}
	return ""
}

func (s *Server) Close() error {
	s.ti.Stop()
	s.detector.Stop()
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Close()
	}
	if s.tlsServer != nil {
		if tlsErr := s.tlsServer.Close(); err == nil {
			err = tlsErr
		}
	}
	return err
}

// clientCertCN returns the common name from a client certificate the TLS stack
// has already verified against the hub CA, or "" when the request arrived
// without one. It reads only VerifiedChains: r.TLS.PeerCertificates holds
// whatever the peer sent, verified or not, and trusting that would make the
// check worthless.
func clientCertCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return ""
	}
	leaf := r.TLS.VerifiedChains[0][0]
	return leaf.Subject.CommonName
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Every path below establishes a role and then calls through here, so a
		// read-only role is enforced once for the whole API rather than route by
		// route. A route added tomorrow is covered without anyone remembering to
		// cover it.
		proceed := func(w http.ResponseWriter, r *http.Request) {
			if !roleAllows(r.Header.Get("X-Role"), r.Method) {
				writeJSONError(w, http.StatusForbidden, "this role can read the fleet but not change it")
				return
			}
			next(w, r)
		}
		// Every header below this line is an assertion by the hub about who the
		// caller is, and handlers act on them. Clear whatever the client sent
		// first. Most were overwritten on every path that reaches next() and so
		// could not be forged, but X-Tenant-ID was not: the admin path never
		// sets it, so an inbound one survived. Not an escalation on its own -
		// the caller already held the admin key - but the invariant is worth
		// stating once here rather than re-deriving it per path.
		for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN"} {
			r.Header.Del(h)
		}
		if cn := clientCertCN(r); cn != "" {
			r.Header.Set("X-Client-CN", cn)
		}
		// 1. Check Bearer JWT Token
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := auth.ValidateJWT(tokenStr, s.adminKey)
			if err == nil && claims != nil {
				r.Header.Set("X-Role", claims.Role)
				r.Header.Set("X-User-ID", claims.UserID)
				r.Header.Set("X-Username", claims.Username)
				if claims.TenantID != "" {
					r.Header.Set("X-Tenant-ID", claims.TenantID)
				}
				proceed(w, r)
				return
			}
		}

		// 2. Check the console session cookie
		//
		// The console no longer hands the admin key to everyone it renders for,
		// so an operator who signed in through Cloudflare Access has nothing to
		// put in X-API-Key. The cookie is that operator's credential, and it is
		// signed by the hub, so it cannot be minted by the browser holding it.
		if op, ok := s.consoleSession(r); ok {
			r.Header.Set("X-Role", op.Role)
			r.Header.Set("X-Username", op.Email)
			proceed(w, r)
			return
		}

		// 3. Check X-API-Key Header and Query Param
		//
		// An address that has just spent a minute presenting wrong keys is not
		// told which of them was close. The check is before the comparison so a
		// locked-out caller cannot keep sampling response times either.
		addr := clientIP(r)
		if s.throttle.blocked(addr) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
			return
		}

		keys := []string{
			strings.TrimSpace(r.Header.Get("X-API-Key")),
			strings.TrimSpace(r.URL.Query().Get("api_key")),
		}

		for _, key := range keys {
			if key == "" {
				continue
			}
			if secretEqual(key, s.adminKey) {
				s.throttle.succeed(addr)
				r.Header.Set("X-Role", "admin")
				r.Header.Set("X-Username", "admin")
				proceed(w, r)
				return
			}
			tenant, err := s.store.GetTenantByAPIKey(key)
			if err == nil && tenant != nil {
				s.throttle.succeed(addr)
				r.Header.Set("X-Role", "tenant")
				r.Header.Set("X-Tenant-ID", tenant.ID)
				r.Header.Set("X-Username", tenant.Name)
				proceed(w, r)
				return
			}
		}

		if s.throttle.fail(addr) {
			log.Printf("[!] %s has failed API authentication %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
		}
		writeJSONError(w, http.StatusUnauthorized, "invalid or missing api key")
	}
}

// versionParts extracts the leading major.minor.patch triple from a reported version
// string. Endpoints may decorate the version with a collection-layer suffix,
// so each component is read up to its first non-digit.
func versionParts(v string) [3]int {
	var out [3]int
	fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	for i := 0; i < 3 && i < len(fields); i++ {
		digits := strings.TrimSpace(fields[i])
		end := 0
		for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
			end++
		}
		out[i], _ = strconv.Atoi(digits[:end])
	}
	return out
}

// compareVersions compares dotted numeric versions: -1 if a < b, 0 if equal, 1 if a > b.
func compareVersions(a, b string) int {
	as, bs := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// desiredAgentVersion resolves the fleet-wide target agent version: the operator-set
// value if present, otherwise the version bundled with this hub build.
func (s *Server) desiredAgentVersion() string {
	if v, _ := s.store.GetSetting("desired_agent_version"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return s.agentVersion
}

// downloadBase is the URL prefix agents fetch packages from.
func (s *Server) downloadBase(r *http.Request) string {
	if base := strings.TrimSuffix(s.hubURL, "/"); base != "" {
		return base
	}
	return requestOrigin(r)
}

// requestOrigin is the origin this request actually arrived on. Whatever it is,
// it demonstrably reaches this hub, which is more than can be said for a
// configured string nobody checked.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// publicURLProblem returns an explanation when --hub-url does not serve this
// hub, and "" when it does or when there is nothing configured.
//
// It does not override the configured value, and deliberately so: a hub often
// cannot reach its own public URL from where it runs - split-horizon DNS and
// hairpin NAT both do this - and a probe failure is not proof the operator
// configured the wrong thing. What it is good for is the case that actually bit
// someone: --hub-url pointing at a domain behind an identity proxy, which
// answers an installer's unauthenticated fetch with a sign-in page, so the
// one-line command piped HTML into a shell and the operator saw a shell syntax
// error with nothing pointing at the URL. The configuration still wins; the
// operator is told, and offered a link built from the origin they reached the
// console on.
func (s *Server) publicURLProblem() string {
	configured := strings.TrimSuffix(s.hubURL, "/")
	if configured == "" || s.publicURLServesHub() {
		return ""
	}
	return "This link points at " + configured + ", the hub's configured public URL, but a fetch of its bootstrap route from here does not come back as this hub would answer it - usually a CDN or an identity proxy in front of it, which will hand the installer a sign-in page instead of the script. It can also mean this hub simply cannot reach its own public address, which is normal on split-horizon DNS and harmless. If the command fails on the host, use the alternate below, or exempt the /bootstrap.* and /download/ paths at the proxy."
}

const (
	publicURLProbeTTL = 5 * time.Minute
	// A failure is cached far more briefly than a success. The probe can fail
	// for reasons that pass in seconds - the listener not up yet at startup, a
	// resolver blip - and a wrong "your public URL is broken" shown to an
	// operator for five minutes is worse than probing again.
	publicURLFailTTL = 30 * time.Second
)

// PublicURLServesHub is publicURLServesHub for callers outside the package -
// the startup banner, which reports the answer once so it is on the record
// before anyone generates an installer.
//
// It retries, because at startup this races the hub's own listener: when
// --hub-url points back at this process, the first probe can be refused simply
// because Start has not finished binding yet, and reporting that as "your
// public URL is broken" would be a lie with a five-minute shelf life.
func (s *Server) PublicURLServesHub() bool {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		if s.refreshPublicURL() {
			return true
		}
	}
	return false
}

// publicURLServesHub reports whether --hub-url answers as this hub does.
//
// The probe is the exact request an operator's installer makes: an
// unauthenticated GET of the bootstrap route. This hub answers that with a JSON
// refusal. A sign-in page, a redirect to one, a CDN error or a timeout all mean
// the URL cannot be pasted onto a host that needs to install from it.
func (s *Server) publicURLServesHub() bool {
	s.publicURLMu.Lock()
	ttl := publicURLProbeTTL
	if !s.publicURLOK {
		ttl = publicURLFailTTL
	}
	if !s.publicURLAt.IsZero() && time.Since(s.publicURLAt) < ttl {
		ok := s.publicURLOK
		s.publicURLMu.Unlock()
		return ok
	}
	s.publicURLMu.Unlock()

	return s.refreshPublicURL()
}

// refreshPublicURL probes and records the answer, ignoring whatever is cached.
// The startup check needs this: its retries exist to outlast a listener that is
// not bound yet, and a retry that reads back the cached failure it is retrying
// would just return the same wrong answer three times.
func (s *Server) refreshPublicURL() bool {
	ok := probeServesHub(strings.TrimSuffix(s.hubURL, "/"))

	s.publicURLMu.Lock()
	s.publicURLOK = ok
	s.publicURLAt = time.Now()
	s.publicURLMu.Unlock()
	return ok
}

func probeServesHub(base string) bool {
	if base == "" {
		return false
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		// A redirect is the failure, not a step towards success: an identity
		// proxy answers with one, and following it would land on a sign-in page
		// that returns 200 and looks fine to a naive check.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(base + "/bootstrap.sh")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json")
}

// agentPackageName is the on-disk filename of an agent package. Signature and
// digest sidecars hang off it, so name resolution has exactly one home.
func agentPackageName(version, pkg string) string {
	switch pkg {
	case "windows-native":
		return "ominull-agent-windows-" + version + ".msi"
	case "deb":
		return "ominull-agent_" + version + "_amd64.deb"
	case "hub":
		return "ominull-hub_" + version + "_amd64.deb"
	default:
		return ""
	}
}

// agentPackageURL builds the download URL for an agent package of the given version.
func (s *Server) agentPackageURL(r *http.Request, version, pkg string) string {
	return s.downloadBase(r) + "/download/" + agentPackageName(version, pkg)
}

// agentUpdateDescriptor assembles everything an agent needs to fetch a release
// and prove it is genuine before installing it.
//
// It fails closed. Both the digest and the detached signature must be on disk
// beside the package or no descriptor is produced at all. Agents verify against
// a public key compiled into them rather than anything the hub serves, so an
// unsigned release is one every agent would refuse anyway; advertising it just
// turns a release mistake into a fleet of failed downloads. Catching it here
// means an unsigned release shows up as "not offered" in one place instead of
// as an install failure on every endpoint.
func (s *Server) agentUpdateDescriptor(r *http.Request, version, pkg string) (map[string]string, bool) {
	name := agentPackageName(version, pkg)
	if _, err := os.Stat(filepath.Join(s.binaryDir, name)); err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(s.binaryDir, name+".sha256"))
	if err != nil {
		return nil, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return nil, false
	}
	if _, err := os.Stat(filepath.Join(s.binaryDir, name+".sig")); err != nil {
		return nil, false
	}
	base := s.downloadBase(r)
	return map[string]string{
		"version":            version,
		"package":            pkg,
		"package_identifier": packageIdentifierForKind(pkg),
		"url":                base + "/download/" + name,
		"signature":          base + "/download/" + name + ".sig",
		"sha256":             fields[0],
	}, true
}

func packageIdentifierForKind(pkg string) string {
	switch pkg {
	case "deb":
		return linuxAgentPackageID
	case "windows-native":
		return windowsAgentPackageID
	case "hub":
		return "ominull-hub"
	default:
		return ""
	}
}

// agentPackageForCapability maps what an agent says it can install onto the
// package the hub serves. An agent that claims nothing is offered nothing.
func agentPackageForCapability(capability string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "deb":
		return "deb", true
	case "msi":
		return "windows-native", true
	}
	return "", false
}

// updatePackageFor resolves the package an endpoint can install for itself.
//
// The reported capability is authoritative. An endpoint that has never
// reported one is not given an update descriptor: the final fleet only accepts
// package-manager-owned Linux and Windows agents.
func updatePackageFor(capability string) (string, bool) {
	if pkg, ok := agentPackageForCapability(capability); ok {
		return pkg, true
	}
	return "", false
}

// pendingAgentUpdate resolves the update an endpoint should apply given the version it
// just reported. It also retires any queued job the endpoint has already satisfied, so
// the agent reporting its new version is what closes the loop on an update.
func (s *Server) pendingAgentUpdate(endpointID, reportedVersion string) (string, bool) {
	target := s.desiredAgentVersion()
	job, _ := s.store.GetAgentUpdateJob(endpointID)
	if job != nil && job.CompletedAt == nil {
		if compareVersions(job.DesiredVersion, target) > 0 {
			target = job.DesiredVersion
		}
		if compareVersions(reportedVersion, job.DesiredVersion) >= 0 {
			s.store.CompleteAgentUpdate(endpointID)
		}
	}
	return target, compareVersions(reportedVersion, target) < 0
}

// handleAgentConfig is the agent-facing configuration poll. Agents call it with their
// endpoint_id; if the hub has queued an update job (or a fleet-wide desired version)
// newer than the agent's reported version, the response carries the update package URL.
func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	if endpointID == "" {
		http.Error(w, `{"error":"endpoint_id is required"}`, http.StatusBadRequest)
		return
	}
	// Same binding as the telemetry route. This one hands back an update
	// descriptor, so answering it for an endpoint the caller cannot prove it is
	// tells whoever asked which release that host is about to install.
	if !s.endpointIdentityOK(w, r, endpointID) {
		return
	}
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		http.Error(w, `{"error":"endpoint not registered"}`, http.StatusNotFound)
		return
	}

	reported := ep.DriverVersion
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		reported = v
	}
	desired, outdated := s.pendingAgentUpdate(endpointID, reported)

	resp := map[string]interface{}{
		"endpoint_id":      ep.ID,
		"agent_version":    reported,
		"latest_version":   desired,
		"update_available": outdated,
	}
	if outdated {
		pkg, selfInstallable := updatePackageFor(ep.UpdateCapability)
		if !selfInstallable {
			resp["update_method"] = "native-package-required"
		} else {
			resp["update_version"] = desired
			resp["package"] = pkg
			resp["update_url"] = s.agentPackageURL(r, desired, pkg)
			if desc, signed := s.agentUpdateDescriptor(r, desired, pkg); signed {
				resp["sha256"] = desc["sha256"]
				resp["signature_url"] = desc["signature"]
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAgentsUpdate lets an operator publish a signed native package update to
// endpoints that report a package-manager-owned installation.
func (s *Server) handleAgentsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EndpointIDs []string `json:"endpoint_ids"`
		All         bool     `json:"all"`
		Version     string   `json:"version"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(req.Version)
	if version == "" {
		version = s.desiredAgentVersion()
	}
	if compareVersions(s.agentVersion, version) > 0 {
		http.Error(w, `{"error":"refusing to downgrade: hub bundle ships agent `+s.agentVersion+`"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.SetSetting("desired_agent_version", version); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var scheduled, unsupported []map[string]string
	for _, ep := range endpoints {
		if !req.All && !contains(req.EndpointIDs, ep.ID) {
			continue
		}
		if ep.Status == "retired" {
			continue
		}
		if compareVersions(ep.DriverVersion, version) >= 0 {
			continue // already up to date
		}
		pkg, selfInstallable := updatePackageFor(ep.UpdateCapability)
		if !selfInstallable {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "endpoint reports no supported native package capability"})
			continue
		}
		// Refuse to queue a job for a release the endpoint could never install.
		// The agent verifies the signature itself and would reject it, so an
		// unsigned release must surface here as one clear answer rather than as
		// a queued job that quietly never completes.
		if _, signed := s.agentUpdateDescriptor(r, version, pkg); !signed {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "no signed " + agentPackageName(version, pkg) + " on the hub; sign the release with scripts/sign-release.sh and redeploy"})
			continue
		}
		if err := s.store.RequestAgentUpdate(ep.ID, version); err == nil {
			scheduled = append(scheduled, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "from": ep.DriverVersion, "to": version})
		}
	}

	scope := "the named endpoints"
	if req.All {
		scope = "the whole fleet"
	}
	s.audit(r, "AGENT_UPDATE_PUSH", version, fmt.Sprintf("Queued agent v%s for %s: %d endpoint(s) scheduled, %d could not self-update", version, scope, len(scheduled), len(unsupported)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"desired_version": version,
		"scheduled":       scheduled,
		"unsupported":     unsupported,
	})
}

// handleAgentsUpdateStatus reports fleet agent-version currency and pending update jobs.
func (s *Server) handleAgentsUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	latest := s.desiredAgentVersion()
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var outdated, retired []map[string]string
	var provenanceIssues []map[string]string
	for _, ep := range endpoints {
		if ep.Status == "retired" {
			retired = append(retired, map[string]string{
				"endpoint_id": ep.ID,
				"hostname":    ep.Hostname,
				"os":          ep.OS,
				"status":      ep.Status,
			})
			continue
		}
		if compareVersions(ep.DriverVersion, latest) < 0 {
			outdated = append(outdated, map[string]string{
				"endpoint_id":    ep.ID,
				"hostname":       ep.Hostname,
				"os":             ep.OS,
				"ip":             ep.IP,
				"driver_version": ep.DriverVersion,
			})
		}
		if reason := provenanceIssue(ep, latest); reason != "" && compareVersions(ep.DriverVersion, latest) >= 0 {
			provenanceIssues = append(provenanceIssues, map[string]string{
				"endpoint_id":                ep.ID,
				"hostname":                   ep.Hostname,
				"os":                         ep.OS,
				"ip":                         ep.IP,
				"driver_version":             ep.DriverVersion,
				"install_type":               ep.InstallType,
				"package_identifier":         ep.PackageIdentifier,
				"registered_package_version": ep.RegisteredPackageVersion,
				"provenance_status":          ep.ProvenanceStatus,
				"reason":                     reason,
			})
		}
	}
	pending, _ := s.store.ListPendingAgentUpdates()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"latest_version":    latest,
		"outdated":          outdated,
		"retired":           retired,
		"provenance_issues": provenanceIssues,
		"native_converged":  len(outdated) == 0 && len(provenanceIssues) == 0,
		"pending":           pending,
	})
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

// bootstrapOptions authenticates a bootstrap request and gathers the enrolment
// it describes. All three generators need the same inputs, and the one that
// matters here is the split between the two URLs: the installer runs against
// hubURL, while the agent it installs is pointed at the TLS transport the hub
// was configured to advertise.
func (s *Server) bootstrapOptions(w http.ResponseWriter, r *http.Request) (bootstrap.Options, bool) {
	addr := clientIP(r)
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
		return bootstrap.Options{}, false
	}
	key := r.URL.Query().Get("key")
	if !secretEqual(key, s.adminKey) {
		if key != "" && s.throttle.fail(addr) {
			log.Printf("[!] %s has failed bootstrap authentication %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
		}
		writeJSONError(w, http.StatusUnauthorized, "valid admin key required")
		return bootstrap.Options{}, false
	}
	s.throttle.succeed(addr)

	// These routes verify the admin key here rather than passing through
	// authMiddleware, so the identity headers the audit log reads are set here
	// too - and cleared first, because on this path nothing else would stop a
	// caller naming itself in the record of what it did.
	for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID"} {
		r.Header.Del(h)
	}
	r.Header.Set("X-Role", "admin")
	r.Header.Set("X-Username", "admin")

	return s.buildEnrolmentOptions(w, r, storage.InstallTicket{
		TenantID:   r.URL.Query().Get("tenant"),
		LocationID: r.URL.Query().Get("location"),
		Role:       r.URL.Query().Get("role"),
		EndpointID: r.URL.Query().Get("endpoint_id"),
	})
}

// buildEnrolmentOptions turns an authorised request into one enrolment. The
// caller has already established that the requester may have it - with the
// admin key, or with a single-use install ticket - and this is the part that is
// the same either way.
func (s *Server) buildEnrolmentOptions(w http.ResponseWriter, r *http.Request, t storage.InstallTicket) (bootstrap.Options, bool) {
	// What the installer is authorised by and what it leaves behind are two
	// different credentials, and used to be the same one.
	//
	// The admin key authorises generating this script. It was then written
	// straight into the agent's configuration file on the endpoint, so every
	// host in the fleet held the hub's admin key in a file on disk for the life
	// of the install: one compromised endpoint could isolate the whole fleet,
	// read every tenant's key and push an agent release. The agent needs a
	// credential to report telemetry, and that is the tenant key - which is
	// what least privilege meant here all along.
	tenantID := strings.TrimSpace(t.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	tenant, err := s.store.GetTenant(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not resolve the enrolment tenant: "+err.Error())
		return bootstrap.Options{}, false
	}
	if tenant == nil || strings.TrimSpace(tenant.APIKey) == "" {
		writeJSONError(w, http.StatusBadRequest,
			"tenant "+tenantID+" has no API key to enrol against; create it through /api/v1/tenants first")
		return bootstrap.Options{}, false
	}
	if secretEqual(tenant.APIKey, s.adminKey) {
		// Started without --admin-key, the hub adopts the default tenant's key
		// as the admin key and the two are one credential. Nothing here can fix
		// that, but an operator should not have to infer it.
		log.Printf("[!] Tenant %q's API key is also this hub's admin key, so the agent this installer enrols will hold admin. Start the hub with a --admin-key distinct from the tenant key.", tenantID)
	}

	// One certificate, once. The script cannot be replayed into a second
	// identity and is worthless an hour after it was generated.
	enrollToken, err := s.store.CreateEnrollmentToken(t.EndpointID, storage.EnrollmentTokenTTL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not mint an enrolment token: "+err.Error())
		return bootstrap.Options{}, false
	}

	hubURL := s.hubURL
	if hubURL == "" {
		hubURL = "https://" + r.Host
	}

	cfID := r.URL.Query().Get("cf_id")
	if cfID == "" {
		cfID = r.Header.Get("CF-Access-Client-Id")
	}
	cfSecret := r.URL.Query().Get("cf_secret")
	if cfSecret == "" {
		cfSecret = r.Header.Get("CF-Access-Client-Secret")
	}

	return bootstrap.Options{
		HubURL:          hubURL,
		AgentHubURL:     s.agentHubURL,
		TenantAPIKey:    tenant.APIKey,
		EnrollmentToken: enrollToken,
		CFClientID:      cfID,
		CFClientSecret:  cfSecret,
		LocationID:      t.LocationID,
		RoleTag:         t.Role,
		EndpointID:      t.EndpointID,
		AgentVersion:    s.agentVersion,
	}, true
}

func (s *Server) handleBootstrapPS1(w http.ResponseWriter, r *http.Request) {
	// A single-use install link first, the admin key second. The link is
	// what the console hands an operator to paste on the host; the key path
	// stays for the scripted callers that already use it.
	opts, presented, ok := s.installTicketOptions(w, r, "windows")
	if presented && !ok {
		return
	}
	if !presented {
		if opts, ok = s.bootstrapOptions(w, r); !ok {
			return
		}
	}
	// The script carries the tenant key and a live enrolment token off the hub.
	// Generating one is how an endpoint joins the fleet, so it belongs in the
	// record even though nothing has been installed yet.
	s.audit(r, "BOOTSTRAP_GENERATED", opts.EndpointID, "Minted a Windows installer carrying the tenant key and a single-use enrolment token")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// The body is a credential. Nothing between here and the operator may keep
	// a copy: not a CDN, not a corporate proxy, not the browser's disk cache.
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(bootstrap.GeneratePowerShell(opts)))
}

func (s *Server) handleBootstrapSH(w http.ResponseWriter, r *http.Request) {
	// A single-use install link first, the admin key second. The link is
	// what the console hands an operator to paste on the host; the key path
	// stays for the scripted callers that already use it.
	opts, presented, ok := s.installTicketOptions(w, r, "linux")
	if presented && !ok {
		return
	}
	if !presented {
		if opts, ok = s.bootstrapOptions(w, r); !ok {
			return
		}
	}
	// The script carries the tenant key and a live enrolment token off the hub.
	// Generating one is how an endpoint joins the fleet, so it belongs in the
	// record even though nothing has been installed yet.
	s.audit(r, "BOOTSTRAP_GENERATED", opts.EndpointID, "Minted a Linux installer carrying the tenant key and a single-use enrolment token")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// The body is a credential. Nothing between here and the operator may keep
	// a copy: not a CDN, not a corporate proxy, not the browser's disk cache.
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(bootstrap.GenerateBash(opts)))
}

func (s *Server) handlePKICACert(w http.ResponseWriter, r *http.Request) {
	if s.pki == nil {
		http.Error(w, "PKI not initialized", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Write(s.pki.GetCAPEM())
}

func (s *Server) handlePKIEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pki == nil {
		http.Error(w, "PKI not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		// EndpointID is what the certificate is issued to. It becomes the
		// common name, and the hub matches it against the endpoint id in every
		// later request - so this, not the hostname, is the identity being
		// minted. Hostname stays for callers that predate it.
		EndpointID string `json:"endpoint_id"`
		Hostname   string `json:"hostname"`
		IP         string `json:"ip"`
		// EnrollmentToken is the single-use credential a generated installer
		// carries. The header form is preferred; this exists because a shell
		// installer already builds a JSON body and adding a field to it is one
		// less thing to get wrong than adding a header.
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.EndpointID)
	if name == "" {
		name = strings.TrimSpace(req.Hostname)
	}
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required: a certificate with no endpoint to name authenticates nothing")
		return
	}

	// Who is allowed to be issued a certificate in this name.
	//
	// The certificate is the whole of the hub's endpoint identity: with
	// --client-certs required it is what separates one endpoint from another,
	// and endpointIdentityOK refuses a request whose certificate names someone
	// else. None of that means anything if the route mints a certificate for
	// any name on request - and it did, to anyone the middleware authenticated,
	// which includes every agent in the fleet holding the shared tenant key.
	//
	// So: an operator (the admin credential) may enrol anything, and an
	// installer presents a single-use token the hub minted for this enrolment
	// when the operator generated the bootstrap script.
	if r.Header.Get("X-Role") != "admin" {
		token := strings.TrimSpace(r.Header.Get("X-Enrollment-Token"))
		if token == "" {
			token = strings.TrimSpace(req.EnrollmentToken)
		}
		if err := s.store.ConsumeEnrollmentToken(token, name); err != nil {
			log.Printf("[!] %s asked for a certificate naming %q without a usable enrolment token: %v",
				clientIP(r), name, err)
			writeJSONError(w, http.StatusForbidden, "certificate enrolment needs the admin credential or a valid single-use enrolment token: "+err.Error())
			return
		}
	}

	bundle, err := s.pki.IssueClientCert(name, req.IP)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[+] Issued a client certificate for endpoint %q to %s.", name, clientIP(r))
	s.audit(r, "PKI_ENROLL", name, "Issued a client certificate naming this endpoint; it is what the hub tells this endpoint from any other by")
	writeJSON(w, http.StatusOK, bundle)
}

// downloadable names the files /download/ will serve.
//
// The route is unauthenticated by necessity - a bootstrap script fetches the
// agent before the endpoint has any credential, and an agent taking an update
// fetches the package the same way - and on a published hub that makes the
// whole directory an anonymous file share. filepath.Base already stopped a
// caller escaping it, but nothing stopped one reading whatever else the
// directory happened to hold, and it is the directory an operator drops files
// into. This is the list of things a client is actually told to fetch:
// the signed release artifacts, and the five payloads the bootstrap scripts
// name. Anything else is not found, whether or not it is on disk.
var (
	downloadArtifact = regexp.MustCompile(`^ominull-(agent_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb|agent-windows-[0-9]+\.[0-9]+\.[0-9]+\.msi|hub_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb)(\.sig|\.sha256)?$`)
	downloadPayloads = map[string]bool{
		// Native installers fetch only signed package artifacts. Raw binaries
		// are intentionally not an install surface.
	}
)

func downloadAllowed(name string) bool {
	return downloadPayloads[name] || downloadArtifact.MatchString(name)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	filename = filepath.Base(filename)

	if !downloadAllowed(filename) {
		log.Printf("[!] %s asked for %q from the download directory, which is not a released artifact.", clientIP(r), filename)
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	path := filepath.Join(s.binaryDir, filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, path)
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.store.ListTenants()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
		return
	}

	if r.Method == http.MethodPost {
		var t storage.Tenant
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if t.ID == "" {
			t.ID = "tenant-" + uuid.New().String()[:8]
		}
		if t.APIKey == "" {
			t.APIKey = "ominull_key_" + uuid.New().String()
		}
		t.CreatedAt = time.Now().UTC()

		if err := s.store.CreateTenant(t); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// The tenant's own key is not in the record. That it now exists is.
		s.audit(r, "CREATE_TENANT", t.ID, "Created tenant "+t.Name+" and issued it an API key")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(t)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	list, err := s.store.ListEndpoints(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i := range list {
		if list[i].Status == "retired" {
			continue
		}
		if time.Since(list[i].LastSeenAt) < 30*time.Second {
			list[i].Status = "online"
		} else {
			list[i].Status = "offline"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// handleRetireEndpoint marks an endpoint as intentionally removed while
// retaining its telemetry, asset identity, certificate history, and audit log.
// It clears recorded isolation first so an operator never retires a host with
// a stale Ominull control order waiting for a heartbeat that will not come.
func (s *Server) handleRetireEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if req.EndpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return
	}
	ep, err := s.store.GetEndpoint(req.EndpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ep == nil {
		writeJSONError(w, http.StatusNotFound, "endpoint not registered")
		return
	}
	if err := s.store.RetireEndpoint(req.EndpointID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	details := "Endpoint retired; telemetry and audit history retained"
	if reason := strings.TrimSpace(req.Reason); reason != "" {
		details += ": " + reason
	}
	s.audit(r, "ENDPOINT_RETIRED", req.EndpointID, details)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "retired", "endpoint_id": req.EndpointID})
}

func (s *Server) handleIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EndpointID string   `json:"endpoint_id"`
		AllowIPs   []string `json:"allow_ips"`
		// Force overrides the readiness gate. It is not a flag for getting past
		// an inconvenient refusal: an operator containing a host that is
		// actively compromised must not be blocked by a stale probe, and that
		// decision is recorded under its own action with their name on it.
		Force bool `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.endpointInScope(w, r, req.EndpointID) {
		return
	}
	if !s.guardIsolation(w, r, req.EndpointID, req.Force) {
		return
	}
	// The allow list is a pinhole through a default-deny rule and reaches the
	// agent's firewall layer. Only addresses belong in it.
	allowIPs := make([]string, 0, len(req.AllowIPs))
	for _, raw := range req.AllowIPs {
		ip, err := validateIP(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "allow_ips: "+err.Error())
			return
		}
		allowIPs = append(allowIPs, ip)
	}

	if err := s.store.SetEndpointIsolation(req.EndpointID, true, allowIPs); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  r.Header.Get("X-Username"),
		Action:    "ISOLATE_HOST",
		Resource:  req.EndpointID,
		Details:   "Host network isolation enabled through the agent control response",
		IPAddress: clientIP(r),
		Timestamp: time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "isolated", "endpoint_id": req.EndpointID})
}

func (s *Server) handleUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.endpointInScope(w, r, req.EndpointID) {
		return
	}

	if err := s.store.SetEndpointIsolation(req.EndpointID, false, nil); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  r.Header.Get("X-Username"),
		Action:    "UNISOLATE_HOST",
		Resource:  req.EndpointID,
		Details:   "Host network isolation lifted",
		IPAddress: clientIP(r),
		Timestamp: time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "unisolated", "endpoint_id": req.EndpointID})
}

func (s *Server) handleBulkIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	var req struct {
		Scope    string   `json:"scope"`
		Value    string   `json:"value"`
		IDs      []string `json:"ids"`
		AllowIPs []string `json:"allow_ips"`
		Force    bool     `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Scope == "" {
		req.Scope = "all"
	}

	allowIPs := make([]string, 0, len(req.AllowIPs))
	for _, raw := range req.AllowIPs {
		ip, err := validateIP(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "allow_ips: "+err.Error())
			return
		}
		allowIPs = append(allowIPs, ip)
	}
	// Scope first, gate second. The gate reads an endpoint's readiness report
	// and answers with its resolvers and its rule set, so running it over
	// caller-supplied ids before checking who owns them would answer questions
	// about other tenants' hosts - and would do it in the body of a refusal,
	// which is the reply nobody reads carefully.
	var scoped []string
	if req.Scope == "ids" && len(req.IDs) > 0 {
		ids, ok := s.scopedEndpointIDs(w, r, req.IDs)
		if !ok {
			return
		}
		scoped = ids
	} else {
		var err error
		scoped, err = s.store.BulkIsolationTargets(tenantID, req.Scope, req.Value)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// One refusal stops the whole batch. Isolating nine of ten and reporting
	// nine is how an operator comes to believe a host is contained when it is
	// not - and the tenth is the one the hub predicted it could not get back.
	for _, id := range scoped {
		if !s.guardIsolation(w, r, id, req.Force) {
			return
		}
	}

	var count int64
	if req.Scope == "ids" && len(req.IDs) > 0 {
		for _, id := range scoped {
			if err := s.store.SetEndpointIsolation(id, true, allowIPs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			count++
		}
	} else {
		var err error
		count, err = s.store.SetBulkIsolation(tenantID, req.Scope, req.Value, true, allowIPs)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	s.audit(r, "BULK_ISOLATE", req.Scope+":"+req.Value, fmt.Sprintf("Cut %d endpoint(s) off the network", count))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "isolated",
		"affected_endpoints": count,
		"scope":              req.Scope,
		"value":              req.Value,
	})
}

func (s *Server) handleBulkUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	var req struct {
		Scope string   `json:"scope"`
		Value string   `json:"value"`
		IDs   []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Scope == "" {
		req.Scope = "all"
	}

	var count int64
	if req.Scope == "ids" && len(req.IDs) > 0 {
		ids, ok := s.scopedEndpointIDs(w, r, req.IDs)
		if !ok {
			return
		}
		for _, id := range ids {
			if err := s.store.SetEndpointIsolation(id, false, nil); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			count++
		}
	} else {
		var err error
		count, err = s.store.SetBulkIsolation(tenantID, req.Scope, req.Value, false, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	s.audit(r, "BULK_UNISOLATE", req.Scope+":"+req.Value, fmt.Sprintf("Returned %d endpoint(s) to the network", count))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "unisolated",
		"affected_endpoints": count,
		"scope":              req.Scope,
		"value":              req.Value,
	})
}

// endpointIdentityOK decides whether a caller may act as endpointID.
//
// The API key says which tenant is calling; it does not say which endpoint,
// because every endpoint in a tenant carries the same key. Until client
// certificates existed, the endpoint id in the request body was simply
// believed, so anyone holding the key could post telemetry as any host, read
// another host's configuration, or take its update descriptor. A verified
// client certificate is the first thing the hub has that actually names the
// caller, so where one is present the body has to agree with it.
//
// A request without a certificate is still accepted: the fleet has to be able
// to migrate onto certificates while it is still reporting. That is what
// --client-certs required closes, once every endpoint has one.
func (s *Server) endpointIdentityOK(w http.ResponseWriter, r *http.Request, endpointID string) bool {
	cn := r.Header.Get("X-Client-CN")
	if cn != "" {
		if cn == endpointID {
			return true
		}
		log.Printf("[!] %s presented a certificate for %q and asked to act as %q; refused.",
			clientIP(r), cn, endpointID)
		writeJSONError(w, http.StatusForbidden, "the client certificate does not name this endpoint")
		return false
	}

	// No certificate on this connection. Whether that is allowed is not a
	// property of the request - it is the fleet-wide setting.
	//
	// The TLS listener enforces --client-certs required at the handshake, but
	// the plain listener has no handshake to enforce it in, and both listeners
	// share one mux. So an operator who had moved the fleet to "required" still
	// had an agent-facing route on :9999 that took an endpoint id out of a
	// request body and believed it, reachable by anything holding the tenant
	// key - which is every endpoint. Requiring the certificate here is what
	// makes the setting mean the same thing on both ports.
	//
	// The admin credential is exempt: an operator posting on behalf of an
	// endpoint (a CLI, a test) is not an endpoint claiming to be one.
	if s.tlsOpts.ClientCerts == ClientCertsRequired && r.Header.Get("X-Role") != "admin" {
		log.Printf("[!] %s asked to act as %q over a connection with no verified client certificate while --client-certs is required; refused.",
			clientIP(r), endpointID)
		writeJSONError(w, http.StatusForbidden,
			"this hub requires a client certificate to report as an endpoint; reach it on the TLS listener with the certificate issued to this endpoint id")
		return false
	}
	return true
}

// endpointInScope reports whether the caller is allowed to act on this
// endpoint, and answers the request itself when it is not.
//
// Isolation is the sharpest control the hub has: it cuts a host off the
// network, and lifting it puts a quarantined host back on. Both routes took an
// endpoint id out of the request body and acted on it without ever asking whose
// endpoint it was, so any tenant could isolate - or release - any host in any
// other tenant. The tenant scoping the listing routes already did is the same
// rule; it just was not applied here.
// scopedEndpointIDs rejects a bulk request when any requested endpoint is
// outside the caller's tenant. The whole request fails rather than silently
// applying to a partial set.
func (s *Server) scopedEndpointIDs(w http.ResponseWriter, r *http.Request, ids []string) ([]string, bool) {
	if r.Header.Get("X-Role") == "admin" {
		return ids, true
	}
	tenantID := r.Header.Get("X-Tenant-ID")
	for _, id := range ids {
		ep, err := s.store.GetEndpoint(id)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
		if ep == nil || (tenantID != "" && ep.TenantID != tenantID) {
			log.Printf("[!] %s (tenant %q) requested endpoint %q outside its scope; refused.", clientIP(r), tenantID, id)
			writeJSONError(w, http.StatusNotFound, "one or more endpoints are not in this scope")
			return nil, false
		}
	}
	return ids, true
}

func (s *Server) endpointInScope(w http.ResponseWriter, r *http.Request, endpointID string) bool {
	if strings.TrimSpace(endpointID) == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return false
	}
	if r.Header.Get("X-Role") == "admin" {
		return true
	}
	tenantID := r.Header.Get("X-Tenant-ID")
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if ep == nil || (tenantID != "" && ep.TenantID != tenantID) {
		log.Printf("[!] %s (tenant %q) requested endpoint %q outside its scope; refused.", clientIP(r), tenantID, endpointID)
		writeJSONError(w, http.StatusNotFound, "no such endpoint in this scope")
		return false
	}
	return true
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := "default"
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	if r.Method == http.MethodPost {
		var batch TelemetryBatchMessage
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := json.Unmarshal(bodyBytes, &batch); err == nil && batch.EndpointID != "" {
			if !s.endpointIdentityOK(w, r, batch.EndpointID) {
				return
			}
			resp, err := s.ingestTelemetry(r, tenantID, batch)
			if err != nil {
				log.Printf("[-] telemetry ingestion failed for %s: %v", batch.EndpointID, err)
				status := http.StatusInternalServerError
				if errors.Is(err, errRetiredEndpoint) {
					status = http.StatusGone
				}
				writeJSONError(w, status, "telemetry was not accepted: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}

		var rawEvents []storage.Event
		if err := json.Unmarshal(bodyBytes, &rawEvents); err == nil {
			if err := s.ingestLegacyEvents(tenantID, rawEvents); err != nil {
				log.Printf("[-] legacy telemetry ingestion failed: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "telemetry was not accepted: "+err.Error())
				return
			}
			qPeers, err := s.store.GetQuarantinedPeers()
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "load quarantined peers: "+err.Error())
				return
			}
			qIPs := make([]string, 0, len(qPeers))
			for _, peer := range qPeers {
				if peer.Active {
					qIPs = append(qIPs, peer.TargetIP)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "quarantined_peers": qIPs})
			return
		}

	}

	endpointID := r.URL.Query().Get("endpoint_id")
	events, err := s.store.QueryEvents(tenantID, endpointID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleThreatIntelIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	iocs, err := s.store.ListIOCs(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iocs)
}

func (s *Server) handleThreatIntelSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		_ = s.ti.SyncAllFeeds(context.Background())
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"syncing","message":"Threat intelligence synchronization initiated in background"}`))
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := "default"
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	alerts, err := s.store.ListAlerts(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	addr := clientIP(r)
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Username == "admin" && secretEqual(req.Password, s.adminKey) {
		s.throttle.succeed(addr)
		token, err := auth.GenerateJWT(auth.Claims{
			UserID:   "usr-admin",
			Username: "admin",
			Role:     auth.RoleAdmin,
			TenantID: "default",
		}, s.adminKey, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_ = s.store.RecordAudit(storage.AuditEntry{
			ID:        uuid.New().String(),
			TenantID:  "default",
			UserID:    "usr-admin",
			Username:  "admin",
			Action:    "LOGIN",
			Resource:  "auth",
			Details:   "Admin user logged in via master key",
			IPAddress: clientIP(r),
			Timestamp: time.Now().UTC(),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "authenticated",
			"token":  token,
			"role":   auth.RoleAdmin,
		})
		return
	}

	if s.throttle.fail(addr) {
		log.Printf("[!] %s has failed console login %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
	}
	writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	logs, err := s.store.ListAuditLogs(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleGetHierarchy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	tree, err := s.store.GetHierarchy(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tree)
}

func (s *Server) handleLocations(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		locs, err := s.store.ListLocations(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(locs)

	case http.MethodPost:
		var loc storage.Location
		if err := json.NewDecoder(r.Body).Decode(&loc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if loc.ID == "" {
			loc.ID = "loc-" + uuid.New().String()[:8]
		}
		if loc.TenantID == "" {
			loc.TenantID = "default"
		}
		if role == "tenant" {
			loc.TenantID = r.Header.Get("X-Tenant-ID")
		}
		loc.CreatedAt = time.Now().UTC()

		if err := s.store.CreateLocation(loc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(loc)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	summary, err := s.store.GetAnalyticsSummary(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleNetworkProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	level := r.URL.Query().Get("level") // "global", "client", "location", "endpoint"
	id := r.URL.Query().Get("id")

	role := r.Header.Get("X-Role")
	if role == "tenant" {
		level = "client"
		id = r.Header.Get("X-Tenant-ID")
	}

	profiles, err := s.store.ListCommProfiles(level, id, 250)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

func (s *Server) handleExclusions(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		exclusions, err := s.store.ListExclusions(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exclusions)

	case http.MethodPost:
		var ex storage.Exclusion
		if err := json.NewDecoder(r.Body).Decode(&ex); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ex.ID == "" {
			ex.ID = "ex-" + uuid.New().String()[:8]
		}
		if ex.TenantID == "" {
			ex.TenantID = "default"
		}
		if role == "tenant" {
			ex.TenantID = r.Header.Get("X-Tenant-ID")
		}
		if ex.Scope == "" {
			ex.Scope = "global"
		}
		ex.Active = true
		ex.CreatedAt = time.Now().UTC()

		if err := s.store.CreateExclusion(ex); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_ = s.store.RecordAudit(storage.AuditEntry{
			ID:        uuid.New().String(),
			TenantID:  ex.TenantID,
			UserID:    r.Header.Get("X-User-ID"),
			Username:  r.Header.Get("X-Username"),
			Action:    "CREATE_EXCLUSION",
			Resource:  ex.ID,
			Details:   fmt.Sprintf("Created security tool exclusion: %s (%s:%d)", ex.Name, ex.ProcessPath, ex.Port),
			IPAddress: strings.Split(r.RemoteAddr, ":")[0],
			Timestamp: time.Now().UTC(),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ex)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteExclusion(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted","id":"` + id + `"}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleToggleExclusion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.ToggleExclusion(req.ID, req.Active); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "id": req.ID, "active": req.Active})
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	anomalies, err := s.store.ListAnomalyAlerts(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anomalies)
}

func (s *Server) handleAcknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.AcknowledgeAnomaly(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "acknowledged", "id": req.ID})
}

/* 7. NETWORK ASSET DISCOVERY & EXTENSIBLE SCANNER HANDLERS */

func (s *Server) handleScannerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Subnet  string `json:"subnet"`
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Subnet == "" {
		req.Subnet = "10.0.0.0/24"
	}
	// The sweep materialises one address at a time before probing anything, so
	// the prefix decides how much memory a single request body can ask for. A
	// /8 is sixteen million of them.
	subnet, err := validateSubnet(req.Subnet)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Subnet = subnet
	prof := scanner.ScanProfile(req.Profile)
	if prof == "" {
		prof = scanner.ProfileStandard
	}

	scanID, err := s.scanner.StartScan(req.Subnet, prof)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit(r, "SCANNER_SWEEP", req.Subnet, "Started a "+string(prof)+" sweep of "+req.Subnet+" (scan "+scanID+")")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID,
		"subnet":  req.Subnet,
		"profile": prof,
		"status":  "running",
	})
}

func (s *Server) handleScannerStatus(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	st, err := s.scanner.GetScanStatus(scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *Server) handleScannerResults(w http.ResponseWriter, r *http.Request) {
	assets := s.scanner.GetDiscoveredAssets()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

func (s *Server) handleScannerCoverage(w http.ResponseWriter, r *http.Request) {
	cov := s.scanner.GetCoverageSummary()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cov)
}

func (s *Server) handleScannerFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP           string `json:"ip"`
		ActualDevice string `json:"actual_device"`
		Vendor       string `json:"vendor"`
		Category     string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.IP == "" || req.ActualDevice == "" {
		http.Error(w, "missing ip or actual_device", http.StatusBadRequest)
		return
	}

	sig, err := s.scanner.TrainSignature(req.IP, req.ActualDevice, req.Vendor, req.Category)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "trained",
		"signature": sig,
	})
}

/* 8. VISUAL COMMUNICATIONS TOPOLOGY GRAPH HANDLER */

func (s *Server) handleTopologyGraph(w http.ResponseWriter, r *http.Request) {
	// Default 24h, not 1h: a known asset that was quiet in the last hour is
	// still on the network, and the graph draws it dimmed rather than
	// pretending it does not exist.
	windowStr := r.URL.Query().Get("window")
	windowDuration := 24 * time.Hour
	switch windowStr {
	case "1h":
		windowDuration = 1 * time.Hour
	case "6h":
		windowDuration = 6 * time.Hour
	case "7d":
		windowDuration = 7 * 24 * time.Hour
	default:
		// Normalised, because the cache key is this string and an unrecognised
		// window already fell through to 24h. Without this "?window=banana"
		// would be a cache entry of its own.
		windowStr = "24h"
	}

	// The graph is admin-only and takes no tenant, so the window is the whole
	// key.
	now := time.Now()
	if cached := s.topology.get(windowStr, now); cached != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached)
		return
	}

	topoData, err := s.store.GetTopologyGraph(windowDuration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(topoData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.topology.put(windowStr, body, now)

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

/* 8b. UNIFIED ASSET GRAPH + FLOW HANDLERS */

// handleAssets returns the whole asset graph: one row per host, however many
// sources know about it, with every source's claim attached so the console can
// show the losing opinions next to the winning one.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The tenant to filter by is the caller's, not the caller's choice: read
	// from the query string, a tenant could ask for the whole asset graph by
	// leaving it empty.
	tenantID := r.URL.Query().Get("tenant_id")
	if r.Header.Get("X-Role") != "admin" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}
	assets, err := s.store.ListAssets(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Retired endpoints remain in the endpoint, telemetry, and audit stores as
	// history, but they are not part of the current fleet. Keep them out of the
	// asset graph so the console cannot call a retired macOS or hub-host row an
	// active or outdated agent.
	endpoints, err := s.store.ListEndpoints(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	retired := make(map[string]struct{})
	for _, ep := range endpoints {
		if ep.Status == "retired" {
			retired[ep.ID] = struct{}{}
		}
	}
	if len(retired) > 0 {
		current := assets[:0]
		for _, asset := range assets {
			if _, isRetired := retired[asset.AgentEndpointID]; isRetired {
				continue
			}
			current = append(current, asset)
		}
		assets = current
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// handleAssetCorrect records an operator's verdict on a field, or withdraws
// one. A correction outranks every other source permanently, and where it
// corrects a device identity it is also fed back into the scanner's signature
// set so the next probe of a similar host gets it right unaided.
func (s *Server) handleAssetCorrect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AssetID  string `json:"asset_id"`
		IP       string `json:"ip"`
		Field    string `json:"field"`
		Value    string `json:"value"`
		Reason   string `json:"reason"`
		Withdraw bool   `json:"withdraw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Field == "" {
		http.Error(w, "missing field", http.StatusBadRequest)
		return
	}

	key := req.AssetID
	if key == "" {
		key = req.IP
	}
	asset, err := s.store.GetAsset(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if req.Withdraw {
		if err := s.store.DropClaim(asset.ID, req.Field, storage.SourceOperator); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if req.Value == "" {
			http.Error(w, "missing value", http.StatusBadRequest)
			return
		}
		if err := s.store.CorrectAsset(asset.ID, req.Field, req.Value, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Feed signature training: an operator naming what a device actually
		// is teaches the fingerprinter, not just this one row.
		if req.Field == storage.FieldCategory && asset.IP != "" {
			if _, err := s.scanner.TrainSignature(asset.IP, req.Value, asset.Vendor, req.Value); err != nil {
				log.Printf("[*] Correction on %s not fed to signature training: %v", asset.IP, err)
			}
		}
	}

	action := "CORRECT_ASSET"
	if req.Withdraw {
		action = "WITHDRAW_CORRECTION"
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.NewString(),
		TenantID:  asset.TenantID,
		UserID:    "admin",
		Username:  "admin",
		Action:    action,
		Resource:  asset.ID,
		Details:   req.Field + " = " + req.Value,
		IPAddress: strings.Split(r.RemoteAddr, ":")[0],
		Timestamp: time.Now().UTC(),
	})

	updated, err := s.store.GetAsset(asset.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

/* 9. SUBNET QUARANTINE MESH HANDLERS */

type MeshQuarantineRequest struct {
	TargetIP  string `json:"target_ip"`
	TargetMAC string `json:"target_mac"`
	Subnet    string `json:"subnet"`
	Reason    string `json:"reason"`
}

func (s *Server) handleMeshQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MeshQuarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Every field below is broadcast to the fleet and applied by an agent
	// running as root. The hub is the only place that sees all of them before
	// they fan out, so it is where they are checked: a target_ip that is not an
	// address has no meaning here and no safe interpretation there.
	targetIP, err := validateIP(req.TargetIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "target_ip: "+err.Error())
		return
	}
	req.TargetIP = targetIP
	// A quarantine names an address every agent then drops in both directions.
	// Naming the hub is the one target with no way back: the fleet would stop
	// being able to reach the only thing that can lift the rule, so the console
	// would show a quarantine it could no longer withdraw. Refused here rather
	// than left to each agent's rule ordering to survive.
	if why := s.hubOwnsAddress(req.TargetIP); why != "" {
		writeJSONError(w, http.StatusConflict,
			"target_ip: "+req.TargetIP+" is this hub's own address ("+why+"). Quarantining it would cut every agent off from the only host that can lift the quarantine.")
		return
	}
	targetMAC, err := validateMAC(req.TargetMAC)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "target_mac: "+err.Error())
		return
	}
	req.TargetMAC = targetMAC
	if strings.TrimSpace(req.Subnet) != "" {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(req.Subnet)); err != nil {
			writeJSONError(w, http.StatusBadRequest, "subnet: not a CIDR subnet")
			return
		}
		req.Subnet = strings.TrimSpace(req.Subnet)
	}
	if req.Reason == "" {
		req.Reason = "Unmanaged/rogue lateral threat quarantine"
	}

	peer, err := s.store.AddQuarantinedPeer(req.TargetIP, req.TargetMAC, req.Subnet, req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit(r, "MESH_QUARANTINE", req.TargetIP, "Recorded a fleet-wide drop rule for "+req.TargetIP+": "+req.Reason)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "quarantined",
		"peer":   peer,
	})
}

func (s *Server) handleMeshUnquarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MeshQuarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetIP == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid request: target_ip is required")
		return
	}
	targetIP, err := validateIP(req.TargetIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "target_ip: "+err.Error())
		return
	}
	req.TargetIP = targetIP

	if err := s.store.RemoveQuarantinedPeer(req.TargetIP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit(r, "MESH_UNQUARANTINE", req.TargetIP, "Withdrew the recorded fleet-wide drop rule for "+req.TargetIP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "unquarantined",
		"target_ip": req.TargetIP,
	})
}

func (s *Server) handleMeshQuarantinedList(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.GetQuarantinedPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// Handler exposes the request table for tests.
func (s *Server) Handler() http.Handler { return limitRequestBodies(s.routes()) }

// routes builds the request table. It is a method rather than a block inside
// Start so a test can exercise the real one: what these handlers are wrapped in
// is as much a security property as what they do, and a test that called a
// handler directly would prove nothing about the middleware in front of it.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// 0. Embedded operator console: the gated document at "/", plus the
	// stylesheet, script and fonts it loads. Asset paths are registered
	// individually so "/" keeps its own not-found behaviour.
	mux.HandleFunc("/", s.handleDashboard)
	for _, assetPath := range consoleAssetPaths() {
		mux.HandleFunc(assetPath, s.handleConsoleAsset)
	}

	// 1. Static Bootstrap & Binary Downloads
	// Reading the thresholds is open to any authenticated operator - an analyst
	// looking at an alert has to be able to see the rule that produced it - and
	// the handler itself refuses a write from anyone but an administrator.
	mux.HandleFunc("/api/v1/detection/tuning", s.authMiddleware(s.detectionTuningGate))

	mux.HandleFunc("/api/v1/enrolment/platforms", s.authMiddleware(s.handleEnrolmentPlatforms))
	mux.HandleFunc("/api/v1/enrolment/script", s.authMiddleware(requireAdmin(s.handleEnrolmentScript)))
	mux.HandleFunc("/bootstrap.ps1", s.handleBootstrapPS1)
	mux.HandleFunc("/bootstrap.sh", s.handleBootstrapSH)
	mux.HandleFunc("/download/", s.handleDownload)

	// 3. Multi-Tenant REST API & Hierarchy
	mux.HandleFunc("/api/v1/hierarchy", s.authMiddleware(s.handleGetHierarchy))
	mux.HandleFunc("/api/v1/locations", s.authMiddleware(s.handleLocations))
	mux.HandleFunc("/api/v1/tenants", s.authMiddleware(requireAdmin(s.handleTenants)))
	mux.HandleFunc("/api/v1/operators", s.authMiddleware(requireAdmin(s.handleOperators)))
	mux.HandleFunc("/api/v1/operators/remove", s.authMiddleware(requireAdmin(s.handleOperatorRemove)))
	mux.HandleFunc("/api/v1/endpoints", s.authMiddleware(s.handleEndpoints))
	mux.HandleFunc("/api/v1/endpoints/retire", s.authMiddleware(requireAdmin(s.handleRetireEndpoint)))
	mux.HandleFunc("/api/v1/agent/config", s.authMiddleware(s.handleAgentConfig))
	mux.HandleFunc("/api/v1/agents/update", s.authMiddleware(s.handleAgentsUpdate))
	mux.HandleFunc("/api/v1/agents/update-status", s.authMiddleware(requireAdmin(s.handleAgentsUpdateStatus)))
	// The baseline isolation policy: what an isolated host is still allowed to
	// reach. Reading it is open to any authenticated operator - an analyst
	// deciding whether to isolate has to be able to see what that would do -
	// but authoring it is an administrator's job, because a rule here is a
	// permanent hole in every isolation the policy's scope covers.
	mux.HandleFunc("/api/v1/baseline/catalogue", s.authMiddleware(s.handleBaselineCatalogue))
	mux.HandleFunc("/api/v1/baseline/policies", s.authMiddleware(s.baselineWriteGuard(s.handleBaselinePolicies)))
	mux.HandleFunc("/api/v1/baseline/policies/delete", s.authMiddleware(requireAdmin(s.handleBaselinePolicyDelete)))
	mux.HandleFunc("/api/v1/baseline/endpoint", s.authMiddleware(s.handleBaselineEndpoint))
	mux.HandleFunc("/api/v1/baseline/propose", s.authMiddleware(s.handleBaselinePropose))

	mux.HandleFunc("/api/v1/endpoints/isolate", s.authMiddleware(s.handleIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate", s.authMiddleware(s.handleUnisolate))
	mux.HandleFunc("/api/v1/endpoints/isolate-bulk", s.authMiddleware(s.handleBulkIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate-bulk", s.authMiddleware(s.handleBulkUnisolate))
	mux.HandleFunc("/api/v1/events", s.authMiddleware(s.handleEvents))

	// 4. Exclusions, traffic profiles, detection, analytics, and threat intel.
	mux.HandleFunc("/api/v1/network-profiles", s.authMiddleware(s.handleNetworkProfiles))
	mux.HandleFunc("/api/v1/exclusions", s.authMiddleware(s.handleExclusions))
	mux.HandleFunc("/api/v1/exclusions/toggle", s.authMiddleware(s.handleToggleExclusion))
	mux.HandleFunc("/api/v1/anomalies", s.authMiddleware(s.handleAnomalies))
	mux.HandleFunc("/api/v1/anomalies/acknowledge", s.authMiddleware(s.handleAcknowledgeAnomaly))
	mux.HandleFunc("/api/v1/analytics/summary", s.authMiddleware(s.handleGetAnalyticsSummary))
	mux.HandleFunc("/api/v1/threatintel/iocs", s.authMiddleware(s.handleThreatIntelIOCs))
	mux.HandleFunc("/api/v1/threatintel/sync", s.authMiddleware(requireAdmin(s.handleThreatIntelSync)))
	mux.HandleFunc("/api/v1/alerts", s.authMiddleware(s.handleAlerts))

	// 5. RBAC Auth & Audit Logging API
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/audit/logs", s.authMiddleware(s.handleAuditLogs))

	// 6. Autonomous PKI & Mutual TLS
	mux.HandleFunc("/api/v1/pki/ca.crt", s.handlePKICACert)
	mux.HandleFunc("/api/v1/pki/enroll", s.authMiddleware(s.handlePKIEnroll))

	// 7. Multi-Tier Asset Discovery & Extensible Scanner API
	// Discovery is an operator tool end to end: it sweeps a subnet from the
	// hub and hands back an inventory of everything on it, agented or not.
	// None of it is reachable by an agent, and the tenant key is on every
	// agent, so none of it is reachable with the tenant key.
	mux.HandleFunc("/api/v1/scanner/scan", s.authMiddleware(requireAdmin(s.handleScannerScan)))
	mux.HandleFunc("/api/v1/scanner/status", s.authMiddleware(requireAdmin(s.handleScannerStatus)))
	mux.HandleFunc("/api/v1/scanner/results", s.authMiddleware(requireAdmin(s.handleScannerResults)))
	mux.HandleFunc("/api/v1/scanner/coverage", s.authMiddleware(requireAdmin(s.handleScannerCoverage)))
	mux.HandleFunc("/api/v1/scanner/feedback", s.authMiddleware(requireAdmin(s.handleScannerFeedback)))

	// 8. Visual Communications Topology Graph API
	mux.HandleFunc("/api/v1/topology/graph", s.authMiddleware(requireAdmin(s.handleTopologyGraph)))

	// 8b. Unified asset graph.
	mux.HandleFunc("/api/v1/assets", s.authMiddleware(s.handleAssets))
	mux.HandleFunc("/api/v1/assets/correct", s.authMiddleware(requireAdmin(s.handleAssetCorrect)))

	// 9. Subnet Quarantine Mesh API (Lateral Isolation for Rogue Assets)
	// Mesh quarantine is persisted and returned in telemetry control state; it
	// lands in a
	// privileged firewall command on every agent that receives it. Nothing
	// with that reach is driven by a credential that ships to endpoints.
	mux.HandleFunc("/api/v1/mesh/quarantine", s.authMiddleware(requireAdmin(s.handleMeshQuarantine)))
	mux.HandleFunc("/api/v1/mesh/unquarantine", s.authMiddleware(requireAdmin(s.handleMeshUnquarantine)))
	mux.HandleFunc("/api/v1/mesh/quarantined", s.authMiddleware(s.handleMeshQuarantinedList))

	return mux
}
