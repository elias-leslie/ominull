package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/storage"
)

// Agent client certificate renewal.
//
// Enrolment issues each agent a client certificate valid for
// pki.ClientCertLifetime (one year) and, until 1.8.104, nothing replaced it:
// the whole fleet, enrolled within a week, would have failed its TLS
// handshakes within the same week a year later (a Linux agent presents the
// expired certificate and the hub refuses the handshake; it has no way back
// short of re-enrolment).
//
// Renewal rides the existing authenticated session. A renewal-capable agent
// says so in its heartbeat (cert_renewal). When the certificate it presented
// on that verified handshake is inside the renewal window, or an operator asked
// for a renewal, the hub issues a new certificate for the same endpoint and
// returns it in the heartbeat reply, the same way it once handed out device
// credentials. The agent tests and installs it and presents it from then on.
// The old certificate stays valid until its own expiry: nothing is revoked, so
// an agent that fails to install the new one keeps working and is offered
// again later.

const (
	// agentCertRenewDaysSetting is the hub setting holding how many days before
	// expiry renewal starts. The default leaves a laptop that is off for weeks
	// plenty of chances; the feed warns at half the window.
	agentCertRenewDaysSetting = "agent_cert_renew_days"
	agentCertRenewDaysDefault = 60
	agentCertRenewDaysMin     = 7
	agentCertRenewDaysMax     = 300
	// A reply carrying a certificate can be lost. Offer again after this many
	// minutes rather than on every heartbeat: each offer generates an RSA key.
	agentCertOfferCooldownSetting = "agent_cert_offer_cooldown_minutes"
	agentCertOfferCooldownDefault = 60
	agentCertOfferCooldownMin     = 10
	agentCertOfferCooldownMax     = 24 * 60
)

// verifiedClientLeaf returns the client certificate the TLS stack verified
// against the hub CA for this request, or nil.
func verifiedClientLeaf(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

// agentCertRenewWindow is how long before expiry a certificate is renewed.
func (s *Server) agentCertRenewWindow() time.Duration {
	days := agentCertRenewDaysDefault
	if v, err := s.store.GetSetting(agentCertRenewDaysSetting); err == nil && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			days = min(max(n, agentCertRenewDaysMin), agentCertRenewDaysMax)
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// agentCertOfferCooldown is how long after an offer the next one waits.
func (s *Server) agentCertOfferCooldown() time.Duration {
	minutes := agentCertOfferCooldownDefault
	if v, err := s.store.GetSetting(agentCertOfferCooldownSetting); err == nil && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			minutes = min(max(n, agentCertOfferCooldownMin), agentCertOfferCooldownMax)
		}
	}
	return time.Duration(minutes) * time.Minute
}

// agentCertRenewalReason says why this heartbeat should carry a new
// certificate, or "" when it should not. leaf is the certificate verified on
// this request (nil when none was presented); credentialAuthed is true when
// the request proved the endpoint's device credential.
func agentCertRenewalReason(st storage.AgentCertState, leaf *x509.Certificate, credentialAuthed bool, now time.Time, window, cooldown time.Duration) string {
	if !st.OfferedAt.IsZero() && now.Sub(st.OfferedAt) < cooldown {
		return ""
	}
	requested := !st.RenewRequestedAt.IsZero()
	if leaf != nil {
		// A certificate issued at T carries NotBefore T - backdate, to the
		// second. It predates the request when T is before the request's
		// second (one issued in that same second counts as after it).
		if requested && leaf.NotBefore.Add(pki.ClientCertBackdate).Before(st.RenewRequestedAt.Truncate(time.Second)) {
			return "requested"
		}
		if leaf.NotAfter.Sub(now) < window {
			return "expiring"
		}
		return ""
	}
	// No certificate on this request. Only an endpoint that proved its own
	// device credential can be given one, and only when it held one that has
	// lapsed (a Windows agent drops an expired certificate and carries on
	// under the credential) or an operator asked.
	if !credentialAuthed {
		return ""
	}
	if requested && (st.SeenAt.IsZero() || st.SeenAt.Before(st.RenewRequestedAt)) {
		return "requested"
	}
	if !st.NotAfter.IsZero() && !now.Before(st.NotAfter) {
		return "lapsed"
	}
	return ""
}

// observeAgentCert records the verified client certificate of a heartbeat and,
// for an agent that can install one, adds a renewed certificate to its reply.
// Failures are logged and never fail the heartbeat: telemetry matters more than
// an early renewal, which is retried.
func (s *Server) observeAgentCert(r *http.Request, endpointID string, capable bool, resp map[string]any, now time.Time) {
	if s.pki == nil || s.tlsOpts.ClientCerts == ClientCertsOff {
		return
	}
	leaf := verifiedClientLeaf(r)
	if leaf != nil && leaf.Subject.CommonName != endpointID {
		// The identity check upstream refuses a mismatch; never renew one.
		return
	}
	if leaf != nil {
		if err := s.store.RecordAgentCertSeen(endpointID, leaf.NotAfter, leaf.SerialNumber.Text(16), now); err != nil {
			log.Printf("[!] Could not record the client certificate of %s: %v", endpointID, err)
		}
	}
	// The reply carries a private key: only ever over TLS.
	if !capable || r.TLS == nil {
		return
	}
	st, err := s.store.GetAgentCertState(endpointID)
	if err != nil {
		log.Printf("[!] Could not read the certificate state of %s: %v", endpointID, err)
		return
	}
	credentialAuthed := r.Header.Get("X-Device-Endpoint-ID") == endpointID
	reason := agentCertRenewalReason(st, leaf, credentialAuthed, now, s.agentCertRenewWindow(), s.agentCertOfferCooldown())
	if reason == "" {
		return
	}
	bundle, err := s.pki.IssueClientCert(endpointID, "")
	if err != nil {
		log.Printf("[!] Could not issue a renewed client certificate for %s: %v", endpointID, err)
		return
	}
	if err := s.store.MarkAgentCertOffered(endpointID, now); err != nil {
		log.Printf("[!] Could not record the certificate offer to %s: %v", endpointID, err)
		return
	}
	resp["client_certificate"] = map[string]string{
		"cert_pem_b64": base64.StdEncoding.EncodeToString(bundle.CertPEM),
		"key_pem_b64":  base64.StdEncoding.EncodeToString(bundle.KeyPEM),
		"pfx_b64":      bundle.PFXBase64,
		"not_after":    bundle.NotAfter.UTC().Format(time.RFC3339),
	}
	old := "none presented"
	if leaf != nil {
		old = "expires " + leaf.NotAfter.UTC().Format("2006-01-02")
	}
	s.auditAs(r, "device:"+endpointID, "AGENT_CERT_RENEWAL_OFFERED", endpointID,
		fmt.Sprintf("Offered a renewed client certificate (%s; current %s; new expires %s)", reason, old, bundle.NotAfter.UTC().Format("2006-01-02")))
}

// handleAgentCertRenewal lists what the hub knows about agent certificates
// (GET) or asks for one endpoint's certificate to be replaced on its next
// heartbeat (POST {"endpoint_id"}). The renewal itself needs no approval: the
// new certificate goes only to the endpoint that proves it is that endpoint.
func (s *Server) handleAgentCertRenewal(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		states, err := s.store.ListAgentCertStates()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "certificate state could not be read")
			return
		}
		out := make([]map[string]any, 0, len(states))
		for _, st := range states {
			row := map[string]any{"endpoint_id": st.EndpointID, "serial": st.Serial}
			if !st.NotAfter.IsZero() {
				row["days_left"] = daysLeft(st.NotAfter, time.Now())
			}
			for k, t := range map[string]time.Time{"not_after": st.NotAfter, "seen_at": st.SeenAt,
				"renew_requested_at": st.RenewRequestedAt, "offered_at": st.OfferedAt} {
				if !t.IsZero() {
					row[k] = t.UTC().Format(time.RFC3339)
				}
			}
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, map[string]any{"renew_days": int(s.agentCertRenewWindow().Hours() / 24), "certificates": out})
	case http.MethodPost:
		var req struct {
			EndpointID string `json:"endpoint_id"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, `send {"endpoint_id": "<id>"}`)
			return
		}
		id := strings.TrimSpace(req.EndpointID)
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
			return
		}
		ep, err := s.store.GetEndpoint(id)
		if err != nil || ep == nil || ep.ID != id {
			writeJSONError(w, http.StatusNotFound, "endpoint not registered")
			return
		}
		if ep.Status == "retired" {
			writeJSONError(w, http.StatusConflict, "endpoint is retired")
			return
		}
		if err := s.store.RequestAgentCertRenewal(id, time.Now().UTC()); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "renewal request could not be saved")
			return
		}
		s.audit(r, "AGENT_CERT_RENEWAL_REQUESTED", id, "Asked for this endpoint's client certificate to be renewed on its next heartbeat")
		writeJSON(w, http.StatusAccepted, map[string]string{"endpoint_id": id, "status": "requested",
			"note": "offered on its next heartbeat if its agent can renew (1.8.104 or later); GET shows offered_at, and a newer not_after once installed"})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// daysLeft is whole days until t, rounded down: an hour past expiry is -1.
func daysLeft(t, now time.Time) int {
	return int(math.Floor(t.Sub(now).Hours() / 24))
}

// agentCertFinding tells Nightshift whether agent certificates are renewing.
// Renewal starts agent_cert_renew_days before expiry; a certificate still in
// use at half that window has failed to renew for weeks and needs a person
// (an agent too old to renew, a machine that has been off, or one that keeps
// failing to install it). Messages may reach a push, so they carry counts and
// never a device name; the machines are the finding's resources. Endpoints
// never seen presenting a certificate are counted as unknown, not as fine;
// they do not raise the finding, since an offline laptop would keep it open.
func (s *Server) agentCertFinding(now time.Time) (feedFinding, error) {
	const uid, title = "ominull.agents.certificate", "Agent client certificates"
	states, err := s.store.ListAgentCertStates()
	if err != nil {
		return feedFinding{}, err
	}
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		return feedFinding{}, err
	}
	byID := map[string]storage.AgentCertState{}
	for _, st := range states {
		byID[st.EndpointID] = st
	}
	window := s.agentCertRenewWindow()
	warn := window / 2
	type entry struct {
		res      feedResource
		notAfter time.Time
	}
	var due []entry
	var unknown []string
	var unknownRes, renewingRes []feedResource
	expired, offline := 0, 0
	next := entry{}
	certs := map[string]any{}
	for _, ep := range endpoints {
		if ep.Status == "retired" {
			continue
		}
		res := feedResource{Type: "endpoint", Name: ep.Hostname, UID: ep.ID}
		st, ok := byID[ep.ID]
		if !ok || st.NotAfter.IsZero() {
			unknown = append(unknown, ep.ID)
			unknownRes = append(unknownRes, res)
			continue
		}
		left := st.NotAfter.Sub(now)
		row := map[string]any{"not_after": st.NotAfter.UTC().Format(time.RFC3339), "days_left": daysLeft(st.NotAfter, now)}
		if ep.DriverVersion != "" {
			row["agent_version"] = ep.DriverVersion
		}
		if !ep.LastSeenAt.IsZero() {
			row["last_seen"] = ep.LastSeenAt.UTC().Format(time.RFC3339)
		}
		if !st.OfferedAt.IsZero() {
			row["offered_at"] = st.OfferedAt.UTC().Format(time.RFC3339)
		}
		certs[ep.ID] = row
		if next.notAfter.IsZero() || st.NotAfter.Before(next.notAfter) {
			next = entry{res, st.NotAfter}
		}
		switch {
		case left < warn:
			due = append(due, entry{res, st.NotAfter})
			if left <= 0 {
				expired++
			}
			if !ep.LastSeenAt.IsZero() && now.Sub(ep.LastSeenAt) > 48*time.Hour {
				offline++
			}
		case left < window && !st.OfferedAt.IsZero():
			renewingRes = append(renewingRes, res)
		}
	}
	sort.Strings(unknown)
	unmapped := map[string]any{"renew_days": int(window.Hours() / 24), "warn_days": int(warn.Hours() / 24),
		"certificates": certs, "unknown": unknown}
	unknownNote := ""
	if len(unknown) > 0 {
		unknownNote = fmt.Sprintf("; expiry unknown for %s not yet seen presenting one", plural(len(unknown), "endpoint", "endpoints"))
	}
	if len(due) > 0 {
		sort.Slice(due, func(i, j int) bool { return due[i].notAfter.Before(due[j].notAfter) })
		var resources []feedResource
		for _, d := range due {
			resources = append(resources, d.res)
		}
		var parts []string
		if expired > 0 {
			parts = append(parts, fmt.Sprintf("%d expired", expired))
		}
		if n := len(due) - expired; n > 0 {
			parts = append(parts, fmt.Sprintf("%d within %d days of expiry", n, int(warn.Hours()/24)))
		}
		if offline > 0 {
			parts = append(parts, fmt.Sprintf("%d off line for over 2 days", offline))
		}
		msg := fmt.Sprintf("%s not renewed (%s). Agents on 1.8.104 or later renew once on line; update older agents, re-enrol any that cannot reconnect",
			plural(len(due), "agent certificate", "agent certificates"), strings.Join(parts, ", "))
		return s.feedFinding(now, uid, title, ocsfSevMedium, ocsfStatusNew, msg+unknownNote, resources, unmapped), nil
	}
	if next.notAfter.IsZero() {
		// Nothing to warn about yet, and nothing known: each agent's next
		// heartbeat records its certificate. Said as unknown, not as fine.
		msg := "No agent has presented a client certificate since the hub began recording them, so no expiry is known yet"
		if len(unknown) > 0 {
			msg += fmt.Sprintf(" (%s)", plural(len(unknown), "endpoint", "endpoints"))
		}
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved, msg, unknownRes, unmapped), nil
	}
	msg := fmt.Sprintf("Agent certificates renew %d days before expiry; the next expires in %d days", int(window.Hours()/24), daysLeft(next.notAfter, now))
	if len(renewingRes) > 0 {
		msg += fmt.Sprintf("; renewal offered to %s", plural(len(renewingRes), "endpoint", "endpoints"))
	}
	resources := append(append([]feedResource{next.res}, renewingRes...), unknownRes...)
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved, msg+unknownNote, resources, unmapped), nil
}
