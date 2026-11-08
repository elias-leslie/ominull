package detector

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// Agent egress: per-runtime baselines for the AI agents on an endpoint.
//
// An agent runtime does what the text in front of it says, and a prompt
// injection is text. What an injected exfiltration looks like on the wire is
// narrow: the runtime reaching a destination it never has, the runtime sending
// far more than it ever does in an hour, or a tool resolving names somewhere
// the router cannot see. Each runtime keeps its own memory of where it goes
// (agent_egress_destinations) and how much it sends (agent_egress_hourly), so
// "Codex reached a new site" is judged against Codex, not against the estate.

const (
	agentUploadDays  = 14
	agentDNSCooldown = time.Hour
)

// firstContactUpload is the new-place line from the tuning: what a new
// destination must be sent (new_dest_upload_mb) within how long of first
// contact (new_dest_window_min) to page.
func firstContactUpload(cfg storage.DetectionTuning) (int64, time.Duration) {
	return int64(cfg.NewDestUploadMB) << 20, time.Duration(cfg.NewDestWindowMin) * time.Minute
}

// publicResolvers are the anycast addresses of the public DNS-over-HTTPS and
// DNS-over-TLS services. A tool talking to one on 443 is resolving names where
// neither the router's resolver log nor this hub's DNS view can see them.
var publicResolvers = func() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, s := range []string{
		"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
		"8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
		"94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220", "76.76.2.0", "76.76.10.0",
		"185.228.168.9", "185.228.169.9", "45.90.28.0", "45.90.30.0", "194.242.2.2",
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
		"2620:fe::fe", "2620:fe::9", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
	} {
		m[netip.MustParseAddr(s)] = true
	}
	return m
}()

var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
	"doh.opendns.com", "dns.nextdns.io", "dns.adguard-dns.com", "doh.mullvad.net", "dns.mullvad.net",
}

func isDoHHost(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, h := range dohHosts {
		if name == h || strings.HasSuffix(name, "."+h) {
			return true
		}
	}
	return false
}

// isResolverBypass reports a connection that resolves names outside the
// estate's own resolvers: plain DNS or DNS-over-TLS to a public address, or
// HTTPS carrying data to a public DoH service. It is recorded, not paged:
// lookups the router cannot see are a visibility gap, not exfiltration.
func isResolverBypass(ev storage.Event) bool {
	if ev.Direction != "OUTBOUND" || isPrivateIP(ev.DstIP) {
		return false
	}
	switch ev.DstPort {
	case 53, 853:
		return true
	case 443:
		// HTTPS to a resolver is a lookup only when something was sent: a
		// reachability probe to 1.1.1.1:443 (0 bytes out) resolves nothing.
		if ev.BytesOut <= 0 {
			return false
		}
		a, err := netip.ParseAddr(ev.DstIP)
		return (err == nil && publicResolvers[a.Unmap()]) || isDoHHost(ev.Domain) || isDoHHost(ev.SNI)
	}
	return false
}

// agentDestination is the unit a runtime's baseline is kept in: the
// registrable domain when the flow carries a name, otherwise the network
// owner, otherwise the /24 (or /48) of the address. The registrable domain
// follows the whole public suffix list, private section included, so each
// tenant of a shared host (x.a.run.app, x.github.io) is its own destination.
//
// On a CDN or rented compute the name is usually borrowed - the hub fills it
// from whatever any client last resolved to that address - and one address
// there serves many sites, so the name alone would let a sink inherit a
// domain the runtime already knows. There the key is the name and the owner.
func agentDestination(domain, sni, dstIP string, geo threatintel.GeoRecord) string {
	for _, name := range []string{domain, sni} {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || strings.ContainsAny(name, " /") {
			continue
		}
		reg, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			reg = name
		}
		if t := strings.TrimSpace(geo.Tenancy); t == storage.TenancyHosting || t == storage.TenancySharedCDN {
			if owner := strings.ToLower(strings.TrimSpace(geo.Org)); owner != "" {
				return reg + "@" + owner
			}
		}
		return reg
	}
	if owner := strings.ToLower(strings.TrimSpace(geo.Org)); owner != "" {
		return "owner:" + owner
	}
	if a, err := netip.ParseAddr(dstIP); err == nil {
		bits := 24
		if a.Unmap().Is6() {
			bits = 48
		}
		if p, err := a.Unmap().Prefix(bits); err == nil {
			return "net:" + p.String()
		}
	}
	return ""
}

// SeedAgentBaselines gives each runtime the destinations the hub has already
// watched it reach, the first time the baseline tables are empty.
func (e *Engine) SeedAgentBaselines() {
	cfg := e.settings()
	n, err := e.store.SeedAgentDestinations(func(path, _, domain, ip string) (string, string) {
		runtime := cfg.AgentRuntimeOf(path)
		if runtime == "" {
			return "", ""
		}
		return runtime, agentDestination(domain, "", ip, threatintel.ResolveGeoIP(ip))
	})
	if err != nil {
		log.Printf("[-] seeding agent egress baselines: %v", err)
	} else if n > 0 {
		log.Printf("[*] Seeded %d agent egress destinations from communication profiles", n)
	}
	// Where each device as a whole has sent anything, for the new-place
	// upload rule (checkNewPlace).
	n, err = e.store.SeedDestinations("seeded_devices", func(path, _, domain, ip string) (string, string) {
		if isPrivateIP(ip) || isSensorProcess(path) {
			return "", ""
		}
		return storage.DeviceDestinations, agentDestination(domain, "", ip, threatintel.ResolveGeoIP(ip))
	})
	if err != nil {
		log.Printf("[-] seeding device destinations: %v", err)
	} else if n > 0 {
		log.Printf("[*] Seeded %d device destinations from communication profiles", n)
	}
}

// checkResolverBypass raises an agent runtime, or a tool it runs, connecting
// to a public DNS service. It is a floor rule: it runs before the expected rules,
// and agent_egress_enabled does not switch it off.
func (e *Engine) checkResolverBypass(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	procName string, isInterpreter bool, now time.Time) {
	if ev.Direction != "OUTBOUND" {
		return
	}
	runtime := cfg.AgentRuntimeOf(ev.ProcessPath)
	// Resolver bypass is judged for the runtimes and for the tools they run:
	// an injected "curl https://dns.google/resolve?name=..." is the shape.
	if (runtime != "" || isInterpreter) && isResolverBypass(ev) {
		key := fmt.Sprintf("dnsbypass:%s:%s:%s", ev.EndpointID, strings.ToLower(procName), ev.DstIP)
		if !e.shouldSuppressAlert(key, agentDNSCooldown) {
			who := procName
			if runtime != "" {
				who = runtime
			}
			e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
				ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
				AnomalyType: "AGENT_DNS_BYPASS", Technique: "T1071.004", Severity: "HIGH",
				Title:       fmt.Sprintf("%s resolving names outside the estate's resolvers", who),
				Description: fmt.Sprintf("%s connected to %s:%d, a public DNS service, so its lookups bypass the router's resolver log.", procName, ev.DstIP, ev.DstPort),
				Details:     fmt.Sprintf("Process: %s | Target: %s:%d | Name: %s | Workload: %s", ev.ProcessPath, ev.DstIP, ev.DstPort, firstNonEmpty(ev.Domain, ev.SNI, "-"), WorkloadOf(ev.ProcessPath, ev.CommandLine)),
				ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
			})
		}
	}
}

func (e *Engine) checkAgentEgress(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	procName string, isInterpreter, warming bool, expect func(kind string) bool, now time.Time) {
	if ev.Direction != "OUTBOUND" {
		return
	}
	runtime := cfg.AgentRuntimeOf(ev.ProcessPath)
	if !cfg.AgentEgressOn || runtime == "" || isPrivateIP(ev.DstIP) {
		return
	}
	// A flow an expected rule covers for both kinds is not learned or judged.
	newDestExpected, uploadExpected := expect(storage.KindAgentNewDest), expect(storage.KindAgentUpload)
	if newDestExpected && uploadExpected {
		return
	}

	dest := agentDestination(ev.Domain, ev.SNI, ev.DstIP, geo)
	if dest != "" && !newDestExpected {
		e.checkAgentDestination(ev, geo, endpoint, cfg, runtime, dest, warming, now)
	}

	if ev.BytesOut <= 0 {
		return
	}
	total, err := e.store.AddAgentUpload(ev.TenantID, ev.EndpointID, runtime, ev.BytesOut, now)
	if err != nil {
		log.Printf("[-] agent upload accounting failed for %s/%s: %v", ev.EndpointID, runtime, err)
		return
	}
	p95, hours, err := e.store.AgentUploadBaseline(ev.TenantID, ev.EndpointID, runtime, now, agentUploadDays)
	if err != nil {
		return
	}
	threshold := max(int64(cfg.AgentUploadFloorMB)<<20, int64(cfg.AgentUploadFactor)*p95)
	// Raised once per runtime and hour, whichever event first finds the hour
	// over the line - also when a tuning change lowers the line mid-hour.
	if total < threshold || warming || uploadExpected {
		return
	}
	first, err := e.store.MarkAgentUploadAlerted(ev.TenantID, ev.EndpointID, runtime, now)
	if err != nil {
		log.Printf("[-] agent upload alert claim failed for %s/%s, reporting anyway: %v", ev.EndpointID, runtime, err)
	} else if !first {
		return
	}
	{
		e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
			ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
			AnomalyType: "AGENT_UPLOAD_VOLUME", Technique: "T1567", Severity: "HIGH",
			Title:       fmt.Sprintf("%s has sent %s this hour", runtime, humanBytes(total)),
			Description: fmt.Sprintf("Agent runtime %s uploaded %s in one hour; its 95th-percentile hour over the last %d days is %s (%d hours with uploads), and the threshold is %s.", runtime, humanBytes(total), agentUploadDays, humanBytes(p95), hours, humanBytes(threshold)),
			Details:     fmt.Sprintf("Runtime: %s | Hour total: %s | Baseline p95: %s over %d hours | Threshold: %s | Last destination: %s:%d (%s)", runtime, humanBytes(total), humanBytes(p95), hours, humanBytes(threshold), ev.DstIP, ev.DstPort, firstNonEmpty(dest, "-")),
			ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
		})
	}
}

// checkAgentDestination judges a runtime reaching dest. Agents read the web
// for a living - documentation, issue trackers, a project's site during a
// bug hunt - so somewhere new is remembered and never reported on its own,
// whoever hosts it: most of the web sits on rented compute, and an address
// the hub could not name is usually a site whose lookup it did not see. What
// is reported, and pages (HIGH), is the exfiltration shape:
// the runtime sending new_dest_upload_mb or more to the new destination
// within new_dest_window_min of first reaching it. A connection's first
// report carries no bytes on Linux (the agent's first counter reading is its
// baseline), so the upload is judged over the destination's first window,
// once, when its total crosses the line.
func (e *Engine) checkAgentDestination(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	runtime, dest string, warming bool, now time.Time) {
	sent := max(ev.BytesOut, 0)
	seen, err := e.store.ObserveAgentDestination(ev.TenantID, ev.EndpointID, runtime, dest, sent, now)
	if err != nil {
		log.Printf("[-] agent egress baseline write failed for %s/%s: %v", ev.EndpointID, runtime, err)
		return
	}
	learnFor := time.Duration(cfg.AgentBaselineDays) * 24 * time.Hour
	if warming || seen.FirstSeen.Sub(seen.Since) < learnFor {
		// Inside the runtime's baseline: learned, not new.
		return
	}
	line, window := firstContactUpload(cfg)
	total := seen.BytesBefore + sent
	large := total >= line && seen.BytesBefore < line && now.Sub(seen.FirstSeen) <= window
	if !large {
		// A first visit is only remembered (ObserveAgentDestination above);
		// nothing is written for it. Only the first-contact upload is a finding.
		return
	}
	e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
		AnomalyType: "AGENT_NEW_DESTINATION", Technique: "T1567", Severity: "HIGH",
		Title: fmt.Sprintf("%s sent %s to a destination it never has: %s", runtime, humanBytes(total), dest),
		Description: fmt.Sprintf("Agent runtime %s sent %s to %s:%d (%s) within %s of first reaching it; nothing it has reached on this endpoint since %s went there before.",
			runtime, humanBytes(total), ev.DstIP, ev.DstPort, describeOwner(geo), minutesPhrase(now.Sub(seen.FirstSeen)), seen.Since.UTC().Format("2006-01-02")),
		Details: fmt.Sprintf("Runtime: %s | Destination: %s | Process: %s | Sent since first contact: %s | First contact: %s | %s",
			runtime, dest, ev.ProcessPath, humanBytes(total), seen.FirstSeen.UTC().Format(time.RFC3339), describeOwner(geo)),
		Evidence:    uploadEvidence(dest, total, seen.FirstSeen),
		ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
	})
}

// minutesPhrase reads a duration within the first-contact window: "a minute",
// "12 minutes".
func minutesPhrase(d time.Duration) string {
	if m := int(d.Minutes()); m > 1 {
		return fmt.Sprintf("%d minutes", m)
	}
	return "a minute"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// uploadEvidence is the first-contact upload a new-destination finding carries.
func uploadEvidence(dest string, sent int64, first time.Time) string {
	fields := map[string]any{"destination": dest, "first_contact": first.UTC().Format(time.RFC3339), "first_upload_bytes": sent}
	raw, _ := json.Marshal(fields)
	return string(raw)
}

// checkNewPlace is the new-place upload rule for every program on a device,
// not only the agent runtimes: the device sending new_dest_upload_mb or more
// to a destination (registrable domain, else network owner) that nothing on
// it has reached before, within new_dest_window_min of first reaching it,
// pages. The device's memory is the runtime-agnostic rows of
// agent_egress_destinations (storage.DeviceDestinations), seeded once from
// the communication profiles. Runtime flows feed the memory but are judged
// by AGENT_NEW_DESTINATION; the sensor's own traffic is left out. It runs
// before the expected rules: a rule is an answer about a destination the
// operator knows, and this rule is about one nobody has seen. Only a rule that
// names this kind (an empty list never covers it) counts the place as seen.
func (e *Engine) checkNewPlace(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	quietPath string, now time.Time) {
	if ev.Direction != "OUTBOUND" || isPrivateIP(ev.DstIP) || isSensorProcess(quietPath) {
		return
	}
	dest := agentDestination(ev.Domain, ev.SNI, ev.DstIP, geo)
	if dest == "" {
		return
	}
	sent := max(ev.BytesOut, 0)
	seen, err := e.store.ObserveAgentDestination(ev.TenantID, ev.EndpointID, storage.DeviceDestinations, dest, sent, now)
	if err != nil {
		log.Printf("[-] device destination write failed for %s: %v", ev.EndpointID, err)
		return
	}
	// A known destination by role is not a new place, however its name reads:
	// an agent runtime talking to its maker's published range (judged by its
	// hourly volume, AGENT_UPLOAD_VOLUME), or a program the operator paired
	// with this network as its job (rclone to Google for the Drive backup). On
	// a shared front end the name is whatever any client last resolved there,
	// and under a private public suffix (x.googleapis.com) every API host is a
	// registrable domain of its own, so the name alone keeps reading the same
	// conversation as a new place. Neither covers rented compute.
	vouched := vouchedWorkload(ev.ProcessPath, ev.CommandLine, ev.AttributionStatus)
	if expectedFor(cfg, expectCtx(ev, geo, endpoint, e.classContext().RoleOf(endpoint), quietPath, vouched))(storage.KindNewPlaceUpload) {
		return
	}
	// Agent runtimes are judged here too: their own first-contact upload
	// (AGENT_NEW_DESTINATION) runs after the expected rules and only while
	// agent_egress_enabled is on, and this rule is a floor. Both firing on
	// one upload is one incident (same family and destination).
	warming, _ := warmingUp(endpoint, cfg, now)
	learnFor := time.Duration(cfg.AgentBaselineDays) * 24 * time.Hour
	if warming || seen.FirstSeen.Sub(seen.Since) < learnFor {
		return
	}
	line, window := firstContactUpload(cfg)
	total := seen.BytesBefore + sent
	if total < line || seen.BytesBefore >= line || now.Sub(seen.FirstSeen) > window {
		return
	}
	who := firstNonEmpty(endpoint.Hostname, ev.EndpointID)
	proc := firstNonEmpty(baseName(ev.ProcessPath), "an unattributed process")
	e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
		AnomalyType: "NEW_PLACE_UPLOAD", Technique: "T1567", Severity: "HIGH",
		Title: fmt.Sprintf("%s sent %s to %s, somewhere it never sent anything before", who, humanBytes(total), dest),
		Description: fmt.Sprintf("%s on %s sent %s to %s:%d (%s) within %s of first reaching it. Nothing on this device has reached %s since %s.",
			proc, who, humanBytes(total), ev.DstIP, ev.DstPort, describeOwner(geo), minutesPhrase(now.Sub(seen.FirstSeen)), dest, seen.Since.UTC().Format("2006-01-02")),
		Details: fmt.Sprintf("Process: %s | Destination: %s | Sent since first contact: %s | First contact: %s | %s",
			firstNonEmpty(ev.ProcessPath, "-"), dest, humanBytes(total), seen.FirstSeen.UTC().Format(time.RFC3339), describeOwner(geo)),
		Evidence:    uploadEvidence(dest, total, seen.FirstSeen),
		ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
	})
}
