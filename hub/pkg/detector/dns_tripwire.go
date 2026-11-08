package detector

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// DNSLookup is one name a device asked the gateway's resolver for.
type DNSLookup struct {
	TenantID string
	RouterID string
	ClientIP string
	Domain   string
	At       time.Time
}

// NoteDNSLookup pages when a device looks up a decoy name (decoy_names: the
// host in a planted credential or config, which nothing legitimate asks
// for), and records a threat-list match when the name is on a bad-domain
// feed (intel, from the threat-intelligence manager; nil when it is not). The
// feed's confidence decides whether that match pages, as for an address. A
// lookup alone isolates nothing: link previews and prefetching ask for names
// nobody visits. It reports whether a finding was written; the caller has
// checked that the client is an address and the domain a DNS name.
func (e *Engine) NoteDNSLookup(l DNSLookup, intel *storage.IOC) bool {
	cfg := e.settings()
	decoy, isDecoy := cfg.DecoyName(l.Domain)
	if !isDecoy && intel == nil {
		return false
	}
	// The cooldown comes before any store read: a device resolving a listed
	// name every second costs one map lookup a time, not an endpoint scan.
	if isDecoy {
		if e.shouldSuppressAlert(fmt.Sprintf("decoy-name:%s:%s", l.ClientIP, decoy), sweepCooldown) {
			return false
		}
	} else if e.shouldSuppressAlert(fmt.Sprintf("intel-domain:%s:%s", l.ClientIP, intel.Value), time.Hour) {
		return false
	}
	if l.TenantID == "" {
		l.TenantID = "default"
	}
	if l.At.IsZero() {
		l.At = time.Now().UTC()
	}
	ep := e.endpointAt(l.TenantID, l.ClientIP)
	host := ep.Hostname
	if host == "" {
		if a, err := e.store.GetAsset(l.ClientIP); err == nil && a != nil && a.Hostname != "" {
			host = a.Hostname
		}
	}
	who := firstNonEmpty(host, l.ClientIP)
	ev := storage.Event{
		TenantID: l.TenantID, EndpointID: ep.ID, SrcIP: l.ClientIP, Domain: l.Domain,
		Protocol: 17, DstPort: 53, Direction: "OUTBOUND", Timestamp: l.At,
	}
	via := "the gateway's DNS log"
	if l.RouterID != "" {
		via = fmt.Sprintf("the DNS log of gateway %s", l.RouterID)
	}

	if isDecoy {
		evidence, _ := json.Marshal(map[string]any{"decoy": decoy, "domain": l.Domain, "destination": l.Domain, "lookup_by": l.ClientIP, "router": l.RouterID})
		e.recordAnomaly(ev, threatintel.GeoRecord{}, ep, storage.AnomalyAlert{
			ID: uuid.New().String(), TenantID: l.TenantID, EndpointID: ep.ID, Hostname: who,
			AnomalyType: "DECOY_TOUCH", Technique: "T1552", Severity: "CRITICAL",
			Title:       fmt.Sprintf("%s looked up decoy name %s", who, l.Domain),
			Description: fmt.Sprintf("%s (%s) asked for %s. Nothing legitimate uses this name: it is the host in a planted credential or config file, so whoever looked it up read that file and tried to use it. Seen in %s.", who, l.ClientIP, l.Domain, via),
			Details:     fmt.Sprintf("Decoy name: %s | Looked up: %s | Client: %s | Source: %s", decoy, l.Domain, l.ClientIP, via),
			Evidence:    string(evidence), Timestamp: l.At,
		})
		e.alertf("[!] ANOMALY ALERT [CRITICAL]: decoy name %s looked up by %s", l.Domain, l.ClientIP)
		return true
	}

	conf := intel.Confidence
	evidence, _ := json.Marshal(map[string]any{
		"domain": l.Domain, "destination": l.Domain, "lookup_by": l.ClientIP, "router": l.RouterID,
		"intel_source": intel.Source, "intel_type": intel.ThreatType, "intel_confidence": conf,
	})
	e.recordAnomaly(ev, threatintel.GeoRecord{}, ep, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: l.TenantID, EndpointID: ep.ID, Hostname: who,
		AnomalyType: "THREAT_INTEL_MATCH", Technique: "T1071.004", Severity: "CRITICAL",
		Title:       fmt.Sprintf("%s looked up threat-listed %s", who, l.Domain),
		Description: fmt.Sprintf("Lookup matched indicator %s from %s (%s, confidence %d%%). Seen in %s.", intel.Value, intel.Source, intel.ThreatType, conf, via),
		Details:     fmt.Sprintf("Domain: %s | Client: %s | Feed: %s | Confidence: %d%%", l.Domain, l.ClientIP, intel.Source, conf),
		Evidence:    string(evidence), Timestamp: l.At,
	})
	e.alertf("[!] DETECTION ALERT [CRITICAL]: %s looked up threat-listed %s (%s, %d%%)", l.ClientIP, l.Domain, intel.Source, conf)
	return true
}

// endpointAt is the enrolled endpoint holding ip: of those not retired, the
// one that reported last (an address a retired machine once held is someone
// else's now). A zero endpoint when none does.
func (e *Engine) endpointAt(tenantID, ip string) storage.Endpoint {
	if ip == "" {
		return storage.Endpoint{}
	}
	eps, err := e.store.ListEndpoints(tenantID)
	if err != nil {
		return storage.Endpoint{}
	}
	var best storage.Endpoint
	for _, ep := range eps {
		if ep.IP != ip || ep.Status == "retired" {
			continue
		}
		if best.ID == "" || ep.LastSeenAt.After(best.LastSeenAt) {
			best = ep
		}
	}
	return best
}
