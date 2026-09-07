package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// The router telemetry API.
//
// A gateway poller posts what it can see; the hub decides what any of it means.
// The endpoint is deliberately narrow: it accepts three kinds of observation and
// returns a count of what was kept and what was thrown away. It never returns
// instructions, because a compromised gateway must not be able to ask the hub to
// tell it what to do next.
//
// Writing is open to any authenticated caller for the same reason agent event
// ingest is: the poller runs with the tenant key, the least-privileged credential
// the estate issues. Reading is likewise open to operators, since a flow table
// nobody can look at is not visibility.

// routerIngestLimit bounds one poll body. Twenty thousand conntrack rows of the
// shape this parses sit comfortably inside it; anything larger is refused before
// it is parsed rather than after.
const routerIngestLimit = 8 << 20 // 8 MiB

// handleRouterTelemetry ingests one poll from a gateway.
func (s *Server) handleRouterTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RouterID string                  `json:"router_id"`
		Label    string                  `json:"label"`
		Leases   []storage.RouterLease   `json:"leases"`
		Flows    []storage.RouterFlow    `json:"flows"`
		DNS      []routerDNSLine         `json:"dns"`
		Resolved []storage.DNSResolution `json:"resolutions"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, routerIngestLimit)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable telemetry: "+err.Error())
		return
	}

	routerID := strings.TrimSpace(req.RouterID)
	if routerID == "" {
		writeJSONError(w, http.StatusBadRequest, "name the router this came from")
		return
	}
	if len(routerID) > 64 {
		routerID = routerID[:64]
	}

	now := time.Now().UTC()
	out := storage.RouterIngestResult{}

	// Each source is folded independently. One malformed section must not cost
	// the others: a gateway whose conntrack parser has broken should still be
	// able to tell us who holds which lease.
	if len(req.Leases) > 0 {
		a, rj, err := s.store.RecordRouterLeases(routerID, req.Leases, now)
		if err != nil {
			log.Printf("[!] router %s: lease ingest failed: %v", routerID, err)
		}
		out.LeasesAccepted, out.LeasesRejected = a, rj
		out.AssetsTouched += a
	}
	if len(req.Flows) > 0 {
		a, rj, err := s.store.RecordRouterFlows(routerID, req.Flows, now)
		if err != nil {
			log.Printf("[!] router %s: flow ingest failed: %v", routerID, err)
		}
		out.FlowsAccepted, out.FlowsRejected = a, rj
	}
	if len(req.DNS) > 0 {
		out.DNSAccepted, out.DNSRejected = s.recordRouterDNS(routerID, req.DNS, now)
	}
	if len(req.Resolved) > 0 {
		a, rj, err := s.store.RecordDNSResolutions(req.Resolved, now)
		if err != nil {
			log.Printf("[!] router %s: resolution ingest failed: %v", routerID, err)
		}
		out.ResolutionsAccepted, out.ResolutionsRejected = a, rj
	}

	summary := fmt.Sprintf("leases %d/%d flows %d/%d dns %d/%d names %d/%d",
		out.LeasesAccepted, out.LeasesAccepted+out.LeasesRejected,
		out.FlowsAccepted, out.FlowsAccepted+out.FlowsRejected,
		out.DNSAccepted, out.DNSAccepted+out.DNSRejected,
		out.ResolutionsAccepted, out.ResolutionsAccepted+out.ResolutionsRejected)
	if err := s.store.TouchRouterSource(routerID, req.Label, summary, now); err != nil {
		log.Printf("[!] router %s: could not record the source: %v", routerID, err)
	}

	writeJSON(w, http.StatusOK, out)
}

// routerDNSLine is one query the gateway's resolver answered.
type routerDNSLine struct {
	ClientIP string    `json:"client_ip"`
	Domain   string    `json:"domain"`
	QType    string    `json:"qtype"`
	At       time.Time `json:"at"`
}

// recordRouterDNS folds resolver logs into the existing DNS telemetry table.
//
// This is the piece that turns an alert reading "104.18.32.7" into one reading
// "the thermostat asked for firmware.nest.com". The hub's own forwarder stays
// disabled - it took a thermostat offline in v1.8.3 and is opt-in for that
// reason - so the gateway's log is the only safe way to learn these names.
func (s *Server) recordRouterDNS(routerID string, lines []routerDNSLine, now time.Time) (int, int) {
	accepted, rejected := 0, 0
	if len(lines) > storage.MaxRouterDNSPerPoll {
		rejected += len(lines) - storage.MaxRouterDNSPerPoll
		lines = lines[:storage.MaxRouterDNSPerPoll]
	}
	for _, l := range lines {
		domain := strings.ToLower(strings.TrimSpace(l.Domain))
		client := strings.TrimSpace(l.ClientIP)
		if domain == "" || len(domain) > 255 || client == "" {
			rejected++
			continue
		}
		at := l.At
		if at.IsZero() {
			at = now
		}
		qtype := strings.ToUpper(strings.TrimSpace(l.QType))
		if qtype == "" {
			qtype = "A"
		}
		if len(qtype) > 16 {
			qtype = qtype[:16]
		}
		err := s.store.RecordDNSEvent(storage.DNSEvent{
			Timestamp: at.UTC(),
			ClientIP:  client,
			Domain:    domain,
			QType:     qtype,
			Action:    "PERMIT",
			Status:    "HIT",
			Upstream:  "router:" + routerID,
			Transport: "udp",
		})
		if err != nil {
			rejected++
			continue
		}
		accepted++
	}
	return accepted, rejected
}

// handleRouterFlows returns stored flow rollups.
func (s *Server) handleRouterFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	filter := storage.RouterFlowFilter{
		SrcIP: strings.TrimSpace(q.Get("src")),
		DstIP: strings.TrimSpace(q.Get("dst")),
	}
	if hours := q.Get("hours"); hours != "" {
		if n, err := strconv.Atoi(hours); err == nil && n > 0 && n <= 24*30 {
			filter.Since = time.Now().UTC().Add(-time.Duration(n) * time.Hour)
		}
	}
	if limit := q.Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil {
			filter.Limit = n
		}
	}

	flows, err := s.store.ListRouterFlows(filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"flows": flows, "count": len(flows)})
}

// handleRouterTalkers answers the question the ingest exists for: which devices
// that carry no agent are talking, and to whom.
func (s *Server) handleRouterTalkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	talkers, err := s.store.SummariseRouterTalkers(since, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Name the ones we already know, so the answer is about devices rather than
	// addresses. An asset with an agent is not interesting here - the point of
	// this view is what the agents cannot see.
	assets, err := s.store.ListAssets("")
	if err == nil {
		byIP := map[string]storage.Asset{}
		for _, a := range assets {
			if a.IP != "" {
				byIP[a.IP] = a
			}
		}
		// Name the destinations too. "10.9.9.9" is not an answer; the resolver
		// already told us the name it was looked up under, and that is the
		// thing an analyst can act on.
		var everyDst []string
		for _, t := range talkers {
			everyDst = append(everyDst, t.Destinations...)
		}
		dstNames, _ := s.store.NamesForIPs(everyDst)

		enriched := make([]map[string]interface{}, 0, len(talkers))
		for _, t := range talkers {
			named := make([]string, 0, len(t.Destinations))
			for _, d := range t.Destinations {
				if n := dstNames[d]; n != "" {
					named = append(named, n+" ("+d+")")
					continue
				}
				named = append(named, d)
			}
			row := map[string]interface{}{
				"ip":            t.IP,
				"conversations": t.Conversations,
				"bytes":         t.Bytes,
				"destinations":  named,
			}
			if a, ok := byIP[t.IP]; ok {
				row["hostname"] = a.Hostname
				row["mac"] = a.MAC
				row["vendor"] = a.Vendor
				row["has_agent"] = a.HasAgent()
			}
			enriched = append(enriched, row)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"talkers": enriched, "hours": hours})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"talkers": talkers, "hours": hours})
}
