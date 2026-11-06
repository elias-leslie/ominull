package detector

import (
	"fmt"
	"sort"
	"time"

	"ominull/hub/pkg/storage"
)

// Routine administration versus a lateral sweep.
//
// An operator's workstation reaches its managed hosts over ssh all day: a
// status check on the hypervisor, a command on a browser VM, the gateway's
// health poll. Three of those inside a minute is the exact shape the sweep
// detector looks for, and it paged at CRITICAL on every one. An expected rule
// that makes LATERAL_PORT_SWEEP expected lets that pass, and only that:
//
//   - the source endpoint is one the rule names (hosts) and is not a parked
//     test guest;
//   - the process is a program the rule names by its installed path (the ssh
//     client), not any process called ssh;
//   - every connection in the window went to the rule's port, and none to a
//     floor port;
//   - every host is inventoried: an enrolled endpoint's address, a lab or
//     infrastructure address (managed hosts without an agent, like the
//     gateway);
//   - there are at most the rule's max_hosts of them.
//
// One unknown host, one other port, one host too many, another program or
// another source, and the window is judged exactly as before. The reason the
// rule gives is the sentence the log line and the tests read.

// sweepTarget is one host the sweep window has seen, with the ports used.
type sweepTarget struct {
	at    time.Time
	ports map[uint16]bool
	// actors are the endpoint-traced actors of the flows to this target
	// ("" for an untraced flow): a sweep is credited to an actor only when
	// every flow in its window carries that one actor.
	actors map[string]bool
}

// sweepActor is the one actor behind every flow of the window, or "".
func sweepActor(window map[string]*sweepTarget) string {
	actor := ""
	for _, t := range window {
		if len(t.actors) != 1 {
			return ""
		}
		for a := range t.actors {
			if a == "" || (actor != "" && a != actor) {
				return ""
			}
			actor = a
		}
	}
	return actor
}

// inventoryTTL bounds how stale the enrolled-address set may be.
const inventoryTTL = time.Minute

// adminFanout says whether a sweep window is routine administration, and why
// or why not. base describes the event that closed the window; each port the
// window reached is asked of the expected rules with the window's host count.
func adminFanout(cfg storage.DetectionTuning, src storage.Endpoint, base storage.ExpectCtx, targets map[string]*sweepTarget, inventoried func(ip string) bool) (bool, string) {
	if storage.NormalizePresence(src.Presence) == storage.PresenceParked {
		return false, "source is a parked test guest"
	}
	base.Kind = storage.KindLateralSweep
	base.Targets = len(targets)
	ports := map[int]bool{}
	ips := make([]string, 0, len(targets))
	for ip, t := range targets {
		ips = append(ips, ip)
		for p := range t.ports {
			ports[int(p)] = true
		}
	}
	sort.Strings(ips)
	rule := ""
	for _, p := range sortedPorts(ports) {
		// A floor port in the window is never routine: SMB, RDP, telnet and
		// RPC are how a worm moves, and no rule explains them.
		if FloorPort(p) {
			return false, fmt.Sprintf("the window reached port %d, which is on the detection floor", p)
		}
		c := base
		c.Port = p
		r, ok := cfg.Expected(c)
		if !ok {
			return false, fmt.Sprintf("no expected rule covers this program from this host to port %d with %d hosts", p, len(targets))
		}
		rule = r.ID
	}
	for _, ip := range ips {
		// The lab and infrastructure networks are the operator's own guests
		// and managed hosts, enrolled or not.
		if !inventoried(ip) && !cfg.IsInfraAddress(ip) && !cfg.IsLabAddress(ip) {
			return false, fmt.Sprintf("%s is not an inventoried host", ip)
		}
	}
	return true, fmt.Sprintf("expected rule %s: %d inventoried hosts", rule, len(ips))
}

func sortedPorts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// inventoried reports whether an address belongs to an enrolled, not retired
// endpoint of the tenant or is a host the asset graph knows. The set is
// re-read at most once a minute.
func (e *Engine) inventoried(tenantID, ip string) bool {
	e.mu.Lock()
	set, ok := e.inventory[tenantID]
	fresh := ok && time.Since(e.inventoryAt[tenantID]) < inventoryTTL
	e.mu.Unlock()
	if !fresh {
		list, err := e.store.ListEndpoints(tenantID)
		if err != nil {
			return false // unknown is not inventoried: the sweep pages
		}
		// The asset graph's addresses count too: the lab guests and devices
		// the router knows but no agent runs on are the network's own hosts.
		set, err = e.store.KnownAssetIPs(tenantID)
		if err != nil {
			set = map[string]bool{}
		}
		for _, ep := range list {
			if ep.Status != "retired" && ep.IP != "" {
				set[ep.IP] = true
			}
		}
		e.mu.Lock()
		e.inventory[tenantID] = set
		e.inventoryAt[tenantID] = time.Now()
		e.mu.Unlock()
	}
	return set[ip]
}

// sweepFloorPorts is every floor port reached anywhere in the window, sorted.
// The evidence's target list keeps ten hosts; this covers all of them.
func sweepFloorPorts(targets map[string]*sweepTarget) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, t := range targets {
		for p := range t.ports {
			if FloorPort(int(p)) && !seen[int(p)] {
				seen[int(p)] = true
				out = append(out, int(p))
			}
		}
	}
	sort.Ints(out)
	return out
}

// sweepTargetList is the window's hosts and ports for the alert's evidence,
// sorted, at most ten.
func sweepTargetList(targets map[string]*sweepTarget) []map[string]any {
	ips := make([]string, 0, len(targets))
	for ip := range targets {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > 10 {
		ips = ips[:10]
	}
	out := make([]map[string]any, 0, len(ips))
	for _, ip := range ips {
		ports := make([]int, 0, len(targets[ip].ports))
		for p := range targets[ip].ports {
			ports = append(ports, int(p))
		}
		sort.Ints(ports)
		out = append(out, map[string]any{"ip": ip, "ports": ports})
	}
	return out
}
