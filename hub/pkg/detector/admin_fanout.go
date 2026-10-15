package detector

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Routine administration versus a lateral sweep.
//
// An operator's workstation reaches its managed hosts over ssh all day: a
// status check on the hypervisor, a command on a browser VM, the gateway's
// health poll. Three of those inside a minute is the exact shape the sweep
// detector looks for, and it paged at CRITICAL on every one. The rule here
// lets that pass, and only that:
//
//   - the source endpoint is one the operator named (admin_fanout_sources)
//     and is not a parked test guest;
//   - the process is the ssh client;
//   - every connection in the window went to port 22;
//   - every host is inventoried: an enrolled endpoint's address, or inside
//     admin_fanout_targets (managed hosts without an agent, like the gateway);
//   - there are at most admin_fanout_max_hosts of them.
//
// One unknown host, one other port, one host too many, another program or
// another source, and the window is judged exactly as before. The reason the
// rule gives is the sentence the log line and the tests read.

// sweepTarget is one host the sweep window has seen, with the ports used.
type sweepTarget struct {
	at    time.Time
	ports map[uint16]bool
}

// inventoryTTL bounds how stale the enrolled-address set may be.
const inventoryTTL = time.Minute

// adminFanoutClients are the programs whose fan-out the rule considers.
var adminFanoutClients = map[string]bool{"ssh": true}

const adminPort = 22

// adminFanout says whether a sweep window is routine administration, and why
// or why not.
func adminFanout(cfg storage.DetectionTuning, src storage.Endpoint, procKey string, targets map[string]*sweepTarget, inventoried func(ip string) bool) (bool, string) {
	switch {
	case !cfg.IsAdminFanoutSource(src.ID):
		return false, "source is not an admin workstation"
	case storage.NormalizePresence(src.Presence) == storage.PresenceParked:
		return false, "source is a parked test guest"
	case !adminFanoutClients[strings.TrimSuffix(procKey, ".exe")]:
		return false, "process is not the ssh client"
	case len(targets) > cfg.AdminFanoutMax:
		return false, fmt.Sprintf("%d hosts is over the admin limit of %d", len(targets), cfg.AdminFanoutMax)
	}
	ips := make([]string, 0, len(targets))
	for ip := range targets {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		for p := range targets[ip].ports {
			if p != adminPort {
				return false, fmt.Sprintf("%s was reached on port %d", ip, p)
			}
		}
		if !inventoried(ip) && !cfg.IsAdminFanoutTarget(ip) {
			return false, fmt.Sprintf("%s is not an inventoried host", ip)
		}
	}
	return true, fmt.Sprintf("ssh to %d inventoried hosts on port 22", len(ips))
}

// inventoried reports whether an address belongs to an enrolled, not retired
// endpoint of the tenant. The set is re-read at most once a minute.
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
		set = map[string]bool{}
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
