package detector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/netaddr"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// checkDecoy pages on any connection to a decoy address (decoy_addrs): an
// address that nothing legitimate on the network uses, so a single touch is
// someone mapping it. Like the sweeps it runs before the expected rules.
func (e *Engine) checkDecoy(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning, now time.Time) {
	if ev.Direction != "OUTBOUND" || len(cfg.DecoyAddrs) == 0 || !cfg.IsDecoy(ev.DstIP, ev.DstPort) {
		return
	}
	key := fmt.Sprintf("decoy:%s:%s", ev.EndpointID, ev.DstIP)
	if e.shouldSuppressAlert(key, sweepCooldown) {
		return
	}
	evidence, _ := json.Marshal(map[string]any{"decoy": ev.DstIP, "port": ev.DstPort, "destination": ev.DstIP})
	e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
		AnomalyType: "DECOY_TOUCH", Technique: "T1046", Severity: "CRITICAL",
		Title:       fmt.Sprintf("%s reached decoy address %s", firstNonEmpty(endpoint.Hostname, ev.EndpointID), ev.DstIP),
		Description: fmt.Sprintf("%s connected to %s port %d. Nothing legitimate uses this address; it is listed as a decoy so that anyone mapping the network shows up.", firstNonEmpty(ev.ProcessPath, "An unattributed process"), ev.DstIP, ev.DstPort),
		Details:     fmt.Sprintf("Decoy: %s:%d | Process: %s | User: %s", ev.DstIP, ev.DstPort, firstNonEmpty(ev.ProcessPath, "-"), firstNonEmpty(ev.UserIdentity, "-")),
		Evidence:    string(evidence),
		ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
	})
	e.alertf("[!] ANOMALY ALERT [CRITICAL]: decoy %s touched by %s (%s)", ev.DstIP, ev.EndpointID, ev.ProcessPath)
}

// labEscapeQuietPorts are what a lab guest legitimately asks of the network
// outside the lab: names, time and an address.
func labEscapeQuietPort(port uint16) bool {
	switch port {
	case 53, 67, 123:
		return true
	}
	return false
}

// checkLabEscape pages when a lab host reaches lab_escape_hosts or more
// private hosts outside the lab (the home or infrastructure zones) within the
// sweep window. Lab guests run untrusted code by design; what they must not
// do is touch the rest of the network. The sensor's own heartbeat and updates
// and the guest's DNS, DHCP and time lookups do not count.
func (e *Engine) checkLabEscape(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, cfg storage.DetectionTuning,
	role, quietPath string, now time.Time) {
	if role != storage.RoleLab || ev.Direction != "OUTBOUND" || servedFlow(ev, cfg) || !isPrivateIP(ev.DstIP) || netaddr.IsLoopback(ev.DstIP) ||
		labEscapeQuietPort(ev.DstPort) || cfg.IsContainerAddress(ev.DstIP) || isSensorProcess(quietPath) ||
		isSensorUpdater(ev, quietPath) {
		return
	}
	destination, err := netaddr.Parse(ev.DstIP)
	if err != nil || !(destination.IsGlobalUnicast() || destination.IsLinkLocalUnicast()) {
		return
	}
	cx := e.classContext()
	zone := cx.ZoneOf(ev.DstIP)
	if zone != zoneHome && zone != zoneInfra {
		return
	}

	procKey := strings.ToLower(firstNonEmpty(baseName(ev.ProcessPath), "unknown"))
	windowKey := "labescape:" + ev.EndpointID
	e.mu.Lock()
	targets := e.lateralTargets[windowKey]
	if targets == nil {
		targets = map[string]*sweepTarget{}
		e.lateralTargets[windowKey] = targets
	}
	for ip, t := range targets {
		if now.Sub(t.at) > lateralWindow {
			delete(targets, ip)
		}
	}
	t := targets[ev.DstIP]
	if t == nil {
		t = &sweepTarget{ports: map[uint16]bool{}, actors: map[string]bool{}}
		targets[ev.DstIP] = t
	}
	t.at = now
	t.ports[ev.DstPort] = true
	t.actors[procKey] = true
	hosts := make([]string, 0, len(targets))
	zones := map[string]int{}
	for ip := range targets {
		hosts = append(hosts, ip)
		zones[cx.ZoneOf(ip)]++
	}
	e.mu.Unlock()

	if len(hosts) < cfg.LabEscapeHosts {
		return
	}
	if e.shouldSuppressAlert("lab_escape:"+ev.EndpointID, sweepCooldown) {
		return
	}
	sort.Strings(hosts)
	evidence, _ := json.Marshal(map[string]any{"zone_hosts": zones, "lab_escape_hosts": hosts, "target_zone": zone, "destination": "lab-escape"})
	who := firstNonEmpty(endpoint.Hostname, ev.EndpointID)
	e.recordAnomaly(ev, geo, endpoint, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
		AnomalyType: "LAB_ESCAPE", Technique: "T1021", Severity: "CRITICAL",
		Title:       fmt.Sprintf("Lab host %s reached %s outside the lab", who, plural(len(hosts), "host")),
		Description: fmt.Sprintf("%s on lab host %s connected to %s port %d, which is on the %s network, not the lab. Lab hosts run untested code and should only reach the lab and the internet.", firstNonEmpty(ev.ProcessPath, "An unattributed process"), who, ev.DstIP, ev.DstPort, zoneLabel(zone)),
		Details:     fmt.Sprintf("Outside hosts: %s | Process: %s | Window: %ds", strings.Join(hosts, ", "), firstNonEmpty(ev.ProcessPath, "-"), int(lateralWindow.Seconds())),
		Evidence:    string(evidence),
		ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
	})
	e.alertf("[!] ANOMALY ALERT [CRITICAL]: lab escape from %s to %s", ev.EndpointID, strings.Join(hosts, ","))
}

// NoteImplausibleRate records, once an hour per endpoint, that its sensor
// reported a transfer rate no link here can carry: a Windows counter wrapping
// at 2^32 or going backwards. Ingest stored the samples unmeasured
// (storage.DropImplausibleRates), so they reach no baseline. It is a
// collector-health note, not an alert; count is how many samples in the
// batch were dropped.
func (e *Engine) NoteImplausibleRate(ev storage.Event, endpoint storage.Endpoint, rate, limit float64, count int, now time.Time) {
	if e.sink != nil || e.shouldSuppressAlert("implausible_rate:"+ev.EndpointID, time.Hour) {
		return
	}
	evidence, _ := json.Marshal(map[string]any{"rate_bytes_per_second": rate, "limit_bytes_per_second": limit, "destination": "collector"})
	e.recordAnomaly(ev, threatintel.GeoRecord{}, endpoint, storage.AnomalyAlert{
		ID: uuid.New().String(), TenantID: ev.TenantID, EndpointID: ev.EndpointID, Hostname: endpoint.Hostname,
		AnomalyType: "COLLECTOR_HEALTH", Severity: "LOW",
		Title:       fmt.Sprintf("OmniNull agent on %s reported an impossible transfer rate", firstNonEmpty(endpoint.Hostname, ev.EndpointID)),
		Description: fmt.Sprintf("The agent reported %s from %s at %.0f Mbit/s, more than any link here carries (the limit is %.0f Mbit/s). That is a byte counter that wrapped or ran backwards, not real traffic. The connection is kept, but its byte counts are left out of the bandwidth figures. Nothing to do.", plural(count, "reading"), firstNonEmpty(baseName(ev.ProcessPath), "an unattributed process"), rate/125000, limit/125000),
		Details:     fmt.Sprintf("Process: %s | Target: %s:%d | Bytes out as reported: %d | Bytes in as reported: %d | Readings left out in this batch: %d", firstNonEmpty(ev.ProcessPath, "-"), ev.DstIP, ev.DstPort, ev.BytesOut, ev.BytesIn, count),
		Evidence:    string(evidence),
		ProcessPath: ev.ProcessPath, DstIP: ev.DstIP, DstPort: ev.DstPort, Timestamp: now,
	})
}

func isSensorProcess(path string) bool {
	switch storage.ProcessPathKey(path) {
	case "/opt/ominull/bin/ominulld", "c:/program files/ominull/ominulld.exe":
		return true
	}
	return false
}

// sensorUpdateDir is where the Linux agent stages an update (agent
// OMINULL_UPDATE_DIR, root-only): its apply.sh fetches the package and its
// signature from the hub with curl, into this directory.
const sensorUpdateDir = "/var/lib/ominull/updates/"

// isSensorUpdater reports whether a connection is the agent updating itself:
// root running the staged apply.sh with the system shell, or one of its two
// curl downloads into the update directory from an https URL at the very
// address and port connected to. quietPath is empty when the agent found the
// reported path is not the file running, so a renamed copy never counts. An
// unprivileged lab program cannot borrow it: curl connects before it opens
// its output file, so the user and the URL are what tell the updater apart.
func isSensorUpdater(ev storage.Event, quietPath string) bool {
	if quietPath == "" || ev.UserIdentity != "root" {
		return false
	}
	path, base := executableOf(quietPath)
	args := strings.Fields(ev.CommandLine)
	if interpreterFamily(base) == "shell" {
		return (strings.HasPrefix(path, "/usr/bin/") || strings.HasPrefix(path, "/bin/")) &&
			len(args) == 2 && args[1] == sensorUpdateDir+"apply.sh"
	}
	if path != "/usr/bin/curl" && path != "/bin/curl" {
		return false
	}
	out := ""
	for i, a := range args {
		if a == "-o" && i+1 < len(args) {
			out = args[i+1]
			break
		}
	}
	if out != sensorUpdateDir+"agent.deb" && out != sensorUpdateDir+"agent.deb.sig" || len(args) < 2 {
		return false
	}
	u, err := url.Parse(args[len(args)-1])
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname() == ev.DstIP && port == strconv.Itoa(int(ev.DstPort))
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func zoneLabel(zone string) string {
	switch zone {
	case zoneInfra:
		return "infrastructure"
	case zoneHome:
		return "home"
	}
	return zone
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func scanEvidence(zone string, ports int) string {
	raw, _ := json.Marshal(map[string]any{"target_zone": zone, "distinct_ports": ports})
	return string(raw)
}

// beaconClassEvidence adds what the classifier needs to a beacon's evidence:
// how many devices reach the destination, whether it is a shared tunnel
// front, and whether a browser is the one holding the conversation.
//
// strengthened marks the second finding of one conversation: raised again
// because it has now held at beacon_page_score for half an hour.
func (e *Engine) beaconClassEvidence(raw string, ev storage.Event, cfg storage.DetectionTuning, procName, owner string, strengthened bool) string {
	fields := map[string]any{}
	if json.Unmarshal([]byte(raw), &fields) != nil || fields == nil {
		fields = map[string]any{}
	}
	if strengthened {
		fields["strengthened"] = true
	}
	name := firstNonEmpty(ev.Domain, ev.SNI)
	if n, err := e.store.DestinationPrevalence(ev.TenantID, ev.DstIP, strings.ToLower(name)); err == nil {
		// The device beaconing is one of them even before its profile row
		// is written.
		fields["beacon_devices"] = max(n, 1)
	} else {
		// Rarity unknown: Classify pages a strong beacon rather than
		// calling it common.
		fields["beacon_devices_unknown"] = true
	}
	if cfg.IsTunnelService(name) {
		fields["tunnel_service"] = true
	}
	if cfg.IsBrowser(procName) {
		fields["browser"] = true
	}
	fields["destination"] = owner
	if name != "" {
		fields["domain"] = name
	}
	out, _ := json.Marshal(fields)
	return string(out)
}
