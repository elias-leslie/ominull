package server

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
)

// Alert detail for the Nightshift feed.
//
// A count ("2 new anomalies, 2 critical") tells the owner that something
// happened and nothing that lets them judge it. The summary finding therefore
// carries the newest paging alerts themselves, each as one plain sentence
// (what was seen, on which host, by which program) plus the facts behind it:
// when, the program and its command line, where it connected, and - when the
// hub can say - the likely cause. Nightshift words the time in the owner's
// zone and adds the ask.
//
// Command lines are the one field that can carry a secret (a token on a
// curl, a password flag), so they are redacted and shortened here, before
// they leave the hub.

const (
	feedAlertMax       = 5
	feedAlertScan      = 200
	feedCommandMax     = 100
	feedDestinationMax = 4
	// feedAlertBytes keeps the summary inside Nightshift's 4 KiB details cap
	// (measured as it measures it, indented), with room for the counts.
	feedAlertBytes = 3000
)

type feedAlert struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	At       string `json:"at"`
	What     string `json:"what"`
	Process  string `json:"process,omitempty"`
	Command  string `json:"command,omitempty"`
	// Destinations is one string ("10.0.0.1:22, 10.0.0.9:22, +2 more"):
	// Nightshift keeps source data at most four levels deep.
	Destinations string `json:"destinations,omitempty"`
	Cause        string `json:"cause,omitempty"`
	// Expected is set when the hub explains the alert as the owner's own
	// automation ("own automation"), one of our agents or services, or a
	// connection test: it is listed, and it does not page.
	Expected string `json:"expected,omitempty"`
	// Actor names the agent session or service the endpoint traced the
	// process to ("Agent in Aico window fb39ca7b"), whether or not that
	// explains the alert.
	Actor string `json:"actor,omitempty"`
}

const secretWord = `(?:pass(?:word|wd|phrase)?|pwd|token|secret|api[_-]?key|auth|bearer|credential|private[_-]?key)`

var (
	// Header values: everything up to the closing quote.
	headerSecret = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|cookie|x-api-key|api-key)\s*:\s*[^'"]+`)
	// name=value and name: value, where the name says secret.
	secretAssign = regexp.MustCompile(`(?i)\b([a-z0-9_-]*` + secretWord + `[a-z0-9_-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s'"]+)`)
	// --flag value, where the flag says secret.
	secretFlag = regexp.MustCompile(`(?i)((?:^|\s)--?[a-z0-9_-]*` + secretWord + `[a-z0-9_-]*)\s+("[^"]*"|'[^']*'|[^\s'"]+)`)
	bearer     = regexp.MustCompile(`(?i)\bbearer\s+[^\s'"]+`)
	// user:password@ in a URL.
	urlCredential = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+):[^@\s/]+@`)
	// Long opaque runs (keys, tokens, hashes): 24+ characters mixing letters
	// and digits, never a path (no slash) or a hyphenated word.
	opaqueRun = regexp.MustCompile(`[A-Za-z0-9+_=]{24,}`)
)

// sanitizeCommand redacts anything secret-looking and shortens the command
// line for display.
func sanitizeCommand(cmd string) string {
	cmd = strings.Join(strings.Fields(cmd), " ")
	cmd = urlCredential.ReplaceAllString(cmd, "$1:***@")
	cmd = headerSecret.ReplaceAllString(cmd, "$1: ***")
	cmd = bearer.ReplaceAllString(cmd, "Bearer ***")
	cmd = secretAssign.ReplaceAllString(cmd, "$1$2***")
	cmd = secretFlag.ReplaceAllString(cmd, "$1 ***")
	cmd = opaqueRun.ReplaceAllStringFunc(cmd, func(run string) string {
		if strings.ContainsAny(run, "0123456789") && strings.IndexFunc(run, unicode.IsLetter) >= 0 {
			return "***"
		}
		return run
	})
	if utf8.RuneCountInString(cmd) > feedCommandMax {
		r := []rune(cmd)
		cmd = strings.TrimSpace(string(r[:feedCommandMax-1])) + "…"
	}
	return cmd
}

type alertEvidence struct {
	CommandLine string `json:"command_line"`
	Targets     []struct {
		IP    string `json:"ip"`
		Ports []int  `json:"ports"`
	} `json:"sweep_targets"`
	AdminRule string `json:"admin_rule"`
	Domain    string `json:"domain"`
	SNI       string `json:"sni"`
	Owner     string `json:"destination_owner"`
	// Actor is what the endpoint agent traced the flow's process to (see
	// actorLabel); SweepActor the one actor behind every flow of a sweep.
	Actor      string `json:"actor"`
	SweepActor string `json:"sweep_actor"`
	// FloorPorts is every floor port the whole sweep window reached (the
	// target list keeps ten hosts). Nil on a sweep raised before the hub
	// recorded it, which is read as a floor sweep.
	FloorPorts *[]int `json:"floor_ports"`
	Protocol   int    `json:"protocol"`
	// BytesOut is nil on findings raised before the hub recorded it.
	BytesOut *int64 `json:"bytes_out"`
}

func describeAlert(a storage.AnomalyAlert, tuning storage.DetectionTuning) feedAlert {
	var ev alertEvidence
	evidenceOK := json.Unmarshal([]byte(a.Evidence), &ev) == nil
	proc := ""
	if p := strings.ReplaceAll(a.ProcessPath, "\\", "/"); p != "" && p != "unknown" {
		proc = filepath.Base(p)
	}
	host := a.Hostname
	if host == "" {
		host = a.EndpointID
	}
	var dests []string
	out := feedAlert{ID: a.ID, Type: a.AnomalyType, Severity: a.Severity, Host: host, At: a.Timestamp.UTC().Format(time.RFC3339),
		Process: proc, Command: sanitizeCommand(ev.CommandLine)}

	var ports []int
	seenPort := map[int]bool{}
	for _, t := range ev.Targets {
		for _, p := range t.Ports {
			if !seenPort[p] {
				seenPort[p] = true
				ports = append(ports, p)
			}
		}
		if len(dests) < feedDestinationMax {
			dests = append(dests, fmt.Sprintf("%s:%s", t.IP, joinInts(t.Ports)))
		}
	}
	if ev.FloorPorts != nil {
		// Floor ports reached by hosts past the ten the evidence lists.
		for _, p := range *ev.FloorPorts {
			if !seenPort[p] {
				seenPort[p] = true
				ports = append(ports, p)
			}
		}
	}
	if n := len(ev.Targets); n > feedDestinationMax {
		dests = append(dests, fmt.Sprintf("+%d more", n-feedDestinationMax))
	}
	if len(ev.Targets) == 0 && a.DstIP != "" {
		dests = []string{fmt.Sprintf("%s:%d", a.DstIP, a.DstPort)}
	}
	out.Destinations = strings.Join(dests, ", ")

	who := "A program"
	if proc != "" {
		who = proc
	}
	actor := actorLabel(ev.Actor)
	if a.AnomalyType == "LATERAL_PORT_SWEEP" {
		// One flow's actor says nothing about the others in the window.
		actor = actorLabel(ev.SweepActor)
	}
	out.Actor = actor
	switch a.AnomalyType {
	case "LATERAL_PORT_SWEEP":
		// The evidence lists ten hosts; the title counts them all.
		n := max(len(ev.Targets), countFromTitle(a.Title))
		out.What = fmt.Sprintf("%s on %s connected to %s on the local network within a minute%s", who, host, plural(n, "host", "hosts"), portPhrase(ports))
		if proc == "ssh" && ev.AdminRule != "" && tuning.IsAdminFanoutSource(a.EndpointID) {
			out.Cause = "Probably your own ssh use from this workstation. It still alerted because " + ev.AdminRule
			if ownSSH(ev) {
				out.Expected = "own automation"
			}
		}
	case "PORT_SCAN_RECON":
		out.What = fmt.Sprintf("%s on %s tried many different ports on %s within 10 seconds", who, host, orUnknown(a.DstIP))
	case "THREAT_INTEL_MATCH":
		out.What = fmt.Sprintf("%s contacted %s, an address on a threat list", host, orUnknown(a.DstIP))
	case "C2_BEACONING":
		out.What = fmt.Sprintf("%s on %s contacted %s on a steady timer, the way remote-control malware checks in", who, host, orUnknown(a.DstIP))
	case "BANDWIDTH_SPIKE":
		out.What = fmt.Sprintf("%s on %s sent far more data than usual to %s", who, host, orUnknown(a.DstIP))
	case "CLOUD_STORAGE_EGRESS":
		out.What = fmt.Sprintf("%s on %s uploaded data to a cloud storage service", who, host)
	case "SENSITIVE_PORT_EGRESS":
		out.What = fmt.Sprintf("%s on %s connected out on port %d, which is normally kept inside the network", who, host, a.DstPort)
	case "ENDPOINT_SILENT":
		out.What = fmt.Sprintf("The OmniNull agent on %s stopped reporting", host)
	case "AGENT_NEW_DESTINATION":
		name := firstName(ev.SNI, ev.Domain, titleDestination(a.Title))
		out.What = fmt.Sprintf("%s on %s reached %s for the first time", who, host, destPhrase(name, a.DstIP, a.DstPort, ev.Owner))
		// Claude Code's native build runs as its version number, so the
		// runtime comes from the tuning's agent_runtimes, not the base name.
		runtime := tuning.AgentRuntimeOf(a.ProcessPath)
		if runtime == "" {
			runtime = proc
		}
		if vendor := tuning.RuntimeVendor(runtime, name); vendor != "" {
			// A cause, not an explanation: on a shared CDN address the name
			// can be any other site's.
			out.Cause = fmt.Sprintf("Probably %s itself: %s is %s's own service", runtime, name, vendor)
		}
	case "AGENT_UPLOAD_VOLUME":
		out.What = fmt.Sprintf("%s on %s uploaded much more than in an ordinary hour", who, host)
	case "AGENT_DNS_BYPASS":
		out.What = fmt.Sprintf("%s on %s connected straight to %s, so any name lookups it made skipped the router", who, host,
			resolverPhrase(firstName(ev.SNI, ev.Domain), a.DstIP, a.DstPort))
		if connectProbe(ev.CommandLine) {
			// The command line is the process's own to rewrite: only a TCP
			// flow that carried nothing out is explained by it.
			if ev.Protocol == 6 && ev.BytesOut != nil && *ev.BytesOut == 0 {
				out.Cause = "A connection test: the command only opened the connection and sent nothing, so it looked nothing up"
				out.Expected = "connection test"
			} else {
				out.Cause = "Probably a connection test (the command only opens the connection)"
			}
		}
	default:
		out.What = fmt.Sprintf("%s on %s", strings.TrimSpace(a.Title), host)
	}
	// A sweep that touches a floor port is never explained, by an actor or by
	// the admin fan-out rule: SMB, RDP, telnet and RPC are how a worm moves.
	// Evidence that does not say which ports the whole window reached is
	// read as a floor sweep.
	unknownPorts := !evidenceOK || ev.FloorPorts == nil
	floor := a.AnomalyType == "LATERAL_PORT_SWEEP" && (unknownPorts || len(*ev.FloorPorts) > 0 || touchesFloorPort(ports, a.DstPort))
	why := floorWhy
	if floor && unknownPorts && !touchesFloorPort(ports, a.DstPort) {
		why = unknownPortsWhy
	}
	if floor {
		out.Expected = ""
	}
	if actor != "" && out.Expected == "" {
		if attributable[a.AnomalyType] && !floor {
			out.Expected = actor
			out.Cause = actor + " ran it"
		} else if floor {
			out.Cause = actor + " ran it. It still asks because " + why
		} else {
			// Ours, but the kind of thing a hijacked agent would do: the owner
			// still looks, told who it was.
			out.Cause = actor + " ran it. It still asks because " + riskyWhy(a.AnomalyType)
		}
	}
	return out
}

// attributable are the kinds one of our agents or services explains: a sweep
// of hosts on the local network the way an operator does, credited only when
// every flow in its window carries that one actor. The egress kinds (a new
// destination, an upload, a resolver bypass, cloud storage) are what a
// prompt-injected agent would do, so naming the agent does not explain them;
// threat-list and beacon matches are never explained.
var attributable = map[string]bool{"LATERAL_PORT_SWEEP": true}

const floorWhy = "it reached SMB, RDP, telnet or RPC ports, which is how a worm spreads"

const unknownPortsWhy = "the alert does not record every port the sweep reached"

func touchesFloorPort(ports []int, dstPort uint16) bool {
	if detector.FloorPort(int(dstPort)) {
		return true
	}
	for _, p := range ports {
		if detector.FloorPort(p) {
			return true
		}
	}
	return false
}

func riskyWhy(anomalyType string) string {
	switch anomalyType {
	case "THREAT_INTEL_MATCH", "C2_BEACONING":
		return "a threat-list or beacon match is never explained by who ran it"
	}
	return "sending data somewhere new is what a hijacked agent would do"
}

var (
	actorAgent   = regexp.MustCompile(`^agent:(claude|codex):([0-9a-f]{4,64})?$`)
	actorService = regexp.MustCompile(`^service:(nightshift|summitflow):([\w@.:-]{1,120}\.(?:service|scope))$`)
)

// actorLabel turns the endpoint's actor ("agent:claude:fb39ca7b",
// "service:nightshift:nightshift-check.service") into owner words; anything
// else is dropped. The agent reads it from the process's own ancestry and
// cgroup, so it only ever describes that endpoint's own alert. The agent
// label matches Nightshift's, which swaps in the Aico window title.
func actorLabel(actor string) string {
	if m := actorAgent.FindStringSubmatch(actor); m != nil {
		tool := map[string]string{"claude": "Claude Code", "codex": "Codex"}[m[1]]
		if m[2] != "" {
			return "Agent in Aico window " + m[2]
		}
		return tool + " session outside Aico"
	}
	if m := actorService.FindStringSubmatch(actor); m != nil {
		return map[string]string{"nightshift": "Nightshift", "summitflow": "SummitFlow"}[m[1]] + " (" + m[2] + ")"
	}
	return ""
}

// probeShape is a shell opening a TCP connection by redirection and reading
// nothing into it (bash's </dev/tcp/host/port), or nc -z: a reachability
// test that sends no payload.
var probeShape = regexp.MustCompile(`^(?:\S*/)?(?:ba|z)?sh -c '?(?:timeout \d+ )?(?:(?:\S*/)?(?:ba)?sh -c )?(?:: |true )?< ?/dev/tcp/[\w.:\[\]-]+/\d+'?$|^(?:\S*/)?(?:nc|ncat|netcat) -[-vw0-9 ]*z[-vw0-9 ]*\s+[\w.:\[\]-]+\s+\d+$`)

func connectProbe(cmd string) bool {
	return probeShape.MatchString(strings.Join(strings.Fields(cmd), " "))
}

func firstName(v ...string) string {
	for _, s := range v {
		s = strings.TrimSpace(s)
		if s != "" && s != "-" && !strings.ContainsAny(s, " /") {
			return s
		}
	}
	return ""
}

// titleDestination reads the destination from an agent-egress title written
// before the evidence carried the name ("codex reached a destination it never
// has: x.oaiusercontent.com@cloudflare, inc.").
func titleDestination(title string) string {
	_, dest, ok := strings.Cut(title, " it never has: ")
	if !ok {
		return ""
	}
	dest, _, _ = strings.Cut(dest, "@")
	if strings.HasPrefix(dest, "owner:") || strings.HasPrefix(dest, "net:") {
		return ""
	}
	return dest
}

func destPhrase(name, ip string, port uint16, owner string) string {
	addr := orUnknown(ip)
	if ip != "" && port != 0 {
		addr = fmt.Sprintf("%s:%d", ip, port)
	}
	parts := addr
	if name != "" {
		parts = name + " (" + addr
		if owner != "" {
			parts += ", " + owner
		}
		parts += ")"
	} else if owner != "" {
		parts += " (" + owner + ")"
	}
	return parts
}

// resolverNames are the public DNS services by address, for the sentence.
var resolverNames = map[string]string{
	"8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
	"1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "1.1.1.2": "Cloudflare DNS", "1.0.0.2": "Cloudflare DNS",
	"1.1.1.3": "Cloudflare DNS", "1.0.0.3": "Cloudflare DNS",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
	"94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS",
}

func resolverPhrase(name, ip string, port uint16) string {
	svc := resolverNames[ip]
	if svc == "" && name != "" {
		svc = name
	}
	if svc == "" {
		svc = "a public DNS service"
	}
	return fmt.Sprintf("%s (%s:%d)", svc, orUnknown(ip), port)
}

// ownSSH: the admin rule failed only because a host was not inventoried
// (ssh, from an admin workstation, port 22 only, within the host limit), which
// is the owner's own ssh to a machine OmniNull does not know yet.
func ownSSH(ev alertEvidence) bool {
	if !strings.HasSuffix(ev.AdminRule, " is not an inventoried host") || len(ev.Targets) == 0 {
		return false
	}
	for _, t := range ev.Targets {
		for _, p := range t.Ports {
			if p != 22 {
				return false
			}
		}
	}
	return true
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ",")
}

func portPhrase(ports []int) string {
	switch len(ports) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(", all on port %d", ports[0])
	default:
		if len(ports) > 4 {
			return fmt.Sprintf(", on %d different ports", len(ports))
		}
		return ", on ports " + strings.ReplaceAll(joinInts(ports), ",", ", ")
	}
}

var hostsInTitle = regexp.MustCompile(`\((\d+) Hosts?\)`)

func countFromTitle(title string) int {
	if m := hostsInTitle.FindStringSubmatch(title); m != nil {
		var n int
		fmt.Sscan(m[1], &n)
		return n
	}
	return 0
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "an unknown address"
	}
	return v
}

// alertSeverity maps an alert's own severity to OCSF: the summary is as
// severe as the worst alert it lists, no more.
func alertSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return ocsfSevCritical
	case "HIGH":
		return ocsfSevHigh
	}
	return ocsfSevInformational
}

// fitAlerts drops alerts from the end until the list fits the byte budget
// (indented, as Nightshift measures it).
func fitAlerts(alerts []feedAlert) []feedAlert {
	for len(alerts) > 0 {
		raw, _ := json.MarshalIndent(alerts, "    ", "  ")
		if len(raw) <= feedAlertBytes {
			break
		}
		alerts = alerts[:len(alerts)-1]
	}
	return alerts
}
