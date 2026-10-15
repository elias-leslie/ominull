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
	// automation ("own automation"): it is listed, and it does not page.
	Expected string `json:"expected,omitempty"`
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
}

func describeAlert(a storage.AnomalyAlert, tuning storage.DetectionTuning) feedAlert {
	var ev alertEvidence
	_ = json.Unmarshal([]byte(a.Evidence), &ev)
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
	switch a.AnomalyType {
	case "LATERAL_PORT_SWEEP":
		n := len(ev.Targets)
		if n == 0 {
			n = countFromTitle(a.Title)
		}
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
		out.What = fmt.Sprintf("%s on %s reached %s for the first time", who, host, orUnknown(a.DstIP))
	case "AGENT_UPLOAD_VOLUME":
		out.What = fmt.Sprintf("%s on %s uploaded much more than in an ordinary hour", who, host)
	case "AGENT_DNS_BYPASS":
		out.What = fmt.Sprintf("%s on %s looked up names without going through the router", who, host)
	default:
		out.What = fmt.Sprintf("%s on %s", strings.TrimSpace(a.Title), host)
	}
	return out
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
