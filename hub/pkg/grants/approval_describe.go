package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"ominull/hub/pkg/scripts"
	"sort"
	"strconv"
	"strings"

	"ominull/hub/pkg/response"
)

// The action name and summary come from the typed payload alone (the route it
// will run, the canonical body and the targets, or the terminal's own action
// payload), so the audit cannot show "Release isolation" over a payload that
// isolates through a handler's mistake. Any action or summary text the caller
// passes is ignored.

type routedPayload struct {
	Route   string          `json:"route"`
	Body    json.RawMessage `json:"body"`
	Targets []string        `json:"targets"`
	// Baselines are an isolation's exceptions, approved with it (agents use
	// only these while isolated).
	Baselines []response.IsolationBaseline `json:"baselines,omitempty"`
}

var routedPayloadKeys = map[string]bool{"route": true, "body": true, "targets": true, "baselines": true}

// checkBaselines validates an isolation's exceptions: each entry names only
// targets, no target twice, and every rule is one the agent accepts (an agent
// refuses the whole grant over one bad rule). It returns the owner's view.
func checkBaselines(list []response.IsolationBaseline, targets []string) (string, error) {
	in := map[string]bool{}
	for _, t := range targets {
		in[t] = true
	}
	seen := map[string]bool{}
	shown := []string{}
	distinct := map[string]bool{}
	for _, b := range list {
		if len(b.Endpoints) == 0 || len(b.Rules) == 0 || len(b.Rules) > response.MaxIsolationRules {
			return "", errors.New("isolation exceptions must name endpoints and 1..64 rules")
		}
		for _, ep := range b.Endpoints {
			if !in[ep] || seen[ep] {
				return "", fmt.Errorf("isolation exceptions name %q, which is not a target or is named twice", cleanText(ep, 64))
			}
			seen[ep] = true
		}
		for _, r := range b.Rules {
			if !r.Valid() {
				return "", errors.New("isolation exceptions carry a rule agents refuse")
			}
			d := fmt.Sprintf("%s %s/%d %s", r.Service, r.Protocol, r.Port, r.Destination)
			if !distinct[d] {
				distinct[d] = true
				if len(shown) < 6 {
					shown = append(shown, d)
				}
			}
		}
	}
	if len(distinct) == 0 {
		return " (no exceptions: hub and loopback only)", nil
	}
	s := " (exceptions: " + strings.Join(shown, ", ")
	if len(distinct) > len(shown) {
		s += fmt.Sprintf(" and %d more", len(distinct)-len(shown))
	}
	return s + ")", nil
}

type routeSpec struct {
	kind   response.ActionKind
	action string
}

var approvalRoutes = map[string]routeSpec{
	"/api/v1/endpoints/isolate":         {ActionKindIsolation, "Isolate host"},
	"/api/v1/endpoints/unisolate":       {ActionKindIsolation, "Release isolation"},
	"/api/v1/endpoints/isolate-bulk":    {ActionKindIsolation, "Isolate hosts"},
	"/api/v1/endpoints/unisolate-bulk":  {ActionKindIsolation, "Release isolation"},
	"/api/v1/endpoints/allow-isolation": {ActionKindIsolation, "Allow host isolation"},
	"/api/v1/agents/update":             {ActionKindAgentUpdate, "Update agents"},
	"/api/v1/mesh/quarantine":           {ActionKindMesh, "Quarantine address"},
	"/api/v1/mesh/unquarantine":         {ActionKindMesh, "Lift quarantine"},
	"/api/v1/endpoints/capabilities":    {ActionKindCapability, "Change what a host accepts"},
}

func decodeJSON(raw []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return dec.Decode(v)
}

func listTargets(t []string) string {
	const show = 6
	if len(t) <= show {
		return strings.Join(t, ", ")
	}
	return strings.Join(t[:show], ", ") + fmt.Sprintf(" and %d more", len(t)-show)
}

// maxTerminalSessionSeconds is the longest session length the hub will
// show; the hub's own bound is the same (terminal.LimitBounds).
const maxTerminalSessionSeconds = 24 * 60 * 60

// ValidAgentLabel reports whether s can be an agent's self-declared label
// (the hub's X-Ominull-Agent header): 1 to 64 printable ASCII characters,
// no quote or backslash (it is shown quoted), no leading or trailing space.
func ValidAgentLabel(s string) bool {
	if s == "" || len(s) > 64 || strings.TrimSpace(s) != s {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// AgentClaim is how an agent's self-declared label is shown: as a claim,
// never as an identity ("an agent calling itself \"claude-ops\"").
func AgentClaim(label string) string {
	if label == "" {
		return "an agent"
	}
	return "an agent calling itself \"" + label + "\""
}

// describeTerminal shows a terminal request; seconds, when set, is how long
// the hub will let the session run. label is an admin-key agent's
// self-declared name, shown as a claim.
func describeTerminal(payload []byte, targets []string, requester string, seconds int64, label string) (string, string, error) {
	var p response.TerminalSessionPayload
	if err := decodeJSON(payload, &p); err != nil || strings.TrimSpace(p.Program) == "" {
		return "", "", errors.New("terminal approval payload must name the program")
	}
	if len(targets) != 1 {
		return "", "", errors.New("a terminal approval covers exactly one endpoint")
	}
	if seconds < 0 || seconds > maxTerminalSessionSeconds {
		return "", "", errors.New("a terminal session runs at most 24 hours")
	}
	length := ""
	if seconds > 0 {
		length = " up to " + spanText(seconds) + ","
	}
	who := requester
	if label != "" {
		who += ", " + AgentClaim(label)
	}
	return "Open terminal", fmt.Sprintf("Interactive %s on %s, recorded,%s for %s",
		cleanText(p.Program, 120), targets[0], length, who), nil
}

// describeScreen shows a screen request in the owner's words: control or
// watch-only, how long, for whom, whether the person at the keyboard is asked
// first, and whether it may open with nobody there to ask. The payload is
// exactly the digested {"mode":...[,"unattended":true]}; anything else in it
// is refused, since the agent digests those bytes and nothing more.
//
// Whether the person at the keyboard is asked is always said, either way:
// leaving the clause out would read the same as not knowing. label is an
// admin-key agent's self-declared name, shown as a claim.
func describeScreen(payload []byte, targets []string, requester string, seconds int64, askFirst bool, label string) (string, string, error) {
	var top map[string]json.RawMessage
	if err := decodeJSON(payload, &top); err != nil {
		return "", "", errors.New("screen approval payload must name the mode")
	}
	for k := range top {
		if k != "mode" && k != "unattended" && k != "ask_first" {
			return "", "", fmt.Errorf("screen approval payload carries an unknown member %q", cleanText(k, 40))
		}
	}
	var p response.ScreenSessionPayload
	if err := decodeJSON(payload, &p); err != nil {
		return "", "", errors.New("screen approval payload must name the mode")
	}
	if _, has := top["unattended"]; has && !p.Unattended {
		return "", "", errors.New(`a screen approval carries "unattended" only as true`)
	}
	if _, has := top["ask_first"]; has && !p.AskFirst {
		return "", "", errors.New(`a screen approval carries "ask_first" only as true`)
	}
	// One byte form per meaning, the one the agent rebuilds and digests:
	// keys in the order mode, unattended, ask_first, no spaces, false
	// members left out. (Not the sorted canonical form other kinds use.)
	if want, err := json.Marshal(p); err != nil || !bytes.Equal(want, payload) {
		return "", "", errors.New(`a screen approval payload is exactly {"mode":...} then "unattended":true and "ask_first":true when set, in that order`)
	}
	// The payload is what the agent enforces, so its ask_first is what the
	// owner is told about.
	askFirst = askFirst || p.AskFirst
	if len(targets) != 1 {
		return "", "", errors.New("a screen approval covers exactly one endpoint")
	}
	if seconds < 0 || seconds > maxTerminalSessionSeconds {
		return "", "", errors.New("a screen session runs at most 24 hours")
	}
	length := ""
	if seconds > 0 {
		length = ", up to " + spanText(seconds)
	}
	// An agent holding the hub's admin key (ominullctl) is named as one, so
	// the owner always knows who will be at the controls.
	agent := strings.HasSuffix(requester, "(api-key)")
	who := ""
	if agent {
		claim := AgentClaim(label)
		who = strings.ToUpper(claim[:1]) + claim[1:] + " (admin key)"
	}
	var action, summary string
	switch {
	case p.Mode == response.ScreenModeControl && agent:
		action = "Control screen"
		summary = fmt.Sprintf("%s will see and control the screen on %s%s", who, targets[0], length)
	case p.Mode == response.ScreenModeView && agent:
		action = "Watch screen"
		summary = fmt.Sprintf("%s will see the screen on %s%s", who, targets[0], length)
	case p.Mode == response.ScreenModeControl:
		action = "Control screen"
		summary = fmt.Sprintf("See and control the screen on %s%s, for %s", targets[0], length, requester)
	case p.Mode == response.ScreenModeView:
		action = "Watch screen"
		summary = fmt.Sprintf("Watch the screen on %s (no control)%s, for %s", targets[0], length, requester)
	default:
		return "", "", errors.New(`a screen approval's mode is "control" or "view"`)
	}
	if askFirst {
		summary += "; the person at the keyboard is asked to allow it first"
	} else {
		summary += "; it opens without asking the person at the keyboard"
	}
	if p.Unattended {
		summary += "; if nobody is signed in to allow it, it opens anyway with nobody at the keyboard"
	}
	return action, summary, nil
}

// spanText reads a length of time the way the owner says it: "4 hours",
// "1 hour 30 minutes", "45 minutes".
func spanText(seconds int64) string {
	h, m := seconds/3600, (seconds%3600+59)/60
	if m == 60 {
		h, m = h+1, 0
	}
	unit := func(n int64, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.FormatInt(n, 10) + " " + many
	}
	switch {
	case h > 0 && m > 0:
		return unit(h, "hour", "hours") + " " + unit(m, "minute", "minutes")
	case h > 0:
		return unit(h, "hour", "hours")
	}
	return unit(m, "minute", "minutes")
}

// describeApproval derives the action and summary the owner sees from the
// digested payload. targets is the sorted, de-duplicated target list.
func describeApproval(kind response.ActionKind, payload []byte, targets []string, requester string) (string, string, error) {
	if kind == response.ActionKindTerminalSession {
		return describeTerminal(payload, targets, requester, 0, "")
	}
	if kind == response.ActionKindScreenSession {
		return describeScreen(payload, targets, requester, 0, false, "")
	}

	if kind == response.ActionKindScriptExec {
		return describePackageRun(payload, targets)
	}

	var p routedPayload
	var top map[string]json.RawMessage
	if err := decodeJSON(payload, &top); err != nil {
		return "", "", errors.New("approval payload must carry route, body and targets")
	}
	for k := range top {
		if !routedPayloadKeys[k] {
			return "", "", fmt.Errorf("approval payload carries an unknown member %q", cleanText(k, 40))
		}
	}
	if err := decodeJSON(payload, &p); err != nil {
		return "", "", errors.New("approval payload must carry route, body and targets")
	}
	isolating := p.Route == "/api/v1/endpoints/isolate" || p.Route == "/api/v1/endpoints/isolate-bulk"
	if _, has := top["baselines"]; has && !isolating {
		return "", "", errors.New("only an isolation carries exceptions")
	}
	spec, ok := approvalRoutes[p.Route]
	if !ok {
		return "", "", fmt.Errorf("route %q is not a signed action", cleanText(p.Route, 80))
	}
	if spec.kind != kind {
		return "", "", fmt.Errorf("route %s does not match kind %s", p.Route, kind)
	}
	if strings.Join(sortedUnique(p.Targets), "\x00") != strings.Join(targets, "\x00") {
		return "", "", errors.New("payload targets differ from the approval's targets")
	}
	if len(p.Body) == 0 {
		p.Body = json.RawMessage("{}")
	}
	n := len(targets)
	list := listTargets(targets)

	switch p.Route {
	case "/api/v1/endpoints/isolate", "/api/v1/endpoints/isolate-bulk":
		var b struct {
			EndpointID string   `json:"endpoint_id"`
			AllowIPs   []string `json:"allow_ips"`
			Force      bool     `json:"force"`
		}
		if err := decodeJSON(p.Body, &b); err != nil {
			return "", "", errors.New("isolation body unreadable")
		}
		if p.Route == "/api/v1/endpoints/isolate" && (n != 1 || b.EndpointID != targets[0]) {
			return "", "", errors.New("isolation body names a different endpoint")
		}
		s := fmt.Sprintf("Cut %d host(s) off the network: %s", n, list)
		if len(b.AllowIPs) > 0 {
			ips := make([]string, 0, len(b.AllowIPs))
			for _, ip := range b.AllowIPs {
				ips = append(ips, cleanText(ip, 64))
			}
			s += " (still allowed: " + strings.Join(ips, ", ") + ")"
		}
		ex, err := checkBaselines(p.Baselines, targets)
		if err != nil {
			return "", "", err
		}
		s += ex
		if b.Force {
			s += " (readiness gate overridden)"
		}
		return spec.action, s, nil
	case "/api/v1/endpoints/unisolate", "/api/v1/endpoints/unisolate-bulk":
		var b struct {
			EndpointID string `json:"endpoint_id"`
		}
		if err := decodeJSON(p.Body, &b); err != nil {
			return "", "", errors.New("release body unreadable")
		}
		if p.Route == "/api/v1/endpoints/unisolate" && (n != 1 || b.EndpointID != targets[0]) {
			return "", "", errors.New("release body names a different endpoint")
		}
		return spec.action, fmt.Sprintf("Return %d host(s) to the network: %s", n, list), nil
	case "/api/v1/endpoints/allow-isolation":
		var b struct {
			EndpointID string `json:"endpoint_id"`
			Reason     string `json:"reason"`
			Revision   *int64 `json:"revision"`
		}
		if err := decodeJSON(p.Body, &b); err != nil || n != 1 || b.EndpointID != targets[0] || b.Revision == nil {
			return "", "", errors.New("allow-isolation body names a different endpoint or no revision")
		}
		return spec.action, fmt.Sprintf("Lift monitor-only (setting %d) on %s: it may be isolated at host level again (reason given: %s)",
			*b.Revision, targets[0], cleanText(b.Reason, 120)), nil
	case "/api/v1/agents/update":
		var b struct {
			Version string   `json:"version"`
			All     bool     `json:"all"`
			Canary  []string `json:"canary"`
		}
		if err := decodeJSON(p.Body, &b); err != nil || strings.TrimSpace(b.Version) == "" {
			return "", "", errors.New("agent update body must name the version")
		}
		s := fmt.Sprintf("Install agent %s on %d host(s): %s", cleanText(b.Version, 40), n, list)
		if b.All {
			s += " (and make it the fleet's desired version)"
		}
		// A staged rollout: the hub installs on the canaries first and holds
		// the rest until they run the version healthily, else halts.
		if len(b.Canary) > 0 {
			inTargets := map[string]bool{}
			for _, t := range targets {
				inTargets[t] = true
			}
			for _, c := range b.Canary {
				if !inTargets[c] {
					return "", "", errors.New("agent update canary is not one of its targets")
				}
			}
			s += fmt.Sprintf(". Staged: %s first; the other %d only once the canaries run it healthily, otherwise the rollout halts",
				strings.Join(b.Canary, ", "), n-len(b.Canary))
		}
		return spec.action, s, nil
	case "/api/v1/endpoints/capabilities":
		var b capabilityPayload
		if err := decodeJSON(p.Body, &b); err != nil || n != 1 || b.EndpointID != targets[0] {
			return "", "", errors.New("capability body names a different endpoint")
		}
		caps, ok := response.ProfileCaps(b.Profile)
		if !ok {
			return "", "", fmt.Errorf("unknown profile %q", cleanText(b.Profile, 24))
		}
		s := fmt.Sprintf("Set %s to profile %s (accepts: %s)", targets[0], b.Profile, strings.Join(caps, ", "))
		if r := cleanText(b.Reason, 120); r != "" {
			s += " (reason given: " + r + ")"
		}
		return spec.action, s, nil
	default: // mesh
		var b struct {
			TargetIP string `json:"target_ip"`
			Reason   string `json:"reason"`
		}
		if err := decodeJSON(p.Body, &b); err != nil {
			return "", "", errors.New("mesh body unreadable")
		}
		ip := net.ParseIP(strings.TrimSpace(b.TargetIP))
		if ip == nil || n != 1 || targets[0] != "mesh:"+ip.String() {
			return "", "", errors.New("mesh body and target disagree on the address")
		}
		if spec.action == "Quarantine address" {
			s := "Every agent drops traffic to and from " + ip.String()
			if r := cleanText(b.Reason, 120); r != "" {
				s += " (reason given: " + r + ")"
			}
			return spec.action, s, nil
		}
		return spec.action, "Agents stop dropping traffic for " + ip.String(), nil
	}
}

// policyLabels are the fields that name or explain a policy entry.
var policyLabels = map[string]bool{"name": true, "reason": true}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// policyDiff lists each top-level field that differs, of those keep accepts:
// a list as the entries it gains and loses, anything else as old -> new.
func policyDiff(before, after map[string]interface{}, keep func(string) bool) []string {
	union := map[string]interface{}{}
	for k, v := range before {
		union[k] = v
	}
	for k, v := range after {
		union[k] = v
	}
	var parts []string
	for _, k := range sortedKeys(union) {
		a, b := before[k], after[k]
		if !keep(k) || policyJSON(a) == policyJSON(b) {
			continue
		}
		la, aList := a.([]interface{})
		lb, bList := b.([]interface{})
		if (aList || a == nil) && (bList || b == nil) {
			had, has := map[string]bool{}, map[string]bool{}
			for _, x := range la {
				had[policyJSON(x)] = true
			}
			for _, x := range lb {
				has[policyJSON(x)] = true
			}
			var d []string
			for _, x := range lb {
				if !had[policyJSON(x)] {
					d = append(d, "+"+policyValue(x))
				}
			}
			for _, x := range la {
				if !has[policyJSON(x)] {
					d = append(d, "-"+policyValue(x))
				}
			}
			parts = append(parts, k+" "+strings.Join(d, " "))
			continue
		}
		parts = append(parts, k+" "+policyValue(a)+" -> "+policyValue(b))
	}
	return parts
}

func policyJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// policyValue renders one value the way the owner reads it: a string as
// itself, an object as its fields.
func policyValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "none"
	case string:
		if t == "" {
			return "\"\""
		}
		return t
	case map[string]interface{}:
		// What an entry matches first, its labels last.
		fields, named := []string{}, []string{}
		for _, k := range sortedKeys(t) {
			if policyLabels[k] {
				named = append(named, k+"="+policyValue(t[k]))
			} else {
				fields = append(fields, k+"="+policyValue(t[k]))
			}
		}
		fields = append(fields, named...)
		return "{" + strings.Join(fields, " ") + "}"
	case []interface{}:
		items := make([]string, 0, len(t))
		for _, x := range t {
			items = append(items, policyValue(x))
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
	return policyJSON(v)
}

// fitLead puts the drill's verdict ahead of the change: in full when the
// change leaves room for it, else in its short form; the change itself must
// still fit in full beside the short form.
func fitLead(lead, short string, parts, labels []string) (string, error) {
	if lead == "" {
		return fitParts(parts, labels)
	}
	joined := 0
	for i, p := range parts {
		if i > 0 {
			joined += 2
		}
		joined += len([]rune(cleanText(p, approvalMaxSummary+1)))
	}
	if joined+2+len([]rune(lead)) > approvalMaxSummary {
		lead = short
	}
	return fitParts(append([]string{lead}, parts...), labels)
}

// fitParts joins every change inside the summary cap; what does not fit is cut
// to an ellipsis (the payload, not the summary, is what the grant is bound
// to). Labels (a name, a reason) follow in whatever room is left, shortened if
// they must be: they explain the change and match nothing.
func fitParts(parts, labels []string) (string, error) {
	out := ""
	for _, p := range parts {
		if out != "" {
			out += "; "
		}
		out += cleanText(p, approvalMaxSummary+1)
	}
	if n := len([]rune(out)); n > approvalMaxSummary {
		return string([]rune(out)[:approvalMaxSummary-1]) + "…", nil
	}
	for _, l := range labels {
		l = cleanText(l, approvalMaxSummary)
		sep := ""
		if out != "" {
			sep = "; "
		}
		room := approvalMaxSummary - len([]rune(out)) - len(sep)
		if room < 16 {
			if room >= 1 {
				out += sep + "…"
			}
			break
		}
		if len([]rune(l)) > room {
			l = string([]rune(l)[:room-1]) + "…"
		}
		out += sep + l
	}
	return out, nil
}

// terminalLimitFields are the remote shell limits in the order the owner reads
// them: the largest sane value, how a value is said, and the phrase around it.
var terminalLimitFields = []struct {
	key    string
	max    float64
	value  func(v float64) string
	phrase string
}{
	{"max_duration_seconds", maxTerminalSessionSeconds, func(v float64) string { return spanText(int64(v)) }, "sessions run up to %s"},
	{"idle_timeout_seconds", maxTerminalSessionSeconds, func(v float64) string { return spanText(int64(v)) }, "idle sessions end after %s"},
	{"max_per_endpoint", 100, func(v float64) string { return strconv.Itoa(int(v)) }, "%s open per endpoint"},
	{"max_per_tenant", 1000, func(v float64) string { return strconv.Itoa(int(v)) }, "%s open in all"},
}

// TerminalLimitsWording says what a change to the remote shell limits does,
// one part per changed limit: "Remote shell: sessions run up to 4 hours (was
// 1 hour)". The hub uses it for its audit row.
func TerminalLimitsWording(before, after map[string]interface{}) (string, error) {
	for _, m := range []map[string]interface{}{before, after} {
		if len(m) != len(terminalLimitFields) {
			return "", errors.New("remote shell limits carry exactly the four limits")
		}
	}
	var parts []string
	for _, f := range terminalLimitFields {
		b, okB := before[f.key].(float64)
		a, okA := after[f.key].(float64)
		if !okA || !okB || a < 1 || b < 1 || a > f.max || b > f.max || a != float64(int64(a)) || b != float64(int64(b)) {
			return "", fmt.Errorf("remote shell limit %s must be a whole number from 1 to %d", f.key, int64(f.max))
		}
		if a != b {
			parts = append(parts, fmt.Sprintf(f.phrase, f.value(a))+" (was "+f.value(b)+")")
		}
	}
	if len(parts) == 0 {
		return "", errors.New("this remote shell limits change changes nothing")
	}
	return "Remote shell: " + strings.Join(parts, "; "), nil
}

// SoftwareCatalogWording is the owner's statement for a catalog entry added
// or changed: the whole entry as the removal package will read it, and for a
// change what differs. The entry must be valid, so nothing the hub sends can
// widen it past the catalog rules. The hub uses it for its audit row.
func SoftwareCatalogWording(target string, before, after map[string]interface{}) (string, error) {
	entry := func(m map[string]interface{}) (*scripts.CatalogEntry, error) {
		raw, _ := json.Marshal(m)
		var e scripts.CatalogEntry
		if err := decodeJSON(raw, &e); err != nil {
			return nil, errors.New("a catalog entry carries only the catalog fields")
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		return &e, nil
	}
	a, err := entry(after)
	if err != nil {
		return "", err
	}
	if target != "catalog:"+a.ID {
		return "", errors.New("a catalog change targets catalog:<id> of the entry it saves")
	}
	if before == nil {
		return fitParts([]string{"Software removal catalog: add " + a.Describe()}, nil)
	}
	b, err := entry(before)
	if err != nil {
		return "", err
	}
	if b.ID != a.ID {
		return "", errors.New("a catalog change keeps the entry's id")
	}
	parts := policyDiff(before, after, func(k string) bool { return k != "note" && k != "name" })
	if len(parts) == 0 {
		return "", errors.New("this catalog change changes nothing the removal package reads")
	}
	return fitParts(append([]string{"Software removal catalog: " + a.Describe()}, parts...), nil)
}

// ScreenAskFirstWording says what a change to the screen ask-first setting
// does. before and after are {"scope", "ask_first"} plus an optional "host"
// label: scope "fleet" (target screen:ask_first) is the default for machines
// without their own setting, any other scope is one endpoint (target
// screen:ask_first:<id>). The hub uses it for its audit row.
func ScreenAskFirstWording(target string, before, after map[string]interface{}) (string, error) {
	var scope string
	var vals [2]bool
	for i, m := range []map[string]interface{}{before, after} {
		if m == nil {
			return "", errors.New("a screen ask-first change carries the setting before and after")
		}
		for k := range m {
			if k != "scope" && k != "ask_first" && k != "host" {
				return "", fmt.Errorf("a screen ask-first setting carries an unknown member %q", cleanText(k, 40))
			}
		}
		sc, _ := m["scope"].(string)
		v, ok := m["ask_first"].(bool)
		if sc == "" || !ok || (i == 1 && sc != scope) {
			return "", errors.New("a screen ask-first setting names one scope and ask_first true or false")
		}
		scope, vals[i] = sc, v
	}
	where := "every machine without its own setting"
	want := "screen:ask_first"
	if scope != "fleet" {
		want += ":" + scope
		where = "endpoint " + cleanText(scope, 64)
		if host, _ := after["host"].(string); host != "" && host != scope {
			where += " (" + cleanText(host, 64) + ")"
		}
	}
	if target != want {
		return "", fmt.Errorf("a screen ask-first change for %s targets %s", cleanText(scope, 64), want)
	}
	if vals[0] == vals[1] {
		return "", errors.New("this screen ask-first change changes nothing")
	}
	if vals[1] {
		return "Screen sessions on " + where + " ask the person at the keyboard to allow them first (was: opened without asking)", nil
	}
	return "Screen sessions on " + where + " open without asking the person at the keyboard first (was: asked first)", nil
}

// RemoteAccessWording says what a change to a machine's remote access
// setting does. before and after are {"endpoint", "off"} plus an optional
// "host" label; the target is remote_access:<endpoint>. The hub uses it for
// its audit row; the hub for the owner.
func RemoteAccessWording(target string, before, after map[string]interface{}) (string, error) {
	var ep string
	var vals [2]bool
	for i, m := range []map[string]interface{}{before, after} {
		if m == nil {
			return "", errors.New("a remote access change carries the setting before and after")
		}
		for k := range m {
			if k != "endpoint" && k != "off" && k != "host" {
				return "", fmt.Errorf("a remote access setting carries an unknown member %q", cleanText(k, 40))
			}
		}
		e, _ := m["endpoint"].(string)
		v, ok := m["off"].(bool)
		if e == "" || !ok || (i == 1 && e != ep) {
			return "", errors.New("a remote access setting names one endpoint and off true or false")
		}
		ep, vals[i] = e, v
	}
	if target != "remote_access:"+ep {
		return "", fmt.Errorf("a remote access change for %s targets remote_access:%s", cleanText(ep, 64), cleanText(ep, 64))
	}
	if vals[0] == vals[1] {
		return "", errors.New("this remote access change changes nothing")
	}
	where := "endpoint " + cleanText(ep, 64)
	if host, _ := after["host"].(string); host != "" && host != ep {
		where += " (" + cleanText(host, 64) + ")"
	}
	if vals[1] {
		return "Remote terminal and screen switched off on " + where + ", for everyone (was: allowed with approval)", nil
	}
	return "Remote terminal and screen allowed again on " + where + ", each session still with approval (was: switched off)", nil
}
