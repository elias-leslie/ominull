package responseauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"ominull/hub/pkg/response"
)

// The owner approves what the authority says, not what the hub says. The hub
// sends a typed payload (the route it will run, the canonical body and the
// targets, or the terminal's own action payload); the authority works out the
// action name and the summary from that payload alone, so a compromised hub
// cannot show "Release isolation" over a payload that isolates. The hub's own
// action and summary text are ignored.

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

// describeApproval derives the action and summary the owner sees from the
// digested payload. targets is the sorted, de-duplicated target list.
func describeApproval(kind response.ActionKind, payload []byte, targets []string, requester string) (string, string, error) {
	if kind == response.ActionKindTerminalSession {
		var p response.TerminalSessionPayload
		if err := decodeJSON(payload, &p); err != nil || strings.TrimSpace(p.Program) == "" {
			return "", "", errors.New("terminal approval payload must name the program")
		}
		if len(targets) != 1 {
			return "", "", errors.New("a terminal approval covers exactly one endpoint")
		}
		return "Open terminal", fmt.Sprintf("Interactive %s on %s, recorded, for %s",
			cleanText(p.Program, 120), targets[0], requester), nil
	}

	if kind == ActionKindDetection {
		return describeDetectionPolicy(payload, targets)
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
		return "", "", fmt.Errorf("route %q is not an owner-approved action", cleanText(p.Route, 80))
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

// detectionPolicyPayload is a loosening of the hub's detection policy: the
// policy as it is saved now and as the change would save it. The digest binds
// both, so a change approved against one saved policy cannot be spent once
// that policy has changed.
type detectionPolicyPayload struct {
	Policy string          `json:"policy"`
	Op     string          `json:"op"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
	// Drill, when present, is the hub's floor drill run against the policy
	// the change would save: the floor cases it would blind.
	Drill *[]string `json:"drill"`
}

var detectionPolicyKeys = map[string]bool{"policy": true, "op": true, "before": true, "after": true, "drill": true}

// drillPart is the floor drill's verdict as the first part of the owner's
// statement, short enough to leave the change itself room: the first two
// cases it would blind, then how many more.
func drillPart(drill *[]string) []string {
	if drill == nil {
		return nil
	}
	cases := *drill
	if len(cases) == 0 {
		return []string{"floor drill: blinds no floor rule"}
	}
	const show = 2
	names := make([]string, 0, show)
	for i, c := range cases {
		if i == show {
			break
		}
		names = append(names, cleanText(c, 48))
	}
	part := fmt.Sprintf("BLINDS %d FLOOR CASE", len(cases))
	if len(cases) != 1 {
		part += "S"
	}
	part += ": " + strings.Join(names, ", ")
	if len(cases) > show {
		part += fmt.Sprintf(" and %d more", len(cases)-show)
	}
	return []string{part}
}

// detectionPolicyOps names each change the hub can ask for, by policy.
var detectionPolicyOps = map[string]map[string]string{
	"detection_tuning": {
		"save":          "Loosen detection tuning",
		"reset":         "Restore shipped detection tuning",
		"suppress_pair": "Mark a conversation expected",
		"learning":      "Apply learning proposals",
	},
	"exclusion": {
		"create": "Add a detection exclusion",
		"enable": "Turn a detection exclusion on",
	},
	// The silence floor itself cannot be switched off, but each host's
	// presence decides when its going quiet is reported, and a retired host
	// is not watched at all.
	"endpoint_watch": {
		"presence": "Expect a host to go quiet",
		"retire":   "Retire a host",
	},
	// A learning window holds the behavioural findings of every host it
	// covers until it ends. Closing one only tightens and asks nobody.
	"learning_window": {
		"open": "Open a learning window",
	},
}

// describeDetectionPolicy shows the owner the change field by field, worked
// out from the before and after the digest covers.
func describeDetectionPolicy(payload []byte, targets []string) (string, string, error) {
	var top map[string]json.RawMessage
	if err := decodeJSON(payload, &top); err != nil {
		return "", "", errors.New("detection policy payload must carry policy, op, before and after")
	}
	for k := range top {
		if !detectionPolicyKeys[k] {
			return "", "", fmt.Errorf("detection policy payload carries an unknown member %q", cleanText(k, 40))
		}
	}
	var p detectionPolicyPayload
	if err := decodeJSON(payload, &p); err != nil {
		return "", "", errors.New("detection policy payload must carry policy, op, before and after")
	}
	action, ok := detectionPolicyOps[p.Policy][p.Op]
	if !ok {
		return "", "", fmt.Errorf("%q %q is not a detection policy change", cleanText(p.Policy, 40), cleanText(p.Op, 40))
	}
	if p.Drill != nil && len(*p.Drill) > 256 {
		return "", "", errors.New("detection policy drill lists more cases than a drill runs")
	}
	drill := drillPart(p.Drill)
	var before, after map[string]interface{}
	if err := decodeJSON(p.After, &after); err != nil || after == nil {
		return "", "", errors.New("detection policy payload must carry the policy after the change")
	}
	if b := bytes.TrimSpace(p.Before); len(b) > 0 && string(b) != "null" {
		if err := decodeJSON(b, &before); err != nil || before == nil {
			return "", "", errors.New("detection policy before must be an object or null")
		}
	}
	if len(targets) != 1 {
		return "", "", errors.New("a detection policy change names exactly one target")
	}
	if p.Policy == "detection_tuning" {
		if targets[0] != "detection:tuning" || before == nil {
			return "", "", errors.New("a tuning change targets detection:tuning and carries the saved tuning")
		}
		parts := policyDiff(before, after, func(string) bool { return true })
		if len(parts) == 0 {
			return "", "", errors.New("this tuning change changes nothing")
		}
		summary, err := fitParts(append(drill, parts...), nil)
		return action, summary, err
	}
	if p.Policy == "endpoint_watch" {
		// How closely the silence floor watches one host: before is the host
		// as watched now, after as the change would leave it.
		if !strings.HasPrefix(targets[0], "endpoint:") || before == nil || before["endpoint_id"] != targets[0][len("endpoint:"):] || after["endpoint_id"] != before["endpoint_id"] {
			return "", "", errors.New("a watch change targets endpoint:<id> and carries the host as watched now")
		}
		parts := policyDiff(before, after, func(k string) bool { return !policyLabels[k] })
		if len(parts) == 0 {
			return "", "", errors.New("this watch change changes nothing")
		}
		host := "host " + policyValue(after["endpoint_id"])
		if name, _ := after["hostname"].(string); name != "" && name != after["endpoint_id"] {
			host += " (" + name + ")"
		}
		var labels []string
		if reason, _ := after["reason"].(string); reason != "" {
			labels = append(labels, "reason "+reason)
		}
		summary, err := fitParts(append([]string{host}, parts...), labels)
		return action, summary, err
	}
	if p.Policy == "learning_window" {
		return describeLearningWindow(action, before, after, targets[0])
	}
	if !strings.HasPrefix(targets[0], "exclusion:") {
		return "", "", errors.New("an exclusion change targets exclusion:<id>")
	}
	if p.Op == "enable" && before == nil {
		return "", "", errors.New("turning an exclusion on carries the saved exclusion")
	}
	// What the exclusion matches comes first and must fit in full; its name
	// and reason only label it, so they take whatever room is left.
	var parts, labels []string
	shown := map[string]bool{"id": true, "tenant_id": true, "active": true, "created_at": true}
	for _, k := range append([]string{"process_path", "dst_ip_range", "port", "protocol", "scope", "scope_value", "expires_at"}, sortedKeys(after)...) {
		v, present := after[k]
		if shown[k] || !present {
			continue
		}
		shown[k] = true
		if v == nil || v == "" || v == float64(0) {
			continue
		}
		if policyLabels[k] {
			labels = append(labels, k+" "+policyValue(v))
		} else {
			parts = append(parts, k+" "+policyValue(v))
		}
	}
	if before != nil && p.Op == "create" {
		// Saving over an existing exclusion renews or rewrites it.
		parts = append([]string{"rewrites " + targets[0][len("exclusion:"):]}, policyDiff(before, after, func(k string) bool { return !policyLabels[k] })...)
		labels = policyDiff(before, after, func(k string) bool { return policyLabels[k] })
	}
	summary, err := fitParts(append(drill, parts...), labels)
	return action, summary, err
}

// learningWindowHolds is what a learning window holds back, as the hub's
// detector decides it (detector.learningHolds). Threat-intelligence matches,
// sensitive ports, sweeps, resolver bypass and silence keep paging.
const learningWindowHolds = "holds beacon, volume and agent egress findings"

// describeLearningWindow shows a window as the hub would open it: what it
// covers and for how long. It names its scope in the target, so an approval
// for one host cannot open a window over the whole estate.
func describeLearningWindow(action string, before, after map[string]interface{}, target string) (string, string, error) {
	scopeType, _ := after["scope_type"].(string)
	scopeID, _ := after["scope_id"].(string)
	hours, _ := after["hours"].(float64)
	switch {
	case before != nil:
		return "", "", errors.New("opening a learning window carries no saved window")
	case target != "learning:"+scopeType+":"+scopeID:
		return "", "", errors.New("a learning window targets learning:<scope_type>:<scope_id> and names the same scope")
	case scopeType != "tenant" && scopeType != "location" && scopeType != "endpoint":
		return "", "", errors.New("a learning window is scoped to a tenant, a location or an endpoint")
	case scopeType != "tenant" && scopeID == "":
		return "", "", errors.New("a location or endpoint learning window names which one")
	case hours < 1 || hours > 90*24 || hours != float64(int(hours)):
		return "", "", errors.New("a learning window lasts a whole number of hours, at most 90 days")
	}
	scope := scopeType + " " + scopeID
	if scopeType == "tenant" && scopeID == "" {
		scope = "every host in every tenant"
	}
	if label, _ := after["scope_label"].(string); label != "" && label != scopeID && scopeID != "" {
		scope += " (" + label + ")"
	}
	n, unit := int(hours), "hour"
	if n%24 == 0 {
		n, unit = n/24, "day"
	}
	if n != 1 {
		unit += "s"
	}
	length := fmt.Sprintf("for %d %s", n, unit)
	parts := []string{scope + " " + length, learningWindowHolds}
	var labels []string
	for _, k := range sortedKeys(after) {
		switch k {
		case "scope_type", "scope_id", "scope_label", "hours":
		case "note":
			if v, _ := after[k].(string); v != "" {
				labels = append(labels, "note "+v)
			}
		default:
			if v := after[k]; v != nil && v != "" {
				parts = append(parts, k+" "+policyValue(v))
			}
		}
	}
	summary, err := fitParts(parts, labels)
	return action, summary, err
}

// policyLabels are the fields that name or explain a policy entry without
// changing what it matches.
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

// ErrApprovalTooLong refuses a detection-policy change whose changes do not
// all fit the owner's statement: the owner's tap is the only human check, so
// nothing the change does may be cut to "and N more".
var ErrApprovalTooLong = errors.New("this change is too large to show the owner in full")

// fitParts joins every change in full inside the statement's summary cap, or
// refuses. Labels (a name, a reason) follow in whatever room is left,
// shortened if they must be: they explain the change and match nothing.
func fitParts(parts, labels []string) (string, error) {
	out := ""
	for _, p := range parts {
		if out != "" {
			out += "; "
		}
		out += cleanText(p, approvalMaxSummary+1)
	}
	if n := len([]rune(out)); n > approvalMaxSummary {
		return "", fmt.Errorf("%w (%d characters, at most %d fit): make it as several smaller changes", ErrApprovalTooLong, n, approvalMaxSummary)
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
