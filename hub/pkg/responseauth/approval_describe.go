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
}

var detectionPolicyKeys = map[string]bool{"policy": true, "op": true, "before": true, "after": true}

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
		parts := policyDiff(before, after)
		if len(parts) == 0 {
			return "", "", errors.New("this tuning change changes nothing")
		}
		return action, fitParts(parts), nil
	}
	if !strings.HasPrefix(targets[0], "exclusion:") {
		return "", "", errors.New("an exclusion change targets exclusion:<id>")
	}
	if p.Op == "enable" && before == nil {
		return "", "", errors.New("turning an exclusion on carries the saved exclusion")
	}
	var parts []string
	shown := map[string]bool{"id": true, "tenant_id": true, "active": true, "created_at": true}
	for _, k := range append([]string{"name", "process_path", "dst_ip_range", "port", "protocol", "scope", "scope_value", "expires_at", "reason"}, sortedKeys(after)...) {
		v, present := after[k]
		if shown[k] || !present {
			continue
		}
		shown[k] = true
		if v == nil || v == "" || v == float64(0) {
			continue
		}
		parts = append(parts, k+" "+policyValue(v))
	}
	if before != nil && p.Op == "create" {
		// Saving over an existing exclusion renews or rewrites it.
		parts = append([]string{"rewrites " + targets[0][len("exclusion:"):]}, policyDiff(before, after)...)
	}
	return action, fitParts(parts), nil
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// policyDiff lists each top-level field that differs: a list as the entries
// it gains and loses, anything else as old -> new.
func policyDiff(before, after map[string]interface{}) []string {
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
		if policyJSON(a) == policyJSON(b) {
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
		fields := []string{}
		for _, k := range sortedKeys(t) {
			fields = append(fields, k+"="+policyValue(t[k]))
		}
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

// fitParts joins the changes inside the statement's summary cap, saying how
// many did not fit rather than dropping them silently.
func fitParts(parts []string) string {
	const partMax = 140
	out := ""
	for i, p := range parts {
		p = cleanText(p, partMax)
		next := out
		if next != "" {
			next += "; "
		}
		next += p
		rest := len(parts) - i - 1
		room := approvalMaxSummary
		if rest > 0 {
			room -= len(fmt.Sprintf("; and %d more", rest))
		}
		if len([]rune(next)) > room {
			return out + fmt.Sprintf("; and %d more", len(parts)-i)
		}
		out = next
	}
	return out
}
