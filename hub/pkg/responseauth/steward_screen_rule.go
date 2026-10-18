package responseauth

// Steward remote screen: the owner's standing "yes" for Nightshift's steward
// to take the screen on one machine when a maintenance run there is stuck.
//
// Nightshift keeps the rule (its Approvals page is the one approval-rule
// store); this authority keeps none. It signs and enforces:
//
//   - Raising: the hub asks with a screen_session request carrying
//     StewardRule. The payload is the screen payload the steward's sessions
//     will carry (mode, and ask_first when the person at the keyboard is
//     asked), the one target is the machine, and StewardRule holds the
//     longest session and whether sessions are held to the maintenance
//     window. The owner reads all of it and taps once. The approval then
//     carries a rule token (ApprovalView.StewardRule): this authority's
//     ed25519 signature, under the tenant response key, over exactly what
//     the owner approved, valid stewardRuleLife. Nightshift stores it. The
//     tap signs no endpoint grant.
//   - Narrowing: Nightshift keeps its own narrowing beside the token (view
//     under control, a shorter session, asking the person at the keyboard,
//     holding sessions to the window). The steward sends it with the token
//     and it is applied as a floor: it can only narrow. Turning a rule off
//     is Nightshift dropping the token. Neither needs a tap.
//   - Using: a screen request is approved here without asking only when it
//     carries a token this authority signed, unexpired, for its one target,
//     the requester is the steward (the hub names a steward-key request
//     "... (steward-key)"; an admin-key agent is "(api-key)" and never
//     matches), it names the stuck run it is for (StewardRun), and its mode,
//     length and ask-first fit the narrowed rule; never unattended.
//   - Only Windows machines whose signed capability profile holds the
//     screen take a steward rule, when it is raised and when it is used. The
//     owner's own infrastructure (the Linux workstation and hypervisor)
//     never does.
//
// What the authority cannot see, the hub holds: that the run really is
// waiting on a dialog or stalled on that machine, and that the window is
// open when the rule says so. Against a hostile hub or Nightshift the bound
// is the token: that machine, that mode, that length, the person at the
// keyboard asked when the owner said so, the agent's banner shown, every
// session audited here and on the hub, and the token's expiry.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/response"
)

const (
	stewardRequesterSuffix = "(steward-key)"
	stewardRulePrefix      = "OMINULL-STEWARD-SCREEN-RULE-V1\n"
	stewardRuleLife        = 90 * 24 * time.Hour
	// StewardScreenMaxSeconds is the longest session a rule may allow.
	StewardScreenMaxSeconds = 4 * 60 * 60
	stewardScreenMinSeconds = 5 * 60
	stewardRunMax           = 80
)

// StewardScreenAsk raises a machine's "Steward remote screen" setting.
type StewardScreenAsk struct {
	MaxSeconds   int64 `json:"max_seconds"`
	OnlyInWindow bool  `json:"only_in_window,omitempty"`
}

// StewardScreenRule is what the owner approved, as the token states it.
type StewardScreenRule struct {
	V            int    `json:"v"`
	TenantID     string `json:"tenant_id"`
	EndpointID   string `json:"endpoint_id"`
	Mode         string `json:"mode"` // view | control
	MaxSeconds   int64  `json:"max_seconds"`
	AskFirst     bool   `json:"ask_first"`
	OnlyInWindow bool   `json:"only_in_window"`
	ApprovalID   string `json:"approval_id"`
	ApproverID   string `json:"approver_id"`
	Created      int64  `json:"created"`
	Expires      int64  `json:"expires"`
}

// StewardScreenNarrow is Nightshift's narrowing of a rule; zero/nil fields
// leave the rule as it is, and nothing here can widen it.
type StewardScreenNarrow struct {
	Mode         string `json:"mode,omitempty"`
	MaxSeconds   int64  `json:"max_seconds,omitempty"`
	AskFirst     bool   `json:"ask_first,omitempty"`
	OnlyInWindow bool   `json:"only_in_window,omitempty"`
}

// IsStewardRequester says whether the hub named this requester as the steward.
func IsStewardRequester(requester string) bool {
	return strings.HasSuffix(requester, stewardRequesterSuffix)
}

func screenModeRank(m string) int {
	switch m {
	case response.ScreenModeView:
		return 1
	case response.ScreenModeControl:
		return 2
	}
	return 0
}

// Narrowed is the rule after Nightshift's narrowing.
func (r StewardScreenRule) Narrowed(n *StewardScreenNarrow) StewardScreenRule {
	if n == nil {
		return r
	}
	if screenModeRank(n.Mode) > 0 && screenModeRank(n.Mode) < screenModeRank(r.Mode) {
		r.Mode = n.Mode
	}
	if n.MaxSeconds > 0 && n.MaxSeconds < r.MaxSeconds {
		r.MaxSeconds = n.MaxSeconds
	}
	r.AskFirst = r.AskFirst || n.AskFirst
	r.OnlyInWindow = r.OnlyInWindow || n.OnlyInWindow
	return r
}

// covers: the rule allows this steward session.
func (r StewardScreenRule) covers(endpoint string, p response.ScreenSessionPayload, askFirst bool, seconds int64, now time.Time) bool {
	return now.Unix() < r.Expires && r.EndpointID == endpoint &&
		screenModeRank(p.Mode) > 0 && screenModeRank(p.Mode) <= screenModeRank(r.Mode) &&
		!p.Unattended && (askFirst || !r.AskFirst) && seconds > 0 && seconds <= r.MaxSeconds
}

// ReadStewardRuleToken reads a token's statement without checking its
// signature (the hub uses it to hold the window; only the authority's check
// approves anything).
func ReadStewardRuleToken(token string) (StewardScreenRule, error) {
	var r StewardScreenRule
	stmt, _, ok := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(stmt)
	if !ok || err != nil || json.Unmarshal(raw, &r) != nil || r.V != 1 {
		return StewardScreenRule{}, errors.New("not a steward screen rule token")
	}
	return r, nil
}

func (a *Authority) signStewardRule(r StewardScreenRule) (string, error) {
	priv, _, err := a.tenantSigningKey(r.TenantID)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, append([]byte(stewardRulePrefix), raw...))
	return base64.RawURLEncoding.EncodeToString(raw) + "." + hex.EncodeToString(sig), nil
}

// verifyStewardRule checks a token is this authority's, for this tenant,
// unexpired.
func (a *Authority) verifyStewardRule(tenantID, token string, now time.Time) (StewardScreenRule, error) {
	stmt, sigHex, ok := strings.Cut(token, ".")
	raw, err1 := base64.RawURLEncoding.DecodeString(stmt)
	sig, err2 := hex.DecodeString(sigHex)
	if !ok || err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return StewardScreenRule{}, errors.New("not a steward screen rule token")
	}
	priv, _, err := a.tenantSigningKey(tenantID)
	if err != nil {
		return StewardScreenRule{}, err
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), append([]byte(stewardRulePrefix), raw...), sig) {
		return StewardScreenRule{}, errors.New("the steward screen rule token was not signed by this authority")
	}
	var r StewardScreenRule
	if err := json.Unmarshal(raw, &r); err != nil || r.V != 1 || r.TenantID != tenantID {
		return StewardScreenRule{}, errors.New("the steward screen rule token is for another tenant")
	}
	if now.Unix() >= r.Expires {
		return StewardScreenRule{}, errors.New("the steward screen rule has expired; the owner raises it again")
	}
	return r, nil
}

// stewardProfileRefusal says why a machine cannot take a steward rule, or
// "": only a Windows machine (the remote screen exists only there; the hub
// names endpoints by platform at enrolment) whose signed capability profile
// holds the screen. The owner's own infrastructure, the Linux workstation and
// hypervisor, never qualifies.
func (a *Authority) stewardProfileRefusal(tenantID, endpointID string) string {
	if !strings.HasPrefix(endpointID, "windows-") {
		return "the steward is allowed only on Windows machines (where the remote screen runs); the owner's own Linux infrastructure never takes a steward rule"
	}
	a.manifests.mu.Lock()
	m := a.manifests.items[tenantID+"\x00"+endpointID]
	a.manifests.mu.Unlock()
	if m == nil {
		return "this machine has no signed capability profile yet, so the steward cannot be allowed on its screen"
	}
	if !slices.Contains(m.Caps, response.CapScreen) {
		return fmt.Sprintf("this machine's capability profile (%s) does not include the remote screen", m.Profile)
	}
	return ""
}

// stewardScreenAskCheck validates a StewardRule request and reads its
// screen payload.
func (a *Authority) stewardScreenAskCheck(in *ApprovalRequestInput, targets []string) (response.ScreenSessionPayload, error) {
	var p response.ScreenSessionPayload
	if in.Kind != response.ActionKindScreenSession {
		return p, errors.New("a steward screen rule is asked for as a screen session")
	}
	if IsStewardRequester(in.Requester) || in.AgentLabel != "" {
		return p, errors.New("the steward cannot ask for its own screen rule; the owner raises it")
	}
	if in.StewardRun != "" || in.StewardRuleToken != "" {
		return p, errors.New("a steward screen rule names no run or token")
	}
	if len(targets) != 1 {
		return p, errors.New("a steward screen rule covers exactly one machine")
	}
	if s := in.StewardRule.MaxSeconds; s < stewardScreenMinSeconds || s > StewardScreenMaxSeconds {
		return p, fmt.Errorf("a steward screen session is allowed %s to %s", spanText(stewardScreenMinSeconds), spanText(StewardScreenMaxSeconds))
	}
	if err := decodeJSON(in.Payload, &p); err != nil {
		return p, errors.New("steward screen rule payload must name the mode")
	}
	if p.Unattended {
		return p, errors.New("the steward never opens a screen with nobody at the keyboard")
	}
	if why := a.stewardProfileRefusal(in.TenantID, targets[0]); why != "" {
		return p, errors.New(why)
	}
	return p, nil
}

// describeStewardScreenAsk is what the owner reads before raising the setting.
func describeStewardScreenAsk(p response.ScreenSessionPayload, askFirst bool, targets []string, ask *StewardScreenAsk) (string, string) {
	what := "see and control the screen"
	if p.Mode == response.ScreenModeView {
		what = "see the screen (no control)"
	}
	summary := fmt.Sprintf("Nightshift's steward may %s on %s without asking you, only to unstick a maintenance run there that is waiting on a dialog or stalled, up to %s each time",
		what, targets[0], spanText(ask.MaxSeconds))
	if ask.OnlyInWindow {
		summary += ", only inside the machine's maintenance window"
	}
	if askFirst {
		summary += "; the person at the keyboard is asked to allow it first"
	} else {
		summary += "; it opens without asking the person at the keyboard"
	}
	summary += ". Every action is recorded; the rule lasts 90 days and can be narrowed or turned off any time in Nightshift"
	return "Let the steward use the screen", summary
}

// stewardScreenMatch reports whether the request's rule token approves this
// steward session, and the narrowed rule it was judged against.
func (a *Authority) stewardScreenMatch(in *ApprovalRequestInput, targets []string, now time.Time) (StewardScreenRule, response.ScreenSessionPayload, bool) {
	var p response.ScreenSessionPayload
	if in.Kind != response.ActionKindScreenSession || in.StewardRule != nil || in.StewardRun == "" || in.StewardRuleToken == "" ||
		!IsStewardRequester(cleanText(in.Requester, 80)) || len(targets) != 1 {
		return StewardScreenRule{}, p, false
	}
	if decodeJSON(in.Payload, &p) != nil {
		return StewardScreenRule{}, p, false
	}
	rule, err := a.verifyStewardRule(in.TenantID, in.StewardRuleToken, now)
	if err != nil {
		a.auditApproval(in.TenantID, in.Requester, "steward_screen_rule_refused", string(in.Kind), targets[0], "", "denied", err.Error())
		return StewardScreenRule{}, p, false
	}
	if why := a.stewardProfileRefusal(in.TenantID, targets[0]); why != "" {
		a.auditApproval(in.TenantID, in.Requester, "steward_screen_rule_refused", string(in.Kind), targets[0], rule.ApprovalID, "denied", why)
		return StewardScreenRule{}, p, false
	}
	rule = rule.Narrowed(in.StewardNarrow)
	return rule, p, rule.covers(targets[0], p, in.AskFirst || p.AskFirst, in.SessionSeconds, now)
}

// mintStewardRule makes the token for an approved steward rule ask.
func (a *Authority) mintStewardRule(v ApprovalView, rec *approvalRecord, approverID string, now time.Time) string {
	var p response.ScreenSessionPayload
	if err := decodeJSON(rec.payload, &p); err != nil || len(v.Targets) != 1 || rec.stewardRule == nil {
		a.auditApproval(v.TenantID, v.Requester, "steward_screen_rule_not_made", v.Kind, "", v.ID, "error", "the approved request is not a steward screen rule")
		return ""
	}
	rule := StewardScreenRule{V: 1, TenantID: v.TenantID, EndpointID: v.Targets[0], Mode: p.Mode,
		MaxSeconds: rec.stewardRule.MaxSeconds, AskFirst: rec.askFirst || p.AskFirst, OnlyInWindow: rec.stewardRule.OnlyInWindow,
		ApprovalID: v.ID, ApproverID: approverID, Created: now.Unix(), Expires: now.Add(stewardRuleLife).Unix()}
	token, err := a.signStewardRule(rule)
	if err != nil {
		a.auditApproval(v.TenantID, v.Requester, "steward_screen_rule_not_made", v.Kind, rule.EndpointID, v.ID, "error", err.Error())
		return ""
	}
	a.auditApproval(v.TenantID, v.Requester, "steward_screen_rule_created", v.Kind, rule.EndpointID, v.ID, "success",
		StewardRuleLabel(rule)+"; lasts until "+time.Unix(rule.Expires, 0).UTC().Format("2006-01-02")+"; approver "+approverID)
	return token
}

// StewardRuleLabel says what a rule allows, for the owner.
func StewardRuleLabel(r StewardScreenRule) string {
	what := "control"
	if r.Mode == response.ScreenModeView {
		what = "watch"
	}
	label := fmt.Sprintf("Steward may %s the screen on %s for stuck maintenance runs, up to %s", what, r.EndpointID, spanText(r.MaxSeconds))
	if r.OnlyInWindow {
		label += ", inside the maintenance window"
	}
	if r.AskFirst {
		label += ", asking the person at the keyboard"
	}
	return label
}
