package main

// ominullctl trust: the rules naming what an isolated machine may still reach,
// and what they come to for one machine. docs/TRUST_FABRIC.md has the precedence.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"ominull/hub/pkg/trustfabric"
)

const trustUsage = `usage: ominullctl trust rules
       ominullctl trust add allow|deny VALUE --scope SCOPE [--port P] [--proto tcp|udp]
                 [--direction in|out] [--locked] [--expires 24h|RFC3339] [--reason TEXT]
       ominullctl trust remove RULE_ID
       ominullctl trust show ENDPOINT [--addr A [--port P] [--proto tcp|udp] [--direction in|out]]

VALUE is an address, a range or a name. SCOPE is provider (the whole fleet), client:ID,
site:ID, group:ROLE_TAG or endpoint:ID; there is no default, so a rule can't reach the
whole fleet by accident. show prints what the hub would give that machine if isolated;
with --addr it also answers whether that one destination is trusted.
`

func (c *APIClient) cmdTrust(args []string) error {
	if len(args) == 0 {
		fmt.Print(trustUsage)
		return nil
	}
	switch args[0] {
	case "rules":
		if len(args) > 1 {
			return errors.New(trustUsage)
		}
		return c.trustRules()
	case "add":
		rule, err := trustRuleFromArgs(args[1:], time.Now())
		if err != nil {
			return err
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/trust/rules", rule)
		if err != nil {
			return err
		}
		var created trustfabric.Rule
		if err := json.Unmarshal(raw, &created); err != nil {
			return fmt.Errorf("the hub's answer could not be read: %w", err)
		}
		c.printOutput(created, func() { printTrustRules([]trustfabric.Rule{created}) })
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New(trustUsage)
		}
		raw, err := c.doRequest(http.MethodDelete, "/api/v1/trust/rules?"+url.Values{"id": {args[1]}}.Encode(), nil)
		if err != nil {
			return err
		}
		var out struct {
			Status string           `json:"status"`
			Rule   trustfabric.Rule `json:"rule"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return fmt.Errorf("the hub's answer could not be read: %w", err)
		}
		c.printOutput(out, func() { fmt.Printf("Removed %s\n", describeTrustRule(out.Rule)) })
		return nil
	case "show":
		return c.trustShow(args[1:])
	}
	return errors.New(trustUsage)
}

func (c *APIClient) trustRules() error {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/trust/rules", nil)
	if err != nil {
		return err
	}
	var out struct {
		Rules []trustfabric.Rule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("the hub's answer could not be read: %w", err)
	}
	c.printOutput(out, func() {
		if len(out.Rules) == 0 {
			fmt.Println("No trust rules.")
			return
		}
		printTrustRules(out.Rules)
	})
	return nil
}

// trustRuleFromArgs turns the arguments after "add" into the rule to create. The hub
// has the last word on what is valid; this only refuses what it can't express.
func trustRuleFromArgs(args []string, now time.Time) (trustfabric.Rule, error) {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return trustfabric.Rule{}, errors.New(trustUsage)
	}
	fs := flag.NewFlagSet("trust add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	scope := fs.String("scope", "", "")
	port := fs.Int("port", 0, "")
	proto := fs.String("proto", "", "")
	direction := fs.String("direction", "", "")
	locked := fs.Bool("locked", false, "")
	expires := fs.String("expires", "", "")
	reason := fs.String("reason", "", "")
	if err := fs.Parse(args[2:]); err != nil {
		return trustfabric.Rule{}, fmt.Errorf("%w\n%s", err, trustUsage)
	}
	if fs.NArg() > 0 {
		return trustfabric.Rule{}, fmt.Errorf("unexpected %q\n%s", fs.Arg(0), trustUsage)
	}
	if *scope == "" {
		return trustfabric.Rule{}, fmt.Errorf("--scope is required\n%s", trustUsage)
	}
	scopeType, scopeID, _ := strings.Cut(*scope, ":")
	rule := trustfabric.Rule{
		ScopeType: scopeType, ScopeID: scopeID, Action: args[0], Value: args[1], Kind: trustValueKind(args[1]),
		Port: *port, Proto: *proto, Direction: *direction, Locked: *locked, Justification: *reason,
	}
	if *expires != "" {
		at, err := parseTrustExpiry(*expires, now)
		if err != nil {
			return trustfabric.Rule{}, err
		}
		rule.ExpiresAt = &at
	}
	return rule, nil
}

func trustValueKind(value string) string {
	if _, err := netip.ParseAddr(value); err == nil {
		return trustfabric.KindIP
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return trustfabric.KindCIDR
	}
	return trustfabric.KindFQDN
}

func parseTrustExpiry(value string, now time.Time) (time.Time, error) {
	if d, err := time.ParseDuration(value); err == nil {
		return now.Add(d).UTC(), nil
	}
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return at.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--expires takes a length like 24h or a time like 2026-12-01T00:00:00Z, not %q", value)
}

func printTrustRules(rules []trustfabric.Rule) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tACTION\tVALUE\tSCOPE\tMATCHES\tFLAGS\tREASON")
	for _, r := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Action, r.Value, trustRuleScope(r), trustRuleMatches(r), trustRuleFlags(r), r.Justification)
	}
	_ = w.Flush()
}

func describeTrustRule(r trustfabric.Rule) string {
	return strings.Join(strings.Fields(strings.Join([]string{r.ID, r.Action, r.Value, trustRuleScope(r), trustRuleMatches(r), trustRuleFlags(r)}, " ")), " ")
}

func trustRuleScope(r trustfabric.Rule) string {
	if r.ScopeID == "" {
		return r.ScopeType
	}
	return r.ScopeType + ":" + r.ScopeID
}

func trustRuleMatches(r trustfabric.Rule) string {
	var parts []string
	if r.Port != 0 {
		parts = append(parts, "port "+strconv.Itoa(r.Port))
	}
	if r.Proto != "" && r.Proto != trustfabric.ProtoAny {
		parts = append(parts, r.Proto)
	}
	if r.Direction != "" && r.Direction != trustfabric.DirBoth {
		parts = append(parts, r.Direction)
	}
	if len(parts) == 0 {
		return "everything"
	}
	return strings.Join(parts, " ")
}

func trustRuleFlags(r trustfabric.Rule) string {
	var parts []string
	if r.Locked {
		parts = append(parts, "locked")
	}
	if r.ExpiresAt != nil {
		parts = append(parts, "until "+r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, ", ")
}

func (c *APIClient) trustShow(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New(trustUsage)
	}
	fs := flag.NewFlagSet("trust show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "", "")
	port := fs.String("port", "", "")
	proto := fs.String("proto", "", "")
	direction := fs.String("direction", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, trustUsage)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected %q\n%s", fs.Arg(0), trustUsage)
	}
	if *addr == "" && (*port != "" || *proto != "" || *direction != "") {
		return fmt.Errorf("--port, --proto and --direction need --addr\n%s", trustUsage)
	}
	query := url.Values{"endpoint_id": {args[0]}}
	for key, value := range map[string]string{"addr": *addr, "port": *port, "proto": *proto, "direction": *direction} {
		if value != "" {
			query.Set(key, value)
		}
	}
	raw, err := c.doRequest(http.MethodGet, "/api/v1/trust/effective?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	if c.cfg.JSONOutput {
		fmt.Println(strings.TrimSpace(string(raw)))
		return nil
	}
	var out struct {
		Policy struct {
			Allow       []string               `json:"allow"`
			Enforced    []string               `json:"enforced"`
			NotEnforced []string               `json:"not_enforced"`
			Withheld    []trustfabric.Withheld `json:"withheld"`
		} `json:"policy"`
		Decision    *trustfabric.Decision `json:"decision"`
		AgentReport string                `json:"agent_report"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("the hub's answer could not be read: %w", err)
	}
	if out.Decision != nil {
		fmt.Printf("%s: %s (%s)\n", *addr, out.Decision.Action, out.Decision.Basis)
	}
	printTrustList := func(label string, items []string) {
		if len(items) == 0 {
			items = []string{"none"}
		}
		fmt.Printf("%s: %s\n", label, strings.Join(items, ", "))
	}
	printTrustList("Rules allow", out.Policy.Allow)
	printTrustList("Agent would enforce", out.Policy.Enforced)
	if len(out.Policy.NotEnforced) > 0 {
		printTrustList("Doesn't fit, stays closed", out.Policy.NotEnforced)
	}
	for _, w := range out.Policy.Withheld {
		fmt.Printf("Opened nothing: rule %s: %s\n", w.RuleID, w.Reason)
	}
	if out.AgentReport != "" {
		fmt.Printf("Agent's last report: %s\n", out.AgentReport)
	}
	return nil
}
