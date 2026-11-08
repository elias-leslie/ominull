package storage

import (
	"database/sql"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Agent egress policy: which agent session made a connection, and what the
// operator says about it.
//
// The endpoint agent traces a process to the agent session behind it and flows
// keep that as agent_session, "<tool>:<window>" (claude:1b16ad8d; the window is
// empty for a session outside an Aico window). It is attribution, not
// authentication: a process of the same user can claim a session.
//
// The policy is an ordered list of rules, first match wins, and is evaluated
// where the question is asked: the Traffic page judges each row against the
// saved policy, so an edit shows at once what it would do. Mode observe only
// shows that. Mode enforce also writes a flag rule's finding (record class:
// kept and counted, never asked about) and sends block rules to the endpoints
// in BlockEndpoints, the only machines that ever hold one.

// Rule actions.
const (
	EgressAllow = "allow"
	EgressFlag  = "flag"
	EgressBlock = "block"
)

// Policy modes.
const (
	EgressObserve = "observe"
	EgressEnforce = "enforce"
)

const (
	maxEgressRules = 64
	// MaxEgressBlockEntries is what one endpoint is sent; the agent holds no more.
	MaxEgressBlockEntries = 32
	maxConversationNames  = 16
	// maxEgressBlockEntryLen is the longest entry the agent's list parser reads whole.
	maxEgressBlockEntryLen = 62
	maxAgentSessionName    = 120
)

// AgentEgressPolicy is the saved policy (DetectionTuning.AgentEgressPolicy).
type AgentEgressPolicy struct {
	Mode           string            `json:"mode"`
	Rules          []AgentEgressRule `json:"rules"`
	BlockEndpoints []string          `json:"block_endpoints"`
}

// AgentEgressRule says what happens to the connections it matches. Runtime and
// Session narrow who: empty means any agent, Session is a session key
// (claude:1b16ad8d), a window id or a glob on the session's name. Domains (a
// name and everything under it) and CIDRs narrow where, either may match;
// Ports narrows further. A rule with no destination matches everywhere.
//
// A firewall knows no names and no later rules, so a block rule must name its
// addresses and come before every allow and flag rule.
type AgentEgressRule struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Runtime string   `json:"runtime,omitempty"`
	Session string   `json:"session,omitempty"`
	Domains []string `json:"domains,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
	Ports   []int    `json:"ports,omitempty"`
}

// EgressVerdict is a rule's answer. Live is false while it only shows what the
// rule would do: the policy is observing, or a block rule's endpoint is not one
// that holds blocks.
type EgressVerdict struct {
	Action string `json:"action"`
	Rule   string `json:"rule"`
	Live   bool   `json:"live"`
}

// EgressSubject is who connected and where.
type EgressSubject struct {
	EndpointID string
	Runtime    string
	Session    string // the session key
	Name       string // the session's name, when known
	Domain     string
	SNI        string
	IP         string
	Port       int
}

func (p AgentEgressPolicy) tidy() AgentEgressPolicy {
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = EgressObserve
	}
	p.BlockEndpoints = tidyEndpointIDs(p.BlockEndpoints)
	for i := range p.Rules {
		r := &p.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		r.Runtime = strings.ToLower(strings.TrimSpace(r.Runtime))
		r.Session = strings.TrimSpace(r.Session)
		for j, d := range r.Domains {
			r.Domains[j] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		}
		for j, c := range r.CIDRs {
			if pre, err := parseEgressPrefix(c); err == nil {
				r.CIDRs[j] = pre.String()
			}
		}
	}
	return p
}

// tidyEndpointIDs trims and dedupes, keeping case: an id is matched exactly.
func tidyEndpointIDs(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range in {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func parseEgressPrefix(v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	pre, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(pre.Addr().Unmap(), pre.Bits()).Masked(), nil
}

var (
	egressRuleID   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,47}$`)
	egressName     = regexp.MustCompile(`^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)*$`)
	egressRuntime  = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	agentSessionRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}:([0-9a-f]{4,64})?$`)
	agentWindowRe  = regexp.MustCompile(`^[0-9a-f]{4,64}$`)
)

func (p AgentEgressPolicy) valid() error {
	if p.Mode != EgressObserve && p.Mode != EgressEnforce {
		return fmt.Errorf("agent egress mode must be observe or enforce")
	}
	if len(p.Rules) > maxEgressRules {
		return fmt.Errorf("agent egress policy holds at most %d rules", maxEgressRules)
	}
	seen := map[string]bool{}
	pastBlocks := false
	for _, r := range p.Rules {
		if !egressRuleID.MatchString(r.ID) {
			return fmt.Errorf("agent egress rule id %q: use lowercase letters, digits, dot, dash or underscore", r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("agent egress rule id %q is used twice", r.ID)
		}
		seen[r.ID] = true
		switch r.Action {
		case EgressAllow, EgressFlag:
			pastBlocks = true
		case EgressBlock:
			if pastBlocks {
				return fmt.Errorf("rule %s: block rules come before allow and flag rules, because a firewall cannot see the rules above them", r.ID)
			}
			if len(r.CIDRs) == 0 || len(r.Domains) > 0 {
				return fmt.Errorf("rule %s: a block rule names addresses, not names, because a firewall cannot see names", r.ID)
			}
			if problem := r.blockProblem(); problem != "" {
				return fmt.Errorf("rule %s: %s", r.ID, problem)
			}
		default:
			return fmt.Errorf("rule %s: action must be allow, flag or block", r.ID)
		}
		if r.Runtime != "" && !egressRuntime.MatchString(r.Runtime) {
			return fmt.Errorf("rule %s: runtime %q is not a runtime name", r.ID, r.Runtime)
		}
		if len(r.Session) > maxAgentSessionName {
			return fmt.Errorf("rule %s: session is longer than %d characters", r.ID, maxAgentSessionName)
		}
		if _, err := path.Match(strings.ToLower(r.Session), ""); err != nil {
			return fmt.Errorf("rule %s: session %q is not a valid pattern", r.ID, r.Session)
		}
		for _, d := range r.Domains {
			if !egressName.MatchString(d) {
				return fmt.Errorf("rule %s: %q is not a domain name", r.ID, d)
			}
		}
		for _, c := range r.CIDRs {
			pre, err := parseEgressPrefix(c)
			if err != nil {
				return fmt.Errorf("rule %s: %q is not an address or range", r.ID, c)
			}
			if r.Action == EgressBlock {
				if problem := egressBlockRangeProblem(pre); problem != "" {
					return fmt.Errorf("rule %s: %s", r.ID, problem)
				}
			}
		}
		for _, port := range r.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("rule %s: port %d is out of range", r.ID, port)
			}
		}
	}
	entries := p.allBlockEntries()
	if len(entries) > MaxEgressBlockEntries {
		return fmt.Errorf("block rules come to %d firewall entries; an agent holds at most %d", len(entries), MaxEgressBlockEntries)
	}
	for _, e := range entries {
		if len(e) > maxEgressBlockEntryLen {
			return fmt.Errorf("block entry %s is longer than an agent can read", e)
		}
	}
	return nil
}

// egressBlockRangeProblem keeps a block rule to what an agent will hold: public
// addresses, no wider than a /8 or /32. Blocks are not signed, so they may never
// reach the local network. A public resolver or the hub may be named: a block
// only touches the session's own sockets.
func egressBlockRangeProblem(pre netip.Prefix) string {
	minBits := 8
	if pre.Addr().Is6() {
		minBits = 32
	}
	if pre.Bits() < minBits {
		return fmt.Sprintf("%s is wider than a block may be (/%d)", pre, minBits)
	}
	if privatePrefixOverlap(pre) {
		return fmt.Sprintf("%s reaches private or local addresses; a block names public addresses only", pre)
	}
	return ""
}

var nonPublicPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/8", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func privatePrefixOverlap(pre netip.Prefix) bool {
	for _, n := range nonPublicPrefixes {
		if n.Overlaps(pre) {
			return true
		}
	}
	return false
}

// Summaries are the rules in words, for the audit delta.
func (p AgentEgressPolicy) Summaries() []string {
	out := make([]string, 0, len(p.Rules))
	for _, r := range p.Rules {
		ports := make([]string, 0, len(r.Ports))
		for _, port := range r.Ports {
			ports = append(ports, strconv.Itoa(port))
		}
		out = append(out, fmt.Sprintf("%s=%s runtime:%s session:%s to:%s ports:%s", r.ID, r.Action, r.Runtime, r.Session,
			strings.Join(append(append([]string{}, r.Domains...), r.CIDRs...), ","), strings.Join(ports, ",")))
	}
	return out
}

func (r AgentEgressRule) matchesWho(s EgressSubject) bool {
	if r.Runtime != "" && r.Runtime != s.Runtime {
		return false
	}
	if r.Session == "" {
		return true
	}
	return r.matchesSession(s.Session, s.Name)
}

func (r AgentEgressRule) matchesSession(key, name string) bool {
	if key != "" && r.Session == key {
		return true
	}
	if i := strings.IndexByte(key, ':'); i >= 0 && key[i+1:] != "" && r.Session == key[i+1:] {
		return true
	}
	if name == "" {
		return false
	}
	// A name may hold a slash; a pattern's * should still cover it.
	flat := strings.NewReplacer("/", "\x00")
	ok, _ := path.Match(flat.Replace(strings.ToLower(r.Session)), flat.Replace(strings.ToLower(name)))
	return ok
}

func (r AgentEgressRule) matchesWhere(s EgressSubject) bool {
	if len(r.Ports) > 0 {
		hit := false
		for _, p := range r.Ports {
			hit = hit || p == s.Port
		}
		if !hit {
			return false
		}
	}
	if len(r.Domains) == 0 && len(r.CIDRs) == 0 {
		return true
	}
	for _, d := range r.Domains {
		bare := strings.TrimPrefix(d, "*.")
		for _, n := range []string{s.Domain, s.SNI} {
			n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
			if n == bare || strings.HasSuffix(n, "."+bare) {
				return true
			}
		}
	}
	if a, err := netip.ParseAddr(s.IP); err == nil {
		a = a.Unmap()
		for _, c := range r.CIDRs {
			if pre, err := parseEgressPrefix(c); err == nil && pre.Contains(a) {
				return true
			}
		}
	}
	return false
}

// Evaluate returns the first matching rule's verdict, or nil for a subject that
// is no agent's or that no rule speaks to.
func (p AgentEgressPolicy) Evaluate(s EgressSubject) *EgressVerdict {
	if s.Runtime == "" && s.Session == "" {
		return nil
	}
	for _, r := range p.Rules {
		if !r.matchesWho(s) || !r.matchesWhere(s) {
			continue
		}
		v := &EgressVerdict{Action: r.Action, Rule: r.ID, Live: p.Mode == EgressEnforce}
		if r.Action == EgressBlock {
			v.Live = v.Live && p.BlocksOn(s.EndpointID)
		}
		return v
	}
	return nil
}

// BlocksOn says whether this endpoint holds block rules while the policy enforces.
func (p AgentEgressPolicy) BlocksOn(endpointID string) bool {
	for _, id := range p.BlockEndpoints {
		if id == endpointID {
			return true
		}
	}
	return false
}

// BlockEntries is what an endpoint enforces: "tool|window|range|port", where a
// tool or window of * means any and port 0 means all.
func (p AgentEgressPolicy) BlockEntries(endpointID string) []string {
	if p.Mode != EgressEnforce || !p.BlocksOn(endpointID) {
		return nil
	}
	return p.allBlockEntries()
}

func (p AgentEgressPolicy) allBlockEntries() []string {
	out := []string{}
	for _, r := range p.Rules {
		if r.Action != EgressBlock {
			continue
		}
		tool, window := r.blockWho()
		ports := r.Ports
		if len(ports) == 0 {
			ports = []int{0}
		}
		for _, c := range r.CIDRs {
			for _, port := range ports {
				out = append(out, fmt.Sprintf("%s|%s|%s|%d", tool, window, c, port))
			}
		}
	}
	return out
}

// blockWho is who a block rule names on the wire. valid refuses a session this
// can't say: a firewall rule can't follow a name, nor tell windowless sessions apart.
func (r AgentEgressRule) blockWho() (tool, window string) {
	tool, window = r.Runtime, "*"
	if agentSessionRe.MatchString(r.Session) {
		i := strings.IndexByte(r.Session, ':')
		tool, window = r.Session[:i], r.Session[i+1:]
	} else if r.Session != "" {
		window = r.Session
	}
	if tool == "" {
		tool = "*"
	}
	return tool, window
}

// blockProblem says why a block rule's session can't be held.
func (r AgentEgressRule) blockProblem() string {
	if r.Session == "" {
		return ""
	}
	if agentSessionRe.MatchString(r.Session) {
		i := strings.IndexByte(r.Session, ':')
		if r.Session[i+1:] == "" {
			return "a block must name a session with a window"
		}
		if r.Runtime != "" && r.Runtime != r.Session[:i] {
			return fmt.Sprintf("session %s is not a %s session", r.Session, r.Runtime)
		}
		return ""
	}
	if agentWindowRe.MatchString(r.Session) {
		return ""
	}
	return "a block names a session by its key or window id, not its name"
}

// AgentSessionOf is the validated session key of a flow: what the agent names,
// or the session the older actor field traced a spawned process to.
func AgentSessionOf(ev Event) string {
	s := ev.AgentSession
	if s == "" {
		s = strings.TrimPrefix(ev.Actor, "agent:")
		if s == ev.Actor {
			return ""
		}
	}
	if !agentSessionRe.MatchString(s) {
		return ""
	}
	return s
}

// AgentSessionTool is the tool of a session key.
func AgentSessionTool(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[:i]
	}
	return ""
}

// AgentSession is what the workstation told the hub about one Aico window.
type AgentSession struct {
	Window   string    `json:"window"`
	Name     string    `json:"name"`
	Tool     string    `json:"tool,omitempty"`
	Project  string    `json:"project,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

func (s *Store) initAgentSessionSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS agent_sessions (
		widget TEXT PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		tool TEXT NOT NULL DEFAULT '',
		project TEXT NOT NULL DEFAULT '',
		last_seen DATETIME NOT NULL
	)`)
	return err
}

// addFlowAgentSession brings an older flow_processes and events view up to the
// column; the view is rebuilt because SQLite views have a fixed column list.
func (s *Store) addFlowAgentSession() error {
	var has int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('flow_processes') WHERE name = 'agent_session'`).Scan(&has); err != nil {
		return err
	}
	if has == 0 {
		if _, err := s.db.Exec(`ALTER TABLE flow_processes ADD COLUMN agent_session TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'agent_session'`).Scan(&has); err != nil {
		return err
	}
	if has == 0 {
		var view int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'view' AND name = 'events'`).Scan(&view); err != nil {
			return err
		}
		if view > 0 {
			if _, err := s.db.Exec(`DROP TRIGGER IF EXISTS trg_events_view_insert; DROP VIEW IF EXISTS events_view_process; DROP VIEW events`); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecordAgentSessions saves what the workstation knows about its windows; a
// window it no longer lists keeps its name for the traffic it left behind.
func (s *Store) RecordAgentSessions(sessions []AgentSession, at time.Time) (int, error) {
	n := 0
	for _, a := range sessions {
		a.Name = strings.TrimSpace(a.Name)
		if len(a.Name) > maxAgentSessionName {
			a.Name = a.Name[:maxAgentSessionName]
		}
		if !agentWindowRe.MatchString(a.Window) || a.Name == "" {
			continue
		}
		if _, err := s.db.Exec(`INSERT INTO agent_sessions (widget, name, tool, project, last_seen) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (widget) DO UPDATE SET name = excluded.name, tool = excluded.tool, project = excluded.project, last_seen = excluded.last_seen`,
			a.Window, a.Name, a.Tool, a.Project, flowTime(at)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ListAgentSessions lists the known windows, newest first.
func (s *Store) ListAgentSessions() ([]AgentSession, error) {
	rows, err := s.db.Query(`SELECT widget, name, tool, project, last_seen FROM agent_sessions ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentSession{}
	for rows.Next() {
		var a AgentSession
		var at interface{}
		if err := rows.Scan(&a.Window, &a.Name, &a.Tool, &a.Project, &at); err != nil {
			return nil, err
		}
		a.LastSeen = scanTime(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentSessionName is one window's name, "" when unknown.
func (s *Store) AgentSessionName(sessionKey string) string {
	i := strings.IndexByte(sessionKey, ':')
	if i < 0 || sessionKey[i+1:] == "" {
		return ""
	}
	var name string
	if err := s.db.QueryRow(`SELECT name FROM agent_sessions WHERE widget = ?`, sessionKey[i+1:]).Scan(&name); err != nil && err != sql.ErrNoRows {
		return ""
	}
	return name
}

// ConversationSession is one agent session's part of a Traffic row.
type ConversationSession struct {
	Key           string         `json:"key"`
	Tool          string         `json:"tool"`
	Name          string         `json:"name,omitempty"`
	Project       string         `json:"project,omitempty"`
	Flows         int64          `json:"flows"`
	MeasuredFlows int64          `json:"measured_flows"`
	BytesIn       int64          `json:"bytes_in"`
	BytesOut      int64          `json:"bytes_out"`
	Blocked       int64          `json:"blocked"`
	FirstSeen     time.Time      `json:"first_seen"`
	LastSeen      time.Time      `json:"last_seen"`
	Verdict       *EgressVerdict `json:"verdict,omitempty"`
	names         []string
}

// SessionTotal is one agent session's traffic in the window.
type SessionTotal struct {
	Key      string `json:"key"`
	Tool     string `json:"tool"`
	Name     string `json:"name,omitempty"`
	Project  string `json:"project,omitempty"`
	Rows     int    `json:"rows"`
	Flows    int64  `json:"flows"`
	BytesOut int64  `json:"bytes_out"`
}

func sessionShare(c TrafficConversation, key string) ConversationSession {
	return ConversationSession{Key: key, Tool: AgentSessionTool(key), Flows: c.Flows, MeasuredFlows: c.MeasuredFlows,
		BytesIn: c.BytesIn, BytesOut: c.BytesOut, Blocked: c.Blocked, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen}
}

// absorb folds another session's part of the same conversation into this row.
func (c *TrafficConversation) absorb(o TrafficConversation) {
	c.Flows += o.Flows
	c.MeasuredFlows += o.MeasuredFlows
	c.BytesIn += o.BytesIn
	c.BytesOut += o.BytesOut
	c.Blocked += o.Blocked
	if o.PeerName > c.PeerName {
		c.PeerName = o.PeerName
	}
	if c.Country == "" {
		c.Country = o.Country
	}
	if o.FirstSeen.Before(c.FirstSeen) {
		c.FirstSeen = o.FirstSeen
	}
	if o.LastSeen.After(c.LastSeen) {
		c.LastSeen = o.LastSeen
	}
	c.Sessions = append(c.Sessions, o.Sessions...)
	c.names = append(c.names, o.names...)
}

// conversationNames are the names one part of a row was reached under, "" for
// flows with none. A row's own PeerName is only the greatest of them, and rules
// match on each, as they do on each flow.
func conversationNames(domains, snis sql.NullString, unnamed int64) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range []sql.NullString{domains, snis} {
		for _, n := range strings.Split(list.String, ",") {
			if n != "" && !seen[n] && len(out) < maxConversationNames {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if unnamed > 0 || len(out) == 0 {
		out = append(out, "")
	}
	return out
}

// nameConversationSessions orders each row's sessions, names them and totals
// them for the session filter.
func (s *Store) nameConversationSessions(rows []TrafficConversation, meta *TrafficConversations) error {
	known, err := s.ListAgentSessions()
	if err != nil {
		return err
	}
	byWindow := make(map[string]AgentSession, len(known))
	for _, a := range known {
		byWindow[a.Window] = a
	}
	totals := map[string]*SessionTotal{}
	for i := range rows {
		ss := rows[i].Sessions
		for j := range ss {
			p := &ss[j]
			if a, ok := byWindow[p.Key[strings.IndexByte(p.Key, ':')+1:]]; ok {
				p.Name, p.Project = a.Name, a.Project
			}
			t := totals[p.Key]
			if t == nil {
				t = &SessionTotal{Key: p.Key, Tool: p.Tool, Name: p.Name, Project: p.Project}
				totals[p.Key] = t
			}
			t.Rows++
			t.Flows += p.Flows
			t.BytesOut += p.BytesOut
		}
		sort.SliceStable(ss, func(a, b int) bool { return ss[a].Flows > ss[b].Flows })
	}
	for _, t := range totals {
		meta.Sessions = append(meta.Sessions, *t)
	}
	sort.Slice(meta.Sessions, func(a, b int) bool {
		if meta.Sessions[a].Flows != meta.Sessions[b].Flows {
			return meta.Sessions[a].Flows > meta.Sessions[b].Flows
		}
		return meta.Sessions[a].Key < meta.Sessions[b].Key
	})
	return nil
}

// onlySession narrows a row to one session's part, or reports it had none.
func (c TrafficConversation) onlySession(key string) (TrafficConversation, bool) {
	for _, p := range c.Sessions {
		if p.Key != key {
			continue
		}
		c.Flows, c.MeasuredFlows, c.BytesIn, c.BytesOut, c.Blocked = p.Flows, p.MeasuredFlows, p.BytesIn, p.BytesOut, p.Blocked
		c.FirstSeen, c.LastSeen = p.FirstSeen, p.LastSeen
		c.Sessions = []ConversationSession{p}
		c.names = nil
		return c, true
	}
	return c, false
}

// isVersionName says a program's file is named only for its version, as in
// claude/versions/2.1.319, which says nothing about what it is.
func isVersionName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func egressRank(v *EgressVerdict) int {
	switch {
	case v == nil:
		return 0
	case v.Action == EgressAllow:
		return 1
	case v.Action == EgressFlag:
		return 2
	}
	return 3
}

// judged names the row's runtime and asks the policy about each part of it, the
// way the detector asks about each flow, and shows the strictest answer. A served
// connection is not this agent reaching out, so the policy has no say.
func (c TrafficConversation) judged(t DetectionTuning) TrafficConversation {
	c.Runtime = t.AgentRuntimeOf(c.ProcessPath)
	if c.Runtime != "" && isVersionName(c.Process) {
		c.Process = c.Runtime
	}
	if len(c.Sessions) > 0 {
		c.Sessions = append([]ConversationSession(nil), c.Sessions...)
	}
	if c.Direction != "out" || len(t.AgentEgressPolicy.Rules) == 0 {
		return c
	}
	strictest := func(runtime, session, name string, names []string) *EgressVerdict {
		if len(names) == 0 {
			names = []string{c.PeerName}
		}
		var worst *EgressVerdict
		for _, n := range names {
			v := t.AgentEgressPolicy.Evaluate(EgressSubject{EndpointID: c.EndpointID, Runtime: runtime, Session: session, Name: name, Domain: n, IP: c.PeerIP, Port: c.Port})
			if egressRank(v) > egressRank(worst) {
				worst = v
			}
		}
		return worst
	}
	if len(c.Sessions) == 0 || len(c.names) > 0 {
		c.Verdict = strictest(c.Runtime, "", "", c.names)
	}
	for i := range c.Sessions {
		p := &c.Sessions[i]
		p.Verdict = strictest(p.Tool, p.Key, p.Name, p.names)
		if egressRank(p.Verdict) > egressRank(c.Verdict) {
			c.Verdict = p.Verdict
		}
	}
	return c
}
