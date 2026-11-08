package storage

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A traffic conversation is one program on one host talking with one peer on
// one service port, folded over the chosen window. It answers "what is talking
// to what" at the grain an operator acts on, and carries the three things that
// make one worth a look: a finding the detector raised about it, a peer this
// program on this host never reached before the window, and blocked flows.
//
// The agent reports a listening socket's replies as OUTBOUND from the service
// port to the client's ephemeral port. Those are folded the other way round
// (direction "in", port = the service port), with the same ephemeral_port_from
// line the detector uses, so a busy listener is one row per client rather than
// one per client socket.

// TrafficConversation is one row of the Traffic page.
type TrafficConversation struct {
	EndpointID    string                `json:"endpoint_id"`
	Hostname      string                `json:"hostname,omitempty"`
	Process       string                `json:"process"`
	ProcessPath   string                `json:"process_path"`
	Direction     string                `json:"direction"` // "out": this host opened it; "in": the peer reached a service here
	PeerIP        string                `json:"peer_ip"`
	PeerName      string                `json:"peer_name,omitempty"`     // TLS server name or reported domain
	PeerHost      string                `json:"peer_host,omitempty"`     // the asset name when the peer is a known host
	PeerEndpoint  string                `json:"peer_endpoint,omitempty"` // the peer's own agent, when it has one
	Country       string                `json:"country,omitempty"`
	Port          int                   `json:"port"`
	Protocol      string                `json:"protocol"`
	Proto         int                   `json:"proto"` // the protocol number, for filters
	Flows         int64                 `json:"flows"`
	MeasuredFlows int64                 `json:"measured_flows"`
	BytesIn       int64                 `json:"bytes_in"`
	BytesOut      int64                 `json:"bytes_out"`
	Blocked       int64                 `json:"blocked"`
	FirstSeen     time.Time             `json:"first_seen"`
	LastSeen      time.Time             `json:"last_seen"`
	New           bool                  `json:"new"`
	KnownSince    *time.Time            `json:"known_since,omitempty"`
	Findings      *ConversationFindings `json:"findings,omitempty"`
	key           conversationKey
}

// ConversationFindings summarises the findings raised about a conversation in
// the window. Open counts unacknowledged paging findings; the rest were
// recorded or already handled.
type ConversationFindings struct {
	Count      int      `json:"count"`
	Open       int      `json:"open"`
	Worst      string   `json:"worst"`
	Title      string   `json:"title"`
	Type       string   `json:"type"`
	HeldReason string   `json:"held_reason,omitempty"`
	IDs        []string `json:"ids"`
}

// TrafficConversationCounts are taken after the search and before the mark
// and direction filters, so each filter chip says what it would show.
type TrafficConversationCounts struct {
	All     int `json:"all"`
	Flagged int `json:"flagged"`
	Open    int `json:"open"`
	New     int `json:"new"`
	Blocked int `json:"blocked"`
	Out     int `json:"out"`
	In      int `json:"in"`
}

// TrafficConversations is the conversations answer for one window.
type TrafficConversations struct {
	AsOf          time.Time                 `json:"as_of"`
	WindowStart   time.Time                 `json:"window_start"`
	WindowEnd     time.Time                 `json:"window_end"`
	RetainedFrom  *time.Time                `json:"retained_from,omitempty"`
	LatestFlow    *time.Time                `json:"latest_flow,omitempty"`
	NewKnown      bool                      `json:"new_known"`
	ProfilesFrom  *time.Time                `json:"profiles_from,omitempty"`
	Counts        TrafficConversationCounts `json:"counts"`
	Matching      int                       `json:"matching"`
	Truncated     bool                      `json:"truncated"`
	Conversations []TrafficConversation     `json:"conversations"`
}

// ConversationQuery narrows the folded set: Search matches host, program,
// peer, name and port; Mark is "flagged", "new" or "blocked"; Direction is
// "in" or "out".
type ConversationQuery struct {
	Search    string
	Mark      string
	Direction string
	Limit     int
	// Sort orders the matching rows before the cut: "" (needs a look first),
	// "volume", "recent" or "flows".
	Sort string
	// EphemeralPortFrom is the tuning line between service and client ports.
	EphemeralPortFrom int
}

type conversationKey struct {
	endpoint, path, dir, peer string
	port, proto               int
}

type conversationCache struct {
	mu      sync.Mutex
	entries map[string]conversationCacheEntry
}

type conversationCacheEntry struct {
	rows     []TrafficConversation
	meta     TrafficConversations
	computed time.Time
}

// QueryTrafficConversations folds the window's flows into conversations.
func (s *Store) QueryTrafficConversations(filter TrafficFilter, q ConversationQuery) (*TrafficConversations, error) {
	if q.EphemeralPortFrom <= 0 {
		q.EphemeralPortFrom = 32768
	}
	if q.Limit <= 0 {
		q.Limit = 300
	}
	if q.Limit > MaxConversations {
		q.Limit = MaxConversations
	}
	now := time.Now().UTC()
	cacheKey := filter.CacheKey() + "|" + strconv.Itoa(q.EphemeralPortFrom)
	rows, meta, ok := s.trafficConv.get(cacheKey, now)
	if !ok {
		var err error
		rows, meta, err = s.foldConversations(filter, q.EphemeralPortFrom, now)
		if err != nil {
			return nil, err
		}
		s.trafficConv.put(cacheKey, rows, meta, now)
	}
	out := meta
	out.Conversations = []TrafficConversation{}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	for _, c := range rows {
		if needle != "" && !c.matches(needle) {
			continue
		}
		out.Counts.All++
		if c.Findings != nil {
			out.Counts.Flagged++
			if c.Findings.Open > 0 {
				out.Counts.Open++
			}
		}
		if c.New {
			out.Counts.New++
		}
		if c.Blocked > 0 {
			out.Counts.Blocked++
		}
		if c.Direction == "in" {
			out.Counts.In++
		} else {
			out.Counts.Out++
		}
		switch q.Mark {
		case "flagged":
			if c.Findings == nil {
				continue
			}
		case "new":
			if !c.New {
				continue
			}
		case "blocked":
			if c.Blocked == 0 {
				continue
			}
		}
		if q.Direction != "" && c.Direction != q.Direction {
			continue
		}
		out.Conversations = append(out.Conversations, c)
	}
	out.Matching = len(out.Conversations)
	sortConversations(out.Conversations, q.Sort)
	if len(out.Conversations) > q.Limit {
		out.Conversations = out.Conversations[:q.Limit]
	}
	out.Truncated = out.Matching > len(out.Conversations)
	return &out, nil
}

// MaxConversations is the most rows one answer carries.
const MaxConversations = 1000

// sortConversations reorders rows that are already in needs-a-look order.
func sortConversations(rows []TrafficConversation, by string) {
	var less func(a, b TrafficConversation) bool
	switch by {
	case "volume":
		less = func(a, b TrafficConversation) bool { return a.BytesIn+a.BytesOut > b.BytesIn+b.BytesOut }
	case "recent":
		less = func(a, b TrafficConversation) bool { return a.LastSeen.After(b.LastSeen) }
	case "flows":
		less = func(a, b TrafficConversation) bool { return a.Flows > b.Flows }
	default:
		return
	}
	sort.SliceStable(rows, func(i, j int) bool { return less(rows[i], rows[j]) })
}

func (c TrafficConversation) matches(needle string) bool {
	for _, v := range []string{c.EndpointID, c.Hostname, c.Process, c.ProcessPath, c.PeerIP, c.PeerName, c.PeerHost, c.Country, strconv.Itoa(c.Port)} {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

func (s *Store) foldConversations(filter TrafficFilter, eph int, now time.Time) ([]TrafficConversation, TrafficConversations, error) {
	start, end, _, _ := ResolveTrafficWindow(filter)
	whereClause, args, _ := buildTrafficWhere(filter, start, end)
	meta := TrafficConversations{AsOf: now, WindowStart: start, WindowEnd: end}

	// Names first: ListEndpoints and ListAssets take the read lock themselves.
	endpoints, err := s.ListEndpoints(filter.TenantID)
	if err != nil {
		return nil, meta, err
	}
	assets, err := s.ListAssets(filter.TenantID)
	if err != nil {
		return nil, meta, err
	}
	findings, err := s.ListAnomalyAlertsBetween(filter.TenantID, start, end.Add(time.Second), false)
	if err != nil {
		return nil, meta, err
	}
	hostOf := map[string]string{}
	endpointAt := map[string]string{}
	for _, ep := range endpoints {
		hostOf[ep.ID] = ep.Hostname
		if ep.IP != "" && ep.Status != "retired" {
			endpointAt[ep.IP] = ep.ID
		}
	}
	nameAt := map[string]string{}
	for _, a := range assets {
		if a.IP != "" && a.Hostname != "" {
			nameAt[a.IP] = a.Hostname
		}
	}

	// Agents report every flow with this host's end as the source, whichever
	// way the packet went (an INBOUND row is a datagram received, mostly the
	// answer to this host's own query), so the peer is always the
	// destination. A flow is served - the peer reached a service here - when
	// this host's port is a service port and the peer's is a client port.
	served := "(src_port > 0 AND src_port < ? AND dst_port >= ?)"
	query := `SELECT endpoint_id, process_path,
		CASE WHEN ` + served + ` THEN 'in' ELSE 'out' END AS dir,
		dst_ip AS peer,
		CASE WHEN ` + served + ` THEN src_port ELSE dst_port END AS svc,
		protocol,
		COALESCE(SUM(samples), 0), COALESCE(SUM(measured_samples), 0),
		COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0),
		COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN samples ELSE 0 END), 0),
		MAX(COALESCE(NULLIF(sni, ''), domain, '')), MAX(country),
		MIN(timestamp), MAX(timestamp)
		FROM events` + whereClause + `
		GROUP BY endpoint_id, process_path, dir, peer, svc, protocol`
	qargs := append([]interface{}{eph, eph, eph, eph}, args...)

	s.mu.RLock()
	defer s.mu.RUnlock()
	meta.RetainedFrom = s.earliestRetainedEvent(filter.TenantID)

	rs, err := s.db.Query(query, qargs...)
	if err != nil {
		return nil, meta, err
	}
	var out []TrafficConversation
	for rs.Next() {
		var c TrafficConversation
		var proto int
		var first, last interface{}
		if err := rs.Scan(&c.EndpointID, &c.ProcessPath, &c.Direction, &c.PeerIP, &c.Port, &proto,
			&c.Flows, &c.MeasuredFlows, &c.BytesIn, &c.BytesOut, &c.Blocked, &c.PeerName, &c.Country, &first, &last); err != nil {
			rs.Close()
			return nil, meta, err
		}
		c.Protocol = ProtocolName(proto)
		c.Proto = proto
		c.FirstSeen, c.LastSeen = scanTime(first), scanTime(last)
		c.Process = processBase(c.ProcessPath)
		c.Hostname = hostOf[c.EndpointID]
		c.PeerHost = nameAt[c.PeerIP]
		c.PeerEndpoint = endpointAt[c.PeerIP]
		if c.Country == "LOCAL" || c.Country == "UNKNOWN" {
			c.Country = ""
		}
		c.key = conversationKey{c.EndpointID, c.ProcessPath, c.Direction, c.PeerIP, c.Port, proto}
		if meta.LatestFlow == nil || c.LastSeen.After(*meta.LatestFlow) {
			t := c.LastSeen
			meta.LatestFlow = &t
		}
		out = append(out, c)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return nil, meta, err
	}

	// New: the communication profiles hold, per host, program and peer, the
	// first time the hub saw them talk (kept while they keep talking). A peer
	// is new when that first time falls inside the window - but only if the
	// profiles reach back before the window, otherwise "new" would mean "the
	// hub was not recording yet".
	// A host enrolled inside the window has no history before it either, so
	// the check is per host as well as fleet-wide.
	var pargs []interface{}
	pq := "SELECT endpoint_id, MIN(first_seen) FROM comm_profiles"
	if filter.TenantID != "" {
		pq += " WHERE tenant_id = ?"
		pargs = append(pargs, filter.TenantID)
	}
	hostFrom := map[string]time.Time{}
	prs, err := s.db.Query(pq+" GROUP BY endpoint_id", pargs...)
	if err != nil {
		return nil, meta, err
	}
	for prs.Next() {
		var ep string
		var t interface{}
		if err := prs.Scan(&ep, &t); err != nil {
			prs.Close()
			return nil, meta, err
		}
		if ft := scanTime(t); !ft.IsZero() {
			hostFrom[ep] = ft
			if meta.ProfilesFrom == nil || ft.Before(*meta.ProfilesFrom) {
				f := ft
				meta.ProfilesFrom = &f
			}
		}
	}
	prs.Close()
	meta.NewKnown = meta.ProfilesFrom != nil && meta.ProfilesFrom.Before(start)
	if len(out) > 0 {
		firstSeen := map[[3]string]time.Time{}
		fq := "SELECT endpoint_id, process_path, dst_ip, MIN(first_seen) FROM comm_profiles"
		if filter.TenantID != "" {
			fq += " WHERE tenant_id = ?"
		}
		fq += " GROUP BY endpoint_id, process_path, dst_ip"
		prs, err = s.db.Query(fq, pargs...)
		if err != nil {
			return nil, meta, err
		}
		for prs.Next() {
			var ep, path, ip string
			var t interface{}
			if err := prs.Scan(&ep, &path, &ip, &t); err != nil {
				prs.Close()
				return nil, meta, err
			}
			firstSeen[[3]string{ep, path, ip}] = scanTime(t)
		}
		prs.Close()
		for i := range out {
			c := &out[i]
			t, ok := firstSeen[[3]string{c.EndpointID, c.ProcessPath, c.PeerIP}]
			if !ok || t.IsZero() {
				continue
			}
			known := t
			c.KnownSince = &known
			from, ok := hostFrom[c.EndpointID]
			c.New = ok && from.Before(start) && !t.Before(start)
		}
	}

	// Findings about the conversation: same host and peer, the same program
	// when the finding names one, and the port the finding's flow would carry:
	// the service port for an outbound row, a client port for a served one.
	byPair := map[[2]string][]int{}
	for i := range out {
		k := [2]string{out[i].EndpointID, out[i].PeerIP}
		byPair[k] = append(byPair[k], i)
	}
	for _, a := range findings {
		if a.DstIP == "" {
			continue
		}
		for _, i := range byPair[[2]string{a.EndpointID, a.DstIP}] {
			c := &out[i]
			if a.ProcessPath != "" && c.ProcessPath != "" && !samePath(a.ProcessPath, c.ProcessPath) {
				continue
			}
			if a.DstPort != 0 {
				if c.Direction == "out" && int(a.DstPort) != c.Port {
					continue
				}
				if c.Direction == "in" && int(a.DstPort) < eph {
					continue
				}
			}
			addFinding(c, a)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := conversationRank(a), conversationRank(b); ra != rb {
			return ra > rb
		}
		if ta, tb := a.BytesIn+a.BytesOut, b.BytesIn+b.BytesOut; ta != tb {
			return ta > tb
		}
		if a.Flows != b.Flows {
			return a.Flows > b.Flows
		}
		return a.LastSeen.After(b.LastSeen)
	})
	return out, meta, nil
}

// conversationRank orders what needs a look first: open findings, then other
// findings, blocked flows, new peers, then everything else.
func conversationRank(c TrafficConversation) int {
	r := 0
	if c.Findings != nil {
		r += 8 + severityRank(c.Findings.Worst)
		if c.Findings.Open > 0 {
			r += 16
		}
	}
	if c.Blocked > 0 {
		r += 4
	}
	if c.New {
		r += 2
	}
	return r
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	case "MEDIUM":
		return 1
	}
	return 0
}

func addFinding(c *TrafficConversation, a AnomalyAlert) {
	f := c.Findings
	if f == nil {
		f = &ConversationFindings{IDs: []string{}}
		c.Findings = f
	}
	f.Count++
	if !a.Acknowledged && a.HeldReason == "" && AlertClass(a) == ClassPage {
		f.Open++
	}
	if f.Worst == "" || severityRank(a.Severity) > severityRank(f.Worst) ||
		(severityRank(a.Severity) == severityRank(f.Worst) && f.HeldReason != "" && a.HeldReason == "") {
		f.Worst = strings.ToUpper(a.Severity)
		f.Title = a.Title
		f.Type = a.AnomalyType
		f.HeldReason = a.HeldReason
	}
	if len(f.IDs) < 5 {
		f.IDs = append(f.IDs, a.ID)
	}
}

func processBase(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	name := parts[len(parts)-1]
	if name == "" || name == "." {
		return "unknown"
	}
	return name
}

// samePath compares program paths the way Windows and Linux agents report
// them: Windows paths ignore case and may use either separator.
func samePath(a, b string) bool {
	if a == b {
		return true
	}
	na := strings.ReplaceAll(a, "\\", "/")
	nb := strings.ReplaceAll(b, "\\", "/")
	if strings.Contains(a, "\\") || strings.Contains(b, "\\") {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

func (c *conversationCache) get(key string, now time.Time) ([]TrafficConversation, TrafficConversations, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || now.Sub(e.computed) > trafficCacheTTL {
		return nil, TrafficConversations{}, false
	}
	return e.rows, e.meta, true
}

func (c *conversationCache) put(key string, rows []TrafficConversation, meta TrafficConversations, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]conversationCacheEntry{}
	}
	for k, e := range c.entries {
		if now.Sub(e.computed) > trafficCacheTTL {
			delete(c.entries, k)
		}
	}
	c.entries[key] = conversationCacheEntry{rows: rows, meta: meta, computed: now}
}
