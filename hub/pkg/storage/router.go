package storage

import (
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/netaddr"
)

// Router telemetry.
//
// The agent sees only the hosts it runs on. Most of an estate - thermostats,
// cameras, plugs, televisions - can never carry an agent, and until the gateway
// tells us about them they do not exist as far as detection is concerned. This
// is the ingest for what the router knows: which leases it has handed out, and
// which conversations are crossing it.
//
// Three rules govern everything here, and they are the reason this file is
// deliberately dull:
//
//  1. The router is an untrusted source. Every field arriving from it is
//     bounded, normalised and validated before it reaches the database. A
//     malformed poll is dropped with a count, never a panic and never a partial
//     write that corrupts the picture.
//  2. Ingest is read-only with respect to the router. Ominull consumes what the
//     gateway reports; it never writes gateway state. Response lives elsewhere.
//  3. Nothing here is unbounded. Flows are rolled up into hourly buckets so the
//     table grows with distinct conversations rather than with packets, and
//     retention prunes it like every other telemetry table.

// Caps. These bound one poll. A router that reports more than this is either
// broken or lying, and in both cases the surplus is dropped rather than trusted.
const (
	MaxRouterLeasesPerPoll = 2000
	MaxRouterFlowsPerPoll  = 20000
	MaxRouterDNSPerPoll    = 20000
	maxRouterFieldLen      = 255
)

// RouterSourceKind names how a router reported. Only one exists today; naming it
// means a second gateway does not have to reshape the table.
const RouterSourceConntrack = "conntrack"

// RouterLease is one DHCP lease as the gateway holds it.
type RouterLease struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RouterFlow is one conversation the gateway is tracking, rolled up to the hour.
//
// Conntrack reports cumulative counters for a live flow and forgets them when
// the entry is evicted, so a raw counter is not a quantity that can be summed
// across polls without double counting. The bucket therefore records the
// highest counter seen for a tuple within its hour, which is the total that
// flow moved while it existed. A new flow reusing the same tuple in the same
// hour restarts from a lower counter; that case is detected and added rather
// than lost.
type RouterFlow struct {
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	DstPort      int    `json:"dst_port"`
	Protocol     string `json:"protocol"`
	OrigBytes    int64  `json:"orig_bytes"`
	ReplyBytes   int64  `json:"reply_bytes"`
	OrigPackets  int64  `json:"orig_packets"`
	ReplyPackets int64  `json:"reply_packets"`
}

// RouterFlowRow is a stored hourly rollup.
type RouterFlowRow struct {
	RouterID     string    `json:"router_id"`
	Bucket       time.Time `json:"bucket"`
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	DstPort      int       `json:"dst_port"`
	Protocol     string    `json:"protocol"`
	OrigBytes    int64     `json:"orig_bytes"`
	ReplyBytes   int64     `json:"reply_bytes"`
	OrigPackets  int64     `json:"orig_packets"`
	ReplyPackets int64     `json:"reply_packets"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// RouterIngestResult reports what one poll actually changed. The counts are the
// point: an operator watching a gateway that has started lying needs to see the
// rejects, not a bare success.
type RouterIngestResult struct {
	LeasesAccepted int `json:"leases_accepted"`
	LeasesRejected int `json:"leases_rejected"`
	FlowsAccepted  int `json:"flows_accepted"`
	FlowsRejected  int `json:"flows_rejected"`
	DNSAccepted    int `json:"dns_accepted"`
	DNSRejected    int `json:"dns_rejected"`
	// Resolutions are the name-to-address answers the resolver gave. They are
	// what lets a finding say "firmware.nest.com" instead of quoting an edge
	// address that will be a different one tomorrow.
	ResolutionsAccepted int `json:"resolutions_accepted"`
	ResolutionsRejected int `json:"resolutions_rejected"`
	AssetsTouched       int `json:"assets_touched"`
}

func (s *Store) initRouterSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS router_flows (
		router_id TEXT NOT NULL,
		bucket INTEGER NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		dst_port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		orig_bytes INTEGER NOT NULL DEFAULT 0,
		reply_bytes INTEGER NOT NULL DEFAULT 0,
		orig_packets INTEGER NOT NULL DEFAULT 0,
		reply_packets INTEGER NOT NULL DEFAULT 0,
		first_seen_at TIMESTAMP NOT NULL,
		last_seen_at TIMESTAMP NOT NULL,
		PRIMARY KEY (router_id, bucket, src_ip, dst_ip, dst_port, protocol)
	);
	CREATE INDEX IF NOT EXISTS idx_router_flows_bucket ON router_flows(bucket);
	CREATE INDEX IF NOT EXISTS idx_router_flows_src ON router_flows(src_ip, bucket);
	CREATE INDEX IF NOT EXISTS idx_router_flows_dst ON router_flows(dst_ip, bucket);

	CREATE TABLE IF NOT EXISTS router_sources (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL DEFAULT '',
		last_seen_at TIMESTAMP,
		last_result TEXT NOT NULL DEFAULT ''
	);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("router schema: %w", err)
	}
	return nil
}

// normaliseMAC lowercases and validates a hardware address. An address we cannot
// parse is not stored under a guess.
func normaliseMAC(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || len(raw) > maxRouterFieldLen {
		return "", false
	}
	hw, err := net.ParseMAC(raw)
	if err != nil {
		return "", false
	}
	return hw.String(), true
}

// normaliseIP validates an address and returns it in canonical form.
func normaliseIP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxRouterFieldLen {
		return "", false
	}
	ip, err := netaddr.Parse(raw)
	if err != nil {
		return "", false
	}
	return ip.String(), true
}

// clampField bounds a free-text field arriving from the gateway. Hostnames are
// chosen by whoever owns the device, which makes them attacker-controlled.
func clampField(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	if len(raw) > maxRouterFieldLen {
		raw = raw[:maxRouterFieldLen]
	}
	return raw
}

// normaliseProtocol keeps the protocol field to the handful we expect.
func normaliseProtocol(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp":
		return "tcp", true
	case "udp":
		return "udp", true
	case "icmp":
		return "icmp", true
	default:
		return "", false
	}
}

// RecordRouterLeases folds a gateway's lease table into the asset store.
//
// A lease is the strongest identity signal an unagented device ever emits: the
// MAC is the device, the hostname is what it calls itself, and the pairing is
// authoritative because the gateway issued it. It lands as a claim from the
// "router" source so it can be weighed against, and corrected by, a scan or an
// agent rather than silently overwriting them.
// vendorFor resolves a hardware address to a manufacturer. It is passed in
// rather than called directly because the OUI registry lives in pkg/scanner,
// which imports this package. A nil func records leases without a vendor.
func (s *Store) RecordRouterLeases(routerID string, leases []RouterLease, vendorFor func(mac string) string, now time.Time) (int, int, error) {
	accepted, rejected := 0, 0
	if len(leases) > MaxRouterLeasesPerPoll {
		rejected += len(leases) - MaxRouterLeasesPerPoll
		leases = leases[:MaxRouterLeasesPerPoll]
	}
	for _, l := range leases {
		mac, okMAC := normaliseMAC(l.MAC)
		ip, okIP := normaliseIP(l.IP)
		if !okMAC || !okIP {
			rejected++
			continue
		}
		host := clampField(l.Hostname)
		// dnsmasq writes "*" when the client offered no name. That is an
		// absence, not a hostname, and must not become one.
		if host == "*" || host == "-" {
			host = ""
		}
		// The lease carries the hardware address, so the manufacturer is
		// already knowable here. Without this an unagented device - which is
		// every device a lease is the only evidence of - shows a blank vendor
		// in the inventory while its OUI sits in the same record.
		vendor := ""
		if vendorFor != nil {
			vendor = vendorFor(mac)
		}
		if err := s.UpsertAssetFromScan(ip, mac, vendor, host, "", "", "", 0.9, nil, now); err != nil {
			rejected++
			continue
		}
		accepted++
	}
	return accepted, rejected, nil
}

// RecordRouterFlows rolls conntrack observations into hourly buckets.
func (s *Store) RecordRouterFlows(routerID string, flows []RouterFlow, now time.Time) (int, int, error) {
	accepted, rejected := 0, 0
	if len(flows) > MaxRouterFlowsPerPoll {
		rejected += len(flows) - MaxRouterFlowsPerPoll
		flows = flows[:MaxRouterFlowsPerPoll]
	}

	bucket := now.UTC().Truncate(time.Hour).Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	read, err := tx.Prepare(`SELECT orig_bytes, reply_bytes, orig_packets, reply_packets
		FROM router_flows WHERE router_id=? AND bucket=? AND src_ip=? AND dst_ip=? AND dst_port=? AND protocol=?`)
	if err != nil {
		return 0, 0, err
	}
	defer read.Close()

	write, err := tx.Prepare(`INSERT INTO router_flows
		(router_id, bucket, src_ip, dst_ip, dst_port, protocol, orig_bytes, reply_bytes, orig_packets, reply_packets, first_seen_at, last_seen_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(router_id, bucket, src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
			orig_bytes=excluded.orig_bytes, reply_bytes=excluded.reply_bytes,
			orig_packets=excluded.orig_packets, reply_packets=excluded.reply_packets,
			last_seen_at=excluded.last_seen_at`)
	if err != nil {
		return 0, 0, err
	}
	defer write.Close()

	for _, f := range flows {
		src, okSrc := normaliseIP(f.SrcIP)
		dst, okDst := normaliseIP(f.DstIP)
		proto, okProto := normaliseProtocol(f.Protocol)
		if !okSrc || !okDst || !okProto || f.DstPort < 0 || f.DstPort > 65535 {
			rejected++
			continue
		}
		if f.OrigBytes < 0 || f.ReplyBytes < 0 || f.OrigPackets < 0 || f.ReplyPackets < 0 {
			rejected++
			continue
		}

		ob, rb, op, rp := f.OrigBytes, f.ReplyBytes, f.OrigPackets, f.ReplyPackets
		var pob, prb, pop, prp int64
		err := read.QueryRow(routerID, bucket, src, dst, f.DstPort, proto).Scan(&pob, &prb, &pop, &prp)
		switch {
		case err == sql.ErrNoRows:
			// first sighting of this tuple in this hour
		case err != nil:
			rejected++
			continue
		default:
			// Counters that went backwards mean conntrack evicted the entry and
			// a new flow reused the tuple. The earlier total is real traffic and
			// is kept by adding rather than replacing.
			if ob < pob || rb < prb {
				ob, rb = pob+ob, prb+rb
				op, rp = pop+op, prp+rp
			} else if ob == pob && rb == prb {
				// nothing moved since the last poll; only last_seen advances
				op, rp = pop, prp
			}
		}

		if _, err := write.Exec(routerID, bucket, src, dst, f.DstPort, proto, ob, rb, op, rp, now.UTC(), now.UTC()); err != nil {
			rejected++
			continue
		}
		accepted++
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return accepted, rejected, nil
}

// TouchRouterSource records that a gateway reported, and what came of it.
func (s *Store) TouchRouterSource(routerID, label, result string, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO router_sources (id, label, last_seen_at, last_result)
		VALUES (?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET label=excluded.label, last_seen_at=excluded.last_seen_at, last_result=excluded.last_result`,
		clampField(routerID), clampField(label), now.UTC(), clampField(result))
	return err
}

// RouterFlowFilter narrows a flow query.
type RouterFlowFilter struct {
	SrcIP string
	DstIP string
	Since time.Time
	Limit int
}

// ListRouterFlows returns stored rollups, newest bucket first.
func (s *Store) ListRouterFlows(f RouterFlowFilter) ([]RouterFlowRow, error) {
	q := `SELECT router_id, bucket, src_ip, dst_ip, dst_port, protocol,
		orig_bytes, reply_bytes, orig_packets, reply_packets, first_seen_at, last_seen_at
		FROM router_flows WHERE 1=1`
	args := []interface{}{}
	if f.SrcIP != "" {
		q += " AND src_ip = ?"
		args = append(args, f.SrcIP)
	}
	if f.DstIP != "" {
		q += " AND dst_ip = ?"
		args = append(args, f.DstIP)
	}
	if !f.Since.IsZero() {
		q += " AND bucket >= ?"
		args = append(args, f.Since.UTC().Truncate(time.Hour).Unix())
	}
	limit := f.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q += " ORDER BY bucket DESC, orig_bytes + reply_bytes DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []RouterFlowRow{}
	for rows.Next() {
		var r RouterFlowRow
		var bucket int64
		if err := rows.Scan(&r.RouterID, &bucket, &r.SrcIP, &r.DstIP, &r.DstPort, &r.Protocol,
			&r.OrigBytes, &r.ReplyBytes, &r.OrigPackets, &r.ReplyPackets, &r.FirstSeenAt, &r.LastSeenAt); err != nil {
			return nil, err
		}
		r.Bucket = time.Unix(bucket, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// RouterTalker is one device summarised by what it talked to.
type RouterTalker struct {
	IP            string   `json:"ip"`
	Conversations int      `json:"conversations"`
	Bytes         int64    `json:"bytes"`
	Destinations  []string `json:"destinations"`
}

// SummariseRouterTalkers answers the question the whole ingest exists for: of the
// devices that can never carry an agent, which ones are talking, and to whom.
func (s *Store) SummariseRouterTalkers(since time.Time, limit int) ([]RouterTalker, error) {
	networks, err := s.TopologyNetworks()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT src_ip, dst_ip, SUM(orig_bytes + reply_bytes) AS b
		FROM router_flows WHERE bucket >= ?
 AND NOT EXISTS (SELECT 1 FROM assets WHERE assets.ip = router_flows.dst_ip)
 GROUP BY src_ip, dst_ip`,
		since.UTC().Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byIP := map[string]*RouterTalker{}
	for rows.Next() {
		var src, dst string
		var b int64
		if err := rows.Scan(&src, &dst, &b); err != nil {
			return nil, err
		}
		if netaddr.IsLocal(dst) {
			continue
		}
		node := TopologyNode{IP: dst}
		describeTopologyNetwork(&node, networks)
		if node.EstateMember || node.AddressScope == "invalid" {
			continue
		}
		t, ok := byIP[src]
		if !ok {
			t = &RouterTalker{IP: src}
			byIP[src] = t
		}
		t.Conversations++
		t.Bytes += b
		if len(t.Destinations) < 20 {
			t.Destinations = append(t.Destinations, dst)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RouterTalker, 0, len(byIP))
	for _, t := range byIP {
		sort.Strings(t.Destinations)
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// PruneOldRouterFlows drops rollups past their retention.
func (s *Store) PruneOldRouterFlows(olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneRouterFlowsLocked(olderThan)
}

// pruneRouterFlowsLocked is the body, for callers that already hold the lock.
func (s *Store) pruneRouterFlowsLocked(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Truncate(time.Hour)
	res, err := s.db.Exec(`DELETE FROM router_flows WHERE bucket < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
