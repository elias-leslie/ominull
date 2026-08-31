package storage

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
The asset graph.

Before this table there were two identity models with no join: agented hosts
were `endpoints` rows keyed by id, and scanned hosts were an in-memory map in
the scanner keyed by IP. A hub restart erased every discovery, and nothing
could join against them, which is why Fleet, Scanner and Topology were three
pages that disagreed with each other.

An asset is keyed on stable identity — MAC where we know one, otherwise
IP + subnet — and carries a nullable agent_endpoint_id. Every field is stored
as a *claim* with a source and a confidence rather than as a column, so:

  - the merge is per field, never per record: the agent can own `hostname`
    while a scan owns `vendor`;
  - losing claims survive, so an operator can see that the scanner said
    "Linux" while the agent says "Ubuntu 24.04";
  - installing an agent on a host we already discovered enriches that row
    instead of creating a second one.
*/

// Claim sources, most to least authoritative. Historical inferred claims have
// no current rank: they remain readable in the database but cannot become
// present-day identity or evidence.
const (
	SourceOperator = "operator"
	SourceAgent    = "agent"
	SourceScan     = "scan"
	SourceInferred = "inferred"
)

// Fields carried as claims. Anything an operator can be shown two opinions
// about belongs here; anything structural (ip, mac, tenant) stays a column.
const (
	FieldHostname = "hostname"
	FieldOS       = "os"
	FieldVendor   = "vendor"
	FieldCategory = "category"
	FieldRole     = "role"
	FieldRisk     = "risk"
)

// sourceRank groups current claims into precedence bands.
func sourceRank(source string) int {
	switch source {
	case SourceOperator:
		return 3
	case SourceAgent:
		return 2
	case SourceScan:
		return 1
	}
	return 0
}

// AssetClaim is one source's opinion about one field.
type AssetClaim struct {
	Field      string    `json:"field"`
	Source     string    `json:"source"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	Rationale  string    `json:"rationale,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Winner     bool      `json:"winner"`
}

// AssetPort is one open port observed by a scan.
type AssetPort struct {
	Port      int     `json:"port"`
	Protocol  string  `json:"protocol"`
	Service   string  `json:"service"`
	Banner    string  `json:"banner"`
	RiskLevel string  `json:"risk_level"`
	LatencyMs float64 `json:"latency_ms"`
}

// Asset is one host on the network, however we came to know about it.
type Asset struct {
	ID              string    `json:"id"`
	IdentityKind    string    `json:"identity_kind"` // "mac" or "ip"
	IdentityValue   string    `json:"identity_value"`
	AgentEndpointID string    `json:"agent_endpoint_id"`
	TenantID        string    `json:"tenant_id"`
	LocationID      string    `json:"location_id"`
	IP              string    `json:"ip"`
	MAC             string    `json:"mac"`
	Subnet          string    `json:"subnet"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`

	// Merged view: the winning claim per field.
	Hostname  string  `json:"hostname"`
	OS        string  `json:"os"`
	Vendor    string  `json:"vendor"`
	Category  string  `json:"category"`
	Role      string  `json:"role"`
	RiskScore string  `json:"risk_score"`
	RoleConf  float64 `json:"role_confidence"`
	Rationale string  `json:"rationale,omitempty"`

	Sources []string     `json:"sources"`
	Claims  []AssetClaim `json:"claims"`
	Ports   []AssetPort  `json:"ports"`
}

// HasAgent reports whether an agent reports for this asset.
func (a Asset) HasAgent() bool { return a.AgentEndpointID != "" }

func (s *Store) initAssetSchema() error {
	// Additive only. Nothing here touches the endpoints table: an existing
	// hub upgrades by gaining three tables, and every endpoint row is
	// projected into an asset the next time the agent checks in.
	schema := `
	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		identity_kind TEXT NOT NULL,
		identity_value TEXT NOT NULL,
		agent_endpoint_id TEXT,
		tenant_id TEXT NOT NULL DEFAULT 'default',
		location_id TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		mac TEXT NOT NULL DEFAULT '',
		subnet TEXT NOT NULL DEFAULT '',
		first_seen_at DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS asset_claims (
		asset_id TEXT NOT NULL,
		field TEXT NOT NULL,
		source TEXT NOT NULL,
		value TEXT NOT NULL,
		confidence REAL NOT NULL DEFAULT 0,
		rationale TEXT NOT NULL DEFAULT '',
		observed_at DATETIME NOT NULL,
		PRIMARY KEY (asset_id, field, source)
	);

	CREATE TABLE IF NOT EXISTS asset_ports (
		asset_id TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL DEFAULT 'tcp',
		service TEXT NOT NULL DEFAULT '',
		banner TEXT NOT NULL DEFAULT '',
		risk_level TEXT NOT NULL DEFAULT 'CLEAN',
		latency_ms REAL NOT NULL DEFAULT 0,
		observed_at DATETIME NOT NULL,
		PRIMARY KEY (asset_id, port, protocol)
	);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_identity ON assets(identity_kind, identity_value);
	CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
	CREATE INDEX IF NOT EXISTS idx_assets_endpoint ON assets(agent_endpoint_id);
	CREATE INDEX IF NOT EXISTS idx_asset_claims_asset ON asset_claims(asset_id);
	CREATE INDEX IF NOT EXISTS idx_asset_ports_asset ON asset_ports(asset_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

/* ------------------------------------------------------------- identity */

// NormalizeMAC returns a lowercase colon-separated MAC, or "" when the input
// is not a usable hardware address. All-zero and broadcast addresses are
// rejected: both appear in ARP tables and neither identifies a host.
func NormalizeMAC(mac string) string {
	var hex strings.Builder
	for _, r := range strings.ToLower(mac) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
		default:
			return ""
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return ""
	}
	if h == "000000000000" || h == "ffffffffffff" {
		return ""
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = h[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

// SubnetOf derives the /24 an IPv4 address sits in. Subnet is only ever used
// to disambiguate IP-keyed identities, so an approximation that is stable per
// address is worth more here than one that needs the real prefix length.
func SubnetOf(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 {
			return ""
		}
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

// AssetIdentity returns the stable key for a host: its MAC where one is
// known, otherwise its address inside a subnet. Identity is what survives a
// hub restart and what a second source joins against.
func AssetIdentity(mac, ip, subnet string) (kind, value string) {
	if m := NormalizeMAC(mac); m != "" {
		return "mac", m
	}
	if subnet == "" {
		subnet = SubnetOf(ip)
	}
	return "ip", ip + "|" + subnet
}

func assetIDFor(kind, value string) string {
	safe := strings.NewReplacer(":", "", "|", "-", "/", "-", ".", "-").Replace(value)
	return "asset-" + kind + "-" + safe
}

// addressSortKey zero-pads a dotted quad so string ordering matches numeric
// ordering. Row order must be stable on identity — never on last_seen_at —
// because rows that reshuffle under the cursor make an isolate click land on
// the wrong host.
func addressSortKey(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "9|" + ip
	}
	out := make([]string, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "9|" + ip
		}
		out[i] = fmt.Sprintf("%03d", n)
	}
	return "0|" + strings.Join(out, ".")
}

/* --------------------------------------------------------------- writes */

// resolveAssetIDLocked finds the asset a (mac, ip, endpoint) triple belongs
// to, creating it when it is new.
//
// The lookup order is what keeps one row per host. An agent installing on a
// host the scanner already found arrives with a MAC the scanner also saw, or
// at least with its IP; either way we land on the existing row and promote it
// to MAC identity rather than opening a second record for the same machine.
func (s *Store) resolveAssetIDLocked(mac, ip, subnet, agentEndpointID string, now time.Time) (string, error) {
	normMAC := NormalizeMAC(mac)
	if subnet == "" {
		subnet = SubnetOf(ip)
	}

	var id string

	if agentEndpointID != "" {
		err := s.db.QueryRow(`SELECT id FROM assets WHERE agent_endpoint_id = ?`, agentEndpointID).Scan(&id)
		if err == nil && id != "" {
			return id, s.reidentifyAssetLocked(id, normMAC, ip, subnet, agentEndpointID, now)
		} else if err != nil && err != sql.ErrNoRows {
			return "", err
		}
	}

	if normMAC != "" {
		err := s.db.QueryRow(`SELECT id FROM assets WHERE identity_kind = 'mac' AND identity_value = ?`, normMAC).Scan(&id)
		if err == nil && id != "" {
			return id, s.reidentifyAssetLocked(id, normMAC, ip, subnet, agentEndpointID, now)
		} else if err != nil && err != sql.ErrNoRows {
			return "", err
		}
	}

	if ip != "" {
		err := s.db.QueryRow(`SELECT id FROM assets WHERE identity_kind = 'ip' AND identity_value = ?`, ip+"|"+subnet).Scan(&id)
		if err == nil && id != "" {
			return id, s.reidentifyAssetLocked(id, normMAC, ip, subnet, agentEndpointID, now)
		} else if err != nil && err != sql.ErrNoRows {
			return "", err
		}
	}

	// Last join before giving up: an address we already know, on a row that
	// is keyed by MAC. This is how a flow-only observation — which never has
	// a hardware address — lands on the host the scanner or the agent
	// already established, instead of forking a second record for it. Only
	// safe in that direction: an observation that carries its own MAC has
	// already been matched above.
	if normMAC == "" && ip != "" {
		err := s.db.QueryRow(`
			SELECT id FROM assets
			WHERE ip = ? AND (subnet = ? OR subnet = '' OR ? = '')
			ORDER BY CASE WHEN agent_endpoint_id IS NOT NULL THEN 0 ELSE 1 END, last_seen_at DESC
			LIMIT 1`, ip, subnet, subnet).Scan(&id)
		if err == nil && id != "" {
			return id, s.reidentifyAssetLocked(id, "", ip, subnet, agentEndpointID, now)
		} else if err != nil && err != sql.ErrNoRows {
			return "", err
		}
	}

	kind, value := AssetIdentity(mac, ip, subnet)
	id = assetIDFor(kind, value)
	_, err := s.db.Exec(`
		INSERT INTO assets (id, identity_kind, identity_value, agent_endpoint_id, tenant_id, location_id, ip, mac, subnet, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, 'default', '', ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		id, kind, value, nullIfEmpty(agentEndpointID), ip, normMAC, subnet, now, now)
	if err != nil {
		return "", err
	}
	return id, nil
}

// reidentifyAssetLocked folds newly learned facts into an existing row. The
// interesting case is identity promotion: a host first seen as an IP gains a
// MAC, and the row's key moves with it so the next sighting from either
// source still lands here.
func (s *Store) reidentifyAssetLocked(id, normMAC, ip, subnet, agentEndpointID string, now time.Time) error {
	if normMAC != "" {
		// Promote to MAC identity unless another row already owns that MAC,
		// in which case leave this row's key alone rather than collide.
		var owner string
		err := s.db.QueryRow(`SELECT id FROM assets WHERE identity_kind = 'mac' AND identity_value = ?`, normMAC).Scan(&owner)
		if err == sql.ErrNoRows {
			if _, err := s.db.Exec(
				`UPDATE assets SET identity_kind = 'mac', identity_value = ?, mac = ? WHERE id = ?`,
				normMAC, normMAC, id); err != nil {
				return err
			}
		} else if err == nil && owner == id {
			if _, err := s.db.Exec(`UPDATE assets SET mac = ? WHERE id = ?`, normMAC, id); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`
		UPDATE assets SET
			ip = CASE WHEN ? != '' THEN ? ELSE ip END,
			subnet = CASE WHEN ? != '' THEN ? ELSE subnet END,
			agent_endpoint_id = CASE WHEN ? != '' THEN ? ELSE agent_endpoint_id END,
			last_seen_at = ?
		WHERE id = ?`,
		ip, ip, subnet, subnet, agentEndpointID, agentEndpointID, now, id)
	return err
}

func nullIfEmpty(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// putClaimLocked records one source's opinion. Claims are keyed on
// (asset, field, source), so a source revises its own opinion and never
// overwrites another's.
func (s *Store) putClaimLocked(assetID, field, source, value string, confidence float64, rationale string, now time.Time) error {
	if value == "" {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO asset_claims (asset_id, field, source, value, confidence, rationale, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asset_id, field, source) DO UPDATE SET
			value = excluded.value,
			confidence = excluded.confidence,
			rationale = excluded.rationale,
			observed_at = excluded.observed_at`,
		assetID, field, source, value, confidence, rationale, now)
	return err
}

// upsertAssetFromEndpointLocked projects an agent check-in onto the asset
// graph. Callers already hold s.mu.
func (s *Store) upsertAssetFromEndpointLocked(ep Endpoint) error {
	now := ep.LastSeenAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	id, err := s.resolveAssetIDLocked(ep.MAC, ep.IP, "", ep.ID, now)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(
		`UPDATE assets SET tenant_id = ?, location_id = CASE WHEN ? != '' THEN ? ELSE location_id END WHERE id = ?`,
		ep.TenantID, ep.LocationID, ep.LocationID, id); err != nil {
		return err
	}

	// The agent is ground truth for what it can see directly.
	if err := s.putClaimLocked(id, FieldHostname, SourceAgent, ep.Hostname, 1.0, "", now); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldOS, SourceAgent, ep.OS, 1.0, "", now); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldRole, SourceAgent, ep.RoleTag, 1.0, "operator-assigned role tag on the agent", now); err != nil {
		return err
	}
	return nil
}

// UpsertAssetFromScan records a probe result. This is what makes discovery
// survive a hub restart: the scanner's in-memory cache is now a cache of
// this table rather than the only copy.
func (s *Store) UpsertAssetFromScan(ip, mac, vendor, hostname, osGuess, category, risk string, confidence float64, ports []AssetPort, seen time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	id, err := s.resolveAssetIDLocked(mac, ip, "", "", seen)
	if err != nil {
		return err
	}

	// A scan's confidence is its fingerprint confidence; vendor comes from
	// the OUI and is worth more than the OS guess derived from it.
	if err := s.putClaimLocked(id, FieldHostname, SourceScan, hostname, confidence, "reverse lookup during probe", seen); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldOS, SourceScan, osGuess, confidence, "TTL and application-delta fingerprint", seen); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldVendor, SourceScan, vendor, 0.9, "OUI lookup on the hardware address", seen); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldCategory, SourceScan, category, confidence, "device signature match on open ports and banners", seen); err != nil {
		return err
	}
	if err := s.putClaimLocked(id, FieldRisk, SourceScan, risk, confidence, "exposure assessment of open ports", seen); err != nil {
		return err
	}

	if _, err := s.db.Exec(`DELETE FROM asset_ports WHERE asset_id = ?`, id); err != nil {
		return err
	}
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		if _, err := s.db.Exec(`
			INSERT INTO asset_ports (asset_id, port, protocol, service, banner, risk_level, latency_ms, observed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
				service = excluded.service,
				banner = excluded.banner,
				risk_level = excluded.risk_level,
				latency_ms = excluded.latency_ms,
				observed_at = excluded.observed_at`,
			id, p.Port, proto, p.Service, p.Banner, p.RiskLevel, p.LatencyMs, seen); err != nil {
			return err
		}
	}
	return nil
}

// UpsertInferredAsset is retained only to preserve historical rows during an
// upgrade. New telemetry never calls it, and mergeClaims excludes this source
// from current identity.
func (s *Store) UpsertInferredAsset(ip, role string, confidence float64, rationale string, seen time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	id, err := s.resolveAssetIDLocked("", ip, "", "", seen)
	if err != nil {
		return err
	}
	return s.putClaimLocked(id, FieldRole, SourceInferred, role, confidence, rationale, seen)
}

// CorrectAsset records an operator's correction. Corrections outrank every
// other source permanently, which is why they are stored as a claim rather
// than applied as an edit. Historical claims stay beside the correction that
// overruled them.
func (s *Store) CorrectAsset(assetID, field, value, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if reason == "" {
		reason = "operator correction"
	}
	return s.putClaimLocked(assetID, field, SourceOperator, value, 1.0, reason, now)
}

// DropClaim removes one source's opinion about one field. Used when an
// operator withdraws a correction, so the remaining evidence decides again.
func (s *Store) DropClaim(assetID, field, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM asset_claims WHERE asset_id = ? AND field = ? AND source = ?`, assetID, field, source)
	return err
}

/* ---------------------------------------------------------------- reads */

// mergeClaims settles every field and marks the winners in place. Highest
// confidence wins per field, never per record — an agent owning `hostname`
// does not stop a scan owning `vendor`.
func mergeClaims(a *Asset, claims []AssetClaim) {
	best := make(map[string]int)
	for i := range claims {
		c := claims[i]
		if sourceRank(c.Source) == 0 {
			continue
		}
		j, seen := best[c.Field]
		if !seen {
			best[c.Field] = i
			continue
		}
		prev := claims[j]
		if sourceRank(c.Source) > sourceRank(prev.Source) ||
			(sourceRank(c.Source) == sourceRank(prev.Source) && c.Confidence > prev.Confidence) ||
			(sourceRank(c.Source) == sourceRank(prev.Source) && c.Confidence == prev.Confidence && c.Source == SourceScan) {
			best[c.Field] = i
		}
	}
	for _, i := range best {
		claims[i].Winner = true
		switch claims[i].Field {
		case FieldHostname:
			a.Hostname = claims[i].Value
		case FieldOS:
			a.OS = claims[i].Value
		case FieldVendor:
			a.Vendor = claims[i].Value
		case FieldCategory:
			a.Category = claims[i].Value
		case FieldRole:
			a.Role = claims[i].Value
			a.RoleConf = claims[i].Confidence
			a.Rationale = claims[i].Rationale
		case FieldRisk:
			a.RiskScore = claims[i].Value
		}
	}
	// Claims render in the expanded row, so give them a stable order:
	// field, then most authoritative source first.
	sort.SliceStable(claims, func(i, j int) bool {
		if claims[i].Field != claims[j].Field {
			return claims[i].Field < claims[j].Field
		}
		if sourceRank(claims[i].Source) != sourceRank(claims[j].Source) {
			return sourceRank(claims[i].Source) > sourceRank(claims[j].Source)
		}
		return claims[i].Confidence > claims[j].Confidence
	})
	a.Claims = claims

	seenSource := make(map[string]bool)
	for _, c := range claims {
		seenSource[c.Source] = true
	}
	for _, src := range []string{SourceAgent, SourceScan, SourceOperator} {
		if seenSource[src] {
			a.Sources = append(a.Sources, src)
		}
	}
}

// ListAssets returns the whole asset graph, merged. tenantID filters when
// non-empty; assets discovered before any client owns them carry the default
// tenant and are always returned.
func (s *Store) ListAssets(tenantID string) ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, identity_kind, identity_value, COALESCE(agent_endpoint_id, ''), tenant_id,
		         location_id, ip, mac, subnet, first_seen_at, last_seen_at
		  FROM assets`
	args := []interface{}{}
	if tenantID != "" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assets := make([]Asset, 0)
	index := make(map[string]int)
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.IdentityKind, &a.IdentityValue, &a.AgentEndpointID, &a.TenantID,
			&a.LocationID, &a.IP, &a.MAC, &a.Subnet, &a.FirstSeenAt, &a.LastSeenAt); err != nil {
			continue
		}
		a.Claims = make([]AssetClaim, 0)
		a.Ports = make([]AssetPort, 0)
		a.Sources = make([]string, 0, 4)
		index[a.ID] = len(assets)
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		return assets, nil
	}

	claimsByAsset := make(map[string][]AssetClaim)
	claimRows, err := s.db.Query(`SELECT asset_id, field, source, value, confidence, rationale, observed_at FROM asset_claims`)
	if err != nil {
		return nil, err
	}
	for claimRows.Next() {
		var id string
		var c AssetClaim
		if err := claimRows.Scan(&id, &c.Field, &c.Source, &c.Value, &c.Confidence, &c.Rationale, &c.ObservedAt); err != nil {
			continue
		}
		claimsByAsset[id] = append(claimsByAsset[id], c)
	}
	claimRows.Close()

	portRows, err := s.db.Query(`SELECT asset_id, port, protocol, service, banner, risk_level, latency_ms FROM asset_ports ORDER BY port ASC`)
	if err != nil {
		return nil, err
	}
	for portRows.Next() {
		var id string
		var p AssetPort
		if err := portRows.Scan(&id, &p.Port, &p.Protocol, &p.Service, &p.Banner, &p.RiskLevel, &p.LatencyMs); err != nil {
			continue
		}
		if i, ok := index[id]; ok {
			assets[i].Ports = append(assets[i].Ports, p)
		}
	}
	portRows.Close()

	for i := range assets {
		mergeClaims(&assets[i], claimsByAsset[assets[i].ID])
	}

	// Stable identity ordering, never last_seen_at.
	sort.SliceStable(assets, func(i, j int) bool {
		ki := addressSortKey(assets[i].IP) + "|" + assets[i].ID
		kj := addressSortKey(assets[j].IP) + "|" + assets[j].ID
		return ki < kj
	})
	return assets, nil
}

// GetAsset returns one asset by id, or by IP when the caller only has an
// address (the console's context menu works from a row, the palette from a
// typed address).
func (s *Store) GetAsset(idOrIP string) (*Asset, error) {
	assets, err := s.ListAssets("")
	if err != nil {
		return nil, err
	}
	for i := range assets {
		if assets[i].ID == idOrIP || assets[i].IP == idOrIP {
			return &assets[i], nil
		}
	}
	return nil, fmt.Errorf("asset %q not found", idOrIP)
}

// BackfillAssetsFromEndpoints projects every existing endpoint into the asset
// graph. Called once at startup so a hub that upgrades into this schema shows
// its whole fleet immediately rather than one host per agent check-in.
func (s *Store) BackfillAssetsFromEndpoints() error {
	eps, err := s.ListEndpoints("")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ep := range eps {
		if err := s.upsertAssetFromEndpointLocked(ep); err != nil {
			return err
		}
	}
	return nil
}
