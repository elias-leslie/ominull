package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	APIKey    string    `json:"api_key"`
	CreatedAt time.Time `json:"created_at"`
}

type Location struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	SubnetCIDR string    `json:"subnet_cidr"`
	CreatedAt  time.Time `json:"created_at"`
}

type Endpoint struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	LocationID        string `json:"location_id"`
	LocationName      string `json:"location_name"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
	IP                string `json:"ip"`
	MAC               string `json:"mac"`
	RoleTag           string `json:"role_tag"`
	InstalledSoftware string `json:"installed_software"`
	DriverVersion     string `json:"driver_version"`
	// UpdateCapability is the package format this endpoint can install for
	// itself: "deb", "pkg", "exe", or "none". The agent reports it, because
	// the OS string is a display label and not a contract - matching on it is
	// one string change away from silently misrouting a fleet-wide update.
	// An agent that reports nothing is "none" and is never offered a package.
	UpdateCapability string `json:"update_capability"`
	Status           string `json:"status"` // online, offline
	// CertCN is the common name of the client certificate this endpoint last
	// reported under, or empty if it has only ever reported under the tenant
	// API key. It is what tells an operator whether the fleet is ready for
	// --client-certs required, which otherwise has to be discovered by turning
	// it on and seeing who falls off.
	CertCN     string    `json:"cert_cn"`
	IsIsolated bool      `json:"is_isolated"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type Event struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EndpointID  string    `json:"endpoint_id"`
	Timestamp   time.Time `json:"timestamp"`
	Layer       string    `json:"layer"`
	Action      string    `json:"action"`    // PERMIT, BLOCK
	Direction   string    `json:"direction"` // INBOUND, OUTBOUND
	Protocol    uint8     `json:"protocol"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	Country     string    `json:"country"`
	ProcessPath string    `json:"process_path"`
	ProcessID   uint32    `json:"process_id"`
	Domain      string    `json:"domain,omitempty"`
	SNI         string    `json:"sni,omitempty"`
}

type CommProfile struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	LocationID    string    `json:"location_id"`
	EndpointID    string    `json:"endpoint_id"`
	Hostname      string    `json:"hostname"`
	ProcessName   string    `json:"process_name"`
	ProcessPath   string    `json:"process_path"`
	DstIP         string    `json:"dst_ip"`
	DstPort       uint16    `json:"dst_port"`
	Protocol      string    `json:"protocol"`
	Direction     string    `json:"direction"`
	Country       string    `json:"country"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	EventCount    int64     `json:"event_count"`
	TotalBytesIn  int64     `json:"total_bytes_in"`
	TotalBytesOut int64     `json:"total_bytes_out"`
	IsBaseline    bool      `json:"is_baseline"`
}

type Exclusion struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Scope       string    `json:"scope"`       // "global", "client", "location", "endpoint"
	ScopeValue  string    `json:"scope_value"` // tenant_id, location_id, or endpoint_id
	Name        string    `json:"name"`
	ProcessPath string    `json:"process_path"`
	DstIPRange  string    `json:"dst_ip_range"`
	Port        uint16    `json:"port"`
	Protocol    string    `json:"protocol"`
	Reason      string    `json:"reason"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

type AnomalyAlert struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	LocationID   string    `json:"location_id"`
	EndpointID   string    `json:"endpoint_id"`
	Hostname     string    `json:"hostname"`
	AnomalyType  string    `json:"anomaly_type"` // "NOVEL_PROCESS_EGRESS", "UNUSUAL_PORT", "BANDWIDTH_SPIKE", "NOVEL_COUNTRY"
	Severity     string    `json:"severity"`     // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Details      string    `json:"details"`
	ProcessPath  string    `json:"process_path"`
	DstIP        string    `json:"dst_ip"`
	DstPort      uint16    `json:"dst_port"`
	Timestamp    time.Time `json:"timestamp"`
	Acknowledged bool      `json:"acknowledged"`
}

type IOC struct {
	ID         string    `json:"id"`
	Value      string    `json:"value"`
	Type       string    `json:"type"`        // "ipv4", "cidr", "domain", "hash"
	Source     string    `json:"source"`      // "feodo", "emerging_threats", "custom"
	ThreatType string    `json:"threat_type"` // "c2", "malware_dist", "scanner"
	Confidence int       `json:"confidence"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type Rule struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // "ip", "cidr", "domain", "process", "port"
	Value      string    `json:"value"`
	Port       uint16    `json:"port"`
	Protocol   string    `json:"protocol"` // "tcp", "udp", "any"
	Action     string    `json:"action"`   // "BLOCK", "PERMIT"
	Scope      string    `json:"scope"`    // "all", "platform", "department", "ids", "group"
	ScopeValue string    `json:"scope_value"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
}

type PolicyGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Scope       string    `json:"scope"`       // "global", "client", "location", "endpoint", "role"
	ScopeValue  string    `json:"scope_value"` // tenant_id, location_id, endpoint_id, or role
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Schedule    string    `json:"schedule"`  // "all", "business_hours", "off_hours"
	Criteria    string    `json:"criteria"`  // JSON string: {"os":"windows","role":"db-server","subnet":"10.0.0.0/24","process":"powershell"}
	Action      string    `json:"action"`    // BLOCK, PERMIT, ISOLATE, ALERT, THROTTLE
	RuleType    string    `json:"rule_type"` // "ip", "cidr", "process", "port", "domain"
	RuleValue   string    `json:"rule_value"`
	Port        uint16    `json:"port"`
	Protocol    string    `json:"protocol"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

type HierarchyClient struct {
	Tenant         Tenant              `json:"tenant"`
	Locations      []HierarchyLocation `json:"locations"`
	TotalEndpoints int                 `json:"total_endpoints"`
	IsolatedCount  int                 `json:"isolated_count"`
}

type HierarchyLocation struct {
	Location       Location   `json:"location"`
	Endpoints      []Endpoint `json:"endpoints"`
	TotalEndpoints int        `json:"total_endpoints"`
	IsolatedCount  int        `json:"isolated_count"`
}

type TopTalker struct {
	Process    string `json:"process"`
	FlowCount  int64  `json:"flow_count"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	TotalBytes int64  `json:"total_bytes"`
}

type GeoCountryStat struct {
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	FlowCount   int64  `json:"flow_count"`
	TotalBytes  int64  `json:"total_bytes"`
	ThreatCount int64  `json:"threat_count"`
}

type QuarantinedPeer struct {
	ID        string    `json:"id"`
	TargetIP  string    `json:"target_ip"`
	TargetMAC string    `json:"target_mac"`
	Subnet    string    `json:"subnet"`
	Reason    string    `json:"reason"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type TopologyNode struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Type       string   `json:"type"` // "managed", "unmanaged", "cloud", "threat", "gateway"
	IP         string   `json:"ip"`
	OS         string   `json:"os"`
	Role       string   `json:"role"`
	Risk       string   `json:"risk"` // "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
	IsIsolated bool     `json:"is_isolated"`
	Group      string   `json:"group"`
	AssetID    string   `json:"asset_id,omitempty"`
	Evidence   []string `json:"evidence"` // agent / scan / inferred / operator
	Confidence float64  `json:"confidence,omitempty"`
	Rationale  string   `json:"rationale,omitempty"`
	// Quiet marks a known asset that said nothing inside the window. Absence
	// is information on a security graph, so it is dimmed, never omitted.
	Quiet bool `json:"quiet"`
}

// TopologyEdgePort is one port's share of an asset pair's traffic. Edges
// aggregate to the pair and carry their ports, so the graph stays readable at
// fleet scale and the detail is still one selection away.
type TopologyEdgePort struct {
	Port       uint16 `json:"port"`
	Protocol   string `json:"protocol"`
	FlowCount  int64  `json:"flow_count"`
	TotalBytes int64  `json:"total_bytes"`
	Verdict    string `json:"verdict"`
}

type TopologyEdge struct {
	ID         string             `json:"id"`
	Source     string             `json:"source"`
	Target     string             `json:"target"`
	Protocol   string             `json:"protocol"`
	Port       uint16             `json:"port"` // heaviest port on the pair
	FlowCount  int64              `json:"flow_count"`
	TotalBytes int64              `json:"total_bytes"`
	Verdict    string             `json:"verdict"` // "clean", "anomalous", "blocked"
	LastSeen   time.Time          `json:"last_seen"`
	Ports      []TopologyEdgePort `json:"ports"`
}

type TopologyMetrics struct {
	TotalNodes          int    `json:"total_nodes"`
	TotalEdges          int    `json:"total_edges"`
	AnomalousEdgeCount  int    `json:"anomalous_edge_count"`
	ManagedNodesCount   int    `json:"managed_nodes_count"`
	UnmanagedNodesCount int    `json:"unmanaged_nodes_count"`
	QuietNodesCount     int    `json:"quiet_nodes_count"`
	InferredNodesCount  int    `json:"inferred_nodes_count"`
	WindowLabel         string `json:"window_label"`
}

type TopologyData struct {
	Nodes   []TopologyNode  `json:"nodes"`
	Edges   []TopologyEdge  `json:"edges"`
	Metrics TopologyMetrics `json:"metrics"`
}

// CountryUnknown is where a flow the GeoIP stage could not place is recorded.
// It used to be recorded as "US".
const CountryUnknown = "UNKNOWN"

type AnalyticsSummary struct {
	TotalBytesIn      int64                `json:"total_bytes_in"`
	TotalBytesOut     int64                `json:"total_bytes_out"`
	TotalEvents       int64                `json:"total_events"`
	TotalBlocks       int64                `json:"total_blocks"`
	TotalPermits      int64                `json:"total_permits"`
	Countries         map[string]int64     `json:"countries"`
	TopProcesses      map[string]int64     `json:"top_processes"`
	SeverityCounts    map[string]int64     `json:"severity_counts"`
	EnforcementCounts map[string]int64     `json:"enforcement_counts"`
	BandwidthTimeline []BandwidthDataPoint `json:"bandwidth_timeline"`
	DiurnalBaseline   map[int]int64        `json:"diurnal_baseline"`
	DiurnalLive       map[int]int64        `json:"diurnal_live"`
	TopTalkers        []TopTalker          `json:"top_talkers"`
	GeoStats          []GeoCountryStat     `json:"geo_stats"`
}

type BandwidthDataPoint struct {
	Timestamp string `json:"timestamp"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	Blocks    int64  `json:"blocks"`
}

type Alert struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EndpointID  string    `json:"endpoint_id"`
	Timestamp   time.Time `json:"timestamp"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Mitigated   bool      `json:"mitigated"`
}

type AuditEntry struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"` // ISOLATE_HOST, ADD_RULE, REVOKE_RULE, SYNC_TI
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	Timestamp time.Time `json:"timestamp"`
}

type Store struct {
	db        *sql.DB
	mu        sync.RWMutex
	analytics analyticsCache
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init failed: %w", err)
	}

	s.seedDefaults()
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		api_key TEXT UNIQUE NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS locations (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		city TEXT NOT NULL DEFAULT "",
		country TEXT NOT NULL DEFAULT "UNKNOWN",
		subnet_cidr TEXT NOT NULL DEFAULT "",
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		location_id TEXT DEFAULT "",
		location_name TEXT DEFAULT "",
		hostname TEXT NOT NULL,
		os TEXT NOT NULL,
		ip TEXT NOT NULL,
		mac TEXT DEFAULT "",
		role_tag TEXT DEFAULT "workstation",
		installed_software TEXT DEFAULT "",
		driver_version TEXT NOT NULL,
		update_capability TEXT DEFAULT "",
		status TEXT NOT NULL,
		is_isolated INTEGER NOT NULL DEFAULT 0,
		cert_cn TEXT DEFAULT "",
		last_seen_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	-- One-shot credentials that authorise a single certificate enrolment.
	-- Only the digest is stored: a token read out of this table is of no use
	-- to whoever read it, which is the point of it being here rather than the
	-- token itself.
	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		token_hash TEXT PRIMARY KEY,
		endpoint_id TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS agent_update_jobs (
		endpoint_id TEXT PRIMARY KEY,
		desired_version TEXT NOT NULL,
		requested_at DATETIME NOT NULL,
		completed_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
		timestamp DATETIME NOT NULL,
		layer TEXT NOT NULL,
		action TEXT NOT NULL,
		direction TEXT NOT NULL,
		protocol INTEGER NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER NOT NULL,
		dst_port INTEGER NOT NULL,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		country TEXT NOT NULL DEFAULT "US",
		process_path TEXT NOT NULL,
		process_id INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS comm_profiles (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		location_id TEXT NOT NULL DEFAULT "",
		endpoint_id TEXT NOT NULL,
		hostname TEXT NOT NULL DEFAULT "",
		process_name TEXT NOT NULL,
		process_path TEXT NOT NULL DEFAULT "",
		dst_ip TEXT NOT NULL,
		dst_port INTEGER NOT NULL,
		protocol TEXT NOT NULL DEFAULT "tcp",
		direction TEXT NOT NULL DEFAULT "OUTBOUND",
		country TEXT NOT NULL DEFAULT "US",
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		event_count INTEGER NOT NULL DEFAULT 1,
		total_bytes_in INTEGER NOT NULL DEFAULT 0,
		total_bytes_out INTEGER NOT NULL DEFAULT 0,
		is_baseline INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS exclusions (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL DEFAULT "default",
		scope TEXT NOT NULL DEFAULT "global",
		scope_value TEXT NOT NULL DEFAULT "",
		name TEXT NOT NULL,
		process_path TEXT NOT NULL DEFAULT "*",
		dst_ip_range TEXT NOT NULL DEFAULT "*",
		port INTEGER NOT NULL DEFAULT 0,
		protocol TEXT NOT NULL DEFAULT "any",
		reason TEXT NOT NULL DEFAULT "",
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS anomaly_alerts (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		location_id TEXT NOT NULL DEFAULT "",
		endpoint_id TEXT NOT NULL,
		hostname TEXT NOT NULL DEFAULT "",
		anomaly_type TEXT NOT NULL,
		severity TEXT NOT NULL DEFAULT "HIGH",
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		details TEXT NOT NULL DEFAULT "",
		process_path TEXT NOT NULL DEFAULT "",
		dst_ip TEXT NOT NULL DEFAULT "",
		dst_port INTEGER NOT NULL DEFAULT 0,
		timestamp DATETIME NOT NULL,
		acknowledged INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS iocs (
		id TEXT PRIMARY KEY,
		value TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL,
		source TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		confidence INTEGER NOT NULL DEFAULT 80,
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		port INTEGER DEFAULT 0,
		protocol TEXT DEFAULT "any",
		action TEXT NOT NULL DEFAULT "BLOCK",
		scope TEXT NOT NULL DEFAULT "all",
		scope_value TEXT DEFAULT "",
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS policy_groups (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT "",
		criteria TEXT NOT NULL DEFAULT "{}",
		action TEXT NOT NULL DEFAULT "BLOCK",
		rule_type TEXT NOT NULL DEFAULT "ip",
		rule_value TEXT NOT NULL DEFAULT "",
		port INTEGER DEFAULT 0,
		protocol TEXT DEFAULT "any",
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
		timestamp DATETIME NOT NULL,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		mitigated INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		details TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS quarantined_peers (
		id TEXT PRIMARY KEY,
		target_ip TEXT NOT NULL UNIQUE,
		target_mac TEXT NOT NULL DEFAULT "",
		subnet TEXT NOT NULL DEFAULT "",
		reason TEXT NOT NULL DEFAULT "",
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_endpoint_time ON events(endpoint_id, timestamp DESC);
	-- timestamp on its own. The two composite indexes above lead on a scope
	-- column, so an operator query - which has no tenant filter - could not use
	-- either one and every time-bounded read fell back to a full scan: the
	-- bandwidth timeline and both halves of the diurnal profile were each
	-- re-reading the whole events table to answer a question about one day.
	CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_locations_tenant ON locations(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_comm_endpoint ON comm_profiles(endpoint_id);
	CREATE INDEX IF NOT EXISTS idx_comm_tenant ON comm_profiles(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_comm_loc ON comm_profiles(location_id);
	CREATE INDEX IF NOT EXISTS idx_exclusions_tenant ON exclusions(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_anomaly_time ON anomaly_alerts(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_policy_groups_tenant ON policy_groups(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs(value);
	CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_tenant_time ON alerts(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Dynamic column migrations
	migrations := []string{
		"ALTER TABLE endpoints ADD COLUMN location_id TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN location_name TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN mac TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN role_tag TEXT DEFAULT 'workstation'",
		"ALTER TABLE endpoints ADD COLUMN installed_software TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN update_capability TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN cert_cn TEXT DEFAULT ''",
		// The isolation allow list used to exist only inside a WebSocket
		// command payload. That channel was never registered, so the list was
		// built, validated and dropped. It is stored here because the agent now
		// reads its isolation state from its own heartbeat reply.
		"ALTER TABLE endpoints ADD COLUMN isolation_allow_ips TEXT DEFAULT ''",
		"ALTER TABLE events ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE events ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE events ADD COLUMN country TEXT NOT NULL DEFAULT 'US'",
		"ALTER TABLE events ADD COLUMN city TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE events ADD COLUMN asn TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE events ADD COLUMN org TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE events ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policy_groups ADD COLUMN scope TEXT NOT NULL DEFAULT 'global'",
		"ALTER TABLE policy_groups ADD COLUMN scope_value TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policy_groups ADD COLUMN schedule TEXT NOT NULL DEFAULT 'all'",
	}
	for _, m := range migrations {
		_, _ = s.db.Exec(m)
	}

	// The asset graph is additive: three new tables and their indexes. It
	// touches nothing above, so an existing hub upgrades without migrating a
	// single endpoints row.
	return s.initAssetSchema()
}

func (s *Store) seedDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	// Single Real Default Home Tenant with automatic 256-bit CSPRNG key generation
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM tenants WHERE id = 'default'").Scan(&count)
	if count == 0 {
		masterKey := os.Getenv("OMINULL_MASTER_KEY")
		if masterKey == "" {
			var tokenBytes [32]byte
			_, _ = rand.Read(tokenBytes[:])
			masterKey = "omi_live_" + hex.EncodeToString(tokenBytes[:])
		}
		defaultTenant := Tenant{
			ID:        "default",
			Name:      "Home Network",
			APIKey:    masterKey,
			CreatedAt: now,
		}
		_, _ = s.db.Exec("INSERT OR IGNORE INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)",
			defaultTenant.ID, defaultTenant.Name, defaultTenant.APIKey, defaultTenant.CreatedAt)
	}

	// Single Real Home Location
	homeLocation := Location{
		ID:         "loc-home",
		TenantID:   "default",
		Name:       "Primary Home LAN",
		City:       "Local",
		Country:    "US",
		SubnetCIDR: "10.0.0.0/24",
		CreatedAt:  now,
	}
	_, _ = s.db.Exec("INSERT OR IGNORE INTO locations (id, tenant_id, name, city, country, subnet_cidr, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		homeLocation.ID, homeLocation.TenantID, homeLocation.Name, homeLocation.City, homeLocation.Country, homeLocation.SubnetCIDR, homeLocation.CreatedAt)
}

func (s *Store) CreateTenant(t Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)",
		t.ID, t.Name, t.APIKey, t.CreatedAt,
	)
	return err
}

func (s *Store) GetTenantByAPIKey(apiKey string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var t Tenant
	err := s.db.QueryRow(
		"SELECT id, name, api_key, created_at FROM tenants WHERE api_key = ?",
		apiKey,
	).Scan(&t.ID, &t.Name, &t.APIKey, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) GetTenant(id string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var t Tenant
	err := s.db.QueryRow(
		"SELECT id, name, api_key, created_at FROM tenants WHERE id = ?",
		id,
	).Scan(&t.ID, &t.Name, &t.APIKey, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTenants() ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, name, api_key, created_at FROM tenants ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.APIKey, &t.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, nil
}

func (s *Store) CreateLocation(l Location) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"INSERT INTO locations (id, tenant_id, name, city, country, subnet_cidr, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		l.ID, l.TenantID, l.Name, l.City, l.Country, l.SubnetCIDR, l.CreatedAt,
	)
	return err
}

func (s *Store) ListLocations(tenantID string) ([]Location, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query("SELECT id, tenant_id, name, city, country, subnet_cidr, created_at FROM locations WHERE tenant_id = ? ORDER BY name ASC", tenantID)
	} else {
		rows, err = s.db.Query("SELECT id, tenant_id, name, city, country, subnet_cidr, created_at FROM locations ORDER BY name ASC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Location
	for rows.Next() {
		var l Location
		if err := rows.Scan(&l.ID, &l.TenantID, &l.Name, &l.City, &l.Country, &l.SubnetCIDR, &l.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, nil
}

func (s *Store) UpsertEndpoint(ep Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ep.TenantID == "" {
		ep.TenantID = "default"
	}

	if ep.LocationID == "" || ep.LocationID == "loc-hq" {
		// Resolve the first location for this tenant
		var locID, locName string
		row := s.db.QueryRow(`SELECT id, name FROM locations WHERE tenant_id = ? ORDER BY created_at ASC LIMIT 1`, ep.TenantID)
		if err := row.Scan(&locID, &locName); err == nil && locID != "" {
			ep.LocationID = locID
			ep.LocationName = locName
		} else {
			ep.LocationID = "loc-home"
			ep.LocationName = "Primary Home LAN"
		}
	} else if ep.LocationName == "" {
		var locName string
		row := s.db.QueryRow(`SELECT name FROM locations WHERE id = ?`, ep.LocationID)
		if err := row.Scan(&locName); err == nil && locName != "" {
			ep.LocationName = locName
		}
	}
	if ep.RoleTag == "" {
		ep.RoleTag = "workstation"
	}
	// A per-OS software list is a reasonable default for a host that reports
	// none. A per-OS *MAC* is not: asset identity keys on the hardware
	// address, so handing every Windows endpoint the same fabricated MAC
	// collapses the whole fleet onto one asset row. An unknown MAC stays
	// empty and identity falls back to address plus subnet.
	if ep.InstalledSoftware == "" {
		if strings.Contains(strings.ToLower(ep.OS), "windows") {
			ep.InstalledSoftware = "Ominull WFP Agent v1.0.0, PowerShell 7.4, Windows Defender, OpenSSH"
		} else if strings.Contains(strings.ToLower(ep.OS), "linux") || strings.Contains(strings.ToLower(ep.OS), "ubuntu") {
			ep.InstalledSoftware = "Ominull eBPF Daemon v1.0.0, Clang 18, bpftool, OpenSSH 9.6p1, systemd"
		} else if strings.Contains(strings.ToLower(ep.OS), "mac") || strings.Contains(strings.ToLower(ep.OS), "darwin") {
			ep.InstalledSoftware = "Ominull PF Engine v1.0.0, Zsh 5.9, Apple pfctl, OpenSSH"
		}
	}

	query := `
	INSERT INTO endpoints (id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, update_capability, status, is_isolated, last_seen_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		hostname=excluded.hostname,
		os=excluded.os,
		ip=excluded.ip,
		mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE endpoints.mac END,
		role_tag=CASE WHEN excluded.role_tag != '' THEN excluded.role_tag ELSE endpoints.role_tag END,
		installed_software=CASE WHEN excluded.installed_software != '' THEN excluded.installed_software ELSE endpoints.installed_software END,
		location_id=CASE WHEN excluded.location_id != '' THEN excluded.location_id ELSE endpoints.location_id END,
		location_name=CASE WHEN excluded.location_name != '' THEN excluded.location_name ELSE endpoints.location_name END,
		driver_version=excluded.driver_version,
		update_capability=CASE WHEN excluded.update_capability != '' THEN excluded.update_capability ELSE endpoints.update_capability END,
		status=excluded.status,
		last_seen_at=excluded.last_seen_at
	`
	if _, err := s.db.Exec(
		query,
		ep.ID, ep.TenantID, ep.LocationID, ep.LocationName, ep.Hostname, ep.OS, ep.IP, ep.MAC,
		ep.RoleTag, ep.InstalledSoftware, ep.DriverVersion, ep.UpdateCapability,
		ep.Status, ep.IsIsolated, ep.LastSeenAt, ep.CreatedAt,
	); err != nil {
		return err
	}

	// Project the check-in onto the asset graph. An agent arriving on a host
	// the scanner already found enriches that asset rather than opening a
	// second record for the same machine.
	return s.upsertAssetFromEndpointLocked(ep)
}

// SetEndpointIsolation records whether an endpoint is cut off, and what it may
// still reach while it is.
//
// The allow list is stored rather than only broadcast: an endpoint applies
// isolation from its own heartbeat reply, so the list has to survive until the
// next heartbeat, a hub restart, and an endpoint that was offline when the
// order was given. Releasing an endpoint clears it - a stale allow list is a
// hole in the next isolation.
func (s *Store) SetEndpointIsolation(id string, isIsolated bool, allowIPs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	allow := ""
	if isIsolated {
		val = 1
		allow = strings.Join(allowIPs, ",")
	}
	_, err := s.db.Exec("UPDATE endpoints SET is_isolated = ?, isolation_allow_ips = ? WHERE id = ?", val, allow, id)
	return err
}

// GetEndpointIsolation reads back what an endpoint should be enforcing. It is
// deliberately narrow: the heartbeat path needs these two columns on every
// request from every endpoint, and nothing else from the row.
func (s *Store) GetEndpointIsolation(id string) (bool, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var isoInt int
	var allow string
	err := s.db.QueryRow("SELECT is_isolated, COALESCE(isolation_allow_ips, '') FROM endpoints WHERE id = ?", id).Scan(&isoInt, &allow)
	if err != nil {
		return false, nil, err
	}
	var ips []string
	for _, part := range strings.Split(allow, ",") {
		if part = strings.TrimSpace(part); part != "" {
			ips = append(ips, part)
		}
	}
	return isoInt != 0, ips, nil
}

func (s *Store) SetBulkIsolation(tenantID string, scope string, value string, isIsolated bool, allowIPs []string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	allow := ""
	if isIsolated {
		val = 1
		allow = strings.Join(allowIPs, ",")
	}

	baseQuery := "UPDATE endpoints SET is_isolated = ?, isolation_allow_ips = ?"
	var args []interface{}
	args = append(args, val, allow)

	switch scope {
	case "all":
		if tenantID != "" {
			baseQuery += " WHERE tenant_id = ?"
			args = append(args, tenantID)
		}
	case "client":
		baseQuery += " WHERE tenant_id = ?"
		args = append(args, value)
	case "location":
		baseQuery += " WHERE location_id = ?"
		args = append(args, value)
	case "platform":
		baseQuery += " WHERE os LIKE ?"
		args = append(args, "%"+value+"%")
		if tenantID != "" {
			baseQuery += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
	case "role":
		baseQuery += " WHERE role_tag = ?"
		args = append(args, value)
		if tenantID != "" {
			baseQuery += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
	}

	res, err := s.db.Exec(baseQuery, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- Agent version tracking & remote update orchestration ----

// AgentUpdateJob tracks a requested remote agent update for one endpoint.
type AgentUpdateJob struct {
	EndpointID     string     `json:"endpoint_id"`
	DesiredVersion string     `json:"desired_version"`
	RequestedAt    time.Time  `json:"requested_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func (s *Store) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SetEndpointCertCN records the certificate an endpoint reported under, or
// clears it when the endpoint reports without one. It is written on every
// check-in rather than only on change: a fleet that quietly stopped presenting
// certificates would otherwise keep showing the last one it ever sent, which is
// the reading an operator would act on before turning --client-certs required
// on and taking the fleet down.
func (s *Store) SetEndpointCertCN(endpointID, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE endpoints SET cert_cn = ? WHERE id = ?", cn, endpointID)
	return err
}

func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// RequestAgentUpdate queues (or refreshes) a remote update job for an endpoint.
func (s *Store) RequestAgentUpdate(endpointID, desiredVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO agent_update_jobs (endpoint_id, desired_version, requested_at)
		VALUES (?, ?, ?) ON CONFLICT(endpoint_id) DO UPDATE SET desired_version = excluded.desired_version, requested_at = excluded.requested_at, completed_at = NULL`,
		endpointID, desiredVersion, time.Now().UTC())
	return err
}

func (s *Store) GetAgentUpdateJob(endpointID string) (*AgentUpdateJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var job AgentUpdateJob
	var completed sql.NullTime
	err := s.db.QueryRow("SELECT endpoint_id, desired_version, requested_at, completed_at FROM agent_update_jobs WHERE endpoint_id = ?", endpointID).
		Scan(&job.EndpointID, &job.DesiredVersion, &job.RequestedAt, &completed)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if completed.Valid {
		job.CompletedAt = &completed.Time
	}
	return &job, nil
}

func (s *Store) ListPendingAgentUpdates() ([]AgentUpdateJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT endpoint_id, desired_version, requested_at, completed_at FROM agent_update_jobs WHERE completed_at IS NULL ORDER BY requested_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []AgentUpdateJob
	for rows.Next() {
		var job AgentUpdateJob
		var completed sql.NullTime
		if err := rows.Scan(&job.EndpointID, &job.DesiredVersion, &job.RequestedAt, &completed); err != nil {
			return nil, err
		}
		if completed.Valid {
			job.CompletedAt = &completed.Time
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// CompleteAgentUpdate marks a queued update job as delivered (agent reported the target version).
func (s *Store) CompleteAgentUpdate(endpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE agent_update_jobs SET completed_at = ? WHERE endpoint_id = ?", time.Now().UTC(), endpointID)
	return err
}

// ListEndpoints returns endpoints in a stable order. Ordering by last_seen_at made rows
// reshuffle on every telemetry heartbeat, which moves a host out from under the operator's
// cursor between refreshes — an isolate click could land on the wrong machine. Hostname is
// stable identity; id breaks ties so the order is fully deterministic.
func (s *Store) ListEndpoints(tenantID string) ([]Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, update_capability, status, COALESCE(cert_cn, ''), is_isolated, last_seen_at, created_at FROM endpoints WHERE tenant_id = ? ORDER BY hostname COLLATE NOCASE ASC, id ASC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, update_capability, status, COALESCE(cert_cn, ''), is_isolated, last_seen_at, created_at FROM endpoints ORDER BY hostname COLLATE NOCASE ASC, id ASC",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Endpoint
	for rows.Next() {
		var ep Endpoint
		var isoInt int
		if err := rows.Scan(
			&ep.ID, &ep.TenantID, &ep.LocationID, &ep.LocationName, &ep.Hostname, &ep.OS, &ep.IP, &ep.MAC,
			&ep.RoleTag, &ep.InstalledSoftware, &ep.DriverVersion, &ep.UpdateCapability,
			&ep.Status, &ep.CertCN, &isoInt, &ep.LastSeenAt, &ep.CreatedAt,
		); err != nil {
			return nil, err
		}
		ep.IsIsolated = isoInt != 0
		list = append(list, ep)
	}
	return list, nil
}

func (s *Store) GetEndpoint(id string) (*Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ep Endpoint
	var isoInt int
	err := s.db.QueryRow(
		"SELECT id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, update_capability, status, COALESCE(cert_cn, ''), is_isolated, last_seen_at, created_at FROM endpoints WHERE id = ? OR hostname = ?",
		id, id,
	).Scan(
		&ep.ID, &ep.TenantID, &ep.LocationID, &ep.LocationName, &ep.Hostname, &ep.OS, &ep.IP, &ep.MAC,
		&ep.RoleTag, &ep.InstalledSoftware, &ep.DriverVersion, &ep.UpdateCapability,
		&ep.Status, &ep.CertCN, &isoInt, &ep.LastSeenAt, &ep.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep.IsIsolated = isoInt != 0
	return &ep, nil
}

func (s *Store) GetHierarchy(tenantID string) ([]HierarchyClient, error) {
	tenants, err := s.ListTenants()
	if err != nil {
		return nil, err
	}
	locations, err := s.ListLocations(tenantID)
	if err != nil {
		return nil, err
	}
	endpoints, err := s.ListEndpoints(tenantID)
	if err != nil {
		return nil, err
	}

	locMap := make(map[string][]Endpoint)
	for _, ep := range endpoints {
		key := ep.LocationID
		if key == "" {
			key = "loc-hq"
		}
		locMap[key] = append(locMap[key], ep)
	}

	tenantLocMap := make(map[string][]HierarchyLocation)
	for _, loc := range locations {
		eps := locMap[loc.ID]
		isoCount := 0
		for _, ep := range eps {
			if ep.IsIsolated {
				isoCount++
			}
		}
		tenantLocMap[loc.TenantID] = append(tenantLocMap[loc.TenantID], HierarchyLocation{
			Location:       loc,
			Endpoints:      eps,
			TotalEndpoints: len(eps),
			IsolatedCount:  isoCount,
		})
	}

	// Attach any orphan endpoints to the first location of their tenant
	for _, ep := range endpoints {
		found := false
		for _, loc := range locations {
			if loc.ID == ep.LocationID {
				found = true
				break
			}
		}
		if !found && len(locations) > 0 {
			for i := range tenantLocMap[ep.TenantID] {
				if tenantLocMap[ep.TenantID][i].Location.TenantID == ep.TenantID {
					tenantLocMap[ep.TenantID][i].Endpoints = append(tenantLocMap[ep.TenantID][i].Endpoints, ep)
					tenantLocMap[ep.TenantID][i].TotalEndpoints++
					if ep.IsIsolated {
						tenantLocMap[ep.TenantID][i].IsolatedCount++
					}
					break
				}
			}
		}
	}

	var result []HierarchyClient
	for _, t := range tenants {
		if tenantID != "" && t.ID != tenantID {
			continue
		}
		locs := tenantLocMap[t.ID]
		if locs == nil {
			locs = []HierarchyLocation{}
		}
		totalEps := 0
		isoEps := 0
		for _, l := range locs {
			totalEps += l.TotalEndpoints
			isoEps += l.IsolatedCount
		}
		result = append(result, HierarchyClient{
			Tenant:         t,
			Locations:      locs,
			TotalEndpoints: totalEps,
			IsolatedCount:  isoEps,
		})
	}

	return result, nil
}

func (s *Store) InsertEvent(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Nothing is invented here either. This path used to store a flow whose
	// agent reported no byte counts as 1420 in and 512 out, and an unlocated
	// flow as "US" - the same two substitutions InsertEventsBatch carried, and
	// the same reason they are gone: a console that shows an invented number is
	// worse than one that shows none, because the invented one is acted on.
	// Only the batch path is live today, so leaving these here left the
	// fabrication one caller away from coming back.
	if ev.Country == "" {
		ev.Country = CountryUnknown
	}

	_, err := s.db.Exec(
		"INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		ev.TenantID, ev.EndpointID, ev.Timestamp, ev.Layer, ev.Action, ev.Direction, ev.Protocol, ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.BytesIn, ev.BytesOut, ev.Country, ev.ProcessPath, ev.ProcessID,
	)
	return err
}

func (s *Store) InsertEventsBatch(events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		// Nothing is invented here any more.
		//
		// A flow whose agent reported no byte counts used to be stored as
		// 1420 in and 512 out. The Windows agent falls back to user-mode socket
		// telemetry, which has no byte accounting, so on this fleet that was
		// 212,427 of 374,318 rows - 56% of every byte figure the console
		// printed, including the bandwidth timeline, the geo ranking and the
		// top-talkers card, was a constant. The comment on the timeline in
		// GetAnalyticsSummary says a console that invents a number is worse
		// than one that shows none, because the invented one is acted on. This
		// was the same defect one layer down, feeding the same cards.
		//
		// An unlocated flow was likewise stored as "US", so traffic the GeoIP
		// stage could not place was attributed to a country on a security
		// console. It is recorded as unknown, and the card names it that.
		if ev.Country == "" {
			ev.Country = CountryUnknown
		}
		_, _ = stmt.Exec(
			ev.TenantID, ev.EndpointID, ev.Timestamp, ev.Layer, ev.Action, ev.Direction, ev.Protocol,
			ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.BytesIn, ev.BytesOut, ev.Country,
			ev.ProcessPath, ev.ProcessID,
		)
	}

	return tx.Commit()
}

func (s *Store) ListEvents(tenantID string, limit int) ([]Event, error) {
	return s.QueryEvents(tenantID, "", limit)
}

func (s *Store) QueryEvents(tenantID string, endpointID string, limit int) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" && endpointID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id FROM events WHERE tenant_id = ? AND endpoint_id = ? ORDER BY timestamp DESC LIMIT ?",
			tenantID, endpointID, limit,
		)
	} else if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
			tenantID, limit,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id FROM events ORDER BY timestamp DESC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Event
	for rows.Next() {
		var ev Event
		if err := rows.Scan(
			&ev.ID, &ev.TenantID, &ev.EndpointID, &ev.Timestamp, &ev.Layer, &ev.Action, &ev.Direction, &ev.Protocol,
			&ev.SrcIP, &ev.DstIP, &ev.SrcPort, &ev.DstPort, &ev.BytesIn, &ev.BytesOut, &ev.Country, &ev.ProcessPath, &ev.ProcessID,
		); err != nil {
			return nil, err
		}
		list = append(list, ev)
	}
	return list, nil
}

/* NETWORK COMMUNICATIONS PROFILING & ANOMALY TRACKING */

func (s *Store) RecordNetworkComms(ev Event, hostname string, locationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanPath := strings.ReplaceAll(ev.ProcessPath, "\\", "/")
	procName := filepath.Base(cleanPath)
	if procName == "." || procName == "/" || procName == "\\" || procName == "" {
		procName = "kernel/system"
	}

	protoStr := "TCP"
	if ev.Protocol == 17 {
		protoStr = "UDP"
	} else if ev.Protocol == 1 {
		protoStr = "ICMP"
	}

	dir := ev.Direction
	if dir == "" {
		dir = "OUTBOUND"
	}
	country := ev.Country
	if country == "" {
		country = "US"
	}
	if locationID == "" {
		locationID = "loc-hq"
	}

	profID := fmt.Sprintf("%s:%s:%s:%d:%s", ev.EndpointID, procName, ev.DstIP, ev.DstPort, dir)

	query := `
	INSERT INTO comm_profiles (id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1)
	ON CONFLICT(id) DO UPDATE SET
		last_seen=excluded.last_seen,
		event_count=comm_profiles.event_count + 1,
		total_bytes_in=comm_profiles.total_bytes_in + excluded.total_bytes_in,
		total_bytes_out=comm_profiles.total_bytes_out + excluded.total_bytes_out
	`
	_, err := s.db.Exec(
		query,
		profID, ev.TenantID, locationID, ev.EndpointID, hostname,
		procName, ev.ProcessPath, ev.DstIP, ev.DstPort,
		protoStr, dir, country, ev.Timestamp, ev.Timestamp,
		ev.BytesIn, ev.BytesOut,
	)
	return err
}

func (s *Store) ListCommProfiles(level string, id string, limit int) ([]CommProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 250
	}

	var (
		rows *sql.Rows
		err  error
	)

	switch level {
	case "endpoint":
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline FROM comm_profiles WHERE endpoint_id = ? OR hostname = ? ORDER BY event_count DESC LIMIT ?", id, id, limit)
	case "location":
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline FROM comm_profiles WHERE location_id = ? ORDER BY event_count DESC LIMIT ?", id, limit)
	case "client":
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline FROM comm_profiles WHERE tenant_id = ? ORDER BY event_count DESC LIMIT ?", id, limit)
	default: // global
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline FROM comm_profiles ORDER BY event_count DESC LIMIT ?", limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]CommProfile, 0)
	for rows.Next() {
		var cp CommProfile
		var baseInt int
		if err := rows.Scan(
			&cp.ID, &cp.TenantID, &cp.LocationID, &cp.EndpointID, &cp.Hostname,
			&cp.ProcessName, &cp.ProcessPath, &cp.DstIP, &cp.DstPort,
			&cp.Protocol, &cp.Direction, &cp.Country,
			&cp.FirstSeen, &cp.LastSeen, &cp.EventCount,
			&cp.TotalBytesIn, &cp.TotalBytesOut, &baseInt,
		); err != nil {
			return nil, err
		}
		cp.IsBaseline = baseInt != 0
		list = append(list, cp)
	}
	return list, nil
}

/* CUSTOM EXCLUSIONS (ALLOWLISTS & PINHOLES) */

func (s *Store) CreateExclusion(ex Exclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if ex.Active {
		actInt = 1
	}

	query := `
	INSERT INTO exclusions (id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name=excluded.name,
		process_path=excluded.process_path,
		dst_ip_range=excluded.dst_ip_range,
		port=excluded.port,
		protocol=excluded.protocol,
		reason=excluded.reason,
		active=excluded.active
	`
	_, err := s.db.Exec(
		query,
		ex.ID, ex.TenantID, ex.Scope, ex.ScopeValue, ex.Name,
		ex.ProcessPath, ex.DstIPRange, ex.Port, ex.Protocol, ex.Reason, actInt, ex.CreatedAt,
	)
	return err
}

func (s *Store) ListExclusions(tenantID string) ([]Exclusion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" && tenantID != "default" {
		rows, err = s.db.Query("SELECT id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at FROM exclusions WHERE tenant_id = ? OR scope = 'global' ORDER BY created_at DESC", tenantID)
	} else {
		rows, err = s.db.Query("SELECT id, tenant_id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at FROM exclusions ORDER BY created_at DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]Exclusion, 0)
	for rows.Next() {
		var ex Exclusion
		var actInt int
		if err := rows.Scan(
			&ex.ID, &ex.TenantID, &ex.Scope, &ex.ScopeValue, &ex.Name,
			&ex.ProcessPath, &ex.DstIPRange, &ex.Port, &ex.Protocol, &ex.Reason, &actInt, &ex.CreatedAt,
		); err != nil {
			return nil, err
		}
		ex.Active = actInt != 0
		list = append(list, ex)
	}
	return list, nil
}

func (s *Store) DeleteExclusion(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM exclusions WHERE id = ?", id)
	return err
}

func (s *Store) ToggleExclusion(id string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if active {
		actInt = 1
	}
	_, err := s.db.Exec("UPDATE exclusions SET active = ? WHERE id = ?", actInt, id)
	return err
}

func (s *Store) IsExclusionMatch(ev Event, locationID string) bool {
	exclusions, err := s.ListExclusions(ev.TenantID)
	if err != nil || len(exclusions) == 0 {
		return false
	}

	for _, ex := range exclusions {
		if !ex.Active {
			continue
		}

		// Check Scope
		switch ex.Scope {
		case "client":
			if ex.ScopeValue != "" && ex.ScopeValue != ev.TenantID {
				continue
			}
		case "location":
			if ex.ScopeValue != "" && ex.ScopeValue != locationID {
				continue
			}
		case "endpoint":
			if ex.ScopeValue != "" && ex.ScopeValue != ev.EndpointID {
				continue
			}
		}

		// Check Protocol
		if ex.Protocol != "any" && ex.Protocol != "" {
			evProto := "tcp"
			if ev.Protocol == 17 {
				evProto = "udp"
			}
			if !strings.EqualFold(ex.Protocol, evProto) {
				continue
			}
		}

		// Check Port
		if ex.Port > 0 && ex.Port != ev.DstPort && ex.Port != ev.SrcPort {
			continue
		}

		// Check Process Path
		if ex.ProcessPath != "*" && ex.ProcessPath != "" {
			procLower := strings.ToLower(ev.ProcessPath)
			targetLower := strings.ToLower(ex.ProcessPath)
			if !strings.Contains(procLower, targetLower) {
				continue
			}
		}

		// Check IP Range / Target
		if ex.DstIPRange != "*" && ex.DstIPRange != "" {
			if strings.Contains(ex.DstIPRange, "/") {
				_, ipNet, err := net.ParseCIDR(ex.DstIPRange)
				if err == nil {
					targetIP := net.ParseIP(ev.DstIP)
					if targetIP == nil || !ipNet.Contains(targetIP) {
						continue
					}
				}
			} else if ex.DstIPRange != ev.DstIP {
				continue
			}
		}

		return true
	}

	return false
}

/* ANOMALY ALERTS */

func (s *Store) CreateAnomalyAlert(a AnomalyAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ackInt := 0
	if a.Acknowledged {
		ackInt = 1
	}

	query := `
	INSERT INTO anomaly_alerts (id, tenant_id, location_id, endpoint_id, hostname, anomaly_type, severity, title, description, details, process_path, dst_ip, dst_port, timestamp, acknowledged)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		severity=excluded.severity,
		description=excluded.description,
		timestamp=excluded.timestamp
	`
	_, err := s.db.Exec(
		query,
		a.ID, a.TenantID, a.LocationID, a.EndpointID, a.Hostname,
		a.AnomalyType, a.Severity, a.Title, a.Description, a.Details,
		a.ProcessPath, a.DstIP, a.DstPort, a.Timestamp, ackInt,
	)
	return err
}

func (s *Store) ListAnomalyAlerts(tenantID string, limit int) ([]AnomalyAlert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, anomaly_type, severity, title, description, details, process_path, dst_ip, dst_port, timestamp, acknowledged FROM anomaly_alerts WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?", tenantID, limit)
	} else {
		rows, err = s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, anomaly_type, severity, title, description, details, process_path, dst_ip, dst_port, timestamp, acknowledged FROM anomaly_alerts ORDER BY timestamp DESC LIMIT ?", limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]AnomalyAlert, 0)
	for rows.Next() {
		var a AnomalyAlert
		var ackInt int
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.LocationID, &a.EndpointID, &a.Hostname,
			&a.AnomalyType, &a.Severity, &a.Title, &a.Description, &a.Details,
			&a.ProcessPath, &a.DstIP, &a.DstPort, &a.Timestamp, &ackInt,
		); err != nil {
			return nil, err
		}
		a.Acknowledged = ackInt != 0
		list = append(list, a)
	}
	return list, nil
}

func (s *Store) AcknowledgeAnomaly(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE anomaly_alerts SET acknowledged = 1 WHERE id = ?", id)
	return err
}

/* THREAT INTEL & RULES */

func (s *Store) UpsertIOCsBatch(iocs []IOC) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO iocs (id, value, type, source, threat_type, confidence, active, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(value) DO UPDATE SET
			confidence=excluded.confidence,
			active=excluded.active,
			last_seen_at=excluded.last_seen_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ioc := range iocs {
		actInt := 0
		if ioc.Active {
			actInt = 1
		}
		_, _ = stmt.Exec(
			ioc.ID, ioc.Value, ioc.Type, ioc.Source, ioc.ThreatType,
			ioc.Confidence, actInt, ioc.CreatedAt, ioc.LastSeenAt,
		)
	}

	return tx.Commit()
}

func (s *Store) GetAnalyticsSummary(tenantID string) (*AnalyticsSummary, error) {
	// Checked before the store lock is taken, not inside it: the point is to
	// keep repeat polls off that lock entirely, and the cache has a lock of its
	// own that no other method reaches.
	now := time.Now()
	if cached := s.analytics.get(tenantID, now); cached != nil {
		return cached, nil
	}

	summary, err := s.analyticsSummaryUncached(tenantID)
	if err != nil {
		return nil, err
	}
	s.analytics.put(tenantID, summary, now)
	return summary, nil
}

func (s *Store) analyticsSummaryUncached(tenantID string) (*AnalyticsSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := &AnalyticsSummary{
		Countries:         make(map[string]int64),
		TopProcesses:      make(map[string]int64),
		SeverityCounts:    make(map[string]int64),
		EnforcementCounts: make(map[string]int64),
		BandwidthTimeline: make([]BandwidthDataPoint, 0),
	}

	// 1, 2 and 9 in one pass over events.
	//
	// These were three separate full scans of the same table: the totals, the
	// country counts, and the geo card's bytes-and-threats by country. Every
	// row carries a country (NOT NULL, defaulted), so grouping by it partitions
	// the table - the totals are the column sums of the same result, and both
	// cards are orderings of it. On the production database each scan was
	// costing about a third of a second through the pure-Go sqlite driver, and
	// the console polls this endpoint; three of them were two thirds of a
	// second spent re-reading the same 340k rows to answer the same question
	// three ways, all of it under the read lock.
	type countryRow struct {
		country                  string
		count, bytesIn, bytesOut int64
		blocks, permits          int64
	}
	var byCountry []countryRow

	var queryEvents string
	var args []interface{}
	queryEvents = `SELECT country, COUNT(*), COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0),
		COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action='PERMIT' THEN 1 ELSE 0 END), 0)
		FROM events`
	if tenantID != "" {
		queryEvents += " WHERE tenant_id = ?"
		args = append(args, tenantID)
	}
	queryEvents += " GROUP BY country"

	if rows, err := s.db.Query(queryEvents, args...); err == nil {
		for rows.Next() {
			var r countryRow
			if err := rows.Scan(&r.country, &r.count, &r.bytesIn, &r.bytesOut, &r.blocks, &r.permits); err == nil {
				byCountry = append(byCountry, r)
				summary.TotalEvents += r.count
				summary.TotalBytesIn += r.bytesIn
				summary.TotalBytesOut += r.bytesOut
				summary.TotalBlocks += r.blocks
				summary.TotalPermits += r.permits
			}
		}
		rows.Close()
	}

	// The countries card is the ten busiest by flow count.
	sort.Slice(byCountry, func(i, j int) bool { return byCountry[i].count > byCountry[j].count })
	for i, r := range byCountry {
		if i >= 10 {
			break
		}
		if r.country == "" {
			continue
		}
		summary.Countries[r.country] = r.count
	}

	// 3. Process aggregation
	var queryProc string
	if tenantID != "" {
		queryProc = "SELECT process_path, COUNT(*) FROM events WHERE tenant_id = ? GROUP BY process_path ORDER BY COUNT(*) DESC LIMIT 10"
	} else {
		queryProc = "SELECT process_path, COUNT(*) FROM events GROUP BY process_path ORDER BY COUNT(*) DESC LIMIT 10"
	}
	pRows, err := s.db.Query(queryProc, args...)
	if err == nil {
		for pRows.Next() {
			var proc string
			var count int64
			if err := pRows.Scan(&proc, &count); err == nil && proc != "" {
				parts := strings.Split(proc, "\\")
				if len(parts) > 1 {
					proc = parts[len(parts)-1]
				}
				parts = strings.Split(proc, "/")
				if len(parts) > 1 {
					proc = parts[len(parts)-1]
				}
				summary.TopProcesses[proc] += count
			}
		}
		pRows.Close()
	}

	// 4. Severity counts
	var querySev string
	if tenantID != "" {
		querySev = "SELECT severity, COUNT(*) FROM alerts WHERE tenant_id = ? GROUP BY severity"
	} else {
		querySev = "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
	}
	sRows, err := s.db.Query(querySev, args...)
	if err == nil {
		for sRows.Next() {
			var sev string
			var count int64
			if err := sRows.Scan(&sev, &count); err == nil {
				summary.SeverityCounts[sev] = count
			}
		}
		sRows.Close()
	}

	// 5. Enforcement mode distribution from endpoints
	var queryEnf string
	if tenantID != "" {
		queryEnf = "SELECT os, driver_version, COUNT(*) FROM endpoints WHERE tenant_id = ? GROUP BY os, driver_version"
	} else {
		queryEnf = "SELECT os, driver_version, COUNT(*) FROM endpoints GROUP BY os, driver_version"
	}
	eRows, err := s.db.Query(queryEnf, args...)
	if err == nil {
		for eRows.Next() {
			var os, ver string
			var count int64
			if err := eRows.Scan(&os, &ver, &count); err == nil {
				osLower := strings.ToLower(os)
				if strings.Contains(osLower, "windows") {
					summary.EnforcementCounts["OS Native WFP"] += count
				} else if strings.Contains(osLower, "linux") || strings.Contains(osLower, "ubuntu") {
					summary.EnforcementCounts["Native eBPF"] += count
				} else if strings.Contains(osLower, "mac") || strings.Contains(osLower, "darwin") {
					summary.EnforcementCounts["OS Native PF"] += count
				} else {
					summary.EnforcementCounts["Ring-0 Callout"] += count
				}
			}
		}
		eRows.Close()
	}

	// 6. Bandwidth over the last hour, in ten-minute buckets, measured.
	//
	// This used to be the all-time totals divided by six with a fixed slope
	// added - so the console drew a tidy declining trend that no traffic had
	// produced, and drew blocked-flow bars above a "0 BLOCKED" figure it had
	// just rendered from the same response. A console that invents a number is
	// worse than one that shows none: the invented one is acted on.
	//
	// Empty buckets are emitted as zeros rather than skipped. A gap in the
	// series is itself the finding - an endpoint that stopped reporting - and
	// dropping it would redraw the chart as though the quiet ten minutes had
	// never happened.
	now := time.Now().UTC()
	const bucketMinutes = 10
	const buckets = 6
	// The last bucket is the one in progress, so the series ends at "now" rather
	// than ten minutes short of it. Anchoring on now-60m instead put the most
	// recent traffic in a bucket past the end of the chart, where it was simply
	// not drawn.
	windowStart := now.Truncate(bucketMinutes * time.Minute).Add(-time.Duration((buckets-1)*bucketMinutes) * time.Minute)

	type bucketRow struct {
		in, out, blocks int64
	}
	measured := make(map[int64]bucketRow, buckets)

	// The bucket index is computed in SQL so one indexed scan of the window
	// replaces six queries. strftime('%s') is seconds since the epoch, which
	// integer-divides into the bucket a row belongs to - but only after the
	// timestamp is trimmed to whole seconds: these are stored as RFC3339 with
	// nanosecond precision, and SQLite's date functions return NULL for more
	// than three fractional digits rather than an error. The WHERE clause still
	// compares the untouched column, so the index on (tenant_id, timestamp) is
	// what selects the window.
	timelineQuery := `SELECT CAST(strftime('%s', substr(timestamp, 1, 19) || 'Z') AS INTEGER) / ? AS bucket,
		COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0),
		COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0)
		FROM events WHERE timestamp >= ?`
	timelineArgs := []interface{}{bucketMinutes * 60, windowStart}
	if tenantID != "" {
		timelineQuery += " AND tenant_id = ?"
		timelineArgs = append(timelineArgs, tenantID)
	}
	timelineQuery += " GROUP BY bucket"

	if tRows, err := s.db.Query(timelineQuery, timelineArgs...); err == nil {
		for tRows.Next() {
			var bucket int64
			var row bucketRow
			if err := tRows.Scan(&bucket, &row.in, &row.out, &row.blocks); err == nil {
				measured[bucket] = row
			}
		}
		tRows.Close()
	}

	for i := 0; i < buckets; i++ {
		t := windowStart.Add(time.Duration(i*bucketMinutes) * time.Minute)
		row := measured[t.Unix()/(bucketMinutes*60)]
		summary.BandwidthTimeline = append(summary.BandwidthTimeline, BandwidthDataPoint{
			Timestamp: t.Format("15:04"),
			BytesIn:   row.in,
			BytesOut:  row.out,
			Blocks:    row.blocks,
		})
	}

	// 7. Diurnal Time-of-Day Activity (Baseline vs Live by Hour 0-23)
	baseline, live, _ := s.diurnalProfilesLocked(tenantID)
	summary.DiurnalBaseline = baseline
	summary.DiurnalLive = live

	// 8. Top Network Talkers.
	//
	// Ranked by bytes, because bytes is what the card prints. Ranking by flow
	// count and printing bytes put the list out of order on its own numbers -
	// a process with 5.1 MB sat above one with 6.2 MB - which reads as a broken
	// table rather than as a different question being answered.
	var ttQuery string
	if tenantID != "" {
		ttQuery = "SELECT process_name, SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out) FROM comm_profiles WHERE tenant_id = ? GROUP BY process_name ORDER BY SUM(total_bytes_in + total_bytes_out) DESC LIMIT 10"
	} else {
		ttQuery = "SELECT process_name, SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out) FROM comm_profiles GROUP BY process_name ORDER BY SUM(total_bytes_in + total_bytes_out) DESC LIMIT 10"
	}
	ttRows, err := s.db.Query(ttQuery, args...)
	if err == nil {
		for ttRows.Next() {
			var tt TopTalker
			if err := ttRows.Scan(&tt.Process, &tt.FlowCount, &tt.BytesIn, &tt.BytesOut); err == nil {
				tt.TotalBytes = tt.BytesIn + tt.BytesOut
				summary.TopTalkers = append(summary.TopTalkers, tt)
			}
		}
		ttRows.Close()
	}

	// 9. GeoIP country distribution and threat metrics: the same scan as above,
	// ordered by bytes rather than by flow count. Ranked by bytes because that
	// is the number the card prints.
	sort.Slice(byCountry, func(i, j int) bool {
		return byCountry[i].bytesIn+byCountry[i].bytesOut > byCountry[j].bytesIn+byCountry[j].bytesOut
	})
	countryNames := map[string]string{
		CountryUnknown: "Unlocated",
		"US":           "United States", "DE": "Germany", "GB": "United Kingdom", "NL": "Netherlands",
		"FR": "France", "CN": "China", "RU": "Russia", "JP": "Japan", "SG": "Singapore",
		"AU": "Australia", "CA": "Canada", "CH": "Switzerland", "SE": "Sweden", "PL": "Poland",
		"KR": "South Korea", "BR": "Brazil", "IN": "India", "LOCAL": "Internal LAN",
	}
	for i, r := range byCountry {
		if i >= 12 {
			break
		}
		gs := GeoCountryStat{
			Country:     r.country,
			FlowCount:   r.count,
			TotalBytes:  r.bytesIn + r.bytesOut,
			ThreatCount: r.blocks,
		}
		if name, ok := countryNames[gs.Country]; ok {
			gs.CountryName = name
		} else {
			gs.CountryName = gs.Country
		}
		summary.GeoStats = append(summary.GeoStats, gs)
	}

	return summary, nil
}

func (s *Store) IsFirstSeenDestination(tenantID, dstIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM comm_profiles WHERE dst_ip = ?", dstIP).Scan(&count)
	if err != nil {
		return false
	}
	return count <= 1
}

// GetDiurnalProfiles takes the read lock and delegates. Callers that already
// hold the lock must use diurnalProfilesLocked instead: sync.RWMutex is not
// reentrant, and a recursive RLock deadlocks the moment a writer queues
// between the two acquisitions - the inner call waits for the writer, the
// writer waits for the outer read lock to drop, and every later reader piles
// up behind them. GetAnalyticsSummary used to call this method while holding
// the lock, which took the whole hub down under a write-heavy load.
func (s *Store) GetDiurnalProfiles(tenantID string) (map[int]int64, map[int]int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.diurnalProfilesLocked(tenantID)
}

// diurnalProfilesLocked returns hourly activity for the last day against the
// average of the seven days before it.
//
// Both halves were wrong. The live series ran
// strftime('%H', timestamp) over the whole events table, and the column holds
// Go's time.String() form ("2026-08-29 03:08:08.215796299 +0000 UTC"), which
// SQLite's date functions answer with NULL rather than an error - so every hour
// came back empty and the "live" curve had been flat zero for as long as it has
// existed. The baseline was not measured at all: it was a hardcoded
// business-hours weight table scaled by the total row count, so the chart drew
// a plausible working day that no traffic had produced. The comment on the
// bandwidth timeline in the caller says a console that invents a number is
// worse than one that shows none. This was the same defect, in the same
// response, left standing.
//
// It is also no longer a full table scan on every console poll. Both queries
// are bounded by timestamp, which is what idx_events_tenant_time indexes.
func (s *Store) diurnalProfilesLocked(tenantID string) (map[int]int64, map[int]int64, error) {
	baseline := make(map[int]int64)
	live := make(map[int]int64)
	for hr := 0; hr < 24; hr++ {
		baseline[hr] = 0
		live[hr] = 0
	}

	now := time.Now().UTC()
	liveFrom := now.Add(-24 * time.Hour)
	const baselineDays = 7
	baselineFrom := liveFrom.Add(-baselineDays * 24 * time.Hour)

	// substr trims the fractional seconds and the zone, which is the only form
	// SQLite will parse here.
	hourly := func(from, to time.Time) map[int]int64 {
		out := make(map[int]int64)
		query := `SELECT CAST(strftime('%H', substr(timestamp, 1, 19) || 'Z') AS INTEGER) AS hr, COUNT(*)
			FROM events WHERE timestamp >= ? AND timestamp < ?`
		args := []interface{}{from, to}
		if tenantID != "" {
			query += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
		query += " GROUP BY hr"

		rows, err := s.db.Query(query, args...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var hr sql.NullInt64
			var count int64
			if err := rows.Scan(&hr, &count); err != nil {
				continue
			}
			if hr.Valid && hr.Int64 >= 0 && hr.Int64 < 24 {
				out[int(hr.Int64)] = count
			}
		}
		return out
	}

	for hr, n := range hourly(liveFrom, now) {
		live[hr] = n
	}
	// The baseline is a typical day, so the seven-day totals are divided back
	// down to one. A hub with less history than that reports the zeros it has
	// rather than a curve it has not measured.
	for hr, n := range hourly(baselineFrom, liveFrom) {
		baseline[hr] = n / baselineDays
	}

	return baseline, live, nil
}

func (s *Store) EvaluatePolicyHierarchy(ev Event, ep Endpoint) (*PolicyGroup, string) {
	policies, err := s.ListPolicyGroups(ev.TenantID)
	if err != nil || len(policies) == 0 {
		return nil, ""
	}

	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	hr := now.Hour()
	isBusinessHours := hr >= 8 && hr < 18

	// 4-Tier Hierarchical Order:
	// Tier 3: Endpoint / Role (Highest Specificity)
	// Tier 2: Location
	// Tier 1: Client / Tenant
	// Tier 0: Global (Broadest Scope)
	var tier3, tier2, tier1, tier0 []PolicyGroup
	for _, p := range policies {
		if !p.Active {
			continue
		}
		switch p.Scope {
		case "endpoint":
			if p.ScopeValue == ev.EndpointID || p.ScopeValue == ep.Hostname {
				tier3 = append(tier3, p)
			}
		case "role":
			if ep.RoleTag != "" && strings.EqualFold(p.ScopeValue, ep.RoleTag) {
				tier3 = append(tier3, p)
			}
		case "location":
			if ep.LocationID != "" && p.ScopeValue == ep.LocationID {
				tier2 = append(tier2, p)
			}
		case "client":
			if p.ScopeValue == ev.TenantID {
				tier1 = append(tier1, p)
			}
		default: // global
			tier0 = append(tier0, p)
		}
	}

	ordered := append(tier3, append(tier2, append(tier1, tier0...)...)...)

	for _, p := range ordered {
		// 1. Time Schedule Match
		if p.Schedule == "business_hours" && !isBusinessHours {
			continue
		}
		if p.Schedule == "off_hours" && isBusinessHours {
			continue
		}

		// 2. Protocol Match
		if p.Protocol != "" && p.Protocol != "any" {
			evProto := "tcp"
			if ev.Protocol == 17 {
				evProto = "udp"
			} else if ev.Protocol == 1 {
				evProto = "icmp"
			}
			if !strings.EqualFold(p.Protocol, evProto) {
				continue
			}
		}

		// 3. Port Match
		if p.Port > 0 && p.Port != ev.DstPort && p.Port != ev.SrcPort {
			continue
		}

		// 4. Rule Type & Value Match
		ruleVal := strings.TrimSpace(p.RuleValue)
		switch p.RuleType {
		case "ip", "cidr":
			if ruleVal != "" && ruleVal != "*" {
				if strings.Contains(ruleVal, "/") {
					_, ipNet, err := net.ParseCIDR(ruleVal)
					if err == nil {
						targetIP := net.ParseIP(ev.DstIP)
						if targetIP == nil || !ipNet.Contains(targetIP) {
							continue
						}
					}
				} else if ruleVal != ev.DstIP {
					continue
				}
			}
		case "process":
			if ruleVal != "" && ruleVal != "*" {
				procLower := strings.ToLower(ev.ProcessPath)
				targetLower := strings.ToLower(ruleVal)
				if !strings.Contains(procLower, targetLower) {
					continue
				}
			}
		}

		return &p, p.Action
	}

	return nil, ""
}

func (s *Store) CreatePolicyGroup(g PolicyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if g.Active {
		actInt = 1
	}
	if g.Scope == "" {
		g.Scope = "global"
	}
	if g.Schedule == "" {
		g.Schedule = "all"
	}

	query := `
	INSERT INTO policy_groups (id, tenant_id, scope, scope_value, name, description, schedule, criteria, action, rule_type, rule_value, port, protocol, active, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		scope=excluded.scope,
		scope_value=excluded.scope_value,
		name=excluded.name,
		description=excluded.description,
		schedule=excluded.schedule,
		criteria=excluded.criteria,
		action=excluded.action,
		rule_type=excluded.rule_type,
		rule_value=excluded.rule_value,
		port=excluded.port,
		protocol=excluded.protocol,
		active=excluded.active
	`
	_, err := s.db.Exec(
		query,
		g.ID, g.TenantID, g.Scope, g.ScopeValue, g.Name, g.Description, g.Schedule,
		g.Criteria, g.Action, g.RuleType, g.RuleValue, g.Port, g.Protocol, actInt, g.CreatedAt,
	)
	return err
}

func (s *Store) ListPolicyGroups(tenantID string) ([]PolicyGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, COALESCE(scope, 'global'), COALESCE(scope_value, ''), name, description, COALESCE(schedule, 'all'), criteria, action, rule_type, rule_value, port, protocol, active, created_at FROM policy_groups WHERE tenant_id = ? OR scope = 'global' ORDER BY created_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, COALESCE(scope, 'global'), COALESCE(scope_value, ''), name, description, COALESCE(schedule, 'all'), criteria, action, rule_type, rule_value, port, protocol, active, created_at FROM policy_groups ORDER BY created_at DESC",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []PolicyGroup
	for rows.Next() {
		var g PolicyGroup
		var actInt int
		if err := rows.Scan(
			&g.ID, &g.TenantID, &g.Scope, &g.ScopeValue, &g.Name, &g.Description, &g.Schedule,
			&g.Criteria, &g.Action, &g.RuleType, &g.RuleValue, &g.Port, &g.Protocol, &actInt, &g.CreatedAt,
		); err != nil {
			return nil, err
		}
		g.Active = actInt != 0
		list = append(list, g)
	}
	return list, nil
}

func (s *Store) DeletePolicyGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM policy_groups WHERE id = ?", id)
	return err
}

func (s *Store) TogglePolicyGroup(id string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if active {
		actInt = 1
	}
	_, err := s.db.Exec("UPDATE policy_groups SET active = ? WHERE id = ?", actInt, id)
	return err
}

func (s *Store) UpsertIOC(ioc IOC) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if ioc.Active {
		actInt = 1
	}

	query := `
	INSERT INTO iocs (id, value, type, source, threat_type, confidence, active, created_at, last_seen_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(value) DO UPDATE SET
		confidence=excluded.confidence,
		active=excluded.active,
		last_seen_at=excluded.last_seen_at
	`
	_, err := s.db.Exec(
		query,
		ioc.ID, ioc.Value, ioc.Type, ioc.Source, ioc.ThreatType,
		ioc.Confidence, actInt, ioc.CreatedAt, ioc.LastSeenAt,
	)
	return err
}

func (s *Store) GetIOC(value string) (*IOC, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ioc IOC
	var actInt int
	err := s.db.QueryRow(
		"SELECT id, value, type, source, threat_type, confidence, active, created_at, last_seen_at FROM iocs WHERE value = ? AND active = 1",
		value,
	).Scan(
		&ioc.ID, &ioc.Value, &ioc.Type, &ioc.Source, &ioc.ThreatType,
		&ioc.Confidence, &actInt, &ioc.CreatedAt, &ioc.LastSeenAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ioc.Active = actInt != 0
	return &ioc, nil
}

func (s *Store) ListIOCs(limit int) ([]IOC, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	rows, err := s.db.Query(
		"SELECT id, value, type, source, threat_type, confidence, active, created_at, last_seen_at FROM iocs WHERE active = 1 ORDER BY confidence DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []IOC
	for rows.Next() {
		var ioc IOC
		var actInt int
		if err := rows.Scan(
			&ioc.ID, &ioc.Value, &ioc.Type, &ioc.Source, &ioc.ThreatType,
			&ioc.Confidence, &actInt, &ioc.CreatedAt, &ioc.LastSeenAt,
		); err != nil {
			return nil, err
		}
		ioc.Active = actInt != 0
		list = append(list, ioc)
	}
	return list, nil
}

func (s *Store) CreateRule(r Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if r.Active {
		actInt = 1
	}

	_, err := s.db.Exec(
		"INSERT INTO rules (id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		r.ID, r.TenantID, r.Name, r.Type, r.Value, r.Port, r.Protocol, r.Action, r.Scope, r.ScopeValue, actInt, r.CreatedAt,
	)
	return err
}

func (s *Store) ListRules(tenantID string) ([]Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at FROM rules WHERE tenant_id = ? AND active = 1 ORDER BY created_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at FROM rules WHERE active = 1 ORDER BY created_at DESC",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Rule
	for rows.Next() {
		var r Rule
		var actInt int
		if err := rows.Scan(
			&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Value, &r.Port, &r.Protocol, &r.Action, &r.Scope, &r.ScopeValue, &actInt, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		r.Active = actInt != 0
		list = append(list, r)
	}
	return list, nil
}

func (s *Store) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM rules WHERE id = ?", id)
	return err
}

func (s *Store) CreateAlert(a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	if a.Mitigated {
		val = 1
	}
	_, err := s.db.Exec(
		"INSERT INTO alerts (id, tenant_id, endpoint_id, timestamp, title, description, severity, mitigated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		a.ID, a.TenantID, a.EndpointID, a.Timestamp, a.Title, a.Description, a.Severity, val,
	)
	return err
}

func (s *Store) ListAlerts(tenantID string, limit int) ([]Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, endpoint_id, timestamp, title, description, severity, mitigated FROM alerts WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
			tenantID, limit,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, endpoint_id, timestamp, title, description, severity, mitigated FROM alerts ORDER BY timestamp DESC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Alert
	for rows.Next() {
		var a Alert
		var mitInt int
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.EndpointID, &a.Timestamp, &a.Title, &a.Description, &a.Severity, &mitInt,
		); err != nil {
			return nil, err
		}
		a.Mitigated = mitInt != 0
		list = append(list, a)
	}
	return list, nil
}

func (s *Store) RecordAudit(entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"INSERT INTO audit_logs (id, tenant_id, user_id, username, action, resource, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		entry.ID, entry.TenantID, entry.UserID, entry.Username, entry.Action, entry.Resource, entry.Details, entry.IPAddress, entry.Timestamp,
	)
	return err
}

func (s *Store) ListAuditLogs(tenantID string, limit int) ([]AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, user_id, username, action, resource, details, ip_address, timestamp FROM audit_logs WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
			tenantID, limit,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, user_id, username, action, resource, details, ip_address, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.Username, &a.Action, &a.Resource, &a.Details, &a.IPAddress, &a.Timestamp,
		); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, nil
}

func (s *Store) GetEndpoints() []Endpoint {
	eps, err := s.ListEndpoints("")
	if err != nil {
		return []Endpoint{}
	}
	return eps
}

// GetTopologyGraph draws the network from the asset graph first and the flow
// table second.
//
// It used to build nodes from endpoints plus whatever IPs happened to appear
// in the last hour of events, labelling everything it did not recognise
// "Unmanaged Internal Host". That is why the graph looked empty: a known host
// that was quiet for an hour did not exist to it, and the hosts it did draw
// carried no identity. Nodes now come from `assets` union flow endpoints, so
// every node arrives with its evidence and its role attached, and an asset
// that said nothing in the window is drawn quiet rather than dropped.
func (s *Store) GetTopologyGraph(timeWindow time.Duration) (TopologyData, error) {
	var data TopologyData
	data.Nodes = make([]TopologyNode, 0)
	data.Edges = make([]TopologyEdge, 0)

	// Read the asset graph before taking the read lock: ListAssets takes it
	// itself, and Go's RWMutex must not be read-locked recursively.
	assets, err := s.ListAssets("")
	if err != nil {
		return data, err
	}
	endpoints, err := s.ListEndpoints("")
	if err != nil {
		return data, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	isolatedByIP := make(map[string]bool)
	endpointByID := make(map[string]Endpoint)
	for _, ep := range endpoints {
		endpointByID[ep.ID] = ep
		if ep.IsIsolated && ep.IP != "" {
			isolatedByIP[ep.IP] = true
		}
	}

	nodeMap := make(map[string]*TopologyNode)
	spoke := make(map[string]bool)

	for i := range assets {
		a := assets[i]
		if a.IP == "" {
			continue
		}
		node := assetNode(a, endpointByID, isolatedByIP)
		nodeMap[a.IP] = &node
	}

	// Endpoints without an asset row yet (a hub mid-upgrade, before the next
	// check-in projects them) still deserve a node.
	for _, ep := range endpoints {
		if ep.IP == "" {
			continue
		}
		if _, ok := nodeMap[ep.IP]; ok {
			continue
		}
		risk := "CLEAN"
		if ep.IsIsolated {
			risk = "CRITICAL"
		}
		nodeMap[ep.IP] = &TopologyNode{
			ID: ep.IP, Label: ep.Hostname, Type: "managed", IP: ep.IP, OS: ep.OS,
			Role: ep.RoleTag, Risk: risk, IsIsolated: ep.IsIsolated, Group: ep.RoleTag,
			Evidence: []string{SourceAgent}, Confidence: 1.0, Quiet: true,
		}
	}

	cutoff := time.Now().UTC().Add(-timeWindow)
	rows, err := s.db.Query(
		`SELECT src_ip, dst_ip, protocol, dst_port, action, SUM(bytes_in + bytes_out), COUNT(*), MAX(timestamp)
		 FROM events
		 WHERE timestamp >= ?
		 GROUP BY src_ip, dst_ip, protocol, dst_port, action`,
		cutoff,
	)
	if err != nil {
		return data, err
	}
	defer rows.Close()

	edgeMap := make(map[string]*TopologyEdge)
	edgePorts := make(map[string]map[string]*TopologyEdgePort)

	for rows.Next() {
		var srcIP, dstIP, action string
		var protoInt int
		var dstPort int
		var totalBytes int64
		var flowCount int64
		var maxTimeRaw interface{}

		if err := rows.Scan(&srcIP, &dstIP, &protoInt, &dstPort, &action, &totalBytes, &flowCount, &maxTimeRaw); err != nil {
			continue
		}
		maxTime := scanTime(maxTimeRaw)
		if srcIP == "127.0.0.1" || dstIP == "127.0.0.1" {
			continue
		}

		ensureFlowNode(nodeMap, srcIP, action, false)
		ensureFlowNode(nodeMap, dstIP, action, true)
		spoke[srcIP] = true
		spoke[dstIP] = true

		protoStr := protoName(protoInt)

		verdict := "clean"
		if action == "BLOCK" {
			verdict = "blocked"
		} else if nodeMap[srcIP].Risk == "CRITICAL" || nodeMap[dstIP].Risk == "CRITICAL" {
			verdict = "anomalous"
		}

		// One edge per asset pair. The previous query grouped by 5-tuple with
		// no cap, which at fleet scale is thousands of edges and an
		// unreadable graph; ports now hang off the pair and expand on
		// selection.
		edgeKey := srcIP + "->" + dstIP
		edge, ok := edgeMap[edgeKey]
		if !ok {
			edge = &TopologyEdge{
				ID: edgeKey, Source: srcIP, Target: dstIP, Protocol: protoStr,
				Verdict: "clean", Ports: make([]TopologyEdgePort, 0, 4),
			}
			edgeMap[edgeKey] = edge
			edgePorts[edgeKey] = make(map[string]*TopologyEdgePort)
		}
		edge.FlowCount += flowCount
		edge.TotalBytes += totalBytes
		if maxTime.After(edge.LastSeen) {
			edge.LastSeen = maxTime
		}
		if verdict == "blocked" || (verdict == "anomalous" && edge.Verdict == "clean") {
			edge.Verdict = verdict
		}

		portKey := fmt.Sprintf("%s/%d", protoStr, dstPort)
		ps, ok := edgePorts[edgeKey][portKey]
		if !ok {
			ps = &TopologyEdgePort{Port: uint16(dstPort), Protocol: protoStr, Verdict: "clean"}
			edgePorts[edgeKey][portKey] = ps
		}
		ps.FlowCount += flowCount
		ps.TotalBytes += totalBytes
		if verdict != "clean" {
			ps.Verdict = verdict
		}
	}

	managedCount := 0
	unmanagedCount := 0
	quietCount := 0
	inferredCount := 0
	for ip, n := range nodeMap {
		n.Quiet = !spoke[ip]
		if n.Quiet {
			quietCount++
		}
		if n.Type == "managed" {
			managedCount++
		} else if n.Type == "unmanaged" {
			unmanagedCount++
		}
		for _, e := range n.Evidence {
			if e == SourceInferred {
				inferredCount++
				break
			}
		}
		data.Nodes = append(data.Nodes, *n)
	}
	sort.SliceStable(data.Nodes, func(i, j int) bool {
		return addressSortKey(data.Nodes[i].IP) < addressSortKey(data.Nodes[j].IP)
	})

	anomEdges := 0
	for key, e := range edgeMap {
		ports := make([]TopologyEdgePort, 0, len(edgePorts[key]))
		for _, ps := range edgePorts[key] {
			ports = append(ports, *ps)
		}
		sort.SliceStable(ports, func(i, j int) bool {
			if ports[i].TotalBytes != ports[j].TotalBytes {
				return ports[i].TotalBytes > ports[j].TotalBytes
			}
			return ports[i].FlowCount > ports[j].FlowCount
		})
		e.Ports = ports
		// Label the pair with its heaviest port only; the rest are one click
		// away rather than stacked on top of each other.
		if len(ports) > 0 {
			e.Port = ports[0].Port
			e.Protocol = ports[0].Protocol
		}
		data.Edges = append(data.Edges, *e)
		if e.Verdict != "clean" {
			anomEdges++
		}
	}
	sort.SliceStable(data.Edges, func(i, j int) bool { return data.Edges[i].ID < data.Edges[j].ID })

	data.Metrics.TotalNodes = len(data.Nodes)
	data.Metrics.TotalEdges = len(data.Edges)
	data.Metrics.AnomalousEdgeCount = anomEdges
	data.Metrics.ManagedNodesCount = managedCount
	data.Metrics.UnmanagedNodesCount = unmanagedCount
	data.Metrics.QuietNodesCount = quietCount
	data.Metrics.InferredNodesCount = inferredCount
	data.Metrics.WindowLabel = windowLabel(timeWindow)

	return data, nil
}

// assetNode projects one asset onto the graph, carrying its evidence and the
// role it was given or deduced instead of a bare address.
func assetNode(a Asset, endpointByID map[string]Endpoint, isolatedByIP map[string]bool) TopologyNode {
	label := a.Hostname
	if label == "" {
		label = a.IP
	}

	nType := "unmanaged"
	risk := a.RiskScore
	isolated := isolatedByIP[a.IP]
	if a.HasAgent() {
		nType = "managed"
		if ep, ok := endpointByID[a.AgentEndpointID]; ok {
			isolated = ep.IsIsolated
			if ep.Hostname != "" {
				label = ep.Hostname
			}
		}
		if risk == "" {
			risk = "CLEAN"
		}
	}
	if risk == "" {
		risk = "MEDIUM"
	}
	if isolated {
		risk = "CRITICAL"
	}

	role := a.Role
	if role == "" {
		role = a.Category
	}
	if role == "" {
		role = "unknown"
	}
	if isGatewayRole(role) || strings.HasSuffix(a.IP, ".1") {
		nType = "gateway"
	}

	group := a.Category
	if group == "" {
		group = role
	}

	return TopologyNode{
		ID: a.IP, Label: label, Type: nType, IP: a.IP,
		OS: a.OS, Role: role, Risk: risk, IsIsolated: isolated, Group: group,
		AssetID: a.ID, Evidence: a.Sources, Confidence: a.RoleConf, Rationale: a.Rationale,
	}
}

func isGatewayRole(role string) bool {
	r := strings.ToLower(role)
	return strings.Contains(r, "router") || strings.Contains(r, "firewall") || strings.Contains(r, "gateway")
}

// ensureFlowNode adds a node for an address seen only in traffic. These are
// the ones the old graph labelled "Unmanaged Internal Host"; they now say
// plainly that flow is the only thing that knows them.
func ensureFlowNode(nodeMap map[string]*TopologyNode, ip, action string, isTarget bool) {
	if _, ok := nodeMap[ip]; ok {
		return
	}
	nType := "unmanaged"
	group := "Seen in traffic only"
	risk := "MEDIUM"

	if !IsPrivateIPv4(ip) {
		nType = "cloud"
		group = "External"
		risk = "CLEAN"
		if isTarget && action == "BLOCK" {
			nType = "threat"
			group = "Blocked destination"
			risk = "CRITICAL"
		}
	}

	nodeMap[ip] = &TopologyNode{
		ID: ip, Label: ip, Type: nType, IP: ip, OS: "", Role: "unknown",
		Risk: risk, Group: group, Evidence: []string{},
	}
}

func windowLabel(d time.Duration) string {
	switch {
	case d >= 7*24*time.Hour:
		return "7d"
	case d >= 24*time.Hour:
		return "24h"
	case d >= 6*time.Hour:
		return "6h"
	}
	return "1h"
}

/* QUARANTINED PEERS (SUBNET MESH ISOLATION) */

func (s *Store) AddQuarantinedPeer(ip, mac, subnet, reason string) (*QuarantinedPeer, error) {
	id := fmt.Sprintf("qpeer-%s", strings.ReplaceAll(ip, ".", "-"))
	peer := &QuarantinedPeer{
		ID:        id,
		TargetIP:  ip,
		TargetMAC: mac,
		Subnet:    subnet,
		Reason:    reason,
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}

	query := `
	INSERT INTO quarantined_peers (id, target_ip, target_mac, subnet, reason, active, created_at)
	VALUES (?, ?, ?, ?, ?, 1, ?)
	ON CONFLICT(target_ip) DO UPDATE SET
		target_mac=excluded.target_mac,
		subnet=excluded.subnet,
		reason=excluded.reason,
		active=1,
		created_at=excluded.created_at
	`
	_, err := s.db.Exec(query, peer.ID, peer.TargetIP, peer.TargetMAC, peer.Subnet, peer.Reason, peer.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to add quarantined peer: %w", err)
	}
	return peer, nil
}

func (s *Store) RemoveQuarantinedPeer(ip string) error {
	query := `DELETE FROM quarantined_peers WHERE target_ip = ?`
	_, err := s.db.Exec(query, ip)
	if err != nil {
		return fmt.Errorf("failed to remove quarantined peer: %w", err)
	}
	return nil
}

func (s *Store) GetQuarantinedPeers() ([]QuarantinedPeer, error) {
	rows, err := s.db.Query(`SELECT id, target_ip, target_mac, subnet, reason, active, created_at FROM quarantined_peers WHERE active = 1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query quarantined peers: %w", err)
	}
	defer rows.Close()

	var peers []QuarantinedPeer
	for rows.Next() {
		var p QuarantinedPeer
		var activeInt int
		if err := rows.Scan(&p.ID, &p.TargetIP, &p.TargetMAC, &p.Subnet, &p.Reason, &activeInt, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Active = activeInt == 1
		peers = append(peers, p)
	}
	return peers, nil
}

func (s *Store) IsPeerQuarantined(ip string) bool {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM quarantined_peers WHERE target_ip = ? AND active = 1`, ip).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}
