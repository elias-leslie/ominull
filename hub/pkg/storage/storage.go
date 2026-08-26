package storage

import (
	"database/sql"
	"fmt"
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
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	LocationID        string    `json:"location_id"`
	LocationName      string    `json:"location_name"`
	Hostname          string    `json:"hostname"`
	OS                string    `json:"os"`
	IP                string    `json:"ip"`
	MAC               string    `json:"mac"`
	RoleTag           string    `json:"role_tag"`
	InstalledSoftware string    `json:"installed_software"`
	DriverVersion     string    `json:"driver_version"`
	Status            string    `json:"status"` // online, offline
	IsIsolated        bool      `json:"is_isolated"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	CreatedAt         time.Time `json:"created_at"`
}

type Event struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EndpointID  string    `json:"endpoint_id"`
	Timestamp   time.Time `json:"timestamp"`
	Layer       string    `json:"layer"`
	Action      string    `json:"action"` // PERMIT, BLOCK
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
}

type IOC struct {
	ID         string    `json:"id"`
	Value      string    `json:"value"`
	Type       string    `json:"type"` // "ipv4", "cidr", "domain", "hash"
	Source     string    `json:"source"` // "feodo", "emerging_threats", "custom"
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
	Action     string    `json:"action"` // "BLOCK", "PERMIT"
	Scope      string    `json:"scope"` // "all", "platform", "department", "ids", "group"
	ScopeValue string    `json:"scope_value"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
}

type PolicyGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Criteria    string    `json:"criteria"` // JSON string: {"os":"windows","role":"db-server","subnet":"10.0.0.0/24","process":"powershell"}
	Action      string    `json:"action"`   // BLOCK, PERMIT, ISOLATE
	RuleType    string    `json:"rule_type"`
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
	db *sql.DB
	mu sync.RWMutex
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
		country TEXT NOT NULL DEFAULT "US",
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
		status TEXT NOT NULL,
		is_isolated INTEGER NOT NULL DEFAULT 0,
		last_seen_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
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

	CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_endpoint_time ON events(endpoint_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_locations_tenant ON locations(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_policy_groups_tenant ON policy_groups(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs(value);
	CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_tenant_time ON alerts(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Dynamic column migrations for existing databases
	migrations := []string{
		"ALTER TABLE endpoints ADD COLUMN location_id TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN location_name TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN mac TEXT DEFAULT ''",
		"ALTER TABLE endpoints ADD COLUMN role_tag TEXT DEFAULT 'workstation'",
		"ALTER TABLE endpoints ADD COLUMN installed_software TEXT DEFAULT ''",
		"ALTER TABLE events ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE events ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE events ADD COLUMN country TEXT NOT NULL DEFAULT 'US'",
	}
	for _, m := range migrations {
		_, _ = s.db.Exec(m)
	}

	return nil
}

func (s *Store) seedDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	// Default MSP Clients
	tenants := []Tenant{
		{ID: "default", Name: "Primary Enterprise / IR Incident", APIKey: "ominull-master-admin-key", CreatedAt: now},
		{ID: "client-acme", Name: "Acme Global Industries (MSP-01)", APIKey: "key-acme-corp-prod", CreatedAt: now},
		{ID: "client-wayne", Name: "Wayne Enterprises R&D (MSP-02)", APIKey: "key-wayne-ent-prod", CreatedAt: now},
	}
	for _, t := range tenants {
		_, _ = s.db.Exec("INSERT OR IGNORE INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)", t.ID, t.Name, t.APIKey, t.CreatedAt)
	}

	// Default Locations
	locations := []Location{
		{ID: "loc-hq", TenantID: "default", Name: "Austin HQ Data Center", City: "Austin, TX", Country: "US", SubnetCIDR: "10.0.0.0/24", CreatedAt: now},
		{ID: "loc-cloud", TenantID: "default", Name: "US-East AWS VPC", City: "Ashburn, VA", Country: "US", SubnetCIDR: "10.100.0.0/16", CreatedAt: now},
		{ID: "loc-acme-hq", TenantID: "client-acme", Name: "New York Corporate Office", City: "New York, NY", Country: "US", SubnetCIDR: "10.0.10.0/24", CreatedAt: now},
		{ID: "loc-wayne-lab", TenantID: "client-wayne", Name: "London Applied Sciences Lab", City: "London", Country: "GB", SubnetCIDR: "172.16.50.0/24", CreatedAt: now},
	}
	for _, l := range locations {
		_, _ = s.db.Exec("INSERT OR IGNORE INTO locations (id, tenant_id, name, city, country, subnet_cidr, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			l.ID, l.TenantID, l.Name, l.City, l.Country, l.SubnetCIDR, l.CreatedAt)
	}

	// Default Policy Groups
	groups := []PolicyGroup{
		{
			ID:          "grp-c2-containment",
			TenantID:    "default",
			Name:        "Automated C2 & Egress Lockdown",
			Description: "Blocks outbound execution from shell processes on all workstations",
			Criteria:    `{"process":["powershell.exe","cmd.exe","bash","nc","curl"]}`,
			Action:      "BLOCK",
			RuleType:    "process",
			RuleValue:   "powershell.exe,bash,nc",
			Port:        0,
			Protocol:    "any",
			Active:      true,
			CreatedAt:   now,
		},
		{
			ID:          "grp-db-protection",
			TenantID:    "default",
			Name:        "Database Server Enclave Isolation",
			Description: "Enforces strict port 5432/3306 permit rules on database servers",
			Criteria:    `{"role":"db-server","subnet":"10.0.0.0/24"}`,
			Action:      "PERMIT",
			RuleType:    "port",
			RuleValue:   "5432",
			Port:        5432,
			Protocol:    "tcp",
			Active:      true,
			CreatedAt:   now,
		},
	}
	for _, g := range groups {
		_, _ = s.db.Exec("INSERT OR IGNORE INTO policy_groups (id, tenant_id, name, description, criteria, action, rule_type, rule_value, port, protocol, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			g.ID, g.TenantID, g.Name, g.Description, g.Criteria, g.Action, g.RuleType, g.RuleValue, g.Port, g.Protocol, 1, g.CreatedAt)
	}
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

	if ep.LocationID == "" {
		ep.LocationID = "loc-hq"
		ep.LocationName = "Austin HQ Data Center"
	}
	if ep.RoleTag == "" {
		ep.RoleTag = "workstation"
	}
	if ep.InstalledSoftware == "" {
		if strings.Contains(strings.ToLower(ep.OS), "windows") {
			ep.InstalledSoftware = "Ominull WFP Agent v1.0.0, PowerShell 7.4, Windows Defender, OpenSSH"
			ep.MAC = "BC:24:11:2E:DA:85"
		} else if strings.Contains(strings.ToLower(ep.OS), "linux") || strings.Contains(strings.ToLower(ep.OS), "ubuntu") {
			ep.InstalledSoftware = "Ominull eBPF Daemon v1.0.0, Clang 18, bpftool, OpenSSH 9.6p1, systemd"
			ep.MAC = "BC:24:11:95:31:52"
		} else if strings.Contains(strings.ToLower(ep.OS), "mac") || strings.Contains(strings.ToLower(ep.OS), "darwin") {
			ep.InstalledSoftware = "Ominull PF Engine v1.0.0, Zsh 5.9, Apple pfctl, OpenSSH"
			ep.MAC = "BC:24:11:D6:AA:5F"
		}
	}

	query := `
	INSERT INTO endpoints (id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, status, is_isolated, last_seen_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		status=excluded.status,
		last_seen_at=excluded.last_seen_at
	`
	_, err := s.db.Exec(
		query,
		ep.ID, ep.TenantID, ep.LocationID, ep.LocationName, ep.Hostname, ep.OS, ep.IP, ep.MAC,
		ep.RoleTag, ep.InstalledSoftware, ep.DriverVersion,
		ep.Status, ep.IsIsolated, ep.LastSeenAt, ep.CreatedAt,
	)
	return err
}

func (s *Store) SetEndpointIsolation(id string, isIsolated bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	if isIsolated {
		val = 1
	}
	_, err := s.db.Exec("UPDATE endpoints SET is_isolated = ? WHERE id = ?", val, id)
	return err
}

func (s *Store) SetBulkIsolation(tenantID string, scope string, value string, isIsolated bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	if isIsolated {
		val = 1
	}

	var (
		res sql.Result
		err error
	)

	baseQuery := "UPDATE endpoints SET is_isolated = ?"
	var args []interface{}
	args = append(args, val)

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

	res, err = s.db.Exec(baseQuery, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) ListEndpoints(tenantID string) ([]Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints WHERE tenant_id = ? ORDER BY last_seen_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, location_id, location_name, hostname, os, ip, mac, role_tag, installed_software, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints ORDER BY last_seen_at DESC",
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
			&ep.RoleTag, &ep.InstalledSoftware, &ep.DriverVersion,
			&ep.Status, &isoInt, &ep.LastSeenAt, &ep.CreatedAt,
		); err != nil {
			return nil, err
		}
		ep.IsIsolated = isoInt != 0
		list = append(list, ep)
	}
	return list, nil
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

	if ev.BytesIn == 0 && ev.BytesOut == 0 {
		ev.BytesIn = 1420
		ev.BytesOut = 512
	}
	if ev.Country == "" {
		ev.Country = "US"
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
		if ev.BytesIn == 0 && ev.BytesOut == 0 {
			ev.BytesIn = 1420
			ev.BytesOut = 512
		}
		if ev.Country == "" {
			ev.Country = "US"
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := &AnalyticsSummary{
		Countries:         make(map[string]int64),
		TopProcesses:      make(map[string]int64),
		SeverityCounts:    make(map[string]int64),
		EnforcementCounts: make(map[string]int64),
		BandwidthTimeline: make([]BandwidthDataPoint, 0),
	}

	// 1. Totals from events
	var queryEvents string
	var args []interface{}
	if tenantID != "" {
		queryEvents = "SELECT COUNT(*), COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0), COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN action='PERMIT' THEN 1 ELSE 0 END), 0) FROM events WHERE tenant_id = ?"
		args = append(args, tenantID)
	} else {
		queryEvents = "SELECT COUNT(*), COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0), COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN action='PERMIT' THEN 1 ELSE 0 END), 0) FROM events"
	}
	_ = s.db.QueryRow(queryEvents, args...).Scan(&summary.TotalEvents, &summary.TotalBytesIn, &summary.TotalBytesOut, &summary.TotalBlocks, &summary.TotalPermits)

	// 2. Country aggregation
	var queryCountry string
	if tenantID != "" {
		queryCountry = "SELECT country, COUNT(*) FROM events WHERE tenant_id = ? GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10"
	} else {
		queryCountry = "SELECT country, COUNT(*) FROM events GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10"
	}
	cRows, err := s.db.Query(queryCountry, args...)
	if err == nil {
		for cRows.Next() {
			var c string
			var count int64
			if err := cRows.Scan(&c, &count); err == nil && c != "" {
				summary.Countries[c] = count
			}
		}
		cRows.Close()
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

	// 6. Generate 6-point timeline trend
	now := time.Now().UTC()
	for i := 5; i >= 0; i-- {
		t := now.Add(-time.Duration(i*10) * time.Minute)
		summary.BandwidthTimeline = append(summary.BandwidthTimeline, BandwidthDataPoint{
			Timestamp: t.Format("15:04"),
			BytesIn:   summary.TotalBytesIn/6 + int64(i*128000),
			BytesOut:  summary.TotalBytesOut/6 + int64(i*64000),
			Blocks:    summary.TotalBlocks/6 + int64(i*2),
		})
	}

	return summary, nil
}

func (s *Store) CreatePolicyGroup(g PolicyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actInt := 0
	if g.Active {
		actInt = 1
	}

	_, err := s.db.Exec(
		"INSERT INTO policy_groups (id, tenant_id, name, description, criteria, action, rule_type, rule_value, port, protocol, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		g.ID, g.TenantID, g.Name, g.Description, g.Criteria, g.Action, g.RuleType, g.RuleValue, g.Port, g.Protocol, actInt, g.CreatedAt,
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
			"SELECT id, tenant_id, name, description, criteria, action, rule_type, rule_value, port, protocol, active, created_at FROM policy_groups WHERE tenant_id = ? ORDER BY created_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, name, description, criteria, action, rule_type, rule_value, port, protocol, active, created_at FROM policy_groups ORDER BY created_at DESC",
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
			&g.ID, &g.TenantID, &g.Name, &g.Description, &g.Criteria, &g.Action, &g.RuleType, &g.RuleValue, &g.Port, &g.Protocol, &actInt, &g.CreatedAt,
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
