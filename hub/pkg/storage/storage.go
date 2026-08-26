package storage

import (
	"database/sql"
	"fmt"
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

type Endpoint struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	IP             string    `json:"ip"`
	DriverVersion  string    `json:"driver_version"`
	Status         string    `json:"status"` // online, offline
	IsIsolated     bool      `json:"is_isolated"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	CreatedAt      time.Time `json:"created_at"`
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
	Scope      string    `json:"scope"` // "all", "platform", "department", "ids"
	ScopeValue string    `json:"scope_value"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
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

	CREATE TABLE IF NOT EXISTS endpoints (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		hostname TEXT NOT NULL,
		os TEXT NOT NULL,
		ip TEXT NOT NULL,
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

	CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_endpoint_time ON events(endpoint_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs(value);
	CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_tenant_time ON alerts(tenant_id, timestamp DESC);
	`
	_, err := s.db.Exec(schema)
	return err
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

func (s *Store) UpsertEndpoint(ep Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	INSERT INTO endpoints (id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		hostname=excluded.hostname,
		os=excluded.os,
		ip=excluded.ip,
		driver_version=excluded.driver_version,
		status=excluded.status,
		is_isolated=excluded.is_isolated,
		last_seen_at=excluded.last_seen_at
	`
	_, err := s.db.Exec(
		query,
		ep.ID, ep.TenantID, ep.Hostname, ep.OS, ep.IP, ep.DriverVersion,
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
	case "platform":
		baseQuery += " WHERE os LIKE ?"
		args = append(args, "%"+value+"%")
		if tenantID != "" {
			baseQuery += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
	case "department":
		baseQuery += " WHERE department = ?"
		args = append(args, value)
		if tenantID != "" {
			baseQuery += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
	case "location":
		baseQuery += " WHERE location = ?"
		args = append(args, value)
		if tenantID != "" {
			baseQuery += " AND tenant_id = ?"
			args = append(args, tenantID)
		}
	default:
		return 0, fmt.Errorf("unknown bulk scope: %s", scope)
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
			"SELECT id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints WHERE tenant_id = ? ORDER BY hostname COLLATE NOCASE ASC, id ASC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints ORDER BY hostname COLLATE NOCASE ASC, id ASC",
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
			&ep.ID, &ep.TenantID, &ep.Hostname, &ep.OS, &ep.IP, &ep.DriverVersion,
			&ep.Status, &isoInt, &ep.LastSeenAt, &ep.CreatedAt,
		); err != nil {
			return nil, err
		}
		ep.IsIsolated = isoInt != 0
		if time.Since(ep.LastSeenAt) < 30*time.Second {
			ep.Status = "online"
		} else {
			ep.Status = "offline"
		}
		list = append(list, ep)
	}
	return list, nil
}

func (s *Store) InsertEventsBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events (
			tenant_id, endpoint_id, timestamp, layer, action, direction,
			protocol, src_ip, dst_ip, src_port, dst_port, process_path, process_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(
			e.TenantID, e.EndpointID, e.Timestamp, e.Layer, e.Action, e.Direction,
			e.Protocol, e.SrcIP, e.DstIP, e.SrcPort, e.DstPort, e.ProcessPath, e.ProcessID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) QueryEvents(tenantID, endpointID string, limit int) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)

	if tenantID != "" && endpointID != "" {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction,
			       protocol, src_ip, dst_ip, src_port, dst_port, process_path, process_id
			FROM events WHERE tenant_id = ? AND endpoint_id = ?
			ORDER BY timestamp DESC LIMIT ?
		`, tenantID, endpointID, limit)
	} else if tenantID != "" {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction,
			       protocol, src_ip, dst_ip, src_port, dst_port, process_path, process_id
			FROM events WHERE tenant_id = ?
			ORDER BY timestamp DESC LIMIT ?
		`, tenantID, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, timestamp, layer, action, direction,
			       protocol, src_ip, dst_ip, src_port, dst_port, process_path, process_id
			FROM events
			ORDER BY timestamp DESC LIMIT ?
		`, limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.EndpointID, &e.Timestamp, &e.Layer, &e.Action, &e.Direction,
			&e.Protocol, &e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.ProcessPath, &e.ProcessID,
		); err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, nil
}

func (s *Store) UpsertIOC(ioc IOC) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	if ioc.Active {
		val = 1
	}
	query := `
	INSERT INTO iocs (id, value, type, source, threat_type, confidence, active, created_at, last_seen_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(value) DO UPDATE SET
		threat_type=excluded.threat_type,
		confidence=excluded.confidence,
		active=excluded.active,
		last_seen_at=excluded.last_seen_at
	`
	_, err := s.db.Exec(
		query,
		ioc.ID, ioc.Value, ioc.Type, ioc.Source, ioc.ThreatType,
		ioc.Confidence, val, ioc.CreatedAt, ioc.LastSeenAt,
	)
	return err
}

func (s *Store) UpsertIOCsBatch(iocs []IOC) error {
	if len(iocs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
	INSERT INTO iocs (id, value, type, source, threat_type, confidence, active, created_at, last_seen_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(value) DO UPDATE SET
		threat_type=excluded.threat_type,
		confidence=excluded.confidence,
		active=excluded.active,
		last_seen_at=excluded.last_seen_at
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, ioc := range iocs {
		val := 0
		if ioc.Active {
			val = 1
		}
		if _, err := stmt.Exec(
			ioc.ID, ioc.Value, ioc.Type, ioc.Source, ioc.ThreatType,
			ioc.Confidence, val, ioc.CreatedAt, ioc.LastSeenAt,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListIOCs(limit int) ([]IOC, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.db.Query(
		"SELECT id, value, type, source, threat_type, confidence, active, created_at, last_seen_at FROM iocs WHERE active = 1 ORDER BY last_seen_at DESC LIMIT ?",
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

func (s *Store) DeleteIOC(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM iocs WHERE id = ?", id)
	return err
}

func (s *Store) CreateRule(r Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := 0
	if r.Active {
		val = 1
	}
	_, err := s.db.Exec(
		"INSERT INTO rules (id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		r.ID, r.TenantID, r.Name, r.Type, r.Value, r.Port, r.Protocol, r.Action, r.Scope, r.ScopeValue, val, r.CreatedAt,
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
			"SELECT id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at FROM rules WHERE tenant_id = ? ORDER BY created_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, name, type, value, port, protocol, action, scope, scope_value, active, created_at FROM rules ORDER BY created_at DESC",
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
