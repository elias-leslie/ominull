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

	CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_endpoint_time ON events(endpoint_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
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

func (s *Store) ListEndpoints(tenantID string) ([]Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints WHERE tenant_id = ? ORDER BY last_seen_at DESC",
			tenantID,
		)
	} else {
		rows, err = s.db.Query(
			"SELECT id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at FROM endpoints ORDER BY last_seen_at DESC",
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
