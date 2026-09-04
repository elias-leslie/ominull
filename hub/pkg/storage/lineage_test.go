package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestLineageAndHashing_MigrationCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_events.db")

	// 1. Manually create legacy schema with pre-Phase-6 events table
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open legacy sqlite: %v", err)
	}
	legacySchema := `
		CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT, api_key TEXT, created_at DATETIME);
		CREATE TABLE endpoints (id TEXT PRIMARY KEY, tenant_id TEXT, hostname TEXT, os TEXT, ip TEXT, driver_version TEXT, status TEXT, is_isolated BOOLEAN, last_seen_at DATETIME, created_at DATETIME);
		CREATE TABLE events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tenant_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
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
			country TEXT NOT NULL DEFAULT 'US',
			process_path TEXT NOT NULL,
			process_id INTEGER NOT NULL
		);
		INSERT INTO tenants (id, name, api_key, created_at) VALUES ('t1', 'Legacy Tenant', 'key-leg', '2026-09-01T00:00:00Z');
		INSERT INTO endpoints (id, tenant_id, hostname, os, ip, driver_version, status, is_isolated, last_seen_at, created_at)
			VALUES ('ep1', 't1', 'leg-host', 'Linux', '10.0.0.10', '1.0.0', 'online', 0, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z');
		INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id)
			VALUES ('t1', 'ep1', '2026-09-01T12:00:00Z', 'linux-socket-v1', 'PERMIT', 'OUTBOUND', 6, '10.0.0.10', '10.0.0.1', 50000, 443, 100, 200, 'US', '/usr/bin/legacy', 1234);
	`
	if _, err := legacyDB.Exec(legacySchema); err != nil {
		t.Fatalf("failed to create legacy schema: %v", err)
	}
	legacyDB.Close()

	// 2. Open via storage.New to trigger dynamic migrations
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed on legacy database: %v", err)
	}
	defer store.Close()

	// 3. Query legacy events to verify migration worked and legacy fields are intact
	events, err := store.QueryEvents("t1", "ep1", 10)
	if err != nil {
		t.Fatalf("QueryEvents on migrated database failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 legacy event, got %d", len(events))
	}

	ev := events[0]
	if ev.ProcessPath != "/usr/bin/legacy" || ev.ProcessID != 1234 {
		t.Errorf("legacy fields corrupted: path=%s, pid=%d", ev.ProcessPath, ev.ProcessID)
	}
	if ev.ProcessInstanceID != "" {
		t.Errorf("expected empty ProcessInstanceID for legacy row, got %q", ev.ProcessInstanceID)
	}
	if ev.ParentPID != 0 {
		t.Errorf("expected 0 ParentPID for legacy row, got %d", ev.ParentPID)
	}
	if ev.ExecutableSHA256 != "" {
		t.Errorf("expected empty ExecutableSHA256 for legacy row, got %q", ev.ExecutableSHA256)
	}
	if ev.AttributionStatus != "" {
		t.Errorf("expected empty AttributionStatus for legacy row, got %q", ev.AttributionStatus)
	}
	if ev.ObservedAt != nil {
		t.Errorf("expected nil ObservedAt for legacy row, got %v", ev.ObservedAt)
	}
}

func TestLineageAndHashing_InsertAndQueryLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "lineage_lifecycle.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	observed := now.Add(-500 * time.Millisecond)

	tenant := Tenant{ID: "t-enrich", Name: "Enriched Tenant", APIKey: "key-enrich", CreatedAt: now}
	if err := store.CreateTenant(tenant); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	ep := Endpoint{
		ID:            "ep-enrich-01",
		TenantID:      tenant.ID,
		Hostname:      "vault-srv",
		OS:            "Linux 6.17.2",
		IP:            "10.0.0.62",
		DriverVersion: "1.8.3",
		Status:        "online",
		LastSeenAt:    now,
		CreatedAt:     now,
	}
	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	// 1. Insert Enriched Event via InsertEvent
	enrichedEvent := Event{
		TenantID:                tenant.ID,
		EndpointID:              ep.ID,
		Timestamp:               now,
		Layer:                   "linux-socket-v1",
		Action:                  "PERMIT",
		Direction:               "OUTBOUND",
		Protocol:                6,
		SrcIP:                   "10.0.0.62",
		DstIP:                   "10.0.0.58",
		SrcPort:                 45678,
		DstPort:                 9443,
		BytesIn:                 1420,
		BytesOut:                850,
		Country:                 "US",
		ProcessPath:             "/usr/bin/curl",
		ProcessID:               5432,
		Domain:                  "hub.example.invalid",
		SNI:                     "hub.example.invalid",
		ProcessInstanceID:       "boot-4f9a:5432:1788541000",
		ParentPID:               1000,
		ParentProcessInstanceID: "boot-4f9a:1000:1788540000",
		CommandLine:             "/usr/bin/curl -s https://hub.example.invalid:9443/api/v1/health",
		UserIdentity:            "root",
		ExecutableSHA256:        "b8f88636e08c48a73a6e975ff8f407b0cf9fe7ebae665e8a69e3805bfde960c1",
		AttributionStatus:       "authoritative",
		ObservedAt:              &observed,
	}

	if err := store.InsertEvent(enrichedEvent); err != nil {
		t.Fatalf("InsertEvent failed: %v", err)
	}

	// 2. Query via QueryEvents
	queried, err := store.QueryEvents(tenant.ID, ep.ID, 10)
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	if len(queried) != 1 {
		t.Fatalf("expected 1 event, got %d", len(queried))
	}

	q := queried[0]
	if q.ProcessInstanceID != enrichedEvent.ProcessInstanceID {
		t.Errorf("ProcessInstanceID mismatch: expected %q, got %q", enrichedEvent.ProcessInstanceID, q.ProcessInstanceID)
	}
	if q.ParentPID != enrichedEvent.ParentPID {
		t.Errorf("ParentPID mismatch: expected %d, got %d", enrichedEvent.ParentPID, q.ParentPID)
	}
	if q.ParentProcessInstanceID != enrichedEvent.ParentProcessInstanceID {
		t.Errorf("ParentProcessInstanceID mismatch: expected %q, got %q", enrichedEvent.ParentProcessInstanceID, q.ParentProcessInstanceID)
	}
	if q.CommandLine != enrichedEvent.CommandLine {
		t.Errorf("CommandLine mismatch: expected %q, got %q", enrichedEvent.CommandLine, q.CommandLine)
	}
	if q.UserIdentity != enrichedEvent.UserIdentity {
		t.Errorf("UserIdentity mismatch: expected %q, got %q", enrichedEvent.UserIdentity, q.UserIdentity)
	}
	if q.ExecutableSHA256 != enrichedEvent.ExecutableSHA256 {
		t.Errorf("ExecutableSHA256 mismatch: expected %q, got %q", enrichedEvent.ExecutableSHA256, q.ExecutableSHA256)
	}
	if q.AttributionStatus != enrichedEvent.AttributionStatus {
		t.Errorf("AttributionStatus mismatch: expected %q, got %q", enrichedEvent.AttributionStatus, q.AttributionStatus)
	}
	if q.ObservedAt == nil || q.ObservedAt.Unix() != observed.Unix() {
		t.Errorf("ObservedAt mismatch: expected %v, got %v", observed, q.ObservedAt)
	}

	// 3. Query via QueryTrafficFlows
	flowsRes, err := store.QueryTrafficFlows(TrafficFilter{
		TenantID:   tenant.ID,
		EndpointID: ep.ID,
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("QueryTrafficFlows failed: %v", err)
	}
	if len(flowsRes.Flows) != 1 {
		t.Fatalf("expected 1 traffic flow, got %d", len(flowsRes.Flows))
	}

	flow := flowsRes.Flows[0]
	if flow.ProcessInstanceID != enrichedEvent.ProcessInstanceID {
		t.Errorf("flow.ProcessInstanceID mismatch: expected %q, got %q", enrichedEvent.ProcessInstanceID, flow.ProcessInstanceID)
	}
	if flow.ParentPID != enrichedEvent.ParentPID {
		t.Errorf("flow.ParentPID mismatch: expected %d, got %d", enrichedEvent.ParentPID, flow.ParentPID)
	}
	if flow.CommandLine != enrichedEvent.CommandLine {
		t.Errorf("flow.CommandLine mismatch: expected %q, got %q", enrichedEvent.CommandLine, flow.CommandLine)
	}
	if flow.ExecutableSHA256 != enrichedEvent.ExecutableSHA256 {
		t.Errorf("flow.ExecutableSHA256 mismatch: expected %q, got %q", enrichedEvent.ExecutableSHA256, flow.ExecutableSHA256)
	}
	if flow.AttributionStatus != enrichedEvent.AttributionStatus {
		t.Errorf("flow.AttributionStatus mismatch: expected %q, got %q", enrichedEvent.AttributionStatus, flow.AttributionStatus)
	}

	// 4. Query via GetTrafficFlowByID
	singleFlow, err := store.GetTrafficFlowByID(flow.ID, tenant.ID)
	if err != nil {
		t.Fatalf("GetTrafficFlowByID failed: %v", err)
	}
	if singleFlow == nil {
		t.Fatalf("expected single flow, got nil")
	}
	if singleFlow.CommandLine != enrichedEvent.CommandLine {
		t.Errorf("singleFlow.CommandLine mismatch: expected %q, got %q", enrichedEvent.CommandLine, singleFlow.CommandLine)
	}
	if singleFlow.ExecutableSHA256 != enrichedEvent.ExecutableSHA256 {
		t.Errorf("singleFlow.ExecutableSHA256 mismatch: expected %q, got %q", enrichedEvent.ExecutableSHA256, singleFlow.ExecutableSHA256)
	}
}

func TestLineageAndHashing_IngestTelemetryBatchCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "telemetry_batch_compat.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)

	tenant := Tenant{ID: "t-batch", Name: "Batch Tenant", APIKey: "key-batch", CreatedAt: now}
	if err := store.CreateTenant(tenant); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	ep := Endpoint{
		ID:            "ep-batch-01",
		TenantID:      tenant.ID,
		Hostname:      "batch-host",
		OS:            "Linux",
		IP:            "10.0.0.100",
		DriverVersion: "1.8.3",
		Status:        "online",
		LastSeenAt:    now,
		CreatedAt:     now,
	}
	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	obs := now.Add(-100 * time.Millisecond)
	batch := []Event{
		// Legacy event without enrichment fields
		{
			TenantID:    tenant.ID,
			EndpointID:  ep.ID,
			Timestamp:   now.Add(-2 * time.Second),
			Layer:       "linux-socket-v1",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.100",
			DstIP:       "1.1.1.1",
			SrcPort:     40001,
			DstPort:     443,
			BytesIn:     500,
			BytesOut:    200,
			ProcessPath: "/bin/legacy-proc",
			ProcessID:   100,
		},
		// Enriched event
		{
			TenantID:                tenant.ID,
			EndpointID:              ep.ID,
			Timestamp:               now.Add(-1 * time.Second),
			Layer:                   "linux-socket-v1",
			Action:                  "PERMIT",
			Direction:               "OUTBOUND",
			Protocol:                6,
			SrcIP:                   "10.0.0.100",
			DstIP:                   "8.8.8.8",
			SrcPort:                 40002,
			DstPort:                 53,
			BytesIn:                 100,
			BytesOut:                50,
			ProcessPath:             "/usr/sbin/named",
			ProcessID:               200,
			ProcessInstanceID:       "boot-b1:200:1788542000",
			ParentPID:               1,
			ParentProcessInstanceID: "boot-b1:1:1788540000",
			CommandLine:             "/usr/sbin/named -f -u bind",
			UserIdentity:            "bind",
			ExecutableSHA256:        "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
			AttributionStatus:       "inferred_cached",
			ObservedAt:              &obs,
		},
	}

	if err := store.InsertTelemetryBatch(batch, ep.Hostname, "loc-test"); err != nil {
		t.Fatalf("InsertTelemetryBatch failed: %v", err)
	}

	events, err := store.QueryEvents(tenant.ID, ep.ID, 10)
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// Events are sorted DESC by timestamp: [0] is the enriched one, [1] is the legacy one
	modern := events[0]
	legacy := events[1]

	if modern.ProcessID != 200 || modern.ProcessInstanceID != "boot-b1:200:1788542000" {
		t.Errorf("modern event corrupted: %v", modern)
	}
	if modern.CommandLine != "/usr/sbin/named -f -u bind" || modern.UserIdentity != "bind" {
		t.Errorf("modern event command_line/user_identity mismatch: %v", modern)
	}
	if modern.AttributionStatus != "inferred_cached" {
		t.Errorf("modern attribution_status mismatch: %s", modern.AttributionStatus)
	}

	if legacy.ProcessID != 100 || legacy.ProcessInstanceID != "" {
		t.Errorf("legacy event corrupted: %v", legacy)
	}
	if legacy.ParentPID != 0 || legacy.CommandLine != "" {
		t.Errorf("legacy event non-empty parent_pid/command_line: %v", legacy)
	}
}
