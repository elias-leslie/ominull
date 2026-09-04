package scripts

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestScripts_StoreLifecycleAndTenantIsolation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"
	sourceV1 := "echo 'Hello from Ominull V1'\n"

	paramSchema := `{
		"parameters": [
			{"name": "target_host", "type": "string", "required": true, "pattern": "^[a-zA-Z0-9.-]+$"},
			{"name": "timeout_sec", "type": "number", "required": false, "default": "30"},
			{"name": "verbose", "type": "boolean", "default": "false"},
			{"name": "mode", "type": "enum", "enum_values": ["quick", "deep"], "default": "quick"}
		]
	}`

	// 1. Create Script V1 under tenantA
	sc, v1, err := store.CreateScript(tenantA, "health_check.sh", "Endpoint health inspection", "/bin/sh", sourceV1, paramSchema, "admin")
	if err != nil {
		t.Fatalf("CreateScript failed: %v", err)
	}
	if sc.LatestVersion != 1 || v1.Version != 1 {
		t.Fatalf("version mismatch: %d vs %d", sc.LatestVersion, v1.Version)
	}

	// 2. Cross-tenant access denied
	_, err = store.GetScript(tenantB, sc.ID)
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected cross-tenant GetScript to fail, got: %v", err)
	}
	_, err = store.GetScriptVersion(tenantB, sc.ID, 1)
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected cross-tenant GetScriptVersion to fail, got: %v", err)
	}
	_, err = store.UpdateScript(tenantB, sc.ID, "echo 'hacked'\n", "", "attacker")
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected cross-tenant UpdateScript to fail, got: %v", err)
	}
	err = store.RetireScript(tenantB, sc.ID)
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected cross-tenant RetireScript to fail, got: %v", err)
	}

	// 3. Append Script Version V2 under tenantA
	sourceV2 := "echo 'Hello from Ominull V2'\nuname -a\n"
	v2, err := store.UpdateScript(tenantA, sc.ID, sourceV2, paramSchema, "admin")
	if err != nil {
		t.Fatalf("UpdateScript failed: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("expected version 2, got %d", v2.Version)
	}

	// 4. Retrieve Exact Versions under tenantA
	retV1, err := store.GetScriptVersion(tenantA, sc.ID, 1)
	if err != nil || retV1.Source != sourceV1 {
		t.Fatalf("failed to retrieve exact version 1: %v", err)
	}

	retV2, err := store.GetScriptVersion(tenantA, sc.ID, 2)
	if err != nil || retV2.Source != sourceV2 {
		t.Fatalf("failed to retrieve exact version 2: %v", err)
	}

	// 5. List Scripts isolates by tenant
	listA, err := store.ListScripts(tenantA)
	if err != nil || len(listA) != 1 {
		t.Fatalf("expected 1 script for tenantA, got %d", len(listA))
	}
	listB, err := store.ListScripts(tenantB)
	if err != nil || len(listB) != 0 {
		t.Fatalf("expected 0 scripts for tenantB, got %d", len(listB))
	}

	// 6. Retire Script
	if err := store.RetireScript(tenantA, sc.ID); err != nil {
		t.Fatalf("RetireScript failed: %v", err)
	}
	_, err = store.UpdateScript(tenantA, sc.ID, "echo 'V3'\n", "", "admin")
	if !errors.Is(err, ErrScriptRetired) {
		t.Fatalf("expected ErrScriptRetired on retired script update, got: %v", err)
	}
}

func TestScripts_InterpreterAllowlistAndBounds(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	validInterpreters := []string{"/bin/sh", "/bin/bash", "powershell.exe", "cmd.exe", "pwsh.exe"}
	for _, interp := range validInterpreters {
		_, _, err := store.CreateScript("tenant-1", "test-"+interp, "desc", interp, "echo test", "", "admin")
		if err != nil {
			t.Fatalf("expected interpreter %q to be allowed, got error: %v", interp, err)
		}
	}

	invalidInterpreters := []string{"/usr/bin/python3", "/bin/zsh", "perl", "ruby", "/usr/bin/env bash"}
	for _, interp := range invalidInterpreters {
		_, _, err := store.CreateScript("tenant-1", "bad-"+interp, "desc", interp, "echo test", "", "admin")
		if !errors.Is(err, ErrInvalidInterpreter) {
			t.Fatalf("expected ErrInvalidInterpreter for %q, got: %v", interp, err)
		}
	}

	// Test source code bounds (MaxScriptSourceBytes = 65536)
	hugeSource := strings.Repeat("A", MaxScriptSourceBytes+1)
	_, _, err = store.CreateScript("tenant-1", "huge.sh", "desc", "/bin/bash", hugeSource, "", "admin")
	if !errors.Is(err, ErrScriptTooLarge) {
		t.Fatalf("expected ErrScriptTooLarge for oversized source, got: %v", err)
	}
}

func TestScripts_ParameterSchemaValidation(t *testing.T) {
	schemaJSON := `{
		"parameters": [
			{"name": "hostname", "type": "string", "required": true, "pattern": "^[a-zA-Z0-9.-]+$"},
			{"name": "port", "type": "number", "required": true},
			{"name": "ssl", "type": "boolean", "default": "true"},
			{"name": "verbosity", "type": "enum", "enum_values": ["debug", "info", "warn"]}
		]
	}`

	schema, err := ValidateSchema(schemaJSON)
	if err != nil {
		t.Fatalf("ValidateSchema failed: %v", err)
	}

	// 1. Valid parameter values
	validVals := map[string]string{
		"hostname":  "example.com",
		"port":      "443",
		"ssl":       "true",
		"verbosity": "info",
	}
	if err := ValidateParameters(schema, validVals); err != nil {
		t.Fatalf("expected valid parameters to pass, got: %v", err)
	}

	// 2. Missing required parameter
	missingReq := map[string]string{
		"port": "443",
	}
	if err := ValidateParameters(schema, missingReq); !errors.Is(err, ErrMissingParameter) {
		t.Fatalf("expected ErrMissingParameter, got: %v", err)
	}

	// 3. Unknown parameter (injection attempt)
	unknownParam := map[string]string{
		"hostname":  "example.com",
		"port":      "443",
		"inject_me": "rm -rf /",
	}
	if err := ValidateParameters(schema, unknownParam); !errors.Is(err, ErrUnknownParameter) {
		t.Fatalf("expected ErrUnknownParameter, got: %v", err)
	}

	// 4. Invalid number
	badNum := map[string]string{
		"hostname": "example.com",
		"port":     "not-a-number",
	}
	if err := ValidateParameters(schema, badNum); !errors.Is(err, ErrInvalidParameter) {
		t.Fatalf("expected ErrInvalidParameter for bad number, got: %v", err)
	}

	// 5. Invalid boolean
	badBool := map[string]string{
		"hostname": "example.com",
		"port":     "443",
		"ssl":      "maybe",
	}
	if err := ValidateParameters(schema, badBool); !errors.Is(err, ErrInvalidParameter) {
		t.Fatalf("expected ErrInvalidParameter for bad boolean, got: %v", err)
	}

	// 6. Invalid enum
	badEnum := map[string]string{
		"hostname":  "example.com",
		"port":      "443",
		"verbosity": "critical",
	}
	if err := ValidateParameters(schema, badEnum); !errors.Is(err, ErrInvalidParameter) {
		t.Fatalf("expected ErrInvalidParameter for bad enum, got: %v", err)
	}

	// 7. Regex pattern mismatch
	badPattern := map[string]string{
		"hostname": "invalid host name with spaces!",
		"port":     "443",
	}
	if err := ValidateParameters(schema, badPattern); !errors.Is(err, ErrInvalidParameter) {
		t.Fatalf("expected ErrInvalidParameter for pattern mismatch, got: %v", err)
	}

	// 8. Script with no parameters rejects non-empty values
	emptySchema, _ := ValidateSchema("")
	if err := ValidateParameters(emptySchema, map[string]string{"foo": "bar"}); !errors.Is(err, ErrUnknownParameter) {
		t.Fatalf("expected ErrUnknownParameter for parameters passed to schema-less script, got: %v", err)
	}
}

func TestScripts_SchedulesLifecycleAndFreezing(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"

	paramSchema := `{
		"parameters": [
			{"name": "target", "type": "string", "required": true}
		]
	}`
	sc, v1, err := store.CreateScript(tenantA, "audit_scan.sh", "Daily audit scanner", "/bin/bash", "echo 'scanning'\n", paramSchema, "operator1")
	if err != nil {
		t.Fatalf("CreateScript failed: %v", err)
	}

	// 1. Reject empty targets
	_, err = store.CreateSchedule(tenantA, sc.ID, 1, nil, map[string]string{"target": "10.0.0.1"}, "daily", time.Now(), nil, 10, 60, 1048576, "operator1")
	if !errors.Is(err, ErrEmptyTargetEndpoints) {
		t.Fatalf("expected ErrEmptyTargetEndpoints, got: %v", err)
	}

	// 2. Reject wildcard targets
	_, err = store.CreateSchedule(tenantA, sc.ID, 1, []string{"*"}, map[string]string{"target": "10.0.0.1"}, "daily", time.Now(), nil, 10, 60, 1048576, "operator1")
	if !errors.Is(err, ErrEmptyTargetEndpoints) {
		t.Fatalf("expected ErrEmptyTargetEndpoints for wildcard, got: %v", err)
	}

	// 3. Create valid schedule
	targets := []string{"ep-linux-01", "ep-linux-02"}
	sched, err := store.CreateSchedule(tenantA, sc.ID, 1, targets, map[string]string{"target": "10.0.0.1"}, "daily", time.Now(), nil, 5, 60, 1048576, "operator1")
	if err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}
	if sched.ScriptDigest != v1.DigestSHA256 {
		t.Fatalf("schedule did not freeze script digest: %s vs %s", sched.ScriptDigest, v1.DigestSHA256)
	}
	if len(sched.TargetEndpoints) != 2 || sched.TargetEndpoints[0] != "ep-linux-01" {
		t.Fatalf("target endpoints snapshot mismatch: %v", sched.TargetEndpoints)
	}
	if sched.Status != "active" {
		t.Fatalf("expected active schedule status, got %s", sched.Status)
	}

	// 4. Tenant isolation: tenantB cannot view schedule
	_, err = store.GetSchedule(tenantB, sched.ID)
	if !errors.Is(err, ErrScheduleNotFound) {
		t.Fatalf("expected ErrScheduleNotFound for cross-tenant schedule get, got: %v", err)
	}

	listB, err := store.ListSchedules(tenantB)
	if err != nil || len(listB) != 0 {
		t.Fatalf("expected 0 schedules for tenantB, got: %d", len(listB))
	}

	listA, err := store.ListSchedules(tenantA)
	if err != nil || len(listA) != 1 {
		t.Fatalf("expected 1 schedule for tenantA, got: %d", len(listA))
	}

	// 5. Cancel schedule
	if err := store.CancelSchedule(tenantA, sched.ID); err != nil {
		t.Fatalf("CancelSchedule failed: %v", err)
	}
	schedCancelled, err := store.GetSchedule(tenantA, sched.ID)
	if err != nil || schedCancelled.Status != "cancelled" {
		t.Fatalf("expected cancelled status, got: %v, status: %s", err, schedCancelled.Status)
	}

	// 6. Cannot cancel already cancelled schedule
	if err := store.CancelSchedule(tenantA, sched.ID); !errors.Is(err, ErrScheduleNotFound) {
		t.Fatalf("expected ErrScheduleNotFound on double cancel, got: %v", err)
	}

	// 7. Retiring script prevents new schedules
	if err := store.RetireScript(tenantA, sc.ID); err != nil {
		t.Fatalf("RetireScript failed: %v", err)
	}
	_, err = store.CreateSchedule(tenantA, sc.ID, 1, targets, map[string]string{"target": "10.0.0.1"}, "daily", time.Now(), nil, 5, 60, 1048576, "operator1")
	if !errors.Is(err, ErrScriptRetired) {
		t.Fatalf("expected ErrScriptRetired when scheduling retired script, got: %v", err)
	}
}
