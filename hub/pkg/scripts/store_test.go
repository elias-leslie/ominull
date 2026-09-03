package scripts

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestScripts_StoreLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantID := "tenant-alpha"
	sourceV1 := "echo 'Hello from Ominull V1'\n"

	// 1. Create Script V1
	sc, v1, err := store.CreateScript(tenantID, "health_check.sh", "Endpoint health inspection", "/bin/sh", sourceV1, "", "admin")
	if err != nil {
		t.Fatalf("CreateScript failed: %v", err)
	}
	if sc.LatestVersion != 1 || v1.Version != 1 {
		t.Fatalf("version mismatch: %d vs %d", sc.LatestVersion, v1.Version)
	}

	// 2. Append Script Version V2
	sourceV2 := "echo 'Hello from Ominull V2'\nuname -a\n"
	v2, err := store.UpdateScript(sc.ID, sourceV2, "", "admin")
	if err != nil {
		t.Fatalf("UpdateScript failed: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("expected version 2, got %d", v2.Version)
	}

	// 3. Retrieve Exact Versions
	retV1, err := store.GetScriptVersion(sc.ID, 1)
	if err != nil || retV1.Source != sourceV1 {
		t.Fatalf("failed to retrieve exact version 1: %v", err)
	}

	retV2, err := store.GetScriptVersion(sc.ID, 2)
	if err != nil || retV2.Source != sourceV2 {
		t.Fatalf("failed to retrieve exact version 2: %v", err)
	}

	// 4. List Scripts
	list, err := store.ListScripts(tenantID)
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 script in list, got %d", len(list))
	}
	if list[0].LatestVersion != 2 {
		t.Fatalf("expected latest version 2, got %d", list[0].LatestVersion)
	}

	// 5. Retire Script
	if err := store.RetireScript(sc.ID); err != nil {
		t.Fatalf("RetireScript failed: %v", err)
	}
	_, err = store.UpdateScript(sc.ID, "echo 'V3'\n", "", "admin")
	if err == nil {
		t.Fatalf("expected update on retired script to fail")
	}
}
