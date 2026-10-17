package scripts

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestParsePackageResult(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in    string
		ok    bool
		state string
	}{
		{"log line\n{\"v\":1,\"state\":\"fixed\",\"reboot\":true,\"changed\":[\"a\"],\"detail\":{}}\r\n", true, "fixed"},
		{"{\"v\":1,\"state\":\"ok\",\"reboot\":false,\"changed\":[]}", true, "ok"},
		{"{\"v\":1,\"state\":\"ok\"}\ntrailing noise", false, ""},
		{"{\"v\":2,\"state\":\"ok\"}", false, ""},
		{"{\"v\":1,\"state\":\"great\"}", false, ""},
		{"", false, ""},
		{"{\"v\":1,\"state\":\"ok\"", false, ""},
	} {
		r, ok := ParsePackageResult(tc.in)
		if ok != tc.ok || (ok && r.State != tc.state) {
			t.Errorf("ParsePackageResult(%q) = %+v, %v; want ok=%v state=%q", tc.in, r, ok, tc.ok, tc.state)
		}
	}
}

func TestClampTimeout(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]int{0: 60, -5: 60, 1: 1, 300: 300, 3600: 3600, 3601: 60} {
		if got := ClampTimeout(in); got != want {
			t.Errorf("ClampTimeout(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestSyncScript(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A library created before scripts had metadata gains the column.
	if _, err := db.Exec(`CREATE TABLE scripts (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
		description TEXT NOT NULL, interpreter TEXT NOT NULL, latest_version INTEGER DEFAULT 1, retired INTEGER DEFAULT 0,
		created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore on a legacy table: %v", err)
	}
	if _, err := NewStore(db); err != nil {
		t.Fatalf("second migration: %v", err)
	}

	schema := `{"parameters":[{"name":"mode","type":"enum","enum":["audit","enforce"],"default":"audit"}]}`
	meta := `{"package":"windows-cleanup","title":"Cleanup","risk":"safe","reboot":true,"timeout":3600}`
	sync := func(source, metadata, desc string) (*Script, *ScriptVersion, string) {
		t.Helper()
		sc, sv, action, err := store.SyncScript("default", "windows-cleanup", desc, "powershell.exe", source, schema, metadata, "ops")
		if err != nil {
			t.Fatalf("SyncScript: %v", err)
		}
		return sc, sv, action
	}
	sc, sv, action := sync("Write-Output 1", meta, "Cleans")
	if action != "created" || sv.Version != 1 || sc.Package() == nil || sc.Package().Timeout != 3600 {
		t.Fatalf("create: %s v%d %+v", action, sv.Version, sc.Package())
	}
	if _, sv, action = sync("Write-Output 1", meta, "Cleans"); action != "unchanged" || sv.Version != 1 {
		t.Fatalf("same source minted a version: %s v%d", action, sv.Version)
	}
	// Metadata or description alone changes in place.
	if sc, sv, action = sync("Write-Output 1", `{"package":"windows-cleanup","title":"Clean up"}`, "Cleans more"); action != "unchanged" || sv.Version != 1 || sc.Package().Title != "Clean up" {
		t.Fatalf("metadata update: %s v%d %+v", action, sv.Version, sc.Package())
	}
	got, _ := store.GetScript("default", sc.ID)
	if got.Package().Title != "Clean up" || got.Description != "Cleans more" {
		t.Fatalf("stored metadata/description not updated: %+v %q", got.Package(), got.Description)
	}
	if _, sv, action = sync("Write-Output 2", meta, "Cleans"); action != "updated" || sv.Version != 2 {
		t.Fatalf("changed source: %s v%d", action, sv.Version)
	}
	if _, _, _, err := store.SyncScript("default", "windows-cleanup", "", "/bin/sh", "x", "", "", "ops"); err == nil {
		t.Fatal("sync accepted an interpreter change")
	}
	if _, _, _, err := store.SyncScript("default", "other", "", "powershell.exe", "x", "", `["not","an","object"]`, "ops"); err == nil {
		t.Fatal("sync accepted non-object metadata")
	}
	list, _ := store.ListScripts("default")
	if len(list) != 1 || list[0].Package() == nil {
		t.Fatalf("list: %+v", list)
	}
}
