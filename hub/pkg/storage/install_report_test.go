package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func testReportStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening a store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInstallReportsCRUD(t *testing.T) {
	store := testReportStore(t)

	report, err := store.CreateInstallReport(InstallReport{
		ClientIP:    "192.168.86.105",
		Platform:    "windows",
		UserAgent:   "Mozilla/5.0 Windows NT 10.0; Win64; x64",
		ErrorOutput: "curl: (56) OpenSSL SSL_read: tlsv13 alert certificate required",
		WindowID:    "win-test-123",
		SystemInfo: map[string]interface{}{
			"platform": "Win32",
			"timezone": "America/New_York",
			"language": "en-US",
		},
	})
	if err != nil {
		t.Fatalf("CreateInstallReport failed: %v", err)
	}
	if report.ID == "" {
		t.Fatalf("expected generated report ID, got empty")
	}

	reports, err := store.ListInstallReports(10)
	if err != nil {
		t.Fatalf("ListInstallReports failed: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].ClientIP != "192.168.86.105" {
		t.Errorf("ClientIP = %q, want 192.168.86.105", reports[0].ClientIP)
	}
	if reports[0].SystemInfo["timezone"] != "America/New_York" {
		t.Errorf("SystemInfo timezone = %v, want America/New_York", reports[0].SystemInfo["timezone"])
	}

	fetched, err := store.GetInstallReport(report.ID)
	if err != nil {
		t.Fatalf("GetInstallReport failed: %v", err)
	}
	if fetched.ErrorOutput != report.ErrorOutput {
		t.Errorf("ErrorOutput = %q, want %q", fetched.ErrorOutput, report.ErrorOutput)
	}

	if err := store.DeleteInstallReport(report.ID); err != nil {
		t.Fatalf("DeleteInstallReport failed: %v", err)
	}
	if _, err := store.GetInstallReport(report.ID); err == nil {
		t.Fatalf("expected report to be deleted, but GetInstallReport succeeded")
	}
}

func TestInstallReportRequiresErrorOutput(t *testing.T) {
	store := testReportStore(t)

	if _, err := store.CreateInstallReport(InstallReport{
		ClientIP:  "192.168.86.105",
		CreatedAt: time.Now().UTC(),
	}); err == nil {
		t.Fatalf("expected empty ErrorOutput to be rejected")
	}
}
