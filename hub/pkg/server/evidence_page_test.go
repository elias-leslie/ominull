package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/evidence"
	"ominull/hub/pkg/storage"
)

func TestEvidencePage(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	get := func(query, role string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", "/console/evidence"+query, nil)
		if role != "" {
			req.AddCookie(sessionFor(t, srv, role, role))
		}
		rec := httptest.NewRecorder()
		srv.handleEvidencePage(rec, req)
		return rec
	}

	srv.responseEnabled = false
	if body := get("", "admin").Body.String(); !strings.Contains(body, "Remote response is turned off") {
		t.Error("a hub without remote response lists evidence")
	}
	srv.responseEnabled = true
	if rec := get("", ""); rec.Code != 303 {
		t.Fatalf("no session answered %d, want a redirect to sign-in", rec.Code)
	}
	if body := get("", "admin").Body.String(); !strings.Contains(body, "No evidence yet.") {
		t.Error("an empty store is not explained")
	}

	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-web", TenantID: "default", Hostname: "web-01", IP: "10.0.0.11", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	b, err := srv.evidenceStore.CreateBundle("default", "ep-web", "job-1", "ir_standard", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.evidenceStore.StoreItem("default", b.ID, "processes.json", "application/json", "collected", []byte(`{"p":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.evidenceStore.StoreItem("default", b.ID, "shell_history.txt", "text/plain", "permission_denied", nil); err != nil {
		t.Fatal(err)
	}
	if err := srv.evidenceStore.SetLegalHold("default", b.ID, "ops@example.invalid", "case 7 <review>", true); err != nil {
		t.Fatal(err)
	}

	body := get("", "admin").Body.String()
	for _, want := range []string{`href="/console/evidence?id=` + b.ID + `"`, "Full triage collection", "web-01", "On hold", "1 on hold"} {
		if !strings.Contains(body, want) {
			t.Errorf("evidence list lacks %q", want)
		}
	}

	body = get("?id="+b.ID, "admin").Body.String()
	for _, want := range []string{
		"Full triage collection from web-01", "processes.json", "Permission denied",
		"set by ops@example.invalid: case 7 &lt;review&gt;", `id="hold-release"`, `src="/evidence.js?v=`,
		`href="/api/v1/evidence/export?id=` + b.ID + `"`, `href="/console/jobs?id=job-1"`, "the hold is released",
		"Without the hold it", `data-arriving="1"`, "Not sealed.", `id="hold-confirm"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("held bundle view lacks %q", want)
		}
	}
	if body := get("?id="+b.ID, "auditor").Body.String(); strings.Contains(body, `id="hold-release"`) {
		t.Error("a read-only role is offered the hold controls")
	}
	if body := get("?id="+b.ID, "analyst").Body.String(); !strings.Contains(body, `id="hold-release"`) {
		t.Error("an analyst, whom the hub lets change holds, is not offered them")
	}
	if body := get("?id=nope", "admin").Body.String(); !strings.Contains(body, "No evidence with ID “nope”.") {
		t.Error("an unknown bundle id is not explained")
	}

	if err := srv.evidenceStore.SetLegalHold("default", b.ID, "ops@example.invalid", "", false); err != nil {
		t.Fatal(err)
	}
	if body := get("?id="+b.ID, "admin").Body.String(); !strings.Contains(body, `id="hold-apply"`) || strings.Contains(body, "the hold is released") {
		t.Error("a released bundle does not offer a hold or still claims to be kept indefinitely")
	}

	expired := srv.buildEvidenceView(&evidence.EvidenceBundle{ID: "b3", RetentionExpiresAt: time.Now().Add(-time.Hour)}, "web-01", func(time.Time) string { return "x" }, time.Now())
	if !expired.ExpiryPassed {
		t.Error("a bundle past its keep-until date is not told apart, so the release confirm would promise a future date")
	}
	sealed := srv.buildEvidenceView(&evidence.EvidenceBundle{ID: "b2", Profile: "terminal_session", ManifestSHA256: "aa", ReceiptSHA256: "bb"}, "web-01", func(time.Time) string { return "" }, time.Now())
	if !sealed.Sealed || sealed.Kind != "Terminal recording" {
		t.Errorf("a sealed terminal recording reads as %+v", sealed)
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KB", 10 << 20: "10.0 MB", 3 << 30: "3.0 GB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
