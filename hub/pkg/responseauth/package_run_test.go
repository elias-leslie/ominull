package responseauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

// packageSource is the released source of a package in packages/windows or
// packages/linux.
func packageSource(t *testing.T, name string) string {
	t.Helper()
	dir, ext, base := "windows", ".ps1", strings.TrimPrefix(name, "windows-")
	if b, ok := strings.CutPrefix(name, "linux-"); ok {
		dir, ext, base = "linux", ".sh", b
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", dir, base+ext))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// packageItem is the payload of one run of a released package. The risk
// argument documents what the test expects; it comes from the release list.
func packageItem(t *testing.T, name, risk, mode string, timeout int, set ...string) string {
	t.Helper()
	src := packageSource(t, name)
	h, err := scripts.ParsePackageHeader(src)
	if err != nil {
		t.Fatal(err)
	}
	if h.Risk != risk {
		t.Fatalf("%s is %s, not %s", name, h.Risk, risk)
	}
	params := h.Defaults()
	for i := 0; i+1 < len(set); i += 2 {
		params[set[i]] = set[i+1]
	}
	params["mode"] = mode
	return execParams(t, "s-"+name, src, params, timeout)
}

func execItem(t *testing.T, id, src, mode string, timeout int) string {
	t.Helper()
	return execParams(t, id, src, map[string]string{"mode": mode}, timeout)
}

func execParams(t *testing.T, id, src string, params map[string]string, timeout int) string {
	t.Helper()
	sum := sha256.Sum256([]byte(src))
	raw, err := json.Marshal(response.ScriptExecPayload{ScriptID: id, ScriptVersion: 1, ScriptDigest: hex.EncodeToString(sum[:]),
		Interpreter: "powershell.exe", Source: src, Parameters: params, TimeoutSeconds: timeout, MaxOutputBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func packageRequest(targets []string, items ...string) *responseauth.AuthorizeInput {
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	payload, _ := json.Marshal(responseauth.PackageRunPayload{Route: responseauth.PackageRunRoute, Items: items, Targets: sorted})
	return &responseauth.AuthorizeInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindScriptExec,
		Targets: targets, Payload: payload}
}

func TestPackageRunGrantsBindEachScript(t *testing.T) {
	auth := newTestAuthority(t)
	a := packageItem(t, "windows-audit", "safe", "enforce", 300)
	b := packageItem(t, "windows-privacy", "safe", "enforce", 300)
	in := packageRequest([]string{"ep-a", "ep-b"}, a, b)
	au, err := auth.Authorize(in)
	if err != nil {
		t.Fatal(err)
	}
	grants := au.Grants
	if len(grants) != 4 {
		t.Fatalf("want one grant per host and script: %d", len(grants))
	}
	seen := map[string]bool{}
	for _, g := range grants {
		if g.ActionKind != response.ActionKindScriptExec || (g.ActionDigest != responseauth.ItemDigest(a) && g.ActionDigest != responseauth.ItemDigest(b)) {
			t.Fatalf("grant not bound to a script payload: %+v", g)
		}
		seen[g.EndpointID+g.ActionDigest] = true
	}
	if len(seen) != 4 {
		t.Fatalf("grants repeat a host/script pair: %v", seen)
	}
}

func TestPackageRunRefusesTamperedScripts(t *testing.T) {
	auth := newTestAuthority(t)
	item := packageItem(t, "windows-audit", "safe", "audit", 300)
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(item), &p)
	p.Source += "Remove-Item C:\\ -Recurse\n"
	bad, _ := json.Marshal(p)
	if _, err := auth.Authorize(packageRequest([]string{"ep-a"}, string(bad))); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a source that does not match its digest was accepted: %v", err)
	}
	in := packageRequest([]string{"ep-a"}, item)
	in.Targets = []string{"ep-b"}
	if _, err := auth.Authorize(in); err == nil {
		t.Fatal("payload targets that differ from the approval's were accepted")
	}
}

func TestPackageRunRefusesAmbiguousKeys(t *testing.T) {
	auth := newTestAuthority(t)
	item := packageItem(t, "windows-audit", "safe", "audit", 300)
	for name, bad := range map[string]string{
		"upper case": strings.Replace(item, `"source"`, `"Source"`, 1),
		"duplicate":  strings.Replace(item, `{"script_id"`, `{"timeout_seconds":5,"script_id"`, 1),
		"trailing":   item + ` {}`,
	} {
		if _, err := auth.Authorize(packageRequest([]string{"ep-a"}, bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The authority's list of released packages is exactly packages/windows and
// packages/linux.
func TestReleasedPackagesMatchTheRepository(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "packages", "windows", "*.ps1"))
	linux, _ := filepath.Glob(filepath.Join("..", "..", "..", "packages", "linux", "*.sh"))
	files = append(files, linux...)
	want := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		line, _, _ := strings.Cut(string(raw), "\n")
		var h struct{ Name, Risk string }
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "# ominull-package:")), &h); err != nil {
			t.Fatal(f, err)
		}
		sum := sha256.Sum256(raw)
		want[hex.EncodeToString(sum[:])] = h.Name + " " + h.Risk
	}
	got := responseauth.ReleasedPackages()
	if len(want) == 0 || fmt.Sprint(want) != fmt.Sprint(got) {
		var b strings.Builder
		for d, v := range want {
			n, r, _ := strings.Cut(v, " ")
			fmt.Fprintf(&b, "  %q: {\"name\": %q, \"risk\": %q},\n", d, n, r)
		}
		t.Fatalf("hub/pkg/responseauth/released_packages.json is out of step with packages/; it should hold:\n%s", b.String())
	}
}

// The hub cannot pass its own script off as a package: only the released
// sources count, whatever the submitted header says.
func TestForgedPackageHeadersAreNotTrusted(t *testing.T) {
	auth := newTestAuthority(t)
	forged := `# ominull-package: {"name":"windows-audit","title":"T","description":"d","risk":"safe","reboot":false,"timeout":300}` + "\nRemove-Item C:\\ -Recurse\n"
	v, err := auth.Authorize(packageRequest([]string{"ep-a"}, execItem(t, "s-forged", forged, "audit", 300)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Summary, "s-forged (audit), up to 5 min, not a released package") {
		t.Fatalf("a forged header was trusted: %q", v.Summary)
	}
	// A released package run with an undeclared or out-of-range setting is
	// refused; under another interpreter it is not the released package.
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(packageItem(t, "windows-audit", "safe", "audit", 300)), &p)
	p.Parameters["extra"] = "1"
	odd, _ := json.Marshal(p)
	if _, err := auth.Authorize(packageRequest([]string{"ep-b"}, string(odd))); err == nil {
		t.Fatal("an undeclared setting was accepted")
	}
	delete(p.Parameters, "extra")
	p.Interpreter = "pwsh.exe"
	other, _ := json.Marshal(p)
	if v, err := auth.Authorize(packageRequest([]string{"ep-b"}, string(other))); err != nil ||
		!strings.Contains(v.Summary, "not a released package") {
		t.Fatalf("another interpreter kept package trust: %v %+v", err, v)
	}
}

// Only the canonical bytes are accepted, so an agent that searches for the
// first "source" member reads what the authority read.
func TestPackageRunRefusesReorderedOrNestedFields(t *testing.T) {
	auth := newTestAuthority(t)
	item := execItem(t, "s-plain", "Write-Output 1\n", "audit", 300)
	evil := "Remove-Item C:\\ -Recurse\n"
	sum := sha256.Sum256([]byte(evil))
	nested := fmt.Sprintf(`{"parameters":{"mode":"audit","script_digest":"%s","source":%q},`, hex.EncodeToString(sum[:]), evil)
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(item), &p)
	for name, bad := range map[string]string{
		"nested first": nested + strings.TrimPrefix(strings.Replace(item, `"parameters":{"mode":"audit"},`, "", 1), "{"),
		"reordered":    `{"script_version":1,` + strings.Replace(strings.TrimPrefix(item, "{"), `"script_version":1,`, "", 1),
		"spaced":       strings.Replace(item, `"interpreter":`, `"interpreter": `, 1),
	} {
		if bad == item {
			t.Fatalf("%s: test payload unchanged", name)
		}
		if _, err := auth.Authorize(packageRequest([]string{"ep-a"}, bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p.Parameters = map[string]string{"mode": "audit", "source": "x"}
	reserved, _ := json.Marshal(p)
	if _, err := auth.Authorize(packageRequest([]string{"ep-a"}, string(reserved))); err == nil {
		t.Error("a parameter named like a payload field was accepted")
	}
}

// A run too long to show whole is cut in the audit words; it is signed
// whole (the grants bind every script).
func TestPackageRunTooLongToShowIsCut(t *testing.T) {
	auth := newTestAuthority(t)
	var items []string
	for i := 0; i < 10; i++ {
		items = append(items, execItem(t, fmt.Sprintf("script-with-a-rather-long-identifier-number-%02d", i), fmt.Sprintf("Write-Output %d\n", i), "audit", 300))
	}
	au, err := auth.Authorize(packageRequest([]string{"ep-a"}, items...))
	if err != nil || len(au.Grants) != 10 || len([]rune(au.Summary)) > 300 {
		t.Fatalf("a long run: %v grants %d summary %d runes", err, len(au.Grants), len([]rune(au.Summary)))
	}
}

// otherValue returns a param name and a valid non-default value for it.
func otherValue(t *testing.T, h *scripts.PackageHeader) []string {
	t.Helper()
	for _, p := range h.Params {
		switch p.Type {
		case "int":
			v := fmt.Sprint(*p.Min)
			if v == p.DefaultValue() {
				v = fmt.Sprint(*p.Max)
			}
			return []string{p.Name, v}
		case "bool":
			return []string{p.Name, map[string]string{"true": "false", "false": "true"}[p.DefaultValue()]}
		}
	}
	t.Fatalf("%s has no int or bool setting", h.Name)
	return nil
}

// Turning on a careful step makes a safe package's run careful, and the
// audit words name the step.
func TestCarefulStepsAreNamed(t *testing.T) {
	auth := newTestAuthority(t)
	h, _ := scripts.ParsePackageHeader(packageSource(t, "windows-performance"))
	var step string
	for _, p := range h.Params {
		if p.Careful {
			step = p.Name
		}
	}
	if step == "" {
		t.Fatal("windows-performance declares no careful step")
	}
	au, err := auth.Authorize(packageRequest([]string{"ep-a"}, packageItem(t, "windows-performance", "safe", "enforce", 300, step, "true")))
	if err != nil || !strings.Contains(au.Summary, "careful steps "+step) || len(au.Grants) != 1 {
		t.Fatalf("a careful step must be named: %v %+v", err, au)
	}
}

func playbookRequest(targets []string, pb *responseauth.PlaybookRun, route string, items ...string) *responseauth.AuthorizeInput {
	in := packageRequest(targets, items...)
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	in.Payload, _ = json.Marshal(responseauth.PackageRunPayload{Route: route, Items: items, Targets: sorted, Playbook: pb})
	return in
}

// A playbook run: steps shown in order with the window, and every grant lives
// for exactly that window. Its route and window are checked.
func TestPlaybookRunsLiveForTheWindow(t *testing.T) {
	auth := newTestAuthority(t)
	audit := packageItem(t, "windows-audit", "safe", "audit", 300)
	cleanup := packageItem(t, "windows-cleanup", "safe", "audit", 3600)
	pb := &responseauth.PlaybookRun{Name: "Weekly tidy", WindowSeconds: 2 * 3600}

	for name, in := range map[string]*responseauth.AuthorizeInput{
		"plain route":  playbookRequest([]string{"ep-a"}, pb, responseauth.PackageRunRoute, audit),
		"no playbook":  playbookRequest([]string{"ep-a"}, nil, responseauth.PlaybookRunRoute, audit),
		"short window": playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{Name: "x", WindowSeconds: 60}, responseauth.PlaybookRunRoute, audit),
		"long window":  playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{Name: "x", WindowSeconds: 25 * 3600}, responseauth.PlaybookRunRoute, audit),
		"no name":      playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{WindowSeconds: 3600}, responseauth.PlaybookRunRoute, audit),
	} {
		if _, err := auth.Authorize(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	in := playbookRequest([]string{"ep-a"}, pb, responseauth.PlaybookRunRoute, cleanup, audit)
	au, err := auth.Authorize(in)
	if err != nil || len(au.Grants) != 2 {
		t.Fatalf("playbook: %v %+v", err, au)
	}
	if !strings.Contains(au.Summary, `Playbook "Weekly tidy" as SYSTEM on ep-a, one step after another, all within 2 hours: 1. windows-cleanup (audit), up to 60 min; 2. windows-audit (audit), up to 5 min`) {
		t.Fatalf("summary: %s", au.Summary)
	}
	grants := au.Grants
	for _, g := range grants {
		if g.ExpiresAt-g.IssuedAt != 2*3600 {
			t.Fatalf("a playbook grant lives %ds, want the approved window", g.ExpiresAt-g.IssuedAt)
		}
	}
}

// A full tune-up (keep awake, seven packages, keep awake off) still fits one
// summary: short names, the shared options said once, nothing dropped.
func TestLongPlaybookFitsOneSummary(t *testing.T) {
	auth := newTestAuthority(t)
	wait := []string{"when_busy", "wait"}
	items := []string{
		packageItem(t, "windows-maintenance-mode", "safe", "enforce", 300, "hours", "6"),
		packageItem(t, "windows-updates", "safe", "enforce", 3600, wait...),
		packageItem(t, "windows-cleanup", "safe", "enforce", 3600, wait...),
		packageItem(t, "windows-debloat", "careful", "enforce", 1800, wait...),
		packageItem(t, "windows-privacy", "safe", "enforce", 600, wait...),
		packageItem(t, "windows-performance", "safe", "enforce", 600, wait...),
		packageItem(t, "windows-software-removal", "careful", "enforce", 3600, wait...),
		packageItem(t, "windows-audit", "safe", "audit", 300),
		packageItem(t, "windows-maintenance-mode", "safe", "revert", 300),
	}
	pb := &responseauth.PlaybookRun{Name: "Laptop tune-up", WindowSeconds: 6 * 3600}
	v, err := auth.Authorize(playbookRequest([]string{"ep-a"}, pb, responseauth.PlaybookRunRoute, items...))
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	for _, want := range []string{`Playbook "Laptop tune-up"`, "within 6 hours", "keep awake on", "updates", "cleanup", "debloat, careful",
		"privacy", "performance", "software-removal, careful", "audit (audit)", "keep awake off", "waits while someone is using the machine"} {
		if !strings.Contains(v.Summary, want) {
			t.Errorf("summary lacks %q: %s", want, v.Summary)
		}
	}
	if strings.Count(v.Summary, "waits while") != 1 {
		t.Errorf("shared option should be said once: %s", v.Summary)
	}
	t.Logf("%d: %s", len([]rune(v.Summary)), v.Summary)
}
