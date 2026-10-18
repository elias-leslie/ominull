package responseauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func packageRequest(targets []string, items ...string) *responseauth.ApprovalRequestInput {
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	payload, _ := json.Marshal(responseauth.PackageRunPayload{Route: responseauth.PackageRunRoute, Items: items, Targets: sorted})
	return &responseauth.ApprovalRequestInput{TenantID: "default", Requester: "admin", Kind: response.ActionKindScriptExec,
		Action: "Run maintenance", Summary: "hub text is ignored", Targets: targets, Payload: payload}
}

func TestPackageRuleCoversExactRunsOnly(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	audit := packageItem(t, "windows-audit", "safe", "enforce", 300)
	cleanup := packageItem(t, "windows-cleanup", "safe", "enforce", 3600)
	laptops := []string{"ep-b", "ep-a"}

	v, err := auth.RequestApproval(packageRequest(laptops, audit, cleanup))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalPending || statementOffer(t, v) != "packages" || v.Action != "Run maintenance" ||
		!strings.Contains(v.Summary, "windows-audit (enforce), up to 5 min") || !strings.Contains(v.Summary, "windows-cleanup (enforce), up to 60 min") {
		t.Fatalf("a safe package run should ask, offer the rule and say what runs: %s %q %q", v.State, statementOffer(t, v), v.Summary)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")}); err != nil {
		t.Fatal(err)
	}
	rules, err := auth.PackageRules("default")
	if err != nil || len(rules) != 1 || len(rules[0].Endpoints) != 2 || rules[0].ApproverID != "owner-phone" {
		t.Fatalf("rule not listed: %v %+v", err, rules)
	}

	// The same runs (or a subset, on a subset of hosts) need no tap, and
	// are not held to the hourly limit.
	for i := 0; i < 40; i++ {
		in := packageRequest([]string{"ep-a"}, audit)
		in.RuleOnly = true
		got, err := auth.RequestApproval(in)
		if err != nil || got.State != responseauth.ApprovalApproved || got.Method != "rule" {
			t.Fatalf("covered run %d: %v %+v", i, err, got)
		}
	}
	// Auditing with the same settings is covered too (switching back to
	// audit never asks).
	twin := packageRequest([]string{"ep-a"}, packageItem(t, "windows-cleanup", "safe", "audit", 3600))
	twin.RuleOnly = true
	if got, err := auth.RequestApproval(twin); err != nil || got.State != responseauth.ApprovalApproved {
		t.Fatalf("the audit twin of a covered run: %v %+v", err, got)
	}
	// Other settings, a longer timeout or another host is a new digest or
	// target: asked for (a rule-only request is refused without asking).
	ah, _ := scripts.ParsePackageHeader(packageSource(t, "windows-audit"))
	changed := otherValue(t, ah)
	for name, in := range map[string]*responseauth.ApprovalRequestInput{
		"settings": packageRequest([]string{"ep-a"}, packageItem(t, "windows-audit", "safe", "enforce", 300, changed...)),
		"timeout":  packageRequest([]string{"ep-a"}, packageItem(t, "windows-audit", "safe", "enforce", 600)),
		"host":     packageRequest([]string{"ep-c"}, audit),
	} {
		in.RuleOnly = true
		if _, err := auth.RequestApproval(in); !errors.Is(err, responseauth.ErrRuleNotCovered) {
			t.Fatalf("%s: rule-only request should be refused, got %v", name, err)
		}
	}
	if p := auth.PendingApprovals(); len(p) != 0 {
		t.Fatalf("rule-only refusals must not ask the owner: %+v", p)
	}

	n, err := auth.ForgetPackageRule("default", rules[0].ID, "admin")
	if err != nil || n != 1 {
		t.Fatalf("forget: %d %v", n, err)
	}
	in := packageRequest([]string{"ep-a"}, audit)
	in.RuleOnly = true
	if _, err := auth.RequestApproval(in); !errors.Is(err, responseauth.ErrRuleNotCovered) {
		t.Fatalf("a removed rule still covers runs: %v", err)
	}
}

func TestCarefulPackagesAreNeverOfferedARule(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	v, err := auth.RequestApproval(packageRequest([]string{"ep-a"},
		packageItem(t, "windows-audit", "safe", "audit", 300), packageItem(t, "windows-debloat", "careful", "enforce", 900)))
	if err != nil {
		t.Fatal(err)
	}
	if statementOffer(t, v) != "" || !strings.Contains(v.Summary, "windows-debloat (enforce), up to 15 min, careful") {
		t.Fatalf("a run with a careful package must not offer a rule: %q %q", statementOffer(t, v), v.Summary)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")}); err == nil {
		t.Fatal("a rule answer on an ask that offers none was accepted")
	}
}

func TestPackageRunGrantsBindEachScript(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	a := packageItem(t, "windows-audit", "safe", "enforce", 300)
	b := packageItem(t, "windows-privacy", "safe", "enforce", 300)
	in := packageRequest([]string{"ep-a", "ep-b"}, a, b)
	v, err := auth.RequestApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(in.Payload)
	grants, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin",
		Kind: response.ActionKindScriptExec, Digest: hex.EncodeToString(sum[:]), Targets: []string{"ep-a", "ep-b"}})
	if err != nil || len(grants) != 4 {
		t.Fatalf("want one grant per host and script: %v %d", err, len(grants))
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
	auth, _, _, _ := newRuleAuthority(t)
	item := packageItem(t, "windows-audit", "safe", "audit", 300)
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(item), &p)
	p.Source += "Remove-Item C:\\ -Recurse\n"
	bad, _ := json.Marshal(p)
	if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, string(bad))); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a source that does not match its digest was accepted: %v", err)
	}
	in := packageRequest([]string{"ep-a"}, item)
	in.Targets = []string{"ep-b"}
	if _, err := auth.RequestApproval(in); err == nil {
		t.Fatal("payload targets that differ from the approval's were accepted")
	}
}

func TestPackageRunRefusesAmbiguousKeys(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	item := packageItem(t, "windows-audit", "safe", "audit", 300)
	for name, bad := range map[string]string{
		"upper case": strings.Replace(item, `"source"`, `"Source"`, 1),
		"duplicate":  strings.Replace(item, `{"script_id"`, `{"timeout_seconds":5,"script_id"`, 1),
		"trailing":   item + ` {}`,
	} {
		if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, bad)); err == nil {
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
	auth, _, _, _ := newRuleAuthority(t)
	forged := `# ominull-package: {"name":"windows-audit","title":"T","description":"d","risk":"safe","reboot":false,"timeout":300}` + "\nRemove-Item C:\\ -Recurse\n"
	v, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, execItem(t, "s-forged", forged, "audit", 300)))
	if err != nil {
		t.Fatal(err)
	}
	if statementOffer(t, v) != "" || !strings.Contains(v.Summary, "s-forged (audit), up to 5 min, not a released package") {
		t.Fatalf("a forged header was trusted: %q %q", statementOffer(t, v), v.Summary)
	}
	// A released package run with an undeclared or out-of-range setting is
	// refused; under another interpreter it is not the released package.
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(packageItem(t, "windows-audit", "safe", "audit", 300)), &p)
	p.Parameters["extra"] = "1"
	odd, _ := json.Marshal(p)
	if _, err := auth.RequestApproval(packageRequest([]string{"ep-b"}, string(odd))); err == nil {
		t.Fatal("an undeclared setting was accepted")
	}
	delete(p.Parameters, "extra")
	p.Interpreter = "pwsh.exe"
	other, _ := json.Marshal(p)
	if v, err := auth.RequestApproval(packageRequest([]string{"ep-b"}, string(other))); err != nil || statementOffer(t, v) != "" ||
		!strings.Contains(v.Summary, "not a released package") {
		t.Fatalf("another interpreter kept package trust: %v %+v", err, v)
	}
}

// Only the canonical bytes are accepted, so an agent that searches for the
// first "source" member reads what the authority read.
func TestPackageRunRefusesReorderedOrNestedFields(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
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
		if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p.Parameters = map[string]string{"mode": "audit", "source": "x"}
	reserved, _ := json.Marshal(p)
	if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, string(reserved))); err == nil {
		t.Error("a parameter named like a payload field was accepted")
	}
}

// A run too long to show whole is refused, never shown cut.
func TestPackageRunTooLongToShowIsRefused(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	var items []string
	for i := 0; i < 10; i++ {
		items = append(items, execItem(t, fmt.Sprintf("script-with-a-rather-long-identifier-number-%02d", i), fmt.Sprintf("Write-Output %d\n", i), "audit", 300))
	}
	if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, items...)); err == nil || !strings.Contains(err.Error(), "run fewer packages") {
		t.Fatalf("an approval that cannot show every script was accepted: %v", err)
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

// A safe package auditing with its default settings runs without a tap;
// changed settings, enforce or a careful package ask, and the ask shows the
// changed values.
func TestBaselineAuditsNeedNoTap(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	auth.UseApprovalRows(false) // the approve-all rules, as before Approvals rows
	for i := 0; i < 40; i++ {   // and no hourly limit
		in := packageRequest([]string{"ep-a", "ep-b"}, packageItem(t, "windows-audit", "safe", "audit", 300), packageItem(t, "windows-cleanup", "safe", "audit", 3600))
		in.RuleOnly = true
		v, err := auth.RequestApproval(in)
		if err != nil || v.State != responseauth.ApprovalApproved || v.Method != "baseline" {
			t.Fatalf("baseline run %d: %v %+v", i, err, v)
		}
	}
	h, _ := scripts.ParsePackageHeader(packageSource(t, "windows-audit"))
	changed := otherValue(t, h)
	for name, item := range map[string]string{
		"settings": packageItem(t, "windows-audit", "safe", "audit", 300, changed...),
		"enforce":  packageItem(t, "windows-audit", "safe", "enforce", 300),
		"careful":  packageItem(t, "windows-debloat", "careful", "audit", 900),
	} {
		in := packageRequest([]string{"ep-a"}, item)
		in.RuleOnly = true
		if _, err := auth.RequestApproval(in); !errors.Is(err, responseauth.ErrRuleNotCovered) {
			t.Errorf("%s: should need the owner, got %v", name, err)
		}
	}
	v, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, packageItem(t, "windows-audit", "safe", "audit", 300, changed...)))
	if err != nil || v.State != responseauth.ApprovalPending || !strings.Contains(v.Summary, "settings "+changed[0]+"="+changed[1]) {
		t.Fatalf("the ask should show the changed setting: %v %+v", err, v)
	}
}

// Turning on a careful step makes a safe package's run careful: asked for
// every time, never offered a rule. Revert is treated like enforce: it is
// never a baseline and never rides on an audit twin.
func TestCarefulStepsAndRevertAlwaysAsk(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
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
	v, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, packageItem(t, "windows-performance", "safe", "enforce", 300, step, "true")))
	if err != nil {
		t.Fatal(err)
	}
	if statementOffer(t, v) != "" || !strings.Contains(v.Summary, "careful steps "+step) {
		t.Fatalf("a careful step must ask without a rule and name the step: %q %q", statementOffer(t, v), v.Summary)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")}); err == nil {
		t.Fatal("a rule answer on a careful step was accepted")
	}

	// Revert with every default is not a baseline.
	in := packageRequest([]string{"ep-a"}, packageItem(t, "windows-performance", "safe", "revert", 300))
	in.RuleOnly = true
	if _, err := auth.RequestApproval(in); !errors.Is(err, responseauth.ErrRuleNotCovered) {
		t.Fatalf("a default revert ran without the owner: %v", err)
	}
	// A rule for enforce does not cover revert.
	enforce := packageItem(t, "windows-performance", "safe", "enforce", 300)
	v, err = auth.RequestApproval(packageRequest([]string{"ep-a"}, enforce))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "rule", Assertion: ap.Assert(v.Challenge, "rule")}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.RequestApproval(in); !errors.Is(err, responseauth.ErrRuleNotCovered) {
		t.Fatalf("an enforce rule covered a revert: %v", err)
	}
}

func playbookRequest(targets []string, pb *responseauth.PlaybookRun, route string, items ...string) *responseauth.ApprovalRequestInput {
	in := packageRequest(targets, items...)
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	in.Payload, _ = json.Marshal(responseauth.PackageRunPayload{Route: route, Items: items, Targets: sorted, Playbook: pb})
	return in
}

// A playbook run: never a baseline, never offered a rule, steps shown in
// order with the window, and every grant lives for exactly that window. Its
// route and window are checked.
func TestPlaybookRunsAskAndLiveForTheWindow(t *testing.T) {
	auth, ap, _, _ := newRuleAuthority(t)
	auth.UseApprovalRows(false) // the approve-all rules, as before Approvals rows
	audit := packageItem(t, "windows-audit", "safe", "audit", 300)
	cleanup := packageItem(t, "windows-cleanup", "safe", "audit", 3600)
	pb := &responseauth.PlaybookRun{Name: "Weekly tidy", WindowSeconds: 2 * 3600}

	rule := playbookRequest([]string{"ep-a"}, pb, responseauth.PlaybookRunRoute, audit, cleanup)
	rule.RuleOnly = true
	if _, err := auth.RequestApproval(rule); !errors.Is(err, responseauth.ErrRuleNotCovered) {
		t.Fatalf("a playbook of baseline audits must still ask: %v", err)
	}
	for name, in := range map[string]*responseauth.ApprovalRequestInput{
		"plain route":  playbookRequest([]string{"ep-a"}, pb, responseauth.PackageRunRoute, audit),
		"no playbook":  playbookRequest([]string{"ep-a"}, nil, responseauth.PlaybookRunRoute, audit),
		"short window": playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{Name: "x", WindowSeconds: 60}, responseauth.PlaybookRunRoute, audit),
		"long window":  playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{Name: "x", WindowSeconds: 25 * 3600}, responseauth.PlaybookRunRoute, audit),
		"no name":      playbookRequest([]string{"ep-a"}, &responseauth.PlaybookRun{WindowSeconds: 3600}, responseauth.PlaybookRunRoute, audit),
	} {
		if _, err := auth.RequestApproval(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	in := playbookRequest([]string{"ep-a"}, pb, responseauth.PlaybookRunRoute, cleanup, audit)
	v, err := auth.RequestApproval(in)
	if err != nil || v.State != responseauth.ApprovalPending || statementOffer(t, v) != "" {
		t.Fatalf("ask: %v %+v", err, v)
	}
	if !strings.Contains(v.Summary, `Playbook "Weekly tidy" as SYSTEM on ep-a, one step after another, all within 2 hours: 1. windows-cleanup (audit), up to 60 min; 2. windows-audit (audit), up to 5 min`) {
		t.Fatalf("summary: %s", v.Summary)
	}
	if _, err := auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: v.ID, Decision: "approve", Assertion: ap.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(in.Payload)
	grants, err := auth.ConsumeApproval(&responseauth.ApprovalConsumeRequest{ID: v.ID, TenantID: "default", Requester: "admin",
		Kind: response.ActionKindScriptExec, Digest: hex.EncodeToString(sum[:]), Targets: []string{"ep-a"}, TTLSeconds: 300})
	if err != nil || len(grants) != 2 {
		t.Fatalf("grants: %v %d", err, len(grants))
	}
	for _, g := range grants {
		if g.ExpiresAt-g.IssuedAt != 2*3600 {
			t.Fatalf("a playbook grant lives %ds, want the approved window", g.ExpiresAt-g.IssuedAt)
		}
	}
}

// A full tune-up (keep awake, seven packages, keep awake off) still fits one
// approval: short names, the shared options said once, nothing dropped.
func TestLongPlaybookFitsOneApproval(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
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
	v, err := auth.RequestApproval(playbookRequest([]string{"ep-a"}, pb, responseauth.PlaybookRunRoute, items...))
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
