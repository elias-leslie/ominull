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
)

// packageSource is the released source of a package in packages/windows.
func packageSource(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "windows", strings.TrimPrefix(name, "windows-")+".ps1"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// packageItem is the payload of one run of a released package. The risk
// argument documents what the test expects; it comes from the release list.
func packageItem(t *testing.T, name, risk, mode string, timeout int) string {
	t.Helper()
	return execItem(t, "s-"+name, packageSource(t, name), mode, timeout)
}

func execItem(t *testing.T, id, src, mode string, timeout int) string {
	t.Helper()
	sum := sha256.Sum256([]byte(src))
	raw, err := json.Marshal(response.ScriptExecPayload{ScriptID: id, ScriptVersion: 1, ScriptDigest: hex.EncodeToString(sum[:]),
		Interpreter: "powershell.exe", Source: src, Parameters: map[string]string{"mode": mode}, TimeoutSeconds: timeout, MaxOutputBytes: 1 << 20})
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
	audit := packageItem(t, "windows-audit", "safe", "audit", 300)
	cleanup := packageItem(t, "windows-cleanup", "safe", "audit", 3600)
	laptops := []string{"ep-b", "ep-a"}

	v, err := auth.RequestApproval(packageRequest(laptops, audit, cleanup))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != responseauth.ApprovalPending || statementOffer(t, v) != "packages" || v.Action != "Run maintenance" ||
		!strings.Contains(v.Summary, "windows-audit (audit), up to 5 min") || !strings.Contains(v.Summary, "windows-cleanup (audit), up to 60 min") {
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
	// Another mode, a longer timeout or another host is a new digest or
	// target: asked for (a rule-only request is refused without asking).
	for name, in := range map[string]*responseauth.ApprovalRequestInput{
		"enforce": packageRequest([]string{"ep-a"}, packageItem(t, "windows-audit", "safe", "enforce", 300)),
		"timeout": packageRequest([]string{"ep-a"}, packageItem(t, "windows-audit", "safe", "audit", 600)),
		"host":    packageRequest([]string{"ep-c"}, audit),
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
	a := packageItem(t, "windows-audit", "safe", "audit", 300)
	b := packageItem(t, "windows-privacy", "safe", "audit", 300)
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

// The authority's list of released packages is exactly packages/windows.
func TestReleasedPackagesMatchTheRepository(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "packages", "windows", "*.ps1"))
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
		t.Fatalf("hub/pkg/responseauth/released_packages.json is out of step with packages/windows; it should hold:\n%s", b.String())
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
	// A released source with other parameters or another interpreter is not
	// the released package either.
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(packageItem(t, "windows-audit", "safe", "audit", 300)), &p)
	p.Parameters["extra"] = "1"
	odd, _ := json.Marshal(p)
	if v, err := auth.RequestApproval(packageRequest([]string{"ep-b"}, string(odd))); err != nil || statementOffer(t, v) != "" ||
		!strings.Contains(v.Summary, "not a released package") {
		t.Fatalf("extra parameters kept package trust: %v %+v", err, v)
	}
}

// Only the canonical bytes are accepted, so an agent that searches for the
// first "source" member reads what the authority read.
func TestPackageRunRefusesReorderedOrNestedFields(t *testing.T) {
	auth, _, _, _ := newRuleAuthority(t)
	item := packageItem(t, "windows-audit", "safe", "audit", 300)
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
	if _, err := auth.RequestApproval(packageRequest([]string{"ep-a"}, items...)); err == nil || !strings.Contains(err.Error(), "split the run") {
		t.Fatalf("an approval that cannot show every script was accepted: %v", err)
	}
}
