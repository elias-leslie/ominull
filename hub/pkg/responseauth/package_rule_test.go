package responseauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

func packageItem(t *testing.T, name, risk, mode string, timeout int) string {
	t.Helper()
	src := `# ominull-package: {"name":"` + name + `","title":"T","description":"d","risk":"` + risk + `","reboot":false,"timeout":300}` + "\nWrite-Output 'x'\n"
	sum := sha256.Sum256([]byte(src))
	raw, err := json.Marshal(response.ScriptExecPayload{ScriptID: "s-" + name, ScriptVersion: 1, ScriptDigest: hex.EncodeToString(sum[:]),
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
