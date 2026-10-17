package scripts

import (
	"strings"
	"testing"
	"time"
)

const testHeader = `# ominull-package: {"name":"x","title":"X","description":"Does x.","category":"maintenance","risk":"safe","reboot":false,"timeout":300,"interval":"daily","params":[` +
	`{"name":"age_days","type":"int","default":14,"min":1,"max":365,"description":"Age."},` +
	`{"name":"deep","type":"bool","default":false,"description":"Deep."},` +
	`{"name":"level","type":"enum","values":["low","high"],"default":"low","description":"Level."},` +
	`{"name":"apps","type":"list","default":["Microsoft.BingNews","*Candy*"],"max_items":4,"description":"Apps."}]}` + "\nWrite-Output 1\n"

func TestPackageParamsDefaultsChecksAndChanges(t *testing.T) {
	h, err := ParsePackageHeader(testHeader)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Defaults()
	if d["age_days"] != "14" || d["deep"] != "false" || d["level"] != "low" || d["apps"] != "Microsoft.BingNews,*Candy*" {
		t.Fatalf("defaults: %v", d)
	}
	run := map[string]string{"mode": "audit", "age_days": "14", "deep": "false", "level": "low", "apps": "Microsoft.BingNews,*Candy*"}
	if err := h.CheckRun(run); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][2]string{
		"range":     {"age_days", "0"},
		"not int":   {"age_days", "014"},
		"bool":      {"deep", "yes"},
		"enum":      {"level", "max"},
		"too many":  {"apps", "a,b,c,d,e"},
		"separator": {"apps", `a\b`},
		"duplicate": {"apps", "A,a"},
		"blank":     {"apps", "a, b"},
		"unset":     {"apps", ""},
	} {
		r := map[string]string{}
		for k, v := range run {
			r[k] = v
		}
		r[bad[0]] = bad[1]
		if err := h.CheckRun(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := map[string]string{}
	for k, v := range run {
		r[k] = v
	}
	delete(r, "deep")
	if h.CheckRun(r) == nil {
		t.Error("a run missing a param was accepted")
	}
	r["deep"], r["extra"] = "true", "1"
	if h.CheckRun(r) == nil {
		t.Error("a run with an undeclared param was accepted")
	}
	run["age_days"], run["apps"] = "30", "Microsoft.BingNews,Spotify"
	if got := strings.Join(h.Changes(run, false), "; "); got != "age_days=30; apps +Spotify -*Candy*" {
		t.Fatalf("changes: %q", got)
	}
	if got := strings.Join(h.Changes(run, true), "; "); got != "age_days; apps +1 -1" {
		t.Fatalf("short changes: %q", got)
	}
	run["apps"] = EmptyList
	if err := h.CheckRun(run); err != nil || len(SplitList(run["apps"])) != 0 {
		t.Fatalf("empty list: %v", err)
	}
}

func TestPackageSettingsResolve(t *testing.T) {
	h, _ := ParsePackageHeader(testHeader)
	on, off, enforce, weekly := true, false, "enforce", "weekly"
	st := IndexSettings([]PackageSetting{
		{Package: "x", Enabled: &on, Params: map[string]string{"age_days": "30", "level": "bogus"}},
		{Package: "x", EndpointID: "ep-1", Mode: &enforce, Interval: &weekly, Params: map[string]string{"age_days": "60"}},
		{Package: CategoryKey("maintenance"), EndpointID: "ep-2", Enabled: &off},
	})
	fleet := st.Effective(h, "")
	if !fleet.Enabled || fleet.Mode != "audit" || fleet.Interval != "daily" || fleet.Params["age_days"] != "30" || fleet.Params["level"] != "low" {
		t.Fatalf("fleet: %+v", fleet)
	}
	e1 := st.Effective(h, "ep-1")
	if !e1.Enabled || e1.Mode != "enforce" || e1.Interval != "weekly" || e1.Params["age_days"] != "60" {
		t.Fatalf("ep-1: %+v", e1)
	}
	if e2 := st.Effective(h, "ep-2"); e2.Enabled || !e2.PackageEnabled || e2.CategoryEnabled {
		t.Fatalf("ep-2 category off: %+v", e2)
	}
	if e := IndexSettings(nil).Effective(h, "ep-1"); e.Enabled || !e.CategoryEnabled {
		t.Fatalf("packages are off and categories on by default: %+v", e)
	}
	if p := e1.RunParams(""); p["mode"] != "enforce" || len(p) != 5 {
		t.Fatalf("run params: %v", p)
	}
	// An expired override falls back to the fleet default.
	past := time.Now().Add(-time.Hour)
	expired := IndexSettingsAt([]PackageSetting{
		{Package: "x", Enabled: &on},
		{Package: "x", EndpointID: "ep-1", Mode: &enforce, Reason: "trial", ExpiresAt: &past},
	}, time.Now())
	if e := expired.Effective(h, "ep-1"); e.Mode != "audit" || !e.Enabled {
		t.Fatalf("expired override still applies: %+v", e)
	}
}

func TestPackageHeaderRejects(t *testing.T) {
	for name, repl := range map[string][2]string{
		"category":     {`"maintenance"`, `"other"`},
		"reserved":     {`"age_days"`, `"path"`},
		"mode":         {`"age_days"`, `"mode"`},
		"no bounds":    {`"min":1,"max":365,`, ``},
		"bad default":  {`"default":"low"`, `"default":"mid"`},
		"list item":    {`"*Candy*"`, `"a,b"`},
		"type":         {`"type":"bool"`, `"type":"float"`},
		"interval":     {`"daily"`, `"monthly"`},
		"unknown key":  {`"risk"`, `"extra":1,"risk"`},
		"no desc":      {`"description":"Deep."`, `"description":""`},
		"no max_items": {`"max_items":4,`, ``},
		"careful int":  {`"min":1,"max":365,`, `"min":1,"max":365,"careful":true,`},
		"careful on":   {`"default":false,"description":"Deep."`, `"default":true,"careful":true,"description":"Deep."`},
	} {
		src := strings.Replace(testHeader, repl[0], repl[1], 1)
		if src == testHeader {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParsePackageHeader(src); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
