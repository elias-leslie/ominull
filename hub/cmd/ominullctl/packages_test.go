package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The repository's packages must pass the same checks the sync applies.
func TestRepositoryPackagesParse(t *testing.T) {
	files, _ := filepath.Glob("../../../packages/windows/*.ps1")
	linux, _ := filepath.Glob("../../../packages/linux/*.sh")
	files = append(files, linux...)
	want := map[string]bool{"windows-updates": true, "windows-cleanup": true, "windows-privacy": true,
		"windows-debloat": true, "windows-performance": true, "windows-audit": true, "windows-maintenance-mode": true, "windows-software-removal": true,
		"linux-maintenance-mode": true}
	for _, f := range files {
		h, _, err := readPackage(f)
		if err != nil {
			t.Error(err)
			continue
		}
		if !want[h.Name] {
			t.Errorf("%s: unexpected package %q", f, h.Name)
		}
		delete(want, h.Name)
	}
	for name := range want {
		t.Errorf("package %s missing from packages/", name)
	}
}

func TestReadPackageRejects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := `{"name":"x","title":"X","description":"Does x.","category":"maintenance","risk":"safe","reboot":false,"timeout":300,"interval":"daily",` +
		`"params":[{"name":"age_days","type":"int","default":14,"min":1,"max":365,"description":"Age in days."}]}`
	for name, body := range map[string]string{
		"noheader":  "Write-Output 1\n",
		"badrisk":   "# ominull-package: " + strings.Replace(good, `"safe"`, `"wild"`, 1) + "\n",
		"timeout":   "# ominull-package: " + strings.Replace(good, `300`, `7200`, 1) + "\n",
		"unknown":   "# ominull-package: " + strings.Replace(good, `"risk"`, `"extra":1,"risk"`, 1) + "\n",
		"bom":       "\xef\xbb\xbf# ominull-package: " + good + "\n",
		"category":  "# ominull-package: " + strings.Replace(good, `"maintenance"`, `"other"`, 1) + "\n",
		"interval":  "# ominull-package: " + strings.Replace(good, `"daily"`, `"monthly"`, 1) + "\n",
		"range":     "# ominull-package: " + strings.Replace(good, `"default":14`, `"default":400`, 1) + "\n",
		"reserved":  "# ominull-package: " + strings.Replace(good, `"age_days"`, `"path"`, 1) + "\n",
		"nodesc":    "# ominull-package: " + strings.Replace(good, `"Age in days."`, `""`, 1) + "\n",
		"oversized": "# ominull-package: " + good + "\n" + strings.Repeat("#", 24*1024),
	} {
		p := filepath.Join(dir, name+".ps1")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readPackage(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := filepath.Join(dir, "good.ps1")
	_ = os.WriteFile(p, []byte("# ominull-package: "+good+"\nWrite-Output 1\n"), 0o600)
	if h, _, err := readPackage(p); err != nil || h.Name != "x" || h.Timeout != 300 {
		t.Fatalf("good package: %+v %v", h, err)
	}
}

// Linux packages parse under sh, print exactly one result line on a
// read-only audit, and fail cleanly on a bad parameter.
func TestLinuxPackagesRun(t *testing.T) {
	files, _ := filepath.Glob("../../../packages/linux/*.sh")
	if len(files) == 0 {
		t.Fatal("no Linux packages")
	}
	run := func(f string, env ...string) (map[string]interface{}, int) {
		t.Helper()
		cmd := exec.Command("/bin/sh", f)
		cmd.Env = env
		out, err := cmd.Output()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		var res map[string]interface{}
		if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &res) != nil || res["v"] != float64(1) {
			t.Fatalf("%s: want one result line, got %q", f, out)
		}
		return res, code
	}
	for _, f := range files {
		if out, err := exec.Command("/bin/sh", "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("%s: sh -n: %v %s", f, err, out)
		}
		res, code := run(f, "OMINULL_PARAM_MODE=audit")
		if (res["state"] == "failed") != (code != 0) || (res["state"] != "ok" && res["state"] != "na") {
			t.Errorf("%s audit: %v exit %d", f, res, code)
		}
		if res, code := run(f, "OMINULL_PARAM_MODE=enforce", "OMINULL_PARAM_HOURS=25"); res["state"] != "failed" || code != 1 {
			t.Errorf("%s: hours=25 must fail before changing anything: %v exit %d", f, res, code)
		}
	}
}
