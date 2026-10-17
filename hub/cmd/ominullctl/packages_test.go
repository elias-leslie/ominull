package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository's packages must pass the same checks the sync applies.
func TestRepositoryPackagesParse(t *testing.T) {
	files, _ := filepath.Glob("../../../packages/windows/*.ps1")
	want := map[string]bool{"windows-updates": true, "windows-cleanup": true, "windows-privacy": true,
		"windows-debloat": true, "windows-performance": true, "windows-audit": true}
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
		t.Errorf("package %s missing from packages/windows", name)
	}
}

func TestReadPackageRejects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := `{"name":"x","title":"X","description":"Does x.","risk":"safe","reboot":false,"timeout":300}`
	for name, body := range map[string]string{
		"noheader":  "Write-Output 1\n",
		"badrisk":   "# ominull-package: " + strings.Replace(good, `"safe"`, `"wild"`, 1) + "\n",
		"timeout":   "# ominull-package: " + strings.Replace(good, `300`, `7200`, 1) + "\n",
		"unknown":   "# ominull-package: " + strings.Replace(good, `"risk"`, `"extra":1,"risk"`, 1) + "\n",
		"bom":       "\xef\xbb\xbf# ominull-package: " + good + "\n",
		"oversized": "# ominull-package: " + good + "\n" + strings.Repeat("#", 16*1024),
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
