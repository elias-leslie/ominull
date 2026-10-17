package scripts

import (
	"strings"
	"testing"
)

func TestSeedCatalogIsValid(t *testing.T) {
	t.Parallel()
	c, err := SeedCatalog()
	if err != nil || len(c) < 15 {
		t.Fatalf("seed: %d entries, %v", len(c), err)
	}
	for _, id := range []string{"epic-games-launcher", "xsplit", "acer-jumpstart", "expressvpn", "overwolf", "roblox-player", "riot-vanguard", "app-explorer", "wavebrowser"} {
		if c.Find(id) == nil {
			t.Errorf("seed lacks %s", id)
		}
	}
	w, _ := c.Wire()
	if len(w) > maxCatalogWire/2 {
		t.Errorf("seed uses %d of %d wire bytes", len(w), maxCatalogWire)
	}
}

func TestCatalogEntryRules(t *testing.T) {
	t.Parallel()
	good := CatalogEntry{ID: "xsplit", Name: "XSplit", Kind: "program", Match: "XSplit*", Category: "game_addons", Method: "msi", Risk: "safe"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(e *CatalogEntry){
		"everything":      func(e *CatalogEntry) { e.Match = "****" },
		"too broad":       func(e *CatalogEntry) { e.Match = "a* b*" },
		"regex":           func(e *CatalogEntry) { e.Match = "X.*|cmd" },
		"quote in match":  func(e *CatalogEntry) { e.Match = `XSplit"` },
		"flag on msi":     func(e *CatalogEntry) { e.Flag = "/S" },
		"free flag":       func(e *CatalogEntry) { e.Method, e.Flag = "registry", "/S & calc" },
		"appx method":     func(e *CatalogEntry) { e.Method = "appx" },
		"category":        func(e *CatalogEntry) { e.Category = "system" },
		"kind":            func(e *CatalogEntry) { e.Kind = "driver" },
		"risk":            func(e *CatalogEntry) { e.Risk = "wild" },
		"timeout":         func(e *CatalogEntry) { e.Timeout = 5 },
		"id":              func(e *CatalogEntry) { e.ID = "X Split" },
		"appx publisher":  func(e *CatalogEntry) { e.Kind, e.Method, e.Publisher = "appx", "appx", "Acme*" },
		"name with angle": func(e *CatalogEntry) { e.Name = "<b>x</b>" },
	} {
		e := good
		mut(&e)
		if e.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	reg := good
	reg.Method, reg.Flag = "registry", "/VERYSILENT /NORESTART"
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	if d := reg.Describe(); !strings.Contains(d, "the program's own uninstaller /VERYSILENT /NORESTART") || !strings.Contains(d, "game_addons") {
		t.Fatal(d)
	}
}

func TestCatalogWire(t *testing.T) {
	t.Parallel()
	c := Catalog{
		{ID: "zz-app", Name: "Zed", Kind: "appx", Match: "Zed.Game", Category: "games", Method: "appx", Risk: "safe", Note: "dropped on the wire"},
		{ID: "aa-prog", Name: "Ay", Kind: "program", Match: "Ay Program*", Category: "trialware", Method: "registry", Flag: "/S", Risk: "careful"},
	}
	w, err := c.Wire()
	if err != nil || strings.Contains(w, "dropped") || strings.Index(w, "aa-prog") > strings.Index(w, "zz-app") {
		t.Fatalf("wire: %s %v", w, err)
	}
	back, err := ParseCatalogWire(w)
	if err != nil || len(back) != 2 {
		t.Fatalf("round trip: %v", err)
	}
	for name, v := range map[string]string{
		"spaced":   strings.Replace(w, `":"`, `": "`, 1),
		"order":    `[` + w[strings.Index(w, `{"id":"zz`):len(w)-1] + `,` + w[1:strings.Index(w, `,{"id":"zz`)] + `]`,
		"unknown":  strings.Replace(w, `"risk":"safe"`, `"risk":"safe","cmd":"x"`, 1),
		"note":     strings.Replace(w, `"risk":"safe"`, `"risk":"safe","note":"n"`, 1),
		"invalid":  strings.Replace(w, `"Zed.Game"`, `"*"`, 1),
		"not json": "XSplit",
	} {
		if _, err := ParseCatalogWire(v); err == nil {
			t.Errorf("%s: accepted %s", name, v)
		}
	}
	if w, _ := (Catalog{}).Wire(); w != "[]" {
		t.Fatal(w)
	}
}

// A catalog param: default [], any valid catalog passes Check, settings
// never set it and the owner sees its size, not its bytes.
func TestCatalogParam(t *testing.T) {
	t.Parallel()
	src := `# ominull-package: {"name":"windows-x","title":"X","description":"d","category":"maintenance","risk":"careful","reboot":false,"timeout":600,"interval":"weekly",` +
		`"params":[{"name":"catalog","type":"catalog","default":[],"description":"From the hub"},{"name":"log_keep","type":"int","default":20,"min":1,"max":200,"description":"d"}]}` + "\nx\n"
	h, err := ParsePackageHeader(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.CatalogParams(); len(got) != 1 || got[0] != "catalog" {
		t.Fatal(got)
	}
	seed, _ := SeedCatalog()
	w, _ := seed.Wire()
	run := map[string]string{"mode": "enforce", "catalog": w, "log_keep": "20"}
	if err := h.CheckRun(run); err != nil {
		t.Fatal(err)
	}
	if ch := h.Changes(run, false); len(ch) != 1 || ch[0] != "catalog of "+itoa(len(seed))+" entries" {
		t.Fatal(ch)
	}
	run["catalog"] = `[{"id":"x"}]`
	if h.CheckRun(run) == nil {
		t.Fatal("a bad catalog passed")
	}
	if _, err := ParsePackageHeader(strings.Replace(src, `"default":[]`, `"default":[{"id":"x"}]`, 1)); err == nil {
		t.Fatal("a catalog default other than [] parsed")
	}
	st := IndexSettings([]PackageSetting{{Package: "windows-x", Params: map[string]string{"catalog": w}}})
	if e := st.Effective(h, ""); e.Params["catalog"] != "[]" {
		t.Fatal("a setting filled the catalog")
	}
	if s := h.Schema(); s.Parameters[1].Type != "catalog" {
		t.Fatal(s.Parameters[1])
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
