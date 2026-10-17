package scripts

// The software catalog: which installed programs a removal package may take
// off a machine and how. Each entry names a match rule (a wildcard on the
// program's display name, optionally its publisher, or an Appx package
// name), a category, the official way to uninstall it and a risk. The hub
// keeps the catalog as data (one settings row, seeded from
// software_catalog_seed.json) and hands it to the package as a "catalog"
// parameter, so a run's digest, and the owner's approval of it, covers the
// exact catalog the run uses. The script never takes a command from the
// catalog: msi runs msiexec /x with the product code the machine itself
// lists, registry runs the machine's own (quiet) uninstall string, plus at
// most one flag from CatalogFlags, appx removes the named package, and
// manual is reported for the owner.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CatalogEntry is one catalog row.
type CatalogEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`                // program (Programs and Features) | appx
	Match     string `json:"match"`               // wildcard on the display name or Appx package name
	Publisher string `json:"publisher,omitempty"` // optional wildcard on the publisher (programs)
	Category  string `json:"category"`
	Method    string `json:"method"`
	Flag      string `json:"flag,omitempty"`    // registry only: one of CatalogFlags
	Timeout   int    `json:"timeout,omitempty"` // seconds; 0 = the run's per-uninstaller timeout
	Risk      string `json:"risk"`              // safe | careful
	Note      string `json:"note,omitempty"`
}

// CatalogCategories are the categories an entry may name, with the words
// the console and the owner's approval use.
var CatalogCategories = map[string]string{
	"games":       "Games",
	"game_addons": "Game add-ons and launchers",
	"oem_bloat":   "Manufacturer extras",
	"trialware":   "Trials",
	"adware":      "Adware and unwanted browsers",
}

// CatalogMethods are the official uninstall methods, by kind.
var CatalogMethods = map[string]map[string]string{
	"program": {
		"msi":      "Windows Installer (msiexec /x, silent)",
		"registry": "the program's own uninstaller",
		"manual":   "needs someone at the screen",
	},
	"appx": {
		"appx":   "remove the Store app for all users",
		"manual": "needs someone at the screen",
	},
}

// CatalogFlags are the only arguments a registry entry may add to a
// program's own uninstall string.
var CatalogFlags = []string{"/S", "/SILENT", "/VERYSILENT /NORESTART", "/quiet", "/quiet /norestart", "/uninstall /quiet", "-uninstall", "--uninstall", "--force-uninstall"}

const (
	maxCatalogEntries   = 200
	maxCatalogWire      = 12 * 1024 // the library caps all values of a run at 16 KiB
	maxCatalogTimeout   = 1800
	minCatalogTimeout   = 30
	catalogParamDefault = "[]"
)

var (
	catalogIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)
	catalogMatchRe = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9 ._*+()&'!-]{2,99}$`)
	catalogTextRe  = regexp.MustCompile(`^[^\x00-\x1f"\\<>]{1,120}$`)
)

// literalChars counts the characters of a pattern that are not wildcards.
func literalChars(p string) int {
	return len(strings.Map(func(r rune) rune {
		if r == '*' || r == ' ' {
			return -1
		}
		return r
	}, p))
}

// Validate checks one entry.
func (e *CatalogEntry) Validate() error {
	switch {
	case !catalogIDRe.MatchString(e.ID):
		return errors.New("id: 2-48 lower-case letters, digits and -")
	case !catalogTextRe.MatchString(e.Name):
		return errors.New("name: 1-120 characters, no quotes, backslashes or angle brackets")
	case CatalogMethods[e.Kind] == nil:
		return errors.New("kind must be program or appx")
	case !catalogMatchRe.MatchString(e.Match):
		return errors.New("match: 3-100 letters, digits, spaces and . _ * + ( ) & ' ! -")
	case literalChars(e.Match) < 4:
		return errors.New("match needs at least 4 characters that are not * or space, so it cannot match everything")
	case e.Publisher != "" && (e.Kind != "program" || !catalogMatchRe.MatchString(e.Publisher)):
		return errors.New("publisher: a wildcard like match, programs only")
	case CatalogCategories[e.Category] == "":
		return fmt.Errorf("category must be one of %s", strings.Join(CatalogCategoryNames(), ", "))
	case CatalogMethods[e.Kind][e.Method] == "":
		return fmt.Errorf("method for a %s must be one of %s", e.Kind, strings.Join(sortedKeys(CatalogMethods[e.Kind]), ", "))
	case e.Flag != "" && (e.Method != "registry" || !validFlag(e.Flag)):
		return fmt.Errorf("flag: registry entries only, one of %s", strings.Join(CatalogFlags, " | "))
	case e.Timeout != 0 && (e.Timeout < minCatalogTimeout || e.Timeout > maxCatalogTimeout):
		return fmt.Errorf("timeout must be %d-%d seconds or left out", minCatalogTimeout, maxCatalogTimeout)
	case e.Risk != "safe" && e.Risk != "careful":
		return errors.New("risk must be safe or careful")
	case e.Note != "" && !catalogTextRe.MatchString(e.Note):
		return errors.New("note: up to 120 characters, no quotes, backslashes or angle brackets")
	}
	return nil
}

func validFlag(f string) bool {
	for _, x := range CatalogFlags {
		if x == f {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CatalogCategoryNames is the category ids in order.
func CatalogCategoryNames() []string { return sortedKeys(CatalogCategories) }

// Catalog is the whole catalog: entries sorted by id, ids unique.
type Catalog []CatalogEntry

// Validate checks every entry and the whole.
func (c Catalog) Validate() error {
	if len(c) > maxCatalogEntries {
		return fmt.Errorf("at most %d entries", maxCatalogEntries)
	}
	seen := map[string]bool{}
	for i := range c {
		if err := c[i].Validate(); err != nil {
			return fmt.Errorf("%s: %v", c[i].ID, err)
		}
		if seen[c[i].ID] {
			return fmt.Errorf("%s appears twice", c[i].ID)
		}
		seen[c[i].ID] = true
	}
	if w, _ := c.Wire(); len(w) > maxCatalogWire {
		return fmt.Errorf("the catalog is over %d bytes on the wire", maxCatalogWire)
	}
	return nil
}

// Sorted is the catalog in id order.
func (c Catalog) Sorted() Catalog {
	out := append(Catalog(nil), c...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Find returns the entry with an id, or nil.
func (c Catalog) Find(id string) *CatalogEntry {
	for i := range c {
		if c[i].ID == id {
			return &c[i]
		}
	}
	return nil
}

// Wire is the parameter value a run carries: the entries in id order as
// compact JSON, without note (the script does not need it).
func (c Catalog) Wire() (string, error) {
	s := c.Sorted()
	for i := range s {
		s[i].Note = ""
	}
	if len(s) == 0 {
		return catalogParamDefault, nil
	}
	raw, err := json.Marshal(s)
	return string(raw), err
}

// ParseCatalogWire reads a catalog parameter; it must be exactly the wire
// form of a valid catalog.
func ParseCatalogWire(v string) (Catalog, error) {
	if len(v) > maxCatalogWire {
		return nil, fmt.Errorf("over %d bytes", maxCatalogWire)
	}
	var c Catalog
	dec := json.NewDecoder(strings.NewReader(v))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, errors.New("not a catalog: " + err.Error())
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	for _, e := range c {
		if e.Note != "" {
			return nil, errors.New("a catalog parameter carries no notes")
		}
	}
	if w, _ := c.Wire(); w != v {
		return nil, errors.New("not in canonical form (entries in id order, compact)")
	}
	return c, nil
}

// Describe says what an entry is for the owner, e.g. "Epic Games Launcher
// (games; matches 'Epic Games Launcher*'; Windows Installer)".
func (e *CatalogEntry) Describe() string {
	what := "matches '" + e.Match + "'"
	if e.Kind == "appx" {
		what = "Store app '" + e.Match + "'"
	}
	if e.Publisher != "" {
		what += " by '" + e.Publisher + "'"
	}
	how := CatalogMethods[e.Kind][e.Method]
	if e.Flag != "" {
		how += " " + e.Flag
	}
	risk := ""
	if e.Risk == "careful" {
		risk = ", careful"
	}
	return fmt.Sprintf("%s (%s; %s; %s%s)", e.Name, e.Category, what, how, risk)
}

//go:embed software_catalog_seed.json
var catalogSeed []byte

// SeedCatalog is the catalog a hub starts with.
func SeedCatalog() (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(catalogSeed, &c); err != nil {
		return nil, err
	}
	return c.Sorted(), c.Validate()
}
