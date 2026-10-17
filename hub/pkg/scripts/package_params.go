package scripts

// The package header and its typed parameters.
//
// Line 1 of every package script is
//
//	# ominull-package: {"name","title","description","category","risk","reboot","timeout","interval","params":[...]}
//
// category is maintenance or security (CIS-style baseline checks): the same
// packages, settings, rule, scheduler and run records serve both. A security
// package's result detail names each check's benchmark reference
// ("cis": "CIS WIN11 1.1.4"), never the benchmark's text.
//
// Each param declares a name, a type (int, bool, enum, list), a default, its
// bounds (min/max for int, values for enum, max_items for list) and a one-line
// description. Tunables (ages, sizes, counts, thresholds, lists) are params;
// safety invariants stay literal in the script and are never params.
//
// On the wire every parameter is a string (agents export OMINULL_PARAM_<NAME>):
// int as decimal, bool as true/false, enum as its value, list as its items
// joined by "," with "-" for the empty list (Windows drops empty variables).
// A package run always carries every parameter, mode included, so the same
// settings are the same bytes (and so the same digest a package rule names).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RunModes: audit reports, enforce changes, revert restores what the package
// recorded before its first change.
var RunModes = map[string]bool{"audit": true, "enforce": true, "revert": true}

// CarefulSteps names the careful steps a run turns on.
func (h *PackageHeader) CarefulSteps(params map[string]string) []string {
	var out []string
	for _, p := range h.Params {
		if p.Careful && params[p.Name] == "true" {
			out = append(out, p.Name)
		}
	}
	return out
}

// PackageCategories are the kinds of package.
var PackageCategories = map[string]bool{"maintenance": true, "security": true}

// PackageHeaderPrefix starts line 1 of a package script.
const PackageHeaderPrefix = "# ominull-package:"

const (
	maxPackageParams   = 24
	maxListItems       = 64
	maxPackageValueLen = 1024
	// EmptyList is the wire value of an empty list parameter.
	EmptyList = "-"
)

// PackageParam is one declared parameter.
type PackageParam struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"` // int | bool | enum | list
	Default     json.RawMessage `json:"default"`
	Min         *int64          `json:"min,omitempty"`
	Max         *int64          `json:"max,omitempty"`
	Values      []string        `json:"values,omitempty"`
	MaxItems    int             `json:"max_items,omitempty"`
	Careful     bool            `json:"careful,omitempty"` // bool only: turns on a careful step (default off)
	Description string          `json:"description"`

	def string // wire form of Default
}

// PackageHeader is line 1 of a package script.
type PackageHeader struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Category    string         `json:"category"` // maintenance | security
	Risk        string         `json:"risk"`     // safe | careful
	Reboot      bool           `json:"reboot"`
	Timeout     int            `json:"timeout"`
	Interval    string         `json:"interval"` // default schedule: hourly | daily | weekly
	Params      []PackageParam `json:"params"`
	// Platform is where the package runs: windows (the default) or linux.
	Platform string `json:"platform,omitempty"`
	// Role marks a package the hub gives a job beyond a scheduled check:
	// maintenance_mode keeps a machine awake (enforce on, revert off, audit
	// reports) and its state is shown and switched on its own.
	Role string `json:"role,omitempty"`
}

// PackagePlatforms maps each platform a package may name to the interpreter
// its runs use and the endpoint OS text that marks a host of that platform.
var PackagePlatforms = map[string]struct{ Interpreter, OS string }{
	"windows": {Interpreter: "powershell.exe", OS: "windows"},
	"linux":   {Interpreter: "/bin/sh", OS: "linux"},
}

// PackageRoles are the roles a header may name.
var PackageRoles = map[string]bool{"maintenance_mode": true}

// RoleMaintenanceMode is the role of the keep-awake package.
const RoleMaintenanceMode = "maintenance_mode"

// PlatformName is the header's platform, windows when unset.
func (h *PackageHeader) PlatformName() string {
	if h.Platform == "" {
		return "windows"
	}
	return h.Platform
}

// Interpreter is what the package's runs are executed with.
func (h *PackageHeader) Interpreter() string {
	return PackagePlatforms[h.PlatformName()].Interpreter
}

// RunsOn says whether a host reporting this OS text runs the package.
func (h *PackageHeader) RunsOn(osText string) bool {
	return strings.Contains(strings.ToLower(osText), PackagePlatforms[h.PlatformName()].OS)
}

var (
	pkgParamNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
	// listItemRe: names of apps, services, update classes; no separators,
	// quotes, backslashes or control characters.
	listItemRe = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9 ._*+()\-]{0,127}$`)
	// reservedPackageParams are names a parameter may not take: payload
	// fields, the run mode, and environment variables a script relies on
	// (agents also export each parameter under its bare name).
	reservedPackageParams = map[string]bool{
		"mode": true, "script_id": true, "script_version": true, "script_digest": true, "interpreter": true, "source": true,
		"parameters": true, "timeout_seconds": true, "max_output_bytes": true,
		"path": true, "pathext": true, "temp": true, "tmp": true, "windir": true, "systemroot": true, "systemdrive": true,
		"comspec": true, "psmodulepath": true, "programdata": true, "programfiles": true, "allusersprofile": true,
		"userprofile": true, "appdata": true, "localappdata": true, "public": true, "username": true, "userdomain": true,
		"computername": true, "os": true, "processor_architecture": true, "number_of_processors": true, "homedrive": true,
		"homepath": true, "commonprogramfiles": true, "driverdata": true, "psexecutionpolicypreference": true,
	}
)

// ParsePackageHeader reads and checks line 1 of a package source.
func ParsePackageHeader(source string) (*PackageHeader, error) {
	line, _, _ := strings.Cut(source, "\n")
	rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), PackageHeaderPrefix)
	if !ok {
		return nil, fmt.Errorf("line 1 must start with %q", PackageHeaderPrefix)
	}
	dec := json.NewDecoder(strings.NewReader(rest))
	dec.DisallowUnknownFields()
	var h PackageHeader
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("package header: %v", err)
	}
	switch {
	case h.Name == "" || h.Title == "" || h.Description == "":
		return nil, errors.New("package header needs name, title and description")
	case !PackageCategories[h.Category]:
		return nil, errors.New("category must be maintenance or security")
	case h.Risk != "safe" && h.Risk != "careful":
		return nil, errors.New("risk must be safe or careful")
	case h.Timeout < 1 || h.Timeout > MaxTimeoutSeconds:
		return nil, fmt.Errorf("timeout must be 1-%d seconds", MaxTimeoutSeconds)
	case len(h.Params) > maxPackageParams:
		return nil, fmt.Errorf("at most %d params", maxPackageParams)
	case h.Platform != "" && PackagePlatforms[h.Platform].Interpreter == "":
		return nil, errors.New("platform must be windows or linux")
	case h.Role != "" && !PackageRoles[h.Role]:
		return nil, errors.New("role must be maintenance_mode or left out")
	}
	if _, ok := RecurrenceInterval(h.Interval); !ok {
		return nil, errors.New("interval must be hourly, daily or weekly")
	}
	seen := map[string]bool{}
	for i := range h.Params {
		p := &h.Params[i]
		if !pkgParamNameRe.MatchString(p.Name) || reservedPackageParams[p.Name] || seen[p.Name] {
			return nil, fmt.Errorf("param %q: name must be a new lower-case identifier that is not reserved", p.Name)
		}
		seen[p.Name] = true
		if p.Careful && (p.Type != "bool" || strings.TrimSpace(string(p.Default)) != "false") {
			return nil, fmt.Errorf("param %s: a careful step is a bool that defaults to false", p.Name)
		}
		if strings.TrimSpace(p.Description) == "" || len(p.Description) > 200 {
			return nil, fmt.Errorf("param %s: needs a one-line description", p.Name)
		}
		def, err := p.defaultWire()
		if err != nil {
			return nil, fmt.Errorf("param %s: %v", p.Name, err)
		}
		if err := p.Check(def); err != nil {
			return nil, fmt.Errorf("param %s: default: %v", p.Name, err)
		}
		p.def = def
	}
	return &h, nil
}

func (p *PackageParam) defaultWire() (string, error) {
	raw := bytes.TrimSpace(p.Default)
	switch p.Type {
	case "int":
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			return "", errors.New("default must be an integer")
		}
		if p.Min == nil || p.Max == nil || *p.Min > *p.Max {
			return "", errors.New("an int needs min <= max")
		}
		return strconv.FormatInt(n, 10), nil
	case "bool":
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return "", errors.New("default must be true or false")
		}
		return strconv.FormatBool(b), nil
	case "enum":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || len(p.Values) == 0 {
			return "", errors.New("an enum needs values and a string default")
		}
		return s, nil
	case "list":
		var items []string
		if err := json.Unmarshal(raw, &items); err != nil {
			return "", errors.New("default must be a list of strings")
		}
		if p.MaxItems < 1 || p.MaxItems > maxListItems {
			return "", fmt.Errorf("a list needs max_items 1-%d", maxListItems)
		}
		for _, it := range items {
			if !listItemRe.MatchString(it) {
				return "", fmt.Errorf("default item %q: letters, digits, space and . _ * + ( ) - only", it)
			}
		}
		return JoinList(items), nil
	case "catalog":
		if string(raw) != "[]" {
			return "", errors.New("a catalog's default is [] (the hub fills in its catalog)")
		}
		return catalogParamDefault, nil
	}
	return "", fmt.Errorf("type %q is not int, bool, enum, list or catalog", p.Type)
}

// DefaultValue is the wire form of the param's default.
func (p *PackageParam) DefaultValue() string { return p.def }

// JoinList is the wire form of a list.
func JoinList(items []string) string {
	if len(items) == 0 {
		return EmptyList
	}
	return strings.Join(items, ",")
}

// SplitList reads a list's wire form.
func SplitList(v string) []string {
	if v == EmptyList || v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// Check validates one wire value.
func (p *PackageParam) Check(v string) error {
	if p.Type == "catalog" {
		_, err := ParseCatalogWire(v)
		return err
	}
	if len(v) > maxPackageValueLen {
		return fmt.Errorf("longer than %d characters", maxPackageValueLen)
	}
	switch p.Type {
	case "int":
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != v {
			return errors.New("not a whole number")
		}
		if n < *p.Min || n > *p.Max {
			return fmt.Errorf("must be %d-%d", *p.Min, *p.Max)
		}
	case "bool":
		if v != "true" && v != "false" {
			return errors.New("must be true or false")
		}
	case "enum":
		for _, e := range p.Values {
			if e == v {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(p.Values, ", "))
	case "list":
		// A script reads an unset or empty variable as "use the default", so
		// an empty list must be spelled out or the run would not be the one
		// approved.
		if v == "" {
			return errors.New("an empty list is written " + EmptyList)
		}
		items := SplitList(v)
		if len(items) > p.MaxItems {
			return fmt.Errorf("at most %d items", p.MaxItems)
		}
		seen := map[string]bool{}
		for _, it := range items {
			if !listItemRe.MatchString(it) || strings.TrimSpace(it) != it {
				return fmt.Errorf("item %q: letters, digits, space and . _ * + ( ) - only", it)
			}
			if seen[strings.ToLower(it)] {
				return fmt.Errorf("item %q appears twice", it)
			}
			seen[strings.ToLower(it)] = true
		}
	default:
		return fmt.Errorf("unknown type %q", p.Type)
	}
	return nil
}

// CatalogParams names the params the hub fills with its software catalog;
// settings never set them.
func (h *PackageHeader) CatalogParams() []string {
	var out []string
	for _, p := range h.Params {
		if p.Type == "catalog" {
			out = append(out, p.Name)
		}
	}
	return out
}

// Param finds a declared param.
func (h *PackageHeader) Param(name string) *PackageParam {
	for i := range h.Params {
		if h.Params[i].Name == name {
			return &h.Params[i]
		}
	}
	return nil
}

// Defaults is every param at its default (mode not included).
func (h *PackageHeader) Defaults() map[string]string {
	out := make(map[string]string, len(h.Params))
	for _, p := range h.Params {
		out[p.Name] = p.def
	}
	return out
}

// CheckRun validates the parameters of a run: mode plus every declared param,
// nothing else.
func (h *PackageHeader) CheckRun(params map[string]string) error {
	if !RunModes[params["mode"]] {
		return errors.New("mode must be audit, enforce or revert")
	}
	if len(params) != len(h.Params)+1 {
		return fmt.Errorf("a run of %s carries mode and its %d params, nothing else", h.Name, len(h.Params))
	}
	for _, p := range h.Params {
		v, ok := params[p.Name]
		if !ok {
			return fmt.Errorf("%s is missing", p.Name)
		}
		if err := p.Check(v); err != nil {
			return fmt.Errorf("%s: %v", p.Name, err)
		}
	}
	return nil
}

// Changes describes the params of a run that differ from their defaults, in
// declaration order: "age_days=30", or for lists "apps +A -B". short gives
// only names and counts.
func (h *PackageHeader) Changes(params map[string]string, short bool) []string {
	var out []string
	for _, p := range h.Params {
		v := params[p.Name]
		if v == p.def {
			continue
		}
		if p.Type == "catalog" {
			// The catalog is hub data, not a setting: name its size, never its bytes.
			n := 0
			if c, err := ParseCatalogWire(v); err == nil {
				n = len(c)
			}
			out = append(out, fmt.Sprintf("%s of %d entries", p.Name, n))
			continue
		}
		if p.Type != "list" {
			if short {
				out = append(out, p.Name)
			} else {
				out = append(out, p.Name+"="+v)
			}
			continue
		}
		added, removed := listDiff(SplitList(p.def), SplitList(v))
		if short {
			out = append(out, fmt.Sprintf("%s +%d -%d", p.Name, len(added), len(removed)))
			continue
		}
		var parts []string
		for _, a := range added {
			parts = append(parts, "+"+a)
		}
		for _, r := range removed {
			parts = append(parts, "-"+r)
		}
		out = append(out, p.Name+" "+strings.Join(parts, " "))
	}
	return out
}

func listDiff(from, to []string) (added, removed []string) {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if strings.EqualFold(x, s) {
				return true
			}
		}
		return false
	}
	for _, t := range to {
		if !in(from, t) {
			added = append(added, t)
		}
	}
	for _, f := range from {
		if !in(to, f) {
			removed = append(removed, f)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Schema is the script library's parameter schema for the package: mode,
// then each param.
func (h *PackageHeader) Schema() ParameterSchema {
	s := ParameterSchema{Parameters: []ParameterDef{{Name: "mode", Type: "enum", Required: true, Default: "audit",
		EnumValues: []string{"audit", "enforce", "revert"}, Description: "audit reports what would change; enforce makes the changes; revert restores what the package recorded before its first change"}}}
	for _, p := range h.Params {
		d := ParameterDef{Name: p.Name, Description: p.Description, Default: p.def, Min: p.Min, Max: p.Max, MaxItems: p.MaxItems}
		switch p.Type {
		case "int":
			d.Type = "integer"
		case "bool":
			d.Type = "boolean"
		case "enum":
			d.Type, d.EnumValues = "enum", p.Values
		case "list":
			d.Type = "list"
		case "catalog":
			d.Type = "catalog"
		}
		s.Parameters = append(s.Parameters, d)
	}
	return s
}
