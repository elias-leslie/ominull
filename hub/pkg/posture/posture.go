// Package posture holds the control packs: named sets of controls, each saying
// where its answer comes from (a package's control result, something the hub
// itself knows, or a person's confirmation). Packs are data, shipped as a seed
// and replaceable on a hub; the answers stay in the package run records.
package posture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Answer states. Unknown is never a failure: nothing has answered yet.
const (
	Pass     = "pass"
	Fail     = "fail"
	Accepted = "accepted"
	NA       = "na"
	Unknown  = "unknown"
)

// What the hub itself can answer. Each needs code, so the set is closed.
const (
	HubAgentReporting    = "agent_reporting"
	HubIsolationReady    = "isolation_ready"
	HubBaselineRecent    = "baseline_recent"
	HubEvidenceRetention = "evidence_retention"
	HubFloorDrill        = "floor_drill"
)

// hubKinds maps each hub answer to the params it requires. A fleet answer has
// one result for the whole hub rather than one per machine.
var hubKinds = map[string]struct {
	fleet  bool
	params []string
}{
	HubAgentReporting:    {},
	HubIsolationReady:    {},
	HubBaselineRecent:    {params: []string{"max_age_days"}},
	HubEvidenceRetention: {fleet: true, params: []string{"alerts_days", "flows_days", "audit_days"}},
	HubFloorDrill:        {fleet: true, params: []string{"max_age_days"}},
}

var severities = []string{"critical", "high", "medium", "low"}

// SeverityRank orders severities, worst first; an unknown one sorts last.
func SeverityRank(s string) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return len(severities)
}

// Evidence says where one answer comes from: exactly one of a package control,
// a hub answer, or a confirmation.
type Evidence struct {
	Platforms []string       `json:"platforms,omitempty"` // linux, windows; empty is every platform
	Package   string         `json:"package,omitempty"`
	Control   string         `json:"control,omitempty"`
	Hub       string         `json:"hub,omitempty"`
	Params    map[string]int `json:"params,omitempty"`
	Attest    bool           `json:"attest,omitempty"`
}

// Fleet is true when the answer covers the whole hub, not one machine.
func (e Evidence) Fleet() bool { return e.Attest || (e.Hub != "" && hubKinds[e.Hub].fleet) }

// Control is one check in a pack. From lists the SHA control ids it was ported
// from; Refs are reference ids only, never benchmark text.
type Control struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Why      string     `json:"why,omitempty"`
	Severity string     `json:"severity"`
	Refs     []string   `json:"refs,omitempty"`
	From     []string   `json:"from,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

// Fleet is true when the control has one answer for the whole hub.
func (c Control) Fleet() bool {
	for _, e := range c.Evidence {
		if e.Fleet() {
			return true
		}
	}
	return false
}

// EvidenceFor picks the evidence that applies to a platform.
func (c Control) EvidenceFor(platform string) (Evidence, bool) {
	for _, e := range c.Evidence {
		if len(e.Platforms) == 0 || slices.Contains(e.Platforms, platform) {
			return e, true
		}
	}
	return Evidence{}, false
}

// Pack is a named set of controls.
type Pack struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	SourceName    string    `json:"source_name,omitempty"`
	SourceVersion string    `json:"source_version,omitempty"`
	SourceURL     string    `json:"source_url,omitempty"`
	Controls      []Control `json:"controls"`
}

// Catalog is every pack in force. An answer older than StaleDays still counts,
// marked stale.
type Catalog struct {
	StaleDays int    `json:"stale_days"`
	Packs     []Pack `json:"packs"`
}

const (
	maxPacks          = 32
	maxControlsInPack = 128
	maxText           = 300
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Validate refuses a catalog the hub could not score.
func (c Catalog) Validate() error {
	if c.StaleDays < 1 || c.StaleDays > 3650 {
		return fmt.Errorf("stale_days must be from 1 to 3650")
	}
	if len(c.Packs) == 0 || len(c.Packs) > maxPacks {
		return fmt.Errorf("a catalog holds 1 to %d packs", maxPacks)
	}
	packs := map[string]bool{}
	for _, p := range c.Packs {
		if !idRe.MatchString(p.ID) || packs[p.ID] {
			return fmt.Errorf("pack id %q is malformed or repeated", p.ID)
		}
		packs[p.ID] = true
		if p.Title == "" || len(p.Title) > maxText || len(p.SourceName) > maxText || len(p.SourceURL) > maxText {
			return fmt.Errorf("pack %s: title is required and each text is at most %d bytes", p.ID, maxText)
		}
		if len(p.Controls) == 0 || len(p.Controls) > maxControlsInPack {
			return fmt.Errorf("pack %s holds 1 to %d controls", p.ID, maxControlsInPack)
		}
		ids := map[string]bool{}
		for _, ctl := range p.Controls {
			if !idRe.MatchString(ctl.ID) || ids[ctl.ID] {
				return fmt.Errorf("pack %s: control id %q is malformed or repeated", p.ID, ctl.ID)
			}
			ids[ctl.ID] = true
			if err := ctl.validate(); err != nil {
				return fmt.Errorf("pack %s control %s: %w", p.ID, ctl.ID, err)
			}
		}
	}
	return nil
}

func (c Control) validate() error {
	if c.Title == "" || len(c.Title) > maxText || len(c.Why) > maxText {
		return fmt.Errorf("title is required and each text is at most %d bytes", maxText)
	}
	if !slices.Contains(severities, c.Severity) {
		return fmt.Errorf("severity must be one of %v", severities)
	}
	if len(c.Evidence) == 0 {
		return fmt.Errorf("evidence is required")
	}
	for _, e := range c.Evidence {
		kinds := 0
		if e.Package != "" {
			kinds++
			if e.Control == "" {
				return fmt.Errorf("package evidence names a control")
			}
		}
		if e.Hub != "" {
			kinds++
			kind, ok := hubKinds[e.Hub]
			if !ok {
				return fmt.Errorf("no hub answer %q", e.Hub)
			}
			for _, name := range kind.params {
				if e.Params[name] < 1 {
					return fmt.Errorf("hub answer %s needs a positive %s", e.Hub, name)
				}
			}
		}
		if e.Attest {
			kinds++
		}
		if kinds != 1 {
			return fmt.Errorf("each evidence is exactly one of package, hub or attest")
		}
		for _, p := range e.Platforms {
			if p != "linux" && p != "windows" {
				return fmt.Errorf("platform %q is not linux or windows", p)
			}
		}
		if e.Fleet() && (len(c.Evidence) > 1 || len(e.Platforms) > 0) {
			return fmt.Errorf("a whole-hub answer is the control's only evidence and has no platforms")
		}
	}
	return nil
}

// Find returns a control by id, from the first pack holding it.
func (c Catalog) Find(id string) *Control {
	for i := range c.Packs {
		for j := range c.Packs[i].Controls {
			if c.Packs[i].Controls[j].ID == id {
				return &c.Packs[i].Controls[j]
			}
		}
	}
	return nil
}

// Score tallies answers. Percent counts pass against fail only: an unknown,
// accepted or not-applicable answer moves it neither way, and with no pass or
// fail it is nil, never zero. Worst is the worst failing severity.
type Score struct {
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Accepted int    `json:"accepted"`
	NA       int    `json:"na"`
	Unknown  int    `json:"unknown"`
	Percent  *int   `json:"percent"`
	Worst    string `json:"worst,omitempty"`
}

// Add counts one answer of a control with this severity.
func (s *Score) Add(state, severity string) {
	switch state {
	case Pass:
		s.Pass++
	case Fail:
		s.Fail++
		if s.Worst == "" || SeverityRank(severity) < SeverityRank(s.Worst) {
			s.Worst = severity
		}
	case Accepted:
		s.Accepted++
	case NA:
		s.NA++
	default:
		s.Unknown++
	}
	s.Percent = nil
	if n := s.Pass + s.Fail; n > 0 {
		pct := s.Pass * 100 / n
		s.Percent = &pct
	}
}

//go:embed packs_seed.json
var seed []byte

// Seed is the catalog a hub starts with.
func Seed() (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(seed, &c); err != nil {
		return Catalog{}, err
	}
	return c, c.Validate()
}
