package posture

import "testing"

func TestSeedIsValidAndCarriesThePortedControls(t *testing.T) {
	t.Parallel()
	c, err := Seed()
	if err != nil {
		t.Fatal(err)
	}
	from := map[string]bool{}
	for _, p := range c.Packs {
		for _, ctl := range p.Controls {
			for _, f := range ctl.From {
				from[f] = true
			}
		}
	}
	// SHA had 17 controls. The 3 macOS ones went with macOS; the other 14 stay.
	if len(from) != 14 {
		t.Fatalf("ported %d SHA controls, want 14: %v", len(from), from)
	}
	if c.Find("ir.console_mfa") == nil || !c.Find("ir.console_mfa").Fleet() || c.Find("ssh.protocol_1_off").Fleet() {
		t.Fatal("scope of a seed control is wrong")
	}
}

func TestValidateRefusesWhatCannotBeScored(t *testing.T) {
	t.Parallel()
	good := func() Catalog {
		return Catalog{StaleDays: 14, Packs: []Pack{{ID: "p", Title: "P", Controls: []Control{
			{ID: "c", Title: "C", Severity: "high", Evidence: []Evidence{{Package: "x", Control: "y"}}},
		}}}}
	}
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Catalog){
		"no stale days":      func(c *Catalog) { c.StaleDays = 0 },
		"no packs":           func(c *Catalog) { c.Packs = nil },
		"bad pack id":        func(c *Catalog) { c.Packs[0].ID = "Bad Id" },
		"no controls":        func(c *Catalog) { c.Packs[0].Controls = nil },
		"bad severity":       func(c *Catalog) { c.Packs[0].Controls[0].Severity = "nope" },
		"no evidence":        func(c *Catalog) { c.Packs[0].Controls[0].Evidence = nil },
		"package no control": func(c *Catalog) { c.Packs[0].Controls[0].Evidence[0].Control = "" },
		"two kinds":          func(c *Catalog) { c.Packs[0].Controls[0].Evidence[0].Attest = true },
		"unknown hub answer": func(c *Catalog) { c.Packs[0].Controls[0].Evidence = []Evidence{{Hub: "nope"}} },
		"hub param missing":  func(c *Catalog) { c.Packs[0].Controls[0].Evidence = []Evidence{{Hub: HubFloorDrill}} },
		"macos platform": func(c *Catalog) {
			c.Packs[0].Controls[0].Evidence[0].Platforms = []string{"macos"}
		},
		"fleet with platform": func(c *Catalog) {
			c.Packs[0].Controls[0].Evidence = []Evidence{{Attest: true, Platforms: []string{"linux"}}}
		},
		"repeated control": func(c *Catalog) {
			c.Packs[0].Controls = append(c.Packs[0].Controls, c.Packs[0].Controls[0])
		},
	} {
		c := good()
		change(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScoreNeverCountsUnknownAsFailure(t *testing.T) {
	t.Parallel()
	var s Score
	s.Add(Unknown, "critical")
	s.Add(NA, "critical")
	s.Add(Accepted, "critical")
	if s.Percent != nil || s.Worst != "" {
		t.Fatalf("no pass or fail yet must read as no score: %+v", s)
	}
	s.Add(Pass, "high")
	s.Add(Fail, "medium")
	s.Add(Fail, "high")
	s.Add(Fail, "low")
	if s.Percent == nil || *s.Percent != 25 || s.Worst != "high" {
		t.Fatalf("%+v", s)
	}
}
