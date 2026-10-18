package main

// ominullctl maint: run maintenance packages under the owner's approval and
// read where each host stands.
//
//	maint run ENDPOINT[,ENDPOINT...] PKG... [--mode audit|enforce|revert] [--no-wait]
//	maint status ENDPOINT
//	maint settings [ENDPOINT]
//	maint set PKG|@CATEGORY [--endpoint ID] [--on|--off] [--mode audit|enforce] [--every hourly|daily|weekly]
//	          [NAME=VALUE ...] [NAME=default ...] [--inherit enabled,mode,every]
//	          [--reason TEXT] [--until YYYY-MM-DD|never] [--reset]
//	  A machine override (--endpoint) needs --reason; --until lets it lapse
//	  back to the fleet default.
//	maint window show [ENDPOINT] | set ENDPOINT|--default RANGE[,RANGE...] [--clock machine|utc] | reset ENDPOINT|--default
//	maint rules | maint forget-rule [ID]

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func (c *APIClient) cmdMaint(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl maint run|wait|script|promote|cancel|window|status|settings|set|rules|forget-rule")
	}
	switch args[0] {
	case "settings":
		ep := ""
		if len(args) > 1 {
			ep = args[1]
		}
		return c.maintSettings(ep)
	case "set":
		return c.maintSet(args[1:])
	case "run":
		return c.maintRun(args[1:])
	case "wait":
		return c.maintWait(args[1:])
	case "script":
		return c.maintScript(args[1:])
	case "promote":
		return c.maintPromote(args[1:])
	case "cancel":
		return c.maintCancel(args[1:])
	case "window":
		return c.maintWindow(args[1:])
	case "status":
		if len(args) != 2 {
			return fmt.Errorf("usage: ominullctl maint status ENDPOINT")
		}
		return c.maintStatus(args[1])
	case "rules":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/approvals/rules", nil)
		if err != nil {
			return err
		}
		var out struct {
			Rules []struct {
				ID       string    `json:"id"`
				Label    string    `json:"label"`
				EndsAt   time.Time `json:"ends_at"`
				LastUsed time.Time `json:"last_used_at"`
			} `json:"package_rules"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || c.cfg.JSONOutput {
			fmt.Println(string(raw))
			return nil
		}
		if len(out.Rules) == 0 {
			fmt.Println("No approve-all rule for maintenance packages.")
		}
		for _, r := range out.Rules {
			fmt.Printf("%s  %s (ends %s)\n", r.ID, r.Label, r.EndsAt.Local().Format("2006-01-02"))
		}
		return nil
	case "forget-rule":
		q := url.Values{"kind": {"packages"}}
		if len(args) > 1 {
			q.Set("id", args[1])
		}
		raw, err := c.doRequest(http.MethodDelete, "/api/v1/approvals/rules?"+q.Encode(), nil)
		if err == nil {
			fmt.Println(string(raw))
		}
		return err
	}
	return fmt.Errorf("usage: ominullctl maint run|wait|script|promote|cancel|window|status|settings|set|rules|forget-rule")
}

// splitMaintArgs separates --mode/--every/--no-wait from positional words.
func splitMaintArgs(args []string) (pos []string, flags map[string]string, err error) {
	flags = map[string]string{"mode": "audit"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-wait":
			flags["no-wait"] = "1"
		case a == "--mode" || a == "--every":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("%s needs a value", a)
			}
			flags[strings.TrimPrefix(a, "--")] = args[i+1]
			i++
		case strings.HasPrefix(a, "--mode=") || strings.HasPrefix(a, "--every="):
			k, v, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			flags[k] = v
		case strings.HasPrefix(a, "--"):
			return nil, nil, fmt.Errorf("unknown flag %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if m := flags["mode"]; m != "audit" && m != "enforce" && m != "revert" {
		return nil, nil, fmt.Errorf("--mode must be audit, enforce or revert")
	}
	return pos, flags, nil
}

func (c *APIClient) maintRun(args []string) error {
	pos, flags, err := splitMaintArgs(args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return fmt.Errorf("usage: ominullctl maint run ENDPOINT[,ENDPOINT...] PKG... [--mode audit|enforce|revert] [--no-wait]")
	}
	body := map[string]interface{}{"endpoint_ids": strings.Split(pos[0], ","), "packages": pos[1:], "mode": flags["mode"]}
	raw, err := c.ownerApproved(http.MethodPost, "/api/v1/maintenance/run", body)
	if err != nil {
		return err
	}
	return c.afterRun(raw, flags["no-wait"] != "")
}

func (c *APIClient) maintStatus(endpoint string) error {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/maintenance?endpoint_id="+url.QueryEscape(endpoint), nil)
	if err != nil {
		return err
	}
	if c.cfg.JSONOutput {
		fmt.Println(string(raw))
		return nil
	}
	var out struct {
		Packages []struct {
			Name    string `json:"name"`
			Risk    string `json:"risk"`
			Version int    `json:"latest_version"`
			Last    *struct {
				State       string     `json:"state"`
				Mode        string     `json:"mode"`
				Reason      string     `json:"reason"`
				Reboot      bool       `json:"reboot"`
				Changed     []string   `json:"changed"`
				Version     int        `json:"version"`
				Pass        int        `json:"pass"`
				Fail        int        `json:"fail"`
				RequestedAt time.Time  `json:"requested_at"`
				CompletedAt *time.Time `json:"completed_at"`
			} `json:"last"`
		} `json:"packages"`
		MaintenanceMode *struct {
			Package string     `json:"package"`
			On      bool       `json:"on"`
			Until   *time.Time `json:"until"`
			Pending string     `json:"pending"`
			Hours   int        `json:"hours"`
		} `json:"maintenance_mode"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("unreadable answer: %s", strings.TrimSpace(string(raw)))
	}
	if m := out.MaintenanceMode; m != nil {
		switch {
		case m.Pending == "check":
			fmt.Printf("maintenance mode: being checked (%s)\n", m.Package)
		case m.Pending != "":
			fmt.Printf("maintenance mode: turning %s (%s)\n", m.Pending, m.Package)
		case m.On && m.Until != nil:
			fmt.Printf("maintenance mode: on until %s (off: ominullctl maint run %s %s --mode revert)\n", m.Until.Local().Format("Mon 15:04"), endpoint, m.Package)
		default:
			fmt.Printf("maintenance mode: off (on for %dh: ominullctl maint run %s %s --mode enforce)\n", m.Hours, endpoint, m.Package)
		}
	}
	if len(out.Packages) == 0 {
		fmt.Println("No maintenance packages fit this host.")
		return nil
	}
	for _, p := range out.Packages {
		if p.Last == nil {
			fmt.Printf("%-20s v%-3d never run\n", p.Name, p.Version)
			continue
		}
		l := p.Last
		at := l.RequestedAt
		if l.CompletedAt != nil {
			at = *l.CompletedAt
		}
		extra := ""
		if l.Reason != "" {
			extra += " - " + l.Reason
		}
		if len(l.Changed) > 0 {
			extra += fmt.Sprintf(" (%d changed)", len(l.Changed))
		}
		if l.Pass+l.Fail > 0 {
			extra += fmt.Sprintf(" (%d of %d controls pass)", l.Pass, l.Pass+l.Fail)
		}
		if l.Reboot {
			extra += " (reboot needed)"
		}
		fmt.Printf("%-20s v%-3d %-9s %-8s %s%s\n", p.Name, l.Version, l.State, l.Mode, at.Local().Format("2006-01-02 15:04"), extra)
	}
	return nil
}

type maintSettingsView struct {
	Categories []struct {
		Name    string `json:"name"`
		FleetOn bool   `json:"fleet_enabled"`
		On      *bool  `json:"enabled"`
	} `json:"categories"`
	Packages []struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Risk     string `json:"risk"`
		Params   []struct {
			Name    string `json:"name"`
			Default string `json:"default"`
		} `json:"params"`
		FleetEff  maintEffective  `json:"fleet_effective"`
		Effective *maintEffective `json:"effective"`
	} `json:"packages"`
}

type maintEffective struct {
	Enabled  bool              `json:"enabled"`
	Mode     string            `json:"mode"`
	Interval string            `json:"interval"`
	Params   map[string]string `json:"params"`
}

func (c *APIClient) maintSettings(endpoint string) error {
	path := "/api/v1/maintenance/settings"
	if endpoint != "" {
		path += "?endpoint_id=" + url.QueryEscape(endpoint)
	}
	raw, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	var v maintSettingsView
	if json.Unmarshal(raw, &v) != nil || c.cfg.JSONOutput {
		fmt.Println(string(raw))
		return nil
	}
	for _, cat := range v.Categories {
		on := cat.FleetOn
		if cat.On != nil {
			on = *cat.On
		}
		fmt.Printf("@%-19s %s\n", cat.Name, map[bool]string{true: "on", false: "off"}[on])
	}
	for _, p := range v.Packages {
		e := p.FleetEff
		if p.Effective != nil {
			e = *p.Effective
		}
		state := "off"
		if e.Enabled {
			state = "on"
		}
		var changed []string
		for _, d := range p.Params {
			if val := e.Params[d.Name]; val != d.Default {
				changed = append(changed, d.Name+"="+val)
			}
		}
		extra := ""
		if len(changed) > 0 {
			extra = "  " + strings.Join(changed, " ")
		}
		fmt.Printf("%-20s %-11s %-7s %-3s %-7s %-6s%s\n", p.Name, p.Category, p.Risk, state, e.Mode, e.Interval, extra)
	}
	return nil
}

func (c *APIClient) maintSet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl maint set PKG|@CATEGORY [--endpoint ID] [--on|--off] [--mode audit|enforce] [--every hourly|daily|weekly] [NAME=VALUE ...] [NAME=default ...] [--inherit enabled,mode,every] [--reason TEXT] [--until YYYY-MM-DD|never] [--reset]")
	}
	body := map[string]interface{}{}
	if strings.HasPrefix(args[0], "@") {
		body["category"] = strings.TrimPrefix(args[0], "@")
	} else {
		body["package"] = args[0]
	}
	params := map[string]interface{}{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "--on", "--off":
			body["enabled"] = a == "--on"
		case "--reset":
			body["reset"] = true
		case "--endpoint", "--mode", "--every", "--inherit", "--reason", "--until":
			v, err := next()
			if err != nil {
				return err
			}
			switch a {
			case "--endpoint":
				body["endpoint_id"] = v
			case "--mode":
				body["mode"] = v
			case "--every":
				body["interval"] = v
			case "--reason":
				body["reason"] = v
			case "--until":
				if v == "never" {
					body["expires_at"] = nil
				} else {
					body["expires_at"] = v
				}
			case "--inherit":
				for _, f := range strings.Split(v, ",") {
					switch f {
					case "enabled", "mode":
						body[f] = nil
					case "every", "interval":
						body["interval"] = nil
					default:
						return fmt.Errorf("--inherit takes enabled, mode or every")
					}
				}
			}
		default:
			k, v, ok := strings.Cut(a, "=")
			if !ok || strings.HasPrefix(a, "--") {
				return fmt.Errorf("unknown argument %s", a)
			}
			if v == "default" {
				params[k] = nil
			} else {
				params[k] = v
			}
		}
	}
	if len(params) > 0 {
		body["params"] = params
	}
	raw, err := c.doRequest(http.MethodPut, "/api/v1/maintenance/settings", body)
	if err != nil {
		return err
	}
	if c.cfg.JSONOutput {
		fmt.Println(string(raw))
		return nil
	}
	fmt.Fprintln(os.Stderr, "[*] Saved. Runs that need your approval (enforce, careful packages, changed settings) ask on their next due pass.")
	ep, _ := body["endpoint_id"].(string)
	return c.maintSettings(ep)
}
