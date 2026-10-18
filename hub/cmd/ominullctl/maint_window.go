package main

// ominullctl maint window: read and change maintenance windows.
//
//	maint window show [ENDPOINT]
//	maint window set ENDPOINT|--default RANGE[,RANGE...] [--clock machine|utc]
//	maint window reset ENDPOINT|--default
//
// RANGE is HH:MM-HH:MM (up to four). Machine time is each machine's own
// clock; utc is the same moment everywhere.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maintWindowUsage = "usage: ominullctl maint window show [ENDPOINT] | set ENDPOINT|--default RANGE[,RANGE...] [--clock machine|utc] | reset ENDPOINT|--default"

type windowView struct {
	EndpointID string   `json:"endpoint_id"`
	Ranges     []string `json:"ranges"`
	Clock      string   `json:"clock"`
	Source     string   `json:"source"`
	OpenNow    *bool    `json:"open_now"`
	NextStart  string   `json:"next_start"`
	Offset     *int     `json:"utc_offset_minutes"`
}

func (c *APIClient) maintWindow(args []string) error {
	if len(args) == 0 || wantsHelp(args) {
		fmt.Println(maintWindowUsage)
		return nil
	}
	switch args[0] {
	case "show":
		if len(args) > 2 {
			return fmt.Errorf(maintWindowUsage)
		}
		path := "/api/v1/maintenance/windows"
		if len(args) == 2 {
			path += "?" + url.Values{"endpoint_id": {args[1]}}.Encode()
		}
		raw, err := c.doRequest(http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		return c.printWindows(raw, len(args) == 2)
	case "set", "reset":
		body, endpoint, err := windowChange(args)
		if err != nil {
			return err
		}
		raw, err := c.doRequest(http.MethodPut, "/api/v1/maintenance/windows", body)
		if err != nil {
			return err
		}
		return c.printWindows(raw, endpoint != "")
	}
	return fmt.Errorf(maintWindowUsage)
}

// windowChange turns set/reset arguments into the PUT body.
func windowChange(args []string) (map[string]interface{}, string, error) {
	verb := args[0]
	endpoint, fleet, clock := "", false, ""
	var ranges []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--default":
			fleet = true
		case a == "--clock" && i+1 < len(rest):
			i++
			clock = rest[i]
		case strings.HasPrefix(a, "--clock="):
			clock = strings.TrimPrefix(a, "--clock=")
		case strings.HasPrefix(a, "-"):
			return nil, "", fmt.Errorf("unknown flag %s\n%s", a, maintWindowUsage)
		case endpoint == "" && !fleet && !strings.Contains(a, ":"):
			endpoint = a
		default:
			for _, r := range strings.Split(a, ",") {
				if r = strings.TrimSpace(r); r != "" {
					ranges = append(ranges, r)
				}
			}
		}
	}
	if fleet == (endpoint != "") {
		return nil, "", fmt.Errorf("name one machine or --default\n%s", maintWindowUsage)
	}
	body := map[string]interface{}{}
	if endpoint != "" {
		body["endpoint_id"] = endpoint
	}
	if verb == "reset" {
		if len(ranges) > 0 || clock != "" {
			return nil, "", fmt.Errorf("reset takes no ranges\n%s", maintWindowUsage)
		}
		body["reset"] = true
		return body, endpoint, nil
	}
	if len(ranges) == 0 {
		return nil, "", fmt.Errorf("set needs at least one range like 01:00-05:00\n%s", maintWindowUsage)
	}
	if clock != "" && clock != "machine" && clock != "utc" {
		return nil, "", fmt.Errorf("--clock is machine or utc")
	}
	body["ranges"] = ranges
	if clock != "" {
		body["clock"] = clock
	}
	return body, endpoint, nil
}

func (c *APIClient) printWindows(raw []byte, single bool) error {
	if c.cfg.JSONOutput {
		fmt.Println(strings.TrimSpace(string(raw)))
		return nil
	}
	if single {
		var v windowView
		if err := json.Unmarshal(raw, &v); err != nil {
			fmt.Println(strings.TrimSpace(string(raw)))
			return nil
		}
		fmt.Println(describeWindow(v.EndpointID, v))
		return nil
	}
	var all struct {
		Default   windowView            `json:"default"`
		Endpoints map[string]windowView `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &all); err != nil {
		fmt.Println(strings.TrimSpace(string(raw)))
		return nil
	}
	fmt.Println(describeWindow("fleet default", all.Default))
	if len(all.Endpoints) == 0 {
		fmt.Println("No machine has its own window; every machine follows the fleet default.")
		return nil
	}
	for _, id := range sortedKeys(all.Endpoints) {
		fmt.Println(describeWindow(id, all.Endpoints[id]))
	}
	return nil
}

func sortedKeys(m map[string]windowView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func describeWindow(name string, v windowView) string {
	clock := "machine time"
	if v.Clock == "utc" {
		clock = "UTC"
	}
	src := map[string]string{"endpoint": "its own", "fleet": "fleet default", "default": "shipped default"}[v.Source]
	line := fmt.Sprintf("%s: %s %s", name, strings.Join(v.Ranges, ", "), clock)
	if src != "" && name != "fleet default" || v.Source == "default" {
		line += " (" + src + ")"
	}
	switch {
	case v.OpenNow != nil && *v.OpenNow:
		line += ", open now"
	case v.NextStart != "":
		if t, err := time.Parse(time.RFC3339, v.NextStart); err == nil {
			line += ", next opens " + t.Local().Format("Mon 15:04")
		}
	case v.EndpointID != "" && v.Clock != "utc" && v.Offset == nil:
		line += ", next start unknown (the machine hasn't reported its clock)"
	}
	return line
}
