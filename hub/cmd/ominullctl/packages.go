package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"ominull/hub/pkg/scripts"
)

// Maintenance packages live in the repository (packages/windows/*.ps1 and
// packages/linux/*.sh). Line 1
// of each is "# ominull-package: {json}"; `ominullctl scripts sync DIR` makes
// the hub's script library match them. The hub appends a version only when the
// source changed, so re-running the sync is free.

const (
	// A script_exec approval carries the source; keep packages well inside it.
	maxPackageBytes = 16 * 1024
)

// packageExt is the file extension of each platform's packages.
var packageExt = map[string]string{"windows": ".ps1", "linux": ".sh"}

// readPackage reads and checks one package file (header contract:
// hub/pkg/scripts/package_params.go).
func readPackage(path string) (*scripts.PackageHeader, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if len(raw) >= maxPackageBytes {
		return nil, "", fmt.Errorf("%s is %d bytes; packages must stay under %d", path, len(raw), maxPackageBytes)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, "", fmt.Errorf("%s starts with a byte-order mark", path)
	}
	h, err := scripts.ParsePackageHeader(string(raw))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", path, err)
	}
	if want := packageExt[h.PlatformName()]; filepath.Ext(path) != want {
		return nil, "", fmt.Errorf("%s: a %s package is a %s file", path, h.PlatformName(), want)
	}
	return h, string(raw), nil
}

func (c *APIClient) cmdScriptsSync(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ominullctl scripts sync DIR   (e.g. packages/windows or packages/linux)")
	}
	var files []string
	for _, ext := range []string{"*.ps1", "*.sh"} {
		found, err := filepath.Glob(filepath.Join(args[0], ext))
		if err != nil {
			return err
		}
		files = append(files, found...)
	}
	if len(files) == 0 {
		return fmt.Errorf("no *.ps1 or *.sh packages in %s", args[0])
	}
	sort.Strings(files)
	type outcome struct {
		Name    string `json:"name"`
		Action  string `json:"action"`
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	var results []outcome
	for _, f := range files {
		h, source, err := readPackage(f)
		if err != nil {
			return err
		}
		meta, _ := json.Marshal(map[string]interface{}{
			"package": h.Name, "title": h.Title, "category": h.Category, "interval": h.Interval, "risk": h.Risk,
			"reboot": h.Reboot, "timeout": h.Timeout, "platform": h.PlatformName(), "role": h.Role,
		})
		schema, _ := json.Marshal(h.Schema())
		raw, err := c.doRequest(http.MethodPost, "/api/v1/scripts", map[string]interface{}{
			"sync": true, "name": h.Name, "description": h.Description, "interpreter": h.Interpreter(),
			"source": source, "parameter_schema_json": string(schema), "metadata": json.RawMessage(meta),
		})
		if err != nil {
			return fmt.Errorf("sync %s: %w", h.Name, err)
		}
		var res struct {
			Action  string `json:"action"`
			Version struct {
				Version int    `json:"version"`
				Digest  string `json:"digest_sha256"`
			} `json:"version"`
		}
		if err := json.Unmarshal(raw, &res); err != nil || res.Action == "" {
			return fmt.Errorf("sync %s: unexpected answer: %s", h.Name, string(raw))
		}
		results = append(results, outcome{h.Name, res.Action, res.Version.Version, res.Version.Digest})
	}
	c.printOutput(results, func() {
		for _, r := range results {
			fmt.Printf("%-22s %-9s v%d %s\n", r.Name, r.Action, r.Version, r.Digest)
		}
	})
	return nil
}
