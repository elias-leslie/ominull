package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Maintenance packages live in the repository (packages/windows/*.ps1). Line 1
// of each is "# ominull-package: {json}"; `ominullctl scripts sync DIR` makes
// the hub's script library match them. The hub appends a version only when the
// source changed, so re-running the sync is free.

const (
	packageHeaderPrefix = "# ominull-package:"
	// A script_exec approval carries the source; keep packages well inside it.
	maxPackageBytes = 16 * 1024
)

// packageParamSchema is every package's one parameter: audit reports drift,
// enforce fixes it.
const packageParamSchema = `{"parameters":[{"name":"mode","type":"enum","enum":["audit","enforce"],"enum_values":["audit","enforce"],"default":"audit","required":true,"description":"audit reports what would change; enforce makes the changes"}]}`

type packageHeader struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Reboot      bool   `json:"reboot"`
	Timeout     int    `json:"timeout"`
}

// readPackage reads and checks one package file.
func readPackage(path string) (packageHeader, string, error) {
	var h packageHeader
	raw, err := os.ReadFile(path)
	if err != nil {
		return h, "", err
	}
	if len(raw) >= maxPackageBytes {
		return h, "", fmt.Errorf("%s is %d bytes; packages must stay under %d", path, len(raw), maxPackageBytes)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return h, "", fmt.Errorf("%s starts with a byte-order mark", path)
	}
	line, _, _ := bufio.NewReader(bytes.NewReader(raw)).ReadLine()
	rest, ok := strings.CutPrefix(string(line), packageHeaderPrefix)
	if !ok {
		return h, "", fmt.Errorf("%s: line 1 must start with %q", path, packageHeaderPrefix)
	}
	dec := json.NewDecoder(strings.NewReader(rest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, "", fmt.Errorf("%s: package header: %v", path, err)
	}
	switch {
	case h.Name == "" || h.Title == "" || h.Description == "":
		return h, "", fmt.Errorf("%s: package header needs name, title and description", path)
	case h.Risk != "safe" && h.Risk != "careful":
		return h, "", fmt.Errorf("%s: risk must be safe or careful", path)
	case h.Timeout < 1 || h.Timeout > 3600:
		return h, "", fmt.Errorf("%s: timeout must be 1-3600 seconds", path)
	}
	return h, string(raw), nil
}

func (c *APIClient) cmdScriptsSync(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ominullctl scripts sync DIR   (e.g. packages/windows)")
	}
	files, err := filepath.Glob(filepath.Join(args[0], "*.ps1"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no *.ps1 packages in %s", args[0])
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
			"package": h.Name, "title": h.Title, "risk": h.Risk, "reboot": h.Reboot, "timeout": h.Timeout,
		})
		raw, err := c.doRequest(http.MethodPost, "/api/v1/scripts", map[string]interface{}{
			"sync": true, "name": h.Name, "description": h.Description, "interpreter": "powershell.exe",
			"source": source, "parameter_schema_json": packageParamSchema, "metadata": json.RawMessage(meta),
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
