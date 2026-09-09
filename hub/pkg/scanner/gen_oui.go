//go:build ignore

// Command gen_oui rebuilds oui_registry.tsv from the IEEE Registration
// Authority's public listings.
//
// IEEE asserts no copyright in these listings and does not restrict their
// distribution, but it does ask that consumers take the data directly from
// IEEE rather than from a redistributor, so that is what this does. Run it
// with `go generate ./pkg/scanner/` when the table is due a refresh; the
// generated file carries the fetch date so staleness is visible.
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The four registries use three unicast assignment sizes. Order here is only cosmetic; the
// lookup consults them longest-first at runtime.
var registries = []struct {
	name    string
	url     string
	nibbles int
}{
	{"MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6},
	{"MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7},
	{"MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9},
	{"IAB", "https://standards-oui.ieee.org/iab/iab.csv", 9},
}

const maxOrgLen = 96

// cleanOrg flattens a registry organisation name into something safe to store
// one-per-line in a TSV and to show to an operator. IEEE names carry trailing
// padding, occasional tabs, and inconsistent whitespace.
func cleanOrg(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxOrgLen {
		s = strings.TrimSpace(s[:maxOrgLen])
	}
	return s
}

func fetch(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// IEEE answers Go's default user agent with HTTP 418, so identify
	// ourselves properly.
	req.Header.Set("User-Agent", "ominull-oui-generator/1.0 (+https://github.com/ominull)")
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func main() {
	type entry struct{ prefix, org string }
	var out []entry
	seen := map[string]string{}
	counts := map[string]int{}
	var skippedGroup, skippedDupe, skippedShort int

	for _, reg := range registries {
		raw, err := fetch(reg.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetch %s: %v\n", reg.name, err)
			os.Exit(1)
		}
		r := csv.NewReader(strings.NewReader(string(raw)))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", reg.name, err)
			os.Exit(1)
		}
		for i, row := range rows {
			if i == 0 || len(row) < 3 {
				continue
			}
			prefix := strings.ToUpper(strings.TrimSpace(row[1]))
			if len(prefix) != reg.nibbles {
				skippedShort++
				continue
			}
			first, err := strconv.ParseUint(prefix[:2], 16, 8)
			if err != nil {
				skippedShort++
				continue
			}
			// The multicast bit can never be set on a device's own unicast
			// address, so a row carrying it (the registry holds two junk
			// placeholders) could only ever produce a false match.
			if first&0x01 != 0 {
				skippedGroup++
				continue
			}
			org := cleanOrg(row[2])
			if org == "" {
				continue
			}
			if prev, dup := seen[prefix]; dup {
				if prev != org {
					fmt.Fprintf(os.Stderr, "note: %s assigned twice (%q, %q); keeping the first\n", prefix, prev, org)
				}
				skippedDupe++
				continue
			}
			seen[prefix] = org
			out = append(out, entry{prefix, org})
			counts[reg.name]++
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].prefix < out[j].prefix })

	var b strings.Builder
	fmt.Fprintf(&b, "# IEEE MAC address block registry, fetched %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "# Source: https://standards-oui.ieee.org/ (IEEE asserts no copyright; distribution unrestricted)\n")
	fmt.Fprintf(&b, "# Regenerate with: go generate ./pkg/scanner/\n")
	fmt.Fprintf(&b, "# MA-L %d, MA-M %d, MA-S %d, IAB %d\n", counts["MA-L"], counts["MA-M"], counts["MA-S"], counts["IAB"])
	for _, e := range out {
		fmt.Fprintf(&b, "%s\t%s\n", e.prefix, e.org)
	}

	if err := os.WriteFile("oui_registry.tsv", []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("oui_registry.tsv: %d assignments (MA-L %d, MA-M %d, MA-S %d, IAB %d); skipped %d group-bit, %d duplicate, %d malformed\n",
		len(out), counts["MA-L"], counts["MA-M"], counts["MA-S"], counts["IAB"], skippedGroup, skippedDupe, skippedShort)
}
