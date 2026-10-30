package vuln

import (
	"reflect"
	"strings"
	"testing"
)

// The console's NVD upload (ParseNVD20) and the feed's paged fetch
// (ParseNVD20WithTotal) must normalize a record the same way: severity from
// CVSS 3.1 else 3.0, the English description else the first, only vulnerable
// CPE matches, and records without an id skipped.
func TestNVD20ParsersNormalizeAlike(t *testing.T) {
	const page = `{
		"totalResults": 7,
		"vulnerabilities": [
			{"cve": {"id": "", "published": "2024-01-01T00:00:00Z"}},
			{"cve": {
				"id": "CVE-2023-0001",
				"published": "2023-03-04T05:06:07Z",
				"descriptions": [{"lang": "fr", "value": "premier"}, {"lang": "de", "value": "zweite"}],
				"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 5.3, "baseSeverity": "medium"}}]},
				"configurations": [{"nodes": [{"cpeMatch": [
					{"vulnerable": false, "criteria": "cpe:2.3:o:example:os:*:*:*:*:*:*:*:*"},
					{"vulnerable": true, "criteria": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"}
				]}]}]
			}},
			{"cve": {
				"id": "CVE-2023-0002",
				"published": "2023-05-06T07:08:09Z",
				"descriptions": [{"lang": "EN", "value": "english"}],
				"metrics": {
					"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
					"cvssMetricV30": [{"cvssData": {"baseScore": 1.0, "baseSeverity": "LOW"}}]
				}
			}}
		]
	}`
	withTotal, total, err := ParseNVD20WithTotal(strings.NewReader(page))
	if err != nil || total != 7 {
		t.Fatalf("ParseNVD20WithTotal: total %d, %v", total, err)
	}
	if len(withTotal) != 2 {
		t.Fatalf("got %d records, want 2 (the one without an id is skipped)", len(withTotal))
	}
	a, b := withTotal[0], withTotal[1]
	if a.CVEID != "CVE-2023-0001" || a.Severity != "MEDIUM" || a.CVSS != 5.3 || a.Description != "premier" {
		t.Fatalf("3.0-only record: %+v", a)
	}
	if strings.Contains(a.CPEPattern, "example:os") || !strings.Contains(a.CPEPattern, "example:app") {
		t.Fatalf("CPE pattern keeps only vulnerable matches: %s", a.CPEPattern)
	}
	if b.Severity != "CRITICAL" || b.CVSS != 9.8 || b.Description != "english" || b.CPEPattern != "null" {
		t.Fatalf("3.1 record: %+v", b)
	}
	plain, err := ParseNVD20(strings.NewReader(page))
	if err != nil || !reflect.DeepEqual(plain, withTotal) {
		t.Fatalf("ParseNVD20 = %+v, %v; want %+v", plain, err, withTotal)
	}
	if _, err := ParseNVD20(strings.NewReader("{")); err == nil || !strings.Contains(err.Error(), "failed to decode NVD 2.0 JSON") {
		t.Fatalf("bad JSON: %v", err)
	}
}
