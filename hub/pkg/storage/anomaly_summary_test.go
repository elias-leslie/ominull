package storage

import (
	"fmt"
	"testing"
	"time"
)

// What this test is about: the console's alert strip is the first thing an
// operator reads on the alerts page, and it used to be built by grouping the
// fifty rows the hub had just returned. On a hub holding thousands of open
// alerts the strip therefore summed to fifty, under a header reporting the real
// total - the two numbers on one screen disagreed by two orders of magnitude
// and neither was labelled as a sample.

func seedAlerts(t *testing.T, store *Store, endpointID, hostname, atype, severity string, n int, acknowledged bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := store.CreateAnomalyAlert(AnomalyAlert{
			ID:           fmt.Sprintf("%s-%s-%s-%d", endpointID, atype, severity, i),
			EndpointID:   endpointID,
			Hostname:     hostname,
			AnomalyType:  atype,
			Severity:     severity,
			Title:        atype,
			Timestamp:    time.Now().UTC().Add(-time.Duration(i) * time.Minute),
			Acknowledged: acknowledged,
		})
		if err != nil {
			t.Fatalf("seeding an alert: %v", err)
		}
	}
}

// TestTheAlertSummaryCountsEveryAlertNotOnePage. The page limit must not reach
// the summary at all: that was the defect.
func TestTheAlertSummaryCountsEveryAlertNotOnePage(t *testing.T) {
	store := newTestStore(t)

	seedAlerts(t, store, "ep-noisy", "workstation-a", "C2_BEACONING", "HIGH", 120, false)
	seedAlerts(t, store, "ep-noisy", "workstation-a", "BANDWIDTH_SPIKE", "CRITICAL", 30, false)
	seedAlerts(t, store, "ep-quiet", "workstation-b", "C2_BEACONING", "MEDIUM", 7, false)

	page, total, err := store.QueryAnomalyAlerts("", 50, 0, true, "", "", "", HeldAny)
	if err != nil {
		t.Fatalf("querying a page: %v", err)
	}
	if len(page) != 50 || total != 157 {
		t.Fatalf("page of %d with total %d; expected 50 of 157", len(page), total)
	}

	groups, err := store.SummarizeAnomalyAlerts("", true, "", "", HeldAny)
	if err != nil {
		t.Fatalf("summarizing: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("summary covered %d hosts; expected 2", len(groups))
	}

	var summed int64
	for _, g := range groups {
		summed += g.Total
	}
	if summed != total {
		t.Errorf("the summary sums to %d but the fleet holds %d open alerts; the strip is a sample again", summed, total)
	}

	// Busiest host first, with its severities split and its types ranked.
	first := groups[0]
	if first.Hostname != "workstation-a" || first.Total != 150 {
		t.Fatalf("busiest host was %q with %d; expected workstation-a with 150", first.Hostname, first.Total)
	}
	if first.High != 120 || first.Critical != 30 || first.Medium != 0 || first.Low != 0 {
		t.Errorf("severity split was crit=%d high=%d med=%d low=%d; expected 30/120/0/0",
			first.Critical, first.High, first.Medium, first.Low)
	}
	if len(first.Types) != 2 || first.Types[0].Type != "C2_BEACONING" || first.Types[0].Count != 120 {
		t.Errorf("types were %+v; expected C2_BEACONING at 120 first", first.Types)
	}
	if first.EndpointID != "ep-noisy" {
		t.Errorf("endpoint id was %q; the strip filters on it, so an empty one makes the tile unclickable", first.EndpointID)
	}
}

// TestTheAlertSummaryHonoursTheFiltersOnTheList. A strip that ignored the
// severity or acknowledged filter would describe a different set than the table
// under it.
func TestTheAlertSummaryHonoursTheFiltersOnTheList(t *testing.T) {
	store := newTestStore(t)

	seedAlerts(t, store, "ep-a", "workstation-a", "C2_BEACONING", "HIGH", 9, false)
	seedAlerts(t, store, "ep-a", "workstation-a", "BANDWIDTH_SPIKE", "LOW", 5, false)
	seedAlerts(t, store, "ep-b", "workstation-b", "C2_BEACONING", "HIGH", 4, true)

	all, err := store.SummarizeAnomalyAlerts("", false, "", "", HeldAny)
	if err != nil {
		t.Fatalf("summarizing everything: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered summary covered %d hosts; expected 2", len(all))
	}

	open, err := store.SummarizeAnomalyAlerts("", true, "", "", HeldAny)
	if err != nil {
		t.Fatalf("summarizing open alerts: %v", err)
	}
	if len(open) != 1 || open[0].Hostname != "workstation-a" || open[0].Total != 14 {
		t.Fatalf("open-only summary was %+v; expected workstation-a alone with 14", open)
	}

	high, err := store.SummarizeAnomalyAlerts("", true, "", "HIGH", HeldAny)
	if err != nil {
		t.Fatalf("summarizing by severity: %v", err)
	}
	if len(high) != 1 || high[0].Total != 9 || high[0].High != 9 {
		t.Fatalf("severity-filtered summary was %+v; expected nine HIGH on one host", high)
	}

	byType, err := store.SummarizeAnomalyAlerts("", true, "BANDWIDTH_SPIKE", "", HeldAny)
	if err != nil {
		t.Fatalf("summarizing by type: %v", err)
	}
	if len(byType) != 1 || byType[0].Total != 5 || len(byType[0].Types) != 1 {
		t.Fatalf("type-filtered summary was %+v; expected five bandwidth spikes on one host", byType)
	}
}

// TestAnAlertWithNoEndpointIdStillAppears. Alerts raised before an endpoint was
// enrolled carry a hostname and nothing else. Grouping them away would hide
// them from the only view that counts them.
func TestAnAlertWithNoEndpointIdStillAppears(t *testing.T) {
	store := newTestStore(t)
	seedAlerts(t, store, "", "orphan-host", "UNUSUAL_PORT", "LOW", 3, false)

	groups, err := store.SummarizeAnomalyAlerts("", true, "", "", HeldAny)
	if err != nil {
		t.Fatalf("summarizing: %v", err)
	}
	if len(groups) != 1 || groups[0].Total != 3 {
		t.Fatalf("summary was %+v; expected one host holding three", groups)
	}
	if groups[0].Hostname != "orphan-host" {
		t.Errorf("host was labelled %q; expected the hostname the alert carries", groups[0].Hostname)
	}
	if groups[0].EndpointID != "" {
		t.Errorf("endpoint id was %q; inventing one would make the tile filter on nothing", groups[0].EndpointID)
	}
}
