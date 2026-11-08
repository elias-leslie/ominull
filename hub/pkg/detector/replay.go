package detector

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Replay re-reads recorded findings through a tuning and says which of them it
// would still raise.
//
// Tuning that cannot be checked against what actually happened is tuning by
// guesswork: an expected rule is written, the alert count drops, and nobody knows
// whether the finding that mattered dropped with it. Replay answers that from
// the findings already in the database. It applies the parts of the tuning
// that a stored finding carries enough to judge - the expected rules, and the
// off-hours cooldown keyed on the counterparty - and leaves every other finding
// as it was, so the result is a conservative estimate: the detectors themselves
// can only silence more, never less.
type ReplayDecision struct {
	ID     string `json:"id"`
	Kept   bool   `json:"kept"`
	Reason string `json:"reason,omitempty"`
}

type ReplaySignature struct {
	Type     string         `json:"type"`
	Host     string         `json:"host"`
	Workload string         `json:"workload"`
	Before   int            `json:"before"`
	After    int            `json:"after"`
	Silenced map[string]int `json:"silenced,omitempty"`
}

type ReplayResult struct {
	Before int `json:"before"`
	After  int `json:"after"`
	// MaySurface bounds what the replay cannot see. A recorded finding the
	// draft silences no longer starts its detector's cooldown, so a finding
	// that cooldown folded live - never recorded - could be raised instead:
	// at most one per silenced cooldown window. After is the floor and
	// After+MaySurface the ceiling.
	MaySurface int               `json:"may_surface"`
	ByType     map[string][2]int `json:"by_type"` // type -> [before, after]
	Signatures []ReplaySignature `json:"signatures"`
	Decisions  []ReplayDecision  `json:"-"`
	// Paging compares what reached the open alert list before detection
	// classes (every finding the tuning keeps, learning-held ones aside) with
	// what pages now: the kept findings Classify names page, grouped into
	// incidents. It is judged by Classify from what each finding carries, so
	// findings recorded before the classes count.
	Paging ReplayPaging `json:"paging"`
}

// ReplayPaging is paging volume before and after the detection classes.
type ReplayPaging struct {
	Before int               `json:"before"`
	After  int               `json:"after"`
	Hunt   int               `json:"hunt"` // kept findings that are now records or digests
	ByType map[string][2]int `json:"by_type"`
	ByHost map[string][2]int `json:"by_host"`
	// ByClass counts the kept findings per class.
	ByClass map[string]int `json:"by_class"`
	// Incidents is how many incidents the pages form (device + rule family
	// + counterparty within page_incident_hours); Pushes adds the
	// escalations, each pushed again.
	Incidents int `json:"incidents"`
	Pushes    int `json:"pushes"`
	// Pages lists the pushes, oldest first, at most replayPageList.
	Pages []ReplayPage `json:"pages"`
}

// ReplayPage is one push the classes would have sent.
type ReplayPage struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Host       string    `json:"host"`
	Severity   string    `json:"severity"`
	At         time.Time `json:"at"`
	Title      string    `json:"title"`
	Reason     string    `json:"reason"`
	Escalation bool      `json:"escalation,omitempty"`
	// Alerts is how many pages the incident held in the replay window.
	Alerts int `json:"alerts"`
}

const replayPageList = 200

// Replay judges findings through a tuning, classifying them with no
// knowledge of the endpoints (ReplayClassified has it).
func Replay(alerts []storage.AnomalyAlert, t storage.DetectionTuning) ReplayResult {
	return ReplayClassified(alerts, t, nil, nil)
}

// ReplayClassified is Replay with the endpoints and the endpoints observed
// running an agent runtime, so roles and zones are the live ones.
func ReplayClassified(alerts []storage.AnomalyAlert, t storage.DetectionTuning, endpoints []storage.Endpoint, observed map[string]bool) ReplayResult {
	cx := NewClassContext(t, endpoints, observed)
	incidentWindow := time.Duration(t.PageIncidentHours) * time.Hour
	type openIncident struct {
		start time.Time // its first page: the window runs from here
		worst string
		page  int // index in Paging.Pages, -1 past the list
	}
	incidents := map[string]*openIncident{}
	sorted := append([]storage.AnomalyAlert(nil), alerts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	cooldown := time.Duration(t.FirstSeenCooldown) * time.Minute
	lastOffHours := map[string]time.Time{}
	lastNovel := map[string]time.Time{}
	lastSilenced := map[string]time.Time{}
	res := ReplayResult{ByType: map[string][2]int{}, Paging: ReplayPaging{ByType: map[string][2]int{}, ByHost: map[string][2]int{},
		ByClass: map[string]int{}, Pages: []ReplayPage{}}}
	sigs := map[string]*ReplaySignature{}

	for _, a := range sorted {
		ev := replayEvidence(a.Evidence)
		workload := WorkloadOf(a.ProcessPath, ev.CommandLine)
		d := ReplayDecision{ID: a.ID, Kept: true}
		rule, expected := expectedRuleFor(t, a, cx.RoleOf(endpointOf(endpoints, a.EndpointID)))
		switch a.AnomalyType {
		case "OFF_HOURS_ACTIVITY":
			if expected {
				d = ReplayDecision{ID: a.ID, Reason: "expected: " + rule.Reason}
				break
			}
			owner := ev.Owner
			if owner == "" {
				owner = "unattributed"
			}
			key := a.EndpointID + "|" + strings.ToLower(workload) + "|" + owner
			if last, ok := lastOffHours[key]; ok && a.Timestamp.Sub(last) < cooldown {
				d = ReplayDecision{ID: a.ID, Reason: fmt.Sprintf("folded: one off-hours finding per program and counterparty per %d min", t.FirstSeenCooldown)}
				break
			}
			lastOffHours[key] = a.Timestamp
		case "NOVEL_PROCESS_EGRESS", "NOVEL_DESTINATION":
			// The detectors' own cooldown keys (detector.go): an interpreter
			// per owner, first-seen per owner across the tenant, or per
			// endpoint when the owner is unnamed. A recorded finding inside a
			// longer cooldown than the one that raised it would not be raised.
			owner := strings.ToLower(strings.TrimSpace(ev.Owner))
			key := "firstseen|" + a.TenantID + "|" + owner
			if a.AnomalyType == "NOVEL_PROCESS_EGRESS" {
				key = "shell|" + a.EndpointID + "|" + processBase(a.ProcessPath) + "|" + firstNonEmpty(owner, "unattributed")
			} else if owner == "" {
				key = "firstseen|" + a.TenantID + "|unattributed|" + a.EndpointID
			}
			if expected {
				d = ReplayDecision{ID: a.ID, Reason: "expected: " + rule.Reason}
				armed := false
				for _, m := range []map[string]time.Time{lastNovel, lastSilenced} {
					if last, ok := m[key]; ok && a.Timestamp.Sub(last) < cooldown {
						armed = true
					}
				}
				if !armed {
					res.MaySurface++
					lastSilenced[key] = a.Timestamp
				}
				break
			}
			if last, ok := lastNovel[key]; ok && a.Timestamp.Sub(last) < cooldown {
				d = ReplayDecision{ID: a.ID, Reason: fmt.Sprintf("folded: the same program and counterparty within the %d min first-seen cooldown", t.FirstSeenCooldown)}
				break
			}
			lastNovel[key] = a.Timestamp
		default:
			if expected {
				d = ReplayDecision{ID: a.ID, Reason: "expected: " + rule.Reason}
			}
		}
		res.Decisions = append(res.Decisions, d)

		host := a.Hostname
		if host == "" {
			host = a.EndpointID
		}
		sk := a.AnomalyType + "\x00" + host + "\x00" + workload
		s := sigs[sk]
		if s == nil {
			s = &ReplaySignature{Type: a.AnomalyType, Host: host, Workload: workload}
			sigs[sk] = s
		}
		s.Before++
		bt := res.ByType[a.AnomalyType]
		bt[0]++
		res.Before++
		if d.Kept {
			s.After++
			bt[1]++
			res.After++
			if a.HeldReason != storage.HeldLearning {
				pt, ph := res.Paging.ByType[a.AnomalyType], res.Paging.ByHost[host]
				pt[0]++
				ph[0]++
				res.Paging.Before++
				class, why := cx.Classify(a)
				res.Paging.ByClass[class]++
				if class == storage.ClassPage {
					pt[1]++
					ph[1]++
					res.Paging.After++
					var cev classEvidence
					_ = json.Unmarshal([]byte(a.Evidence), &cev)
					key := incidentKey(a, cev)
					inc := incidents[key]
					push, escalation := false, false
					switch {
					case inc == nil || a.Timestamp.Sub(inc.start) >= incidentWindow:
						inc = &openIncident{start: a.Timestamp, worst: a.Severity, page: -1}
						incidents[key] = inc
						res.Paging.Incidents++
						push = true
					case sevRank[a.Severity] > sevRank[inc.worst]:
						inc.worst = a.Severity
						push, escalation = true, true
					}
					if push {
						res.Paging.Pushes++
						inc.page = -1
						if len(res.Paging.Pages) < replayPageList {
							inc.page = len(res.Paging.Pages)
							res.Paging.Pages = append(res.Paging.Pages, ReplayPage{ID: a.ID, Type: a.AnomalyType, Host: host,
								Severity: a.Severity, At: a.Timestamp, Title: a.Title, Reason: why, Escalation: escalation})
						}
					}
					if inc.page >= 0 {
						res.Paging.Pages[inc.page].Alerts++
					}
				} else {
					res.Paging.Hunt++
				}
				res.Paging.ByType[a.AnomalyType], res.Paging.ByHost[host] = pt, ph
			}
		} else {
			if s.Silenced == nil {
				s.Silenced = map[string]int{}
			}
			s.Silenced[d.Reason]++
		}
		res.ByType[a.AnomalyType] = bt
	}
	for _, s := range sigs {
		res.Signatures = append(res.Signatures, *s)
	}
	sort.Slice(res.Signatures, func(i, j int) bool {
		a, b := res.Signatures[i], res.Signatures[j]
		if a.Before != b.Before {
			return a.Before > b.Before
		}
		return a.Type+a.Host+a.Workload < b.Type+b.Host+b.Workload
	})
	return res
}

type replayFields struct {
	CommandLine string
	Attribution string
	ASN         string
	Owner       string
	Tenancy     string
}

func replayEvidence(raw string) replayFields {
	var f struct {
		CommandLine string `json:"command_line"`
		Attribution string `json:"attribution_status"`
		ASN         string `json:"destination_asn"`
		Owner       string `json:"destination_owner"`
		Tenancy     string `json:"destination_tenancy"`
	}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &f)
	}
	return replayFields{CommandLine: f.CommandLine, Attribution: strings.TrimSpace(f.Attribution), ASN: strings.TrimSpace(f.ASN), Owner: strings.ToLower(strings.TrimSpace(f.Owner)), Tenancy: strings.TrimSpace(f.Tenancy)}
}

// processBase is the program's name without its path, lower-cased.
func processBase(path string) string {
	return strings.ToLower(strings.TrimSpace(baseName(path)))
}

// endpointOf finds an endpoint by id; an unknown one is a zero endpoint (the
// default role).
func endpointOf(endpoints []storage.Endpoint, id string) storage.Endpoint {
	for _, e := range endpoints {
		if e.ID == id {
			return e
		}
	}
	return storage.Endpoint{ID: id}
}

// expectedRuleFor says whether the tuning's expected rules make a stored
// finding expected. A lateral sweep is left as it was: its host count is not
// stored whole.
// ExpectedBy says whether the tuning's rules make a stored finding expected today, and by which rule.
// A finding it covers would not be raised again; role is its endpoint's role (ClassContext.RoleOf).
func ExpectedBy(t storage.DetectionTuning, a storage.AnomalyAlert, role string) (storage.ExpectedRule, bool) {
	return expectedRuleFor(t, a, role)
}

func expectedRuleFor(t storage.DetectionTuning, a storage.AnomalyAlert, role string) (storage.ExpectedRule, bool) {
	kinds := FindingKinds(a)
	if a.AnomalyType == storage.KindLateralSweep {
		return storage.ExpectedRule{}, false
	}
	c := FindingExpectCtx(a, role)
	for _, kind := range kinds {
		c.Kind = kind
		if r, ok := t.Expected(c); ok {
			return r, true
		}
	}
	return storage.ExpectedRule{}, false
}
