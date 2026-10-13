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
// guesswork: an exclusion is written, the alert count drops, and nobody knows
// whether the finding that mattered dropped with it. Replay answers that from
// the findings already in the database. It applies the parts of the tuning
// that a stored finding carries enough to judge - the known workloads, and the
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
	Before     int               `json:"before"`
	After      int               `json:"after"`
	ByType     map[string][2]int `json:"by_type"` // type -> [before, after]
	Signatures []ReplaySignature `json:"signatures"`
	Decisions  []ReplayDecision  `json:"-"`
}

func Replay(alerts []storage.AnomalyAlert, t storage.DetectionTuning) ReplayResult {
	sorted := append([]storage.AnomalyAlert(nil), alerts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	cooldown := time.Duration(t.FirstSeenCooldown) * time.Minute
	lastOffHours := map[string]time.Time{}
	res := ReplayResult{ByType: map[string][2]int{}}
	sigs := map[string]*ReplaySignature{}

	for _, a := range sorted {
		ev := replayEvidence(a.Evidence)
		workload := WorkloadOf(a.ProcessPath, ev.CommandLine)
		d := ReplayDecision{ID: a.ID, Kept: true}
		switch a.AnomalyType {
		case "OFF_HOURS_ACTIVITY":
			if k, ok := t.KnownService(workload); ok {
				d = ReplayDecision{ID: a.ID, Reason: "known service, runs around the clock: " + k.Reason}
				break
			}
			owner := ev.Owner
			if owner == "" {
				owner = "unattributed"
			}
			key := a.EndpointID + "|" + processBase(a.ProcessPath) + "|" + owner
			if last, ok := lastOffHours[key]; ok && a.Timestamp.Sub(last) < cooldown {
				d = ReplayDecision{ID: a.ID, Reason: fmt.Sprintf("folded: one off-hours finding per program and counterparty per %d min", t.FirstSeenCooldown)}
				break
			}
			lastOffHours[key] = a.Timestamp
		case "NOVEL_PROCESS_EGRESS", "NOVEL_DESTINATION":
			if k, ok := t.KnownWorkloadFor(workload, ev.Owner, ev.Tenancy); ok {
				d = ReplayDecision{ID: a.ID, Reason: "known workload: " + k.Reason}
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
	Owner       string
	Tenancy     string
}

func replayEvidence(raw string) replayFields {
	var f struct {
		CommandLine string `json:"command_line"`
		Owner       string `json:"destination_owner"`
		Tenancy     string `json:"destination_tenancy"`
	}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &f)
	}
	return replayFields{CommandLine: f.CommandLine, Owner: strings.ToLower(strings.TrimSpace(f.Owner)), Tenancy: strings.TrimSpace(f.Tenancy)}
}
