package storage

import (
	"encoding/json"
	"strings"
	"time"
)

// Aico owns machine inventory, intent and liveness. Each push reply carries
// its view of the fleet (AicoMachine); the hub keeps the latest here and reads
// it where it would otherwise keep a list of its own. A host Aico does not know
// (the Windows laptops) falls back to the endpoint's stored presence, as does a
// view gone stale, apart from the bounded memory of a machine last off (Word).
const aicoFleetSetting = "aico_fleet"

// AicoMachine is one machine in Aico's reply. The dates are the hub's own: Aico's
// rows do not carry them. UpSince is when a reply first said the machine was up
// (a guest started a minute ago has an agent that has not had time to report),
// OffAt the last reply that said it was off, HeardAt the last reply naming it.
type AicoMachine struct {
	Machine string    `json:"machine"`
	Intent  string    `json:"intent"`
	Up      *bool     `json:"up"`
	Reports bool      `json:"reports"`
	UpSince time.Time `json:"up_since,omitempty"`
	OffAt   time.Time `json:"off_at,omitempty"`
	HeardAt time.Time `json:"heard_at,omitempty"`
}

// AicoFleet is the latest view and when it arrived.
type AicoFleet struct {
	At       time.Time     `json:"at"`
	Machines []AicoMachine `json:"machines"`
}

// aicoFleetMax bounds what one reply can make the hub store.
const aicoFleetMax = 1000

// ShortHost is a host name as Aico names machines: the part before the first
// dot, in lower case.
func ShortHost(name string) string {
	short, _, _ := strings.Cut(strings.TrimSpace(name), ".")
	return strings.ToLower(short)
}

// SaveAicoFleet stores a reply. UpSince carries over from a view still fresh (a
// gap may hide a restart, so it starts again after one); only an explicit off
// resets it. A machine a reply cannot read or leaves out keeps what was known of
// it, because a Proxmox read failure or an Aico restart says nothing about the
// machine. Entries with no name are dropped.
func (s *Store) SaveAicoFleet(machines []AicoMachine, now time.Time) error {
	previous, err := s.AicoFleet()
	if err != nil {
		return err
	}
	cfg := s.GetDetectionTuning()
	fresh := previous.Fresh(now, time.Duration(cfg.AicoFleetFreshMinutes)*time.Minute)
	memory := time.Duration(cfg.AicoFleetOffMemoryHours) * time.Hour
	known := map[string]AicoMachine{}
	for _, m := range previous.Machines {
		if !fresh {
			m.UpSince = time.Time{}
		}
		known[m.Machine] = m
	}
	now = now.UTC()
	out := AicoFleet{At: now, Machines: make([]AicoMachine, 0, len(machines))}
	named := map[string]bool{}
	for _, m := range machines {
		m.Machine = ShortHost(m.Machine)
		if m.Machine == "" || named[m.Machine] || len(out.Machines) >= aicoFleetMax {
			continue
		}
		named[m.Machine] = true
		was := known[m.Machine]
		m.UpSince, m.OffAt, m.HeardAt = time.Time{}, time.Time{}, now
		switch {
		case m.Up == nil:
			m.UpSince, m.OffAt = was.UpSince, was.OffAt
		case *m.Up:
			m.UpSince = was.UpSince
			if m.UpSince.IsZero() {
				m.UpSince = now
			}
		default:
			m.OffAt = now
		}
		out.Machines = append(out.Machines, m)
	}
	for _, was := range previous.Machines {
		if named[was.Machine] || len(out.Machines) >= aicoFleetMax || now.Sub(was.HeardAt) > memory {
			continue
		}
		out.Machines = append(out.Machines, AicoMachine{Machine: was.Machine, Intent: was.Intent,
			UpSince: known[was.Machine].UpSince, OffAt: was.OffAt, HeardAt: was.HeardAt})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return s.SetSetting(aicoFleetSetting, string(raw))
}

// AicoFleet reads the latest view; the zero value before the first reply.
func (s *Store) AicoFleet() (AicoFleet, error) {
	raw, err := s.GetSetting(aicoFleetSetting)
	if err != nil || raw == "" {
		return AicoFleet{}, err
	}
	var out AicoFleet
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return AicoFleet{}, nil // an unreadable view is no view; the next reply replaces it
	}
	return out, nil
}

// Fresh says whether the view is recent enough to act on.
func (f AicoFleet) Fresh(now time.Time, within time.Duration) bool {
	return !f.At.IsZero() && now.Sub(f.At) <= within
}

// AicoWord is what Aico's view says about a machine right now.
type AicoWord int

const (
	// AicoNoWord: Aico does not know the machine, or cannot tell; stored
	// presence decides.
	AicoNoWord AicoWord = iota
	AicoSaysUp
	AicoSaysOff
)

// Word reads the view for a host name. A fresh yes or no is the answer. When
// that lapses, a machine last called off and not meant to be always on stays off
// for a bounded time (aico_fleet_off_memory_hours): its agent's silence would
// otherwise read as news the moment Aico restarts. Nothing else is remembered: a
// machine meant to be always on goes back to being watched at once.
func (f AicoFleet) Word(hostname string, now time.Time, t DetectionTuning) (AicoMachine, AicoWord) {
	short := ShortHost(hostname)
	if short == "" {
		return AicoMachine{}, AicoNoWord
	}
	for _, m := range f.Machines {
		if m.Machine != short {
			continue
		}
		if f.Fresh(now, time.Duration(t.AicoFleetFreshMinutes)*time.Minute) && m.Up != nil {
			if *m.Up {
				return m, AicoSaysUp
			}
			return m, AicoSaysOff
		}
		if m.Intent != "always" && !m.OffAt.IsZero() &&
			now.Sub(m.OffAt) <= time.Duration(t.AicoFleetOffMemoryHours)*time.Hour {
			return m, AicoSaysOff
		}
		return m, AicoNoWord
	}
	return AicoMachine{}, AicoNoWord
}

// NewestEndpoints names, per short host name, the endpoint Aico's word applies
// to: the one heard from last, so an old row from before a re-enrolment is not
// called a dark sensor on a machine whose new agent is reporting.
func NewestEndpoints(list []Endpoint) map[string]string {
	newest := map[string]string{}
	seen := map[string]time.Time{}
	for _, ep := range list {
		short := ShortHost(ep.Hostname)
		if short == "" || ep.Status == "retired" || ep.DriverVersion == "enrolling" {
			continue
		}
		if _, ok := newest[short]; !ok || ep.LastSeenAt.After(seen[short]) {
			newest[short], seen[short] = ep.ID, ep.LastSeenAt
		}
	}
	return newest
}
