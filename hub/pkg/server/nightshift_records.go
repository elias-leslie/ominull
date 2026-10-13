package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Typed anomaly records (nightshift.findings/v2).
//
// v2 is the v1 document plus anomaly_records: one record per device, kind and
// baseline window, so Nightshift's learner can see how each kind of finding
// on each device ended. A record is ids, an enum, counts and times - no
// hostname, domain, title or other text from the finding - and a device is
// named by an opaque id, because OmniNull's endpoint ids carry hostnames.
//
// An outcome is verified only when OmniNull itself confirms it, from
// structured state, never from the free-text reason:
//   - incident/verdict: an operator closed a finding in the window with the
//     verdict malicious; incident/isolation: the device was isolated in it.
//   - benign/auto_resolved: every finding was closed by a tuning rule.
//   - benign/acknowledged: every finding was closed by a tuning rule or by an
//     operator with the verdict benign, at least one by an operator.
//   - benign/recurrence: a kind that is not inherently hostile, still open,
//     raised on the device in at least feedRecurrenceWindows earlier windows,
//     none with an incident and at least one verified by tuning or operator.
// A plain acknowledgement (one, a batch, "acknowledge all", a quiet pair)
// gives no verdict, so it verifies nothing. A device with an incident has
// every benign label before the incident withdrawn: those windows may have
// been its beginning. Everything else is unverified, and the learner must not
// train on it.

const (
	nightshiftSchemaV2    = "nightshift.findings/v2"
	feedDeviceSaltSetting = "nightshift_device_salt"
	feedRecordWeeks       = 5 // the current ISO week and the four before it
	feedRecurrenceWindows = 3
	feedMaxRecords        = 500
	// The whole document must stay under Nightshift's 256 KiB cap: records
	// get what the v1 findings leave of feedDocumentBytes, never more than
	// feedRecordBytes.
	feedDocumentBytes  = 224 << 10
	feedRecordBytes    = 160 << 10
	feedMaxOutcomeDays = 50000

	outcomeBenign      = "benign"
	outcomeIncident    = "incident"
	outcomeUnverified  = "unverified"
	sourceAcknowledged = "acknowledged"
	sourceAutoResolved = "auto_resolved"
	sourceRecurrence   = "recurrence"
	sourceIsolation    = "isolation"
	sourceVerdict      = "verdict"
	kindOther          = "other"
)

// recordKinds is the fixed kind enum. A type not listed is "other", so a new
// detector never puts a new string on the wire.
var recordKinds = map[string]string{
	"NOVEL_DESTINATION":     "novel_destination",
	"NOVEL_PROCESS_EGRESS":  "novel_process_egress",
	"NOVEL_COUNTRY":         "novel_country",
	"UNUSUAL_PORT":          "unusual_port",
	"OFF_HOURS_ACTIVITY":    "off_hours",
	"C2_BEACONING":          "beaconing",
	"BANDWIDTH_SPIKE":       "bandwidth_spike",
	"LATERAL_PORT_SWEEP":    "lateral_sweep",
	"ENDPOINT_SILENT":       "endpoint_silent",
	"ENDPOINT_RETURNED":     "endpoint_returned",
	"AGENT_NEW_DESTINATION": "agent_new_destination",
	"AGENT_UPLOAD_VOLUME":   "agent_upload_volume",
	"AGENT_DNS_BYPASS":      "agent_dns_bypass",
	"THREAT_INTEL_MATCH":    "threat_intel",
}

// noRecurrence are kinds whose repetition is never evidence they are benign:
// a beacon that keeps beaconing is the attack working.
var noRecurrence = map[string]bool{
	"beaconing": true, "threat_intel": true, "lateral_sweep": true, "agent_dns_bypass": true,
	"agent_upload_volume": true, kindOther: true,
}

func recordKind(anomalyType string) string {
	if k, ok := recordKinds[anomalyType]; ok {
		return k
	}
	return kindOther
}

type anomalyRecord struct {
	DeviceID         string `json:"device_id"`
	Kind             string `json:"kind"`
	Count            int    `json:"count"`
	FirstSeen        int64  `json:"first_seen"` // epoch ms
	LastSeen         int64  `json:"last_seen"`
	BaselineWindowID string `json:"baseline_window_id"` // ISO week, e.g. 2026-W42
	Outcome          string `json:"outcome"`
	Verified         bool   `json:"verified"`
	OutcomeSource    string `json:"outcome_source,omitempty"`

	endpoint                        string
	open, tuning, benign, malicious int
	windowStart                     time.Time
}

// isoWeek names the baseline window containing t and returns its start.
func isoWeek(t time.Time) (string, time.Time) {
	t = t.UTC()
	y, w := t.ISOWeek()
	wd := (int(t.Weekday()) + 6) % 7 // Monday = 0
	start := time.Date(t.Year(), t.Month(), t.Day()-wd, 0, 0, 0, 0, time.UTC)
	return fmt.Sprintf("%04d-W%02d", y, w), start
}

// deviceSalt returns the hub's secret for device ids. It is created once and
// never replaced: a new salt would silently rename every device.
func (s *Server) deviceSalt() ([]byte, error) {
	v, err := s.store.GetSetting(feedDeviceSaltSetting)
	if err != nil {
		return nil, err
	}
	if v == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		if v, err = s.store.SetSettingOnce(feedDeviceSaltSetting, hex.EncodeToString(raw)); err != nil {
			return nil, err
		}
	}
	salt, err := hex.DecodeString(v)
	if err != nil || len(salt) < 16 {
		return nil, fmt.Errorf("setting %s is not a usable salt; device ids are withheld rather than renamed", feedDeviceSaltSetting)
	}
	return salt, nil
}

func deviceID(salt []byte, endpointID string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(endpointID))
	return "dev_" + hex.EncodeToString(m.Sum(nil))[:20]
}

// anomalyRecords builds the v2 records, newest window first. It reports
// whether the list was cut, by count, by size (budget bytes of JSON) or
// because the read was capped.
func (s *Server) anomalyRecords(now time.Time, budget int) ([]anomalyRecord, bool, error) {
	_, thisWeek := isoWeek(now)
	since := thisWeek.AddDate(0, 0, -7*(feedRecordWeeks-1))
	// Recurrence looks further back than the records shown.
	history := since.AddDate(0, 0, -7*feedRecurrenceWindows)
	days, readCut, err := s.store.ListAnomalyOutcomeDays(history, feedMaxOutcomeDays)
	if err != nil {
		return nil, false, err
	}
	isolations, err := s.store.ListIsolationEvents(history)
	if err != nil {
		return nil, false, err
	}
	salt, err := s.deviceSalt()
	if err != nil {
		return nil, false, err
	}
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, false, err
	}
	thisWeekID := mustWeek(now)
	incident := map[string]bool{} // endpoint|week
	for _, ep := range endpoints {
		if ep.IsIsolated {
			incident[ep.ID+"|"+thisWeekID] = true
		}
	}
	for _, e := range isolations {
		incident[e.Resource+"|"+mustWeek(e.At)] = true
	}

	recs := map[string]*anomalyRecord{}
	for _, d := range days {
		wk, start := isoWeek(d.First)
		kind := recordKind(d.AnomalyType)
		key := d.EndpointID + "|" + kind + "|" + wk
		r := recs[key]
		if r == nil {
			r = &anomalyRecord{Kind: kind, BaselineWindowID: wk, endpoint: d.EndpointID, windowStart: start, FirstSeen: d.First.UnixMilli()}
			recs[key] = r
		}
		r.Count += d.Count
		r.FirstSeen = min(r.FirstSeen, d.First.UnixMilli())
		r.LastSeen = max(r.LastSeen, d.Last.UnixMilli())
		r.open += d.Open
		r.tuning += d.Tuning
		r.benign += d.Benign
		r.malicious += d.Malicious
		if d.Malicious > 0 {
			incident[d.EndpointID+"|"+wk] = true
		}
	}
	// The latest incident per device withdraws benign labels before it.
	lastIncident := map[string]string{}
	for k := range incident {
		ep, wk, _ := strings.Cut(k, "|")
		if wk > lastIncident[ep] {
			lastIncident[ep] = wk
		}
	}

	type dk struct{ e, k string }
	windows := map[dk][]*anomalyRecord{}
	for _, r := range recs {
		windows[dk{r.endpoint, r.Kind}] = append(windows[dk{r.endpoint, r.Kind}], r)
	}
	for _, list := range windows {
		sort.Slice(list, func(i, j int) bool { return list[i].windowStart.Before(list[j].windowStart) })
		for i, r := range list {
			r.DeviceID = deviceID(salt, r.endpoint)
			closedVerified := r.tuning + r.benign
			switch {
			case r.malicious > 0:
				r.Outcome, r.Verified, r.OutcomeSource = outcomeIncident, true, sourceVerdict
			case incident[r.endpoint+"|"+r.BaselineWindowID]:
				r.Outcome, r.Verified, r.OutcomeSource = outcomeIncident, true, sourceIsolation
			case r.open == 0 && closedVerified == r.Count && r.benign == 0:
				r.Outcome, r.Verified, r.OutcomeSource = outcomeBenign, true, sourceAutoResolved
			case r.open == 0 && closedVerified == r.Count:
				r.Outcome, r.Verified, r.OutcomeSource = outcomeBenign, true, sourceAcknowledged
			case !noRecurrence[r.Kind] && recurredWithoutIncident(list[:i], incident):
				r.Outcome, r.Verified, r.OutcomeSource = outcomeBenign, true, sourceRecurrence
			default:
				r.Outcome = outcomeUnverified
			}
			if r.Outcome == outcomeBenign && r.BaselineWindowID < lastIncident[r.endpoint] {
				r.Outcome, r.Verified, r.OutcomeSource = outcomeUnverified, false, ""
			}
		}
	}

	out := make([]anomalyRecord, 0, len(recs))
	for _, r := range recs {
		if r.windowStart.Before(since) {
			continue
		}
		// A window the capped read may have cut short has wrong counts.
		if readCut && r.Verified {
			r.Outcome, r.Verified, r.OutcomeSource = outcomeUnverified, false, ""
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BaselineWindowID != out[j].BaselineWindowID {
			return out[i].BaselineWindowID > out[j].BaselineWindowID
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].DeviceID+out[i].Kind < out[j].DeviceID+out[j].Kind
	})
	truncated := readCut
	size := 0
	for i := range out {
		b, _ := json.Marshal(out[i])
		size += len(b) + 1
		if i >= feedMaxRecords || size > budget {
			out, truncated = out[:i], true
			break
		}
	}
	return out, truncated, nil
}

func mustWeek(t time.Time) string { w, _ := isoWeek(t); return w }

// recurredWithoutIncident reports whether the earlier windows of one device
// and kind number at least feedRecurrenceWindows, none saw an incident, and at
// least one was confirmed benign by tuning or an operator - so the chain
// starts from a judgement, not from findings nobody looked at.
func recurredWithoutIncident(earlier []*anomalyRecord, incident map[string]bool) bool {
	if len(earlier) < feedRecurrenceWindows {
		return false
	}
	confirmed := false
	for _, p := range earlier {
		if p.malicious > 0 || incident[p.endpoint+"|"+p.BaselineWindowID] {
			return false
		}
		if p.OutcomeSource == sourceAcknowledged || p.OutcomeSource == sourceAutoResolved {
			confirmed = true
		}
	}
	return confirmed
}
