package server

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
)

// The weekly floor drill (detector/drill.go), run inside the hub process: not
// by a timer under a user account, which an agent could disable, and not
// through /api/v1/events. Each run's outcome is kept in one setting, and the
// Nightshift feed raises a CRITICAL when the last run missed a floor rule or
// the drill has not run for more than eight days.

const (
	floorDrillSetting = "detection.floor_drill"
	floorDrillEvery   = 7 * 24 * time.Hour
	floorDrillOverdue = 8 * 24 * time.Hour
	// floorDrillTick is how often the hub checks whether a drill is due. A
	// drill that missed runs again on every tick, so a fix clears it within
	// the hour.
	floorDrillTick = time.Hour
)

type floorDrillRecord struct {
	RanAt  time.Time `json:"ran_at"`
	Cases  int       `json:"cases"`
	Missed []string  `json:"missed,omitempty"`
}

// runFloorDrill runs the drill against the live tuning and exclusions, judges
// each case, and records the outcome.
func (s *Server) runFloorDrill(now time.Time) floorDrillRecord {
	rec := floorDrillRecord{RanAt: now.UTC()}
	cases, err := detector.Drill(s.store, now)
	if err != nil {
		rec.Missed = append(rec.Missed, "the drill could not run: "+err.Error())
	}
	for _, c := range cases {
		rec.Cases++
		if miss := judgeDrillCase(c); miss != "" {
			rec.Missed = append(rec.Missed, miss)
		}
	}
	raw, _ := json.Marshal(rec)
	if err := s.store.SetSetting(floorDrillSetting, string(raw)); err != nil {
		log.Printf("[-] Detection floor drill: the outcome could not be recorded: %v", err)
	}
	if len(rec.Missed) > 0 {
		log.Printf("[!] Detection floor drill missed %d of %d floor rules: %s", len(rec.Missed), rec.Cases, strings.Join(rec.Missed, "; "))
	} else {
		log.Printf("[+] Detection floor drill: all %d floor rules raised", rec.Cases)
	}
	return rec
}

// judgeDrillCase says what is wrong with one case, or "": its finding must be
// raised, isolate where the rule isolates, and not be explained away on the
// feed (an actor, the admin ssh rule or a connection test).
func judgeDrillCase(c detector.DrillCase) string {
	f, ok := c.Raised()
	if !ok {
		return fmt.Sprintf("%s: no %s was raised", c.Rule, c.Want)
	}
	if c.WantIsolated && !c.Isolated {
		return c.Rule + ": raised, but the endpoint was not isolated"
	}
	if expected := describeAlert(f, c.Tuning).Expected; expected != "" {
		return fmt.Sprintf("%s: raised, but the feed explains it as %q and would not ask", c.Rule, expected)
	}
	return ""
}

// lastFloorDrill reads the recorded outcome; false when there is none.
func (s *Server) lastFloorDrill() (floorDrillRecord, bool) {
	raw, err := s.store.GetSetting(floorDrillSetting)
	var rec floorDrillRecord
	if err != nil || raw == "" || json.Unmarshal([]byte(raw), &rec) != nil || rec.RanAt.IsZero() {
		return floorDrillRecord{}, false
	}
	return rec, true
}

// floorDrillDue runs the drill when none has run, the last one is a week old,
// or the last one missed.
func (s *Server) floorDrillDue(now time.Time) {
	rec, ok := s.lastFloorDrill()
	if ok && len(rec.Missed) == 0 && now.Sub(rec.RanAt) < floorDrillEvery {
		return
	}
	s.runFloorDrill(now)
}

func (s *Server) floorDrillLoop() {
	t := time.NewTicker(floorDrillTick)
	defer t.Stop()
	for range t.C {
		s.floorDrillDue(time.Now().UTC())
	}
}

// floorDrillFinding is the drill on the Nightshift feed.
func (s *Server) floorDrillFinding(now time.Time) feedFinding {
	const uid, title = "ominull.detection.drill", "Detection floor drill"
	rec, ok := s.lastFloorDrill()
	switch {
	case !ok:
		return s.feedFinding(now, uid, title, ocsfSevCritical, ocsfStatusNew,
			"The weekly detection floor drill has never run on this hub, so nothing shows that the floor detectors still raise", nil, nil)
	case len(rec.Missed) > 0:
		return s.feedFinding(now, uid, title, ocsfSevCritical, ocsfStatusNew,
			fmt.Sprintf("The detection floor drill missed %d of %d floor rules, so a real one would go unreported: %s. A tuning or exclusion change is the likely cause; check the day's detection policy changes",
				len(rec.Missed), rec.Cases, strings.Join(rec.Missed, "; ")),
			nil, map[string]any{"ran_at": rec.RanAt.Format(time.RFC3339), "missed": rec.Missed})
	case now.Sub(rec.RanAt) > floorDrillOverdue:
		return s.feedFinding(now, uid, title, ocsfSevCritical, ocsfStatusNew,
			fmt.Sprintf("The weekly detection floor drill last ran %s ago (%s); it runs inside the hub, so the hub's drill loop has stopped", humanAge(now.Sub(rec.RanAt)), rec.RanAt.Format(time.RFC3339)),
			nil, map[string]any{"ran_at": rec.RanAt.Format(time.RFC3339)})
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
		fmt.Sprintf("The detection floor drill raised all %d floor rules at %s", rec.Cases, rec.RanAt.Format(time.RFC3339)),
		nil, map[string]any{"ran_at": rec.RanAt.Format(time.RFC3339)})
}
