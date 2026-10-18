package scripts

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A maintenance window: up to four daily ranges ("HH:MM-HH:MM", a range may
// cross midnight) in the machine's own time, or in UTC. As a run parameter
// it is the ranges joined by commas, with a trailing Z for UTC; the package
// preludes read exactly that (packages/windows/*.ps1 Test-InWindow,
// packages/linux/reboot.sh in_window).

const MaxWindowRanges = 4

var rangeRe = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$`)

type Window struct {
	Ranges []string `json:"ranges"`
	UTC    bool     `json:"utc,omitempty"`
}

// ParseWindow reads a window run parameter.
func ParseWindow(v string) (Window, error) {
	w := Window{}
	if strings.HasSuffix(v, "Z") {
		w.UTC, v = true, strings.TrimSuffix(v, "Z")
	}
	w.Ranges = strings.Split(v, ",")
	return w, w.Check()
}

// Check says whether the window is usable.
func (w Window) Check() error {
	if len(w.Ranges) == 0 || len(w.Ranges) > MaxWindowRanges {
		return fmt.Errorf("a maintenance window is 1 to %d HH:MM-HH:MM ranges (24-hour)", MaxWindowRanges)
	}
	for _, r := range w.Ranges {
		m := rangeRe.FindStringSubmatch(r)
		if m == nil || m[1]+m[2] == m[3]+m[4] {
			return errors.New("each maintenance window range is HH:MM-HH:MM (24-hour), start and end different")
		}
	}
	return nil
}

// Param is the window as a run parameter.
func (w Window) Param() string {
	s := strings.Join(w.Ranges, ",")
	if w.UTC {
		s += "Z"
	}
	return s
}

func minutesOf(hhmm string) int {
	return int(hhmm[0]-'0')*600 + int(hhmm[1]-'0')*60 + int(hhmm[3]-'0')*10 + int(hhmm[4]-'0')
}

// clockAt is now on the window's clock: UTC, or machine time at
// offsetMinutes east of UTC. ok is false for machine time with no offset.
func (w Window) clockAt(now time.Time, offsetMinutes *int) (time.Time, bool) {
	if w.UTC {
		return now.UTC(), true
	}
	if offsetMinutes == nil {
		return time.Time{}, false
	}
	return now.UTC().Add(time.Duration(*offsetMinutes) * time.Minute), true
}

// Contains says whether now falls in the window. known is false when the
// window is in machine time and the machine's UTC offset is unknown.
func (w Window) Contains(now time.Time, offsetMinutes *int) (in, known bool) {
	t, ok := w.clockAt(now, offsetMinutes)
	if !ok {
		return false, false
	}
	n := t.Hour()*60 + t.Minute()
	for _, r := range w.Ranges {
		s, e := minutesOf(r[:5]), minutesOf(r[6:])
		if (s <= e && n >= s && n < e) || (s > e && (n >= s || n < e)) {
			return true, true
		}
	}
	return false, true
}

// NextStart is when the window next opens after now (now itself when it is
// open), as an instant. known is false as for Contains.
func (w Window) NextStart(now time.Time, offsetMinutes *int) (time.Time, bool) {
	t, ok := w.clockAt(now, offsetMinutes)
	if !ok {
		return time.Time{}, false
	}
	if in, _ := w.Contains(now, offsetMinutes); in {
		return now, true
	}
	n := t.Hour()*60 + t.Minute()
	best := -1
	for _, r := range w.Ranges {
		d := (minutesOf(r[:5]) - n + 1440) % 1440
		if best < 0 || d < best {
			best = d
		}
	}
	start := now.Truncate(time.Minute).Add(time.Duration(best) * time.Minute)
	return start, true
}
