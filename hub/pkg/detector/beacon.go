package detector

import (
	"fmt"
	"math"
	"sort"
	"time"

	"ominull/hub/pkg/storage"
)

// beaconSample is one outbound connection to one destination by one process.
// The payload size is kept alongside the instant because a command-and-control
// check-in is uniform in both: the same request, on the same timer. Regularity
// on its own describes every keepalive an operating system has.
type beaconSample struct {
	at    time.Time
	bytes int64
}

// beaconWindow holds a bounded history for one endpoint/destination/process.
type beaconWindow struct {
	samples []beaconSample
}

// beaconWindowCap bounds memory per conversation. It has to be comfortably
// above the largest sample count an operator can ask for.
const beaconWindowCap = 256

// BeaconEvidence is what the detector saw, in the terms an operator can argue
// with. It travels into the alert: a verdict with no evidence is a verdict
// nobody can overturn, and this detector's whole problem was that it produced
// verdicts nobody could check.
type BeaconEvidence struct {
	Samples       int
	SpanMinutes   float64
	MeanInterval  float64 // seconds
	StdDev        float64 // seconds
	CoefVariation float64 // stddev / mean
	MedianRatio   float64 // median absolute deviation / median interval
	SizeVariation float64 // coefficient of variation of bytes out
	Score         float64 // 0..1
	Regularity    float64
	Consistency   float64
	Uniformity    float64
}

// Summary is the one line that goes next to the alert.
func (b BeaconEvidence) Summary() string {
	// A negative variation means the agent reported no payload sizes at all,
	// which is not the same as "they never varied" and must not be printed as
	// a percentage.
	payload := fmt.Sprintf("payload varies %.0f%%", b.SizeVariation*100)
	if b.SizeVariation < 0 {
		payload = "payload size not reported"
	}
	return fmt.Sprintf(
		"score %.2f | every %.1fs (+/- %.1fs, %.0f%% jitter) | %d check-ins over %.0f min | %s",
		b.Score, b.MeanInterval, b.StdDev, b.CoefVariation*100, b.Samples, b.SpanMinutes, payload)
}

// record adds one observation and scores the conversation so far.
//
// The rule this replaces was: four observations, three intervals, and a
// standard deviation under 1.5 seconds. Every one of those is satisfied by a
// service that polls twice a minute, which is what an operating system does all
// day, and it is why a freshly installed workstation that had never run
// anything reported command-and-control traffic.
//
// What is actually distinctive about a beacon is that it is regular *relative
// to its own period*, that it stays regular for a long time, and that every
// check-in carries about the same amount of data. Each of those is scored
// separately and they are combined, so no single one of them can convict.
func (bw *beaconWindow) record(t time.Time, bytesOut int64, cfg storage.DetectionTuning) (BeaconEvidence, bool) {
	bw.samples = append(bw.samples, beaconSample{at: t, bytes: bytesOut})
	if len(bw.samples) > beaconWindowCap {
		bw.samples = bw.samples[len(bw.samples)-beaconWindowCap:]
	}

	ev := BeaconEvidence{Samples: len(bw.samples)}
	if len(bw.samples) < cfg.BeaconMinSamples {
		return ev, false
	}

	span := bw.samples[len(bw.samples)-1].at.Sub(bw.samples[0].at)
	ev.SpanMinutes = span.Minutes()
	if span < time.Duration(cfg.BeaconMinSpanMin)*time.Minute {
		// Regular for ninety seconds is a burst, not a beacon.
		return ev, false
	}

	deltas := make([]float64, 0, len(bw.samples)-1)
	for i := 1; i < len(bw.samples); i++ {
		d := bw.samples[i].at.Sub(bw.samples[i-1].at).Seconds()
		// Connections opened together are one check-in, not two, and counting
		// them as a zero-length interval makes any burst look metronomic.
		if d < 0.5 {
			continue
		}
		deltas = append(deltas, d)
	}
	if len(deltas) < cfg.BeaconMinSamples-1 {
		return ev, false
	}

	mean := meanOf(deltas)
	ev.MeanInterval = mean
	if mean < float64(cfg.BeaconMinInterval) || mean > float64(cfg.BeaconMaxInterval) {
		return ev, false
	}

	ev.StdDev = stdDevOf(deltas, mean)
	if mean > 0 {
		ev.CoefVariation = ev.StdDev / mean
	}
	ev.MedianRatio = madRatio(deltas)
	ev.SizeVariation = sizeVariation(bw.samples)

	// Regularity: how tight the intervals are relative to the period itself.
	// A 0.15 coefficient of variation is the point at which a human stops
	// calling something "roughly every minute" and starts calling it "on a
	// timer"; it reaches zero by 0.60, where the traffic is plainly irregular.
	ev.Regularity = ramp(ev.CoefVariation, 0.15, 0.60)

	// Consistency: the same question asked robustly, so that a handful of
	// missed or doubled beats cannot rescue an irregular conversation, and
	// cannot condemn a regular one either.
	ev.Consistency = ramp(ev.MedianRatio, 0.10, 0.50)

	// Uniformity: check-ins that carry the same payload every time. A backup, a
	// sync client and a video call are all regular; none of them are uniform.
	// Absent byte counts score neutrally rather than favourably.
	if ev.SizeVariation < 0 {
		ev.Uniformity = 0.5
	} else {
		ev.Uniformity = ramp(ev.SizeVariation, 0.10, 1.00)
	}

	ev.Score = 0.45*ev.Regularity + 0.35*ev.Consistency + 0.20*ev.Uniformity
	return ev, ev.Score >= cfg.BeaconScore
}

// ramp scores a "lower is more suspicious" measure into 0..1: at or below good
// it is 1, at or above bad it is 0, linear between.
func ramp(v, good, bad float64) float64 {
	if v <= good {
		return 1
	}
	if v >= bad {
		return 0
	}
	return (bad - v) / (bad - good)
}

func meanOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func stdDevOf(v []float64, mean float64) float64 {
	if len(v) < 2 {
		return 0
	}
	var acc float64
	for _, x := range v {
		d := x - mean
		acc += d * d
	}
	return math.Sqrt(acc / float64(len(v)-1))
}

// madRatio is the median absolute deviation over the median, a dispersion
// measure that a few outliers cannot move. A beacon that misses two beats still
// scores low here; a bursty conversation with one long gap does not suddenly
// score low just because its mean moved.
func madRatio(v []float64) float64 {
	if len(v) == 0 {
		return 1
	}
	med := medianOf(v)
	if med <= 0 {
		return 1
	}
	devs := make([]float64, len(v))
	for i, x := range v {
		devs[i] = math.Abs(x - med)
	}
	return medianOf(devs) / med
}

func medianOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// sizeVariation returns the coefficient of variation of the payload sizes, or
// -1 when the agent did not report any. Reporting nothing must not be read as
// "perfectly uniform".
func sizeVariation(samples []beaconSample) float64 {
	vals := make([]float64, 0, len(samples))
	for _, s := range samples {
		if s.bytes > 0 {
			vals = append(vals, float64(s.bytes))
		}
	}
	if len(vals) < 3 {
		return -1
	}
	m := meanOf(vals)
	if m <= 0 {
		return -1
	}
	return stdDevOf(vals, m) / m
}
