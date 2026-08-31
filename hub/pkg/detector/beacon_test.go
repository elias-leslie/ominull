package detector

import (
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// feed replays a conversation into a fresh window and reports the last verdict.
func feed(t *testing.T, cfg storage.DetectionTuning, n int, interval time.Duration, jitter func(i int) time.Duration, size func(i int) int64) (BeaconEvidence, bool) {
	t.Helper()
	bw := &beaconWindow{}
	at := time.Now().UTC().Add(-interval * time.Duration(n+1))
	var ev BeaconEvidence
	var hit bool
	for i := 0; i < n; i++ {
		at = at.Add(interval)
		if jitter != nil {
			at = at.Add(jitter(i))
		}
		var b int64 = 0
		if size != nil {
			b = size(i)
		}
		ev, hit = bw.record(at, b, cfg)
	}
	return ev, hit
}

// The reported false positive, exactly: a handful of connections a couple of
// seconds apart on a machine that had just been installed. Under the rule this
// replaces - four samples, three intervals, standard deviation under 1.5s -
// this was command-and-control traffic.
func TestAShortRegularBurstIsNotABeacon(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	ev, hit := feed(t, cfg, 5, 2*time.Second, nil, nil)
	if hit {
		t.Fatalf("five packets over eight seconds called a beacon: %s", ev.Summary())
	}
}

// A macOS push keepalive: perfectly regular, but only for a minute or two
// before the connection is replaced. Regularity alone must not convict.
func TestARegularKeepaliveInsideTheSpanIsNotABeacon(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	ev, hit := feed(t, cfg, 14, 10*time.Second, nil, func(i int) int64 { return 200 })
	if hit {
		t.Fatalf("a two-minute keepalive called a beacon: %s", ev.Summary())
	}
	if ev.SpanMinutes >= float64(cfg.BeaconMinSpanMin) {
		t.Fatalf("test does not exercise the span floor: span %.1f min", ev.SpanMinutes)
	}
}

// The real thing: a long, metronomic conversation with a uniform payload.
func TestASustainedUniformConversationIsABeacon(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	ev, hit := feed(t, cfg, 30, 60*time.Second,
		func(i int) time.Duration { return time.Duration((i%3)-1) * 900 * time.Millisecond },
		func(i int) int64 { return int64(480 + i%5) })
	if !hit {
		t.Fatalf("a 30-minute metronomic check-in was missed: %s", ev.Summary())
	}
	if ev.Score < cfg.BeaconScore {
		t.Fatalf("score %.2f below threshold %.2f", ev.Score, cfg.BeaconScore)
	}
}

// A sync client or a backup is regular but not uniform: the payload is whatever
// changed. That difference is the whole reason payload size is scored.
func TestARegularTransferWithVaryingPayloadScoresLower(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	uniform, _ := feed(t, cfg, 30, 60*time.Second, nil, func(i int) int64 { return 500 })
	varying, _ := feed(t, cfg, 30, 60*time.Second, nil, func(i int) int64 { return int64(1000 * (1 + i%40)) })
	if varying.Score >= uniform.Score {
		t.Fatalf("payload variation did not lower the score: uniform %.2f, varying %.2f", uniform.Score, varying.Score)
	}
}

// Human traffic. Same destination, all day, at whatever interval a person
// happens to produce.
func TestIrregularHumanTrafficIsNotABeacon(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	gaps := []time.Duration{4, 91, 12, 220, 7, 33, 400, 19, 61, 8, 140, 25, 310, 16, 77, 5, 190, 44, 9, 260}
	bw := &beaconWindow{}
	at := time.Now().UTC().Add(-4 * time.Hour)
	var ev BeaconEvidence
	var hit bool
	for i := 0; i < 40; i++ {
		at = at.Add(gaps[i%len(gaps)] * time.Second)
		ev, hit = bw.record(at, int64(2000+i*137), cfg)
		if hit {
			t.Fatalf("human browsing called a beacon at sample %d: %s", i, ev.Summary())
		}
	}
}

// Connections opened together are one check-in, not several. Counting them as
// zero-length intervals let an irregular conversation borrow regularity from
// its own bursts.
func TestSimultaneousConnectionsDoNotManufactureRegularity(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	gaps := []time.Duration{40, 190, 15, 260, 8, 95, 330, 22}
	bw := &beaconWindow{}
	at := time.Now().UTC().Add(-2 * time.Hour)
	var ev BeaconEvidence
	var hit bool
	for i := 0; i < 30; i++ {
		at = at.Add(gaps[i%len(gaps)] * time.Second)
		// Four sockets opened at once, then an irregular wait.
		for k := 0; k < 4; k++ {
			ev, hit = bw.record(at.Add(time.Duration(k)*15*time.Millisecond), 0, cfg)
			if hit {
				t.Fatalf("simultaneous sockets manufactured a beacon at %d: %s", i, ev.Summary())
			}
		}
	}
}

// Nothing reported the payload size. That is missing evidence, not evidence of
// uniformity, and it must not read as a percentage.
func TestAbsentPayloadSizesAreSaidPlainly(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	ev, _ := feed(t, cfg, 20, 60*time.Second, nil, nil)
	if ev.SizeVariation >= 0 {
		t.Fatalf("expected the absent-size sentinel, got %.2f", ev.SizeVariation)
	}
	if got := ev.Summary(); !strings.Contains(got, "payload size not reported") {
		t.Fatalf("summary hides the missing evidence: %q", got)
	}
	if ev.Uniformity != 0.5 {
		t.Fatalf("absent sizes scored %.2f, expected a neutral 0.50", ev.Uniformity)
	}
}

// The evidence is the point: an operator has to be able to read the verdict.
func TestTheVerdictCarriesItsEvidence(t *testing.T) {
	cfg := storage.DefaultDetectionTuning()
	ev, hit := feed(t, cfg, 30, 60*time.Second, nil, func(i int) int64 { return 500 })
	if !hit {
		t.Fatal("expected a beacon to score")
	}
	for _, want := range []struct {
		name string
		got  float64
	}{
		{"samples", float64(ev.Samples)},
		{"span", ev.SpanMinutes},
		{"interval", ev.MeanInterval},
		{"score", ev.Score},
	} {
		if want.got <= 0 {
			t.Errorf("%s missing from the evidence", want.name)
		}
	}
	if s := ev.Summary(); len(s) < 40 {
		t.Errorf("summary too thin to act on: %q", s)
	}
}

// An operator who widens the threshold gets what they asked for, and one who
// tightens it does too. The numbers are theirs.
func TestTheThresholdIsTheOperators(t *testing.T) {
	loose := storage.DefaultDetectionTuning()
	loose.BeaconScore = 0.10
	loose.BeaconMinSamples = 6
	loose.BeaconMinSpanMin = 1
	if _, hit := feed(t, loose, 8, 30*time.Second, nil, nil); !hit {
		t.Error("a deliberately loose tuning still refused to fire")
	}

	strict := storage.DefaultDetectionTuning()
	strict.BeaconScore = 0.99
	if _, hit := feed(t, strict, 30, 60*time.Second,
		func(i int) time.Duration { return time.Duration((i%5)-2) * time.Second }, nil); hit {
		t.Error("a deliberately strict tuning fired anyway")
	}
}
