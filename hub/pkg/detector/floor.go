package detector

import (
	"fmt"
	"time"

	"ominull/hub/pkg/storage"
)

// The detection floor.
//
// These are the lists and numbers the floor detectors run on: the
// sensitive-port list, the bandwidth burst and outlier bounds, the port-sweep
// and lateral-sweep thresholds, and how long a host may go quiet. They stay
// in code because raising any of them suppresses alerts, and each has changed
// at most once. The tuning row (storage.DetectionTuning) may tighten past
// them; where it holds a weaker value, ClampToFloor runs the floor instead and
// says so on the Nightshift feed's detection-policy note. If a threshold here
// ever moves into the tuning, the bandwidth, sweep and lateral numbers move
// together.

// floorPorts are SMB, RDP, telnet and RPC: how a worm moves. No exclusion,
// actor or admin rule explains a flow on one.
var floorPorts = [...]int{23, 135, 445, 3389}

// FloorPort says whether a port is on the sensitive-port floor.
func FloorPort(p int) bool {
	for _, f := range floorPorts {
		if p == f {
			return true
		}
	}
	return false
}

// Bandwidth.
const (
	// bandwidthOutlierZ and bandwidthOutlierBytes make a baselined transfer an
	// outlier: a modified z-score past 3.5 and more than a megabyte.
	bandwidthOutlierZ     = 3.5
	bandwidthOutlierBytes = 1 << 20
	// bandwidthCriticalZ makes an outlier CRITICAL rather than HIGH.
	bandwidthCriticalZ = 8
	// bandwidthBurstBytes is a single transfer large enough to raise without
	// a baseline. It is raised even with bandwidth_enabled off.
	bandwidthBurstBytes = 10 << 20
	// floorBandwidthMinSamples is the most transfers a process may need before
	// its baseline counts (the tuning's bandwidth_min_samples).
	floorBandwidthMinSamples = 20
	// floorWarmupHours is the longest a new endpoint's behavioural findings,
	// the bandwidth burst among them, may be held (the tuning's warmup_hours).
	floorWarmupHours = 24
)

// Port sweep: distinct destination ports from one process within the window.
const (
	portSweepWindow     = 10 * time.Second
	portSweepPorts      = 30
	portSweepShellPorts = 15
)

// Lateral sweep: distinct LAN hosts from one process within the window, lower
// for a shell or interpreter and lower again off-hours on a workstation.
const (
	lateralWindow             = 60 * time.Second
	lateralHosts              = 20
	lateralHostsOffHours      = 10
	lateralShellHosts         = 6
	lateralShellHostsOffHours = 3
	// floorAdminFanoutMax is the most inventoried hosts one admin ssh fan-out
	// may reach before the sweep pages anyway (admin_fanout_max_hosts).
	floorAdminFanoutMax = storage.AdminFanoutMaxDefault
)

// sweepCooldown is how long a port or lateral sweep from one process stays one
// finding.
const sweepCooldown = 10 * time.Minute

// floorSilenceMinutes is the longest an always-on host may go quiet before it
// is reported (silence_after_minutes). Silence itself cannot be switched off.
const floorSilenceMinutes = 15

// ClampToFloor runs the floor wherever the tuning is weaker, and names each
// place it did. A tuning stricter than the floor is returned as it is.
func ClampToFloor(t storage.DetectionTuning) (storage.DetectionTuning, []string) {
	var notes []string
	ceiling := func(field string, v *int, max int) {
		if *v > max {
			notes = append(notes, fmt.Sprintf("%s %d is past the floor and runs at %d", field, *v, max))
			*v = max
		}
	}
	if !t.SilenceOn {
		notes = append(notes, "silence_enabled off is below the floor and runs on")
		t.SilenceOn = true
	}
	ceiling("silence_after_minutes", &t.SilenceAfterMinutes, floorSilenceMinutes)
	ceiling("bandwidth_min_samples", &t.BandwidthMinSamples, floorBandwidthMinSamples)
	ceiling("warmup_hours", &t.WarmupHours, floorWarmupHours)
	ceiling("admin_fanout_max_hosts", &t.AdminFanoutMax, floorAdminFanoutMax)
	if !t.BandwidthOn {
		notes = append(notes, fmt.Sprintf("bandwidth_enabled is off, so only transfers over %d MB are raised", bandwidthBurstBytes>>20))
	}
	return t, notes
}
