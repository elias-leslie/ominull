package detector

import (
	"fmt"
	"time"

	"ominull/hub/pkg/storage"
)

// The detection floor.
//
// These are the lists and numbers the floor detectors run on: the
// sensitive-port list, the port-sweep
// and lateral-sweep thresholds, and how long a host may go quiet. They stay
// in code because raising any of them suppresses alerts, and each has changed
// at most once. The tuning row (storage.DetectionTuning) may tighten past
// them; where it holds a weaker value, ClampToFloor runs the floor instead and
// says so on the Aico push's detection-policy note. If a threshold here
// ever moves into the tuning, the bandwidth, sweep and lateral numbers move
// together.
//
// A weaker silence_after_minutes, bandwidth_cooldown_minutes, warmup_hours or rule
// max_hosts runs at the floor value and the detection-policy note says so
// (floor_clamped); a stricter value runs as saved. Silence cannot be switched off.
// The threat-list match, sensitive-port egress, port sweep, lateral sweep and
// resolver bypass run before the expected rules and ignore them (the infrastructure
// paths in code, run as their own account, stay exempt from the sweeps), apart from
// the admin ssh rule bounding a fan-out to inventoried hosts on port 22, never one
// that reaches a floor port. The 10 MB burst still yields to a rule naming it:
// Windows Update and Delivery Optimization upload tens of megabytes as svchost.exe,
// and a backup program's rule for its storage service exists for exactly that.

// floorPorts are SMB, RDP, telnet and RPC: how a worm moves. No expected rule,
// actor or admin rule explains a flow on one.
var floorPorts = storage.FloorPortList

// FloorPort says whether a port is on the sensitive-port floor.
func FloorPort(p int) bool { return storage.IsFloorPort(p) }

// Bandwidth.
const (
	// floorBandwidthCooldown is the longest one process's bandwidth finding
	// stays one finding (bandwidth_cooldown_minutes).
	floorBandwidthCooldown = 5
	// floorWarmupHours is the longest a new endpoint's behavioural findings may be held (the tuning's warmup_hours).
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
	// may reach before the sweep pages anyway (an expected rule's max_hosts).
	floorAdminFanoutMax = storage.AdminFanoutMaxDefault
)

// sweepCooldown is how long a port or lateral sweep from one process stays one
// finding.
const sweepCooldown = 10 * time.Minute

// floorSilenceMinutes is the longest an always-on host may go quiet before it
// is reported (silence_after_minutes). No setting switches silence off; Aico's
// authenticated reply saying a machine is off is what stops it for that machine
// (storage.AicoFleet.Word), and Aico then answers for that machine being down.
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
	ceiling("bandwidth_cooldown_minutes", &t.BandwidthCooldown, floorBandwidthCooldown)
	ceiling("warmup_hours", &t.WarmupHours, floorWarmupHours)
	// An admin fan-out rule may admit at most floorAdminFanoutMax hosts.
	rules := make([]storage.ExpectedRule, len(t.ExpectedRules))
	for i, r := range t.ExpectedRules {
		ceiling("expected rule "+r.ID+" max_hosts", &r.MaxHosts, floorAdminFanoutMax)
		rules[i] = r
	}
	t.ExpectedRules = rules
	// The must-page rules (class.go) have floors too: a tuning may make them
	// page sooner, never later.
	ceiling("intel_page_confidence", &t.IntelPageConfidence, floorIntelPageConfidence)
	ceiling("lan_sweep_hosts", &t.LANSweepHosts, lateralHosts)
	ceiling("lab_escape_hosts", &t.LabEscapeHosts, floorLabEscapeHosts)
	ceiling("new_dest_upload_mb", &t.NewDestUploadMB, floorNewDestUploadMB)
	ceiling("page_incident_hours", &t.PageIncidentHours, floorPageIncidentHours)
	ceiling("beacon_page_span_min", &t.BeaconPageSpanMin, floorBeaconPageSpanMin)
	if t.NewDestWindowMin < floorNewDestWindowMin {
		notes = append(notes, fmt.Sprintf("new_dest_window_min %d is below the floor and runs at %d", t.NewDestWindowMin, floorNewDestWindowMin))
		t.NewDestWindowMin = floorNewDestWindowMin
	}
	if t.BeaconPageScore > floorBeaconPageScore {
		notes = append(notes, fmt.Sprintf("beacon_page_score %.2f is past the floor and runs at %.2f", t.BeaconPageScore, floorBeaconPageScore))
		t.BeaconPageScore = floorBeaconPageScore
	}
	if t.MaxPlausibleRateMbps < floorMaxPlausibleRateMbps {
		notes = append(notes, fmt.Sprintf("max_plausible_rate_mbps %d is below the floor and runs at %d", t.MaxPlausibleRateMbps, floorMaxPlausibleRateMbps))
		t.MaxPlausibleRateMbps = floorMaxPlausibleRateMbps
	}
	return t, notes
}

// Must-page floors.
const (
	// floorIntelPageConfidence is the highest confidence a threat-intel match
	// may need before it pages.
	floorIntelPageConfidence = 90
	// floorLabEscapeHosts is the most hosts outside the lab a lab host may
	// reach before it pages.
	floorLabEscapeHosts = 3
	// floorNewDestUploadMB and floorNewDestWindowMin bound the new-place
	// upload: at most 10 MB, judged over at least the first half hour.
	floorNewDestUploadMB  = 10
	floorNewDestWindowMin = 30
	// floorBeaconPageScore is the highest score a beacon may need to page.
	floorBeaconPageScore = 0.95
	// floorMaxPlausibleRateMbps is the lowest rate the tuning may call
	// implausible: 2.5 Gb/s, faster than any link a laptop has here.
	floorMaxPlausibleRateMbps = 2500
	// floorPageIncidentHours is the longest one incident may hold its alerts.
	floorPageIncidentHours = 24
	// floorBeaconPageSpanMin is the longest a strong beacon may need to hold
	// before it pages.
	floorBeaconPageSpanMin = 30
)
