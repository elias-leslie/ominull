package server

import (
	"errors"
	"fmt"
	"strings"

	"ominull/hub/pkg/storage"
)

var errInvalidTelemetryObservation = errors.New("invalid telemetry observation")

func validateObservationBatch(events []storage.Event, health storage.CollectorHealthList) error {
	bad := func(message string) error { return fmt.Errorf("%w: %s", errInvalidTelemetryObservation, message) }
	if len(events) > 64 {
		return bad("a telemetry batch may contain at most 64 event records")
	}
	if len(health) > 8 {
		return bad("too many collector health records")
	}
	names := map[string]bool{}
	for _, h := range health {
		if h.ScopeOmitted > h.Dropped || h.SchemaOmitted > h.Dropped-h.ScopeOmitted {
			return bad("omission reasons exceed the dropped observation count")
		}
		if strings.TrimSpace(h.Name) == "" || len(h.Name) > 64 || names[h.Name] {
			return bad("collector names must be bounded and unique")
		}
		names[h.Name] = true
		switch h.State {
		case "active", "unavailable", "error", "not_started":
		default:
			return bad("unknown collector state")
		}
	}
	for _, ev := range events {
		o := ev.Observation
		if len(o.Source) > 64 {
			return bad("observation source is too long")
		}
		switch o.ByteBasis {
		case "", "unknown", "udp_payload", "tcp_socket_counter":
		default:
			return bad("unknown byte basis")
		}
		switch o.Timing {
		case "", "unknown", "socket_io", "counter_sample":
		default:
			return bad("unknown observation timing")
		}
		if o.ByteBasis == "udp_payload" && ev.Protocol != 17 {
			return bad("UDP payload basis requires UDP protocol")
		}
		if o.ByteBasis == "tcp_socket_counter" && ev.Protocol != 6 {
			return bad("TCP counter basis requires TCP protocol")
		}
		if o.Source != "" && (o.Count == 0 || o.FirstAt == nil || o.LastAt == nil) {
			return bad("measured observations require count and interval")
		}
		if (o.FirstAt == nil) != (o.LastAt == nil) {
			return bad("observation interval requires both boundaries")
		}
		if o.FirstAt != nil && (o.FirstAt.IsZero() || o.LastAt.IsZero() || o.LastAt.Before(*o.FirstAt)) {
			return bad("invalid observation interval")
		}
		if o.LastAt != nil && !ev.Timestamp.IsZero() && !o.LastAt.Equal(ev.Timestamp) {
			return bad("event timestamp must equal the last observed time")
		}
	}
	return nil
}

func applyCollectorLoss(events []storage.Event, previous, current storage.CollectorHealthList) {
	prior := map[string]uint64{}
	previousBuffers := map[string]uint64{}
	for _, h := range previous {
		prior[h.Name] = unlocatedCollectorLoss(h)
		previousBuffers[h.Name] = h.BuffersLost
	}
	for _, h := range current {
		delta := unlocatedCollectorLoss(h)
		if delta >= prior[h.Name] {
			delta -= prior[h.Name]
		}
		for i := range events {
			if events[i].Observation.Source == h.Name && h.BuffersLost != previousBuffers[h.Name] {
				events[i].Observation.Incomplete = true
			}
			if events[i].Observation.Source == h.Name && events[i].Observation.Lost < delta {
				events[i].Observation.Lost = delta
			}
		}
	}
}

// Unsupported link-local observations have a known scope and never enter the
// public-peer cadence windows. Their omission is not evidence of missing
// observations from a different peer. Unknown schema and queue loss still are.
func unlocatedCollectorLoss(h storage.CollectorHealth) uint64 {
	if h.Dropped >= h.ScopeOmitted {
		return h.Dropped - h.ScopeOmitted
	}
	return h.Dropped
}
