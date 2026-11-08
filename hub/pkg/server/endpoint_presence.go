package server

import "ominull/hub/pkg/storage"

// endpointWatch is a host as the silence floor watches it, for the owner's
// approval: the digest binds it, so an approval asked while the host was
// watched one way is refused once that has changed.
type endpointWatch struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Presence   string `json:"presence"`
	Status     string `json:"status"`
	Isolated   bool   `json:"isolated"`
	Reason     string `json:"reason,omitempty"`
}

func watchView(ep storage.Endpoint) endpointWatch {
	presence := storage.NormalizePresence(ep.Presence)
	if presence == "" {
		presence = storage.PresenceAlwaysOn
	}
	status := ep.Status
	if status != "retired" {
		// online and offline only describe the last heartbeat; the
		// approval binds whether the host is watched, not when it last spoke.
		status = "active"
	}
	return endpointWatch{EndpointID: ep.ID, Hostname: ep.Hostname, Presence: presence, Status: status, Isolated: ep.IsIsolated}
}
