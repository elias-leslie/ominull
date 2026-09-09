package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"ominull/hub/pkg/diagnostics"
	"ominull/hub/pkg/ipv6guard"
)

func (s *Server) persistIPv6Observations(batch []ipv6guard.Observation, c ipv6guard.Config) {
	findings, err := s.store.RecordIPv6Observations(batch, c)
	if err == nil {
		for _, f := range findings {
			if err = s.detector.RecordIPv6Finding(f, c); err != nil {
				break
			}
			if err = s.store.MarkIPv6Alert(f.ID, f.Observation.LastSeen); err != nil {
				break
			}
		}
	}
	s.ipv6Monitor.PersistenceResult(err)
}
func (s *Server) handleIPv6Monitor(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		var cfg ipv6guard.Config
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&cfg) != nil || cfg.Validate() != nil {
			writeJSONError(w, 400, "invalid IPv6 monitor configuration")
			return
		}
		if cfg.Enabled {
			if _, err := net.InterfaceByName(cfg.Interface); err != nil {
				writeJSONError(w, 400, "interface is unavailable")
				return
			}
			if tenant, err := s.store.GetTenant(cfg.TenantID); err != nil || tenant == nil {
				writeJSONError(w, 400, "choose an existing tenant")
				return
			}
		}
		if err := s.store.SetIPv6GuardConfig(cfg); err != nil {
			writeJSONError(w, 500, "could not save monitor configuration")
			return
		}
		_ = s.ipv6Monitor.Configure(cfg) // status reports capability/start failures explicitly
		s.audit(r, "CONFIGURE_IPV6_MONITOR", "ipv6.monitor", "Updated passive IPv6 monitoring and approved infrastructure")
	case http.MethodGet:
	default:
		writeJSONError(w, 405, "method not allowed")
		return
	}
	cfg, err := s.store.IPv6GuardConfig()
	if err != nil {
		writeJSONError(w, 500, "could not read monitor configuration")
		return
	}
	observations, err := s.store.IPv6Observations(cfg.TenantID)
	if err != nil {
		writeJSONError(w, 500, "could not read IPv6 observations")
		return
	}
	interfaces := []string{}
	if list, err := net.Interfaces(); err == nil {
		for _, iface := range list {
			if iface.Flags&net.FlagLoopback == 0 {
				interfaces = append(interfaces, iface.Name)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"config": cfg, "status": s.ipv6Monitor.Status(), "observations": observations, "interfaces": interfaces, "history_limit": 100, "retained_limit": 2048})
}
func (s *Server) checkIPv6Monitor(context.Context) diagnostics.Result {
	cfg, err := s.store.IPv6GuardConfig()
	if err != nil {
		return diag("ipv6_monitor", "IPv6 infrastructure monitoring", diagnostics.Fail, "Configuration unavailable", err.Error(), "Repair the stored configuration")
	}
	if !cfg.Enabled {
		return diag("ipv6_monitor", "IPv6 infrastructure monitoring", diagnostics.NotConfigured, "Passive monitoring is disabled", "No IPv6 packet coverage is claimed", "Choose an observed link and approved infrastructure in Policy")
	}
	status := s.ipv6Monitor.Status()
	if !status.Active || status.Error != "" || status.PersistenceError != "" {
		return diag("ipv6_monitor", "IPv6 infrastructure monitoring", diagnostics.Fail, "Configured monitor is not healthy", status.Error+" "+status.PersistenceError, "Check the selected interface and CAP_NET_RAW permission")
	}
	return diag("ipv6_monitor", "IPv6 infrastructure monitoring", diagnostics.Pass, "Capturing on "+cfg.Interface, "Only visible complete IPv6 ND, DHCPv6 and UDP WPAD queries are interpreted; fragments/encrypted/relay packets are not decoded", "An empty trust list records observations without approving discovered infrastructure")
}
