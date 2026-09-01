package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

func parseTrafficFilter(s *Server, r *http.Request) storage.TrafficFilter {
	q := r.URL.Query()
	tenantID := s.tenantFromRequest(r)

	limit := 50
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	proto := 0
	if pStr := q.Get("protocol"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			proto = p
		} else {
			switch strings.ToUpper(pStr) {
			case "TCP":
				proto = 6
			case "UDP":
				proto = 17
			case "ICMP":
				proto = 1
			}
		}
	}

	port := 0
	if portStr := q.Get("port"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	} else if portStr := q.Get("dst_port"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	var from, to time.Time
	if fromStr := q.Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	measuredOnly := false
	if mStr := q.Get("measured_only"); mStr == "true" || mStr == "1" {
		measuredOnly = true
	}

	return storage.TrafficFilter{
		TenantID:     tenantID,
		Range:        q.Get("range"),
		From:         from,
		To:           to,
		EndpointID:   strings.TrimSpace(q.Get("endpoint_id")),
		SrcIP:        strings.TrimSpace(q.Get("src_ip")),
		DstIP:        strings.TrimSpace(q.Get("dst_ip")),
		Process:      strings.TrimSpace(q.Get("process")),
		Domain:       strings.TrimSpace(q.Get("domain")),
		Country:      strings.TrimSpace(q.Get("country")),
		Protocol:     proto,
		Port:         port,
		Direction:    strings.TrimSpace(q.Get("direction")),
		Action:       strings.TrimSpace(q.Get("action")),
		MeasuredOnly: measuredOnly,
		Cursor:       strings.TrimSpace(q.Get("cursor")),
		Limit:        limit,
	}
}

// handleTrafficOverview returns aggregated volume, trends, distributions, rankings and heatmap.
func (s *Server) handleTrafficOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := parseTrafficFilter(s, r)
	overview, err := s.store.QueryTrafficOverview(filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, overview)
}

// handleTrafficFlows returns paginated raw flows matching filter criteria.
func (s *Server) handleTrafficFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if this is a single flow detail request: /api/v1/traffic/flows/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/traffic/flows")
	path = strings.TrimPrefix(path, "/")
	if path != "" {
		s.handleTrafficFlowDetail(w, r, path)
		return
	}

	filter := parseTrafficFilter(s, r)
	result, err := s.store.QueryTrafficFlows(filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTrafficFlowDetail(w http.ResponseWriter, r *http.Request, flowID string) {
	tenantID := s.tenantFromRequest(r)
	flow, err := s.store.GetTrafficFlowByID(flowID, tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if flow == nil {
		writeJSONError(w, http.StatusNotFound, "flow not found")
		return
	}

	writeJSON(w, http.StatusOK, flow)
}
