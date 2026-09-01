package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// handleDNSStatus returns current operational status of the DNS server.
func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.dnsServer != nil {
		writeJSON(w, http.StatusOK, s.dnsServer.Status())
	} else {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"state":         "disabled",
			"listen_addr":   "",
			"upstreams":     []string{},
			"allow_rules":   0,
			"block_rules":   0,
			"cache_entries": 0,
			"queries_total": 0,
			"cache_hits":    0,
			"blocked_total": 0,
			"errors_total":  0,
		})
	}
}

// handleDNSEvents returns tenant-scoped recent DNS queries and sinkhole drops.
func (s *Server) handleDNSEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := s.tenantFromRequest(r)
	q := r.URL.Query()

	limit := 100
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}
	offset := 0
	if oStr := q.Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	filter := storage.DNSEventFilter{
		ClientIP: strings.TrimSpace(q.Get("client_ip")),
		Domain:   strings.TrimSpace(q.Get("domain")),
		Action:   strings.TrimSpace(q.Get("action")),
		Status:   strings.TrimSpace(q.Get("status")),
		Limit:    limit,
		Offset:   offset,
	}

	if fromStr := q.Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filter.From = t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			filter.To = t
		}
	}

	events, total, err := s.store.ListDNSEvents(tenantID, filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if events == nil {
		events = []storage.DNSEvent{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"events": events,
	})
}

// handleDNSPolicy handles listing, creating/updating, and deleting DNS permit/block policies.
func (s *Server) handleDNSPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)

	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.ListDNSRules(tenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rules == nil {
			rules = []storage.DNSRule{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"rules": rules,
			"total": len(rules),
		})

	case http.MethodPut, http.MethodPost:
		var req struct {
			ID      string `json:"id"`
			Domain  string `json:"domain"`
			Action  string `json:"action"`
			Source  string `json:"source"`
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Domain == "" {
			writeJSONError(w, http.StatusBadRequest, "domain is required")
			return
		}
		action := strings.ToUpper(strings.TrimSpace(req.Action))
		if action != "ALLOW" && action != "BLOCK" {
			action = "BLOCK"
		}
		source := strings.TrimSpace(req.Source)
		if source == "" {
			source = "local"
		}

		rule := storage.DNSRule{
			ID:        req.ID,
			TenantID:  tenantID,
			Domain:    req.Domain,
			Action:    action,
			Source:    source,
			Comment:   strings.TrimSpace(req.Comment),
			CreatedAt: time.Now().UTC(),
		}
		if err := s.store.SaveDNSRule(&rule); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if s.dnsServer != nil {
			s.dnsServer.ReloadRules()
		}

		s.audit(r, "DNS_POLICY_SAVE", rule.Domain,
			fmt.Sprintf("DNS policy %s %q saved (%s)", rule.Action, rule.Domain, rule.Source))

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "saved",
			"rule":   rule,
		})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			var req struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err == nil {
				id = strings.TrimSpace(req.ID)
			}
		}
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "id is required")
			return
		}

		if err := s.store.DeleteDNSRule(id, tenantID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if s.dnsServer != nil {
			s.dnsServer.ReloadRules()
		}

		s.audit(r, "DNS_POLICY_DELETE", id, "DNS policy deleted")

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "deleted",
			"id":     id,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDNSPolicyTest evaluates a test domain against active DNS policy rules.
func (s *Server) handleDNSPolicyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" && r.Method == http.MethodPost {
		var req struct {
			Domain string `json:"domain"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		domain = strings.TrimSpace(req.Domain)
	}

	if domain == "" {
		writeJSONError(w, http.StatusBadRequest, "domain is required")
		return
	}

	if s.dnsServer != nil {
		writeJSON(w, http.StatusOK, s.dnsServer.TestPolicy(domain))
	} else {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"domain":       domain,
			"verdict":      "PERMIT",
			"is_allowed":   false,
			"is_blocked":   false,
			"block_reason": "DNS server not active",
		})
	}
}
