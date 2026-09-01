package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FleetConsensusCandidate represents a shared communication pattern across a fleet cohort.
type FleetConsensusCandidate struct {
	CohortKey      string  `json:"cohort_key"`
	OS             string  `json:"os"`
	Role           string  `json:"role"`
	Service        string  `json:"service"`
	Destination    string  `json:"destination"`
	Protocol       string  `json:"protocol"`
	Port           int     `json:"port"`
	EndpointsCount int     `json:"endpoints_count"`
	TotalInCohort  int     `json:"total_in_cohort"`
	ConsensusRatio float64 `json:"consensus_ratio"`
}

// ComputeFleetConsensus analyzes observed network services across endpoint cohorts
// (grouped by OS family and role) and identifies common infrastructure dependencies
// that achieve consensus (defaults to >= 70% of the cohort).
func (s *Store) ComputeFleetConsensus(tenantID string, thresholdRatio float64) ([]FleetConsensusCandidate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if thresholdRatio <= 0 || thresholdRatio > 1.0 {
		thresholdRatio = 0.70
	}

	// 1. Gather all active endpoints in the tenant
	query := "SELECT id, COALESCE(os,''), COALESCE(role_tag,''), COALESCE(observed_services,'') FROM endpoints"
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		query += " WHERE tenant_id = ?"
		rows, err = s.db.Query(query, tenantID)
	} else {
		rows, err = s.db.Query(query)
	}
	if err != nil {
		return nil, fmt.Errorf("query endpoints for fleet consensus: %w", err)
	}
	defer rows.Close()

	type EndpointEntry struct {
		ID       string
		OSFamily string
		Role     string
		Observed []ObservedService
	}

	cohortTotals := make(map[string]int)
	var endpoints []EndpointEntry

	for rows.Next() {
		var (
			id, osStr, roleStr, obsJSON string
		)
		if err := rows.Scan(&id, &osStr, &roleStr, &obsJSON); err != nil {
			return nil, fmt.Errorf("scan endpoint: %w", err)
		}

		osFamily := "linux"
		if strings.Contains(strings.ToLower(osStr), "windows") {
			osFamily = "windows"
		}
		if roleStr == "" {
			roleStr = "workstation"
		}
		cohortKey := fmt.Sprintf("%s:%s", osFamily, roleStr)
		cohortTotals[cohortKey]++

		var observed []ObservedService
		if obsJSON != "" && obsJSON != "null" {
			_ = json.Unmarshal([]byte(obsJSON), &observed)
		}

		endpoints = append(endpoints, EndpointEntry{
			ID:       id,
			OSFamily: osFamily,
			Role:     roleStr,
			Observed: observed,
		})
	}

	// 2. Count distinct endpoints per cohort observing each (service, destination)
	type ServiceKey struct {
		CohortKey   string
		Service     string
		Destination string
	}
	patternEndpoints := make(map[ServiceKey]map[string]struct{})

	for _, ep := range endpoints {
		cohortKey := fmt.Sprintf("%s:%s", ep.OSFamily, ep.Role)
		for _, o := range ep.Observed {
			dest := strings.TrimSpace(o.Destination)
			if dest == "" || alwaysPermitted(dest) {
				continue
			}
			sk := ServiceKey{
				CohortKey:   cohortKey,
				Service:     o.Service,
				Destination: dest,
			}
			if patternEndpoints[sk] == nil {
				patternEndpoints[sk] = make(map[string]struct{})
			}
			patternEndpoints[sk][ep.ID] = struct{}{}
		}
	}

	// 3. Filter by consensus threshold ratio
	var candidates []FleetConsensusCandidate
	for sk, epSet := range patternEndpoints {
		totalInCohort := cohortTotals[sk.CohortKey]
		if totalInCohort == 0 {
			continue
		}
		count := len(epSet)
		ratio := float64(count) / float64(totalInCohort)

		if ratio >= thresholdRatio {
			parts := strings.Split(sk.CohortKey, ":")
			osFamily := parts[0]
			role := parts[1]

			spec, hasSpec := serviceSpec(sk.Service)
			proto := "udp"
			port := 53
			if hasSpec {
				proto = spec.Protocol
				if len(spec.Ports) > 0 {
					port = spec.Ports[0]
				}
			}

			candidates = append(candidates, FleetConsensusCandidate{
				CohortKey:      sk.CohortKey,
				OS:             osFamily,
				Role:           role,
				Service:        sk.Service,
				Destination:    sk.Destination,
				Protocol:       proto,
				Port:           port,
				EndpointsCount: count,
				TotalInCohort:  totalInCohort,
				ConsensusRatio: ratio,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ConsensusRatio != candidates[j].ConsensusRatio {
			return candidates[i].ConsensusRatio > candidates[j].ConsensusRatio
		}
		if candidates[i].CohortKey != candidates[j].CohortKey {
			return candidates[i].CohortKey < candidates[j].CohortKey
		}
		return candidates[i].Destination < candidates[j].Destination
	})

	return candidates, nil
}

// ProposeFleetConsensusRules generates BaselineRule records based on fleet cohort consensus.
func (s *Store) ProposeFleetConsensusRules(tenantID string, thresholdRatio float64) ([]BaselineRule, error) {
	candidates, err := s.ComputeFleetConsensus(tenantID, thresholdRatio)
	if err != nil {
		return nil, err
	}

	var rules []BaselineRule
	now := time.Now().UTC()
	for _, c := range candidates {
		rule := BaselineRule{
			Service:     c.Service,
			Destination: c.Destination,
			Protocol:    c.Protocol,
			Port:        c.Port,
			Note:        fmt.Sprintf("Fleet consensus (%.0f%% of %s %s cohort, %d/%d hosts)", c.ConsensusRatio*100, c.OS, c.Role, c.EndpointsCount, c.TotalInCohort),
			CreatedAt:   now,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
