package server

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// Two ways the hub can quietly watch less than it seems to: a bad-domain list that
// stopped loading, and an agent Aico has no machine for.

const (
	// domainFeedStaleHoursSetting is the hub setting holding how long a list may fail
	// before it is worth a look: one failed hourly fetch is ordinary weather.
	domainFeedStaleHoursSetting = "domain_feed_stale_hours"
	domainFeedStaleHoursDefault = 24
	domainFeedStaleHoursMax     = 720
	// domainFeedFailingSetting holds each failing list's first failure, so a restart
	// doesn't restart the count. A hub restarted daily would otherwise never say.
	domainFeedFailingSetting = "domain_feed_failing_since"
)

func (s *Server) domainFeedStale() time.Duration {
	hours := domainFeedStaleHoursDefault
	if v, err := s.store.GetSetting(domainFeedStaleHoursSetting); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			hours = min(max(n, 1), domainFeedStaleHoursMax)
		}
	}
	return time.Duration(hours) * time.Hour
}

func (s *Server) domainFeedFinding(now time.Time) feedFinding {
	var statuses []threatintel.DomainFeedStatus
	if s.ti != nil {
		statuses = s.domainFeedFailures(s.ti.DomainFeedStatuses(), now)
	}
	severity, status, message := judgeDomainFeeds(s.domainIntelFeeds(), statuses, now, s.domainFeedStale())
	return s.feedFinding(now, "ominull.threatintel.domain_feeds", "Bad-domain lists", severity, status, message,
		nil, map[string]any{"feeds": statuses})
}

// domainFeedFailures gives each failing list its earliest known first failure and
// keeps that record for the next hub run.
func (s *Server) domainFeedFailures(statuses []threatintel.DomainFeedStatus, now time.Time) []threatintel.DomainFeedStatus {
	raw, _ := s.store.GetSetting(domainFeedFailingSetting)
	saved := map[string]time.Time{}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &saved); err != nil {
			log.Printf("[-] %s: %v", domainFeedFailingSetting, err)
		}
	}
	next := make(map[string]time.Time, len(saved))
	out := make([]threatintel.DomainFeedStatus, len(statuses))
	for i, st := range statuses {
		out[i] = st
		if st.Error == "" {
			continue
		}
		since := now
		if st.FailingSince != nil {
			since = *st.FailingSince
		}
		if first, ok := saved[st.Name]; ok && first.Before(since) {
			since = first
		}
		next[st.Name] = since
		out[i].FailingSince = &since
	}
	if encoded, err := json.Marshal(next); err == nil && string(encoded) != raw && !(raw == "" && len(next) == 0) {
		if err := s.store.SetSetting(domainFeedFailingSetting, string(encoded)); err != nil {
			log.Printf("[-] %s: %v", domainFeedFailingSetting, err)
		}
	}
	return out
}

// judgeDomainFeeds grades the listed feeds. A list that never loaded for want of a key
// is low: someone has been asked for it, so it is no daily item. A list that has failed
// for longer than stale is medium, whether it never loaded or is running on its last
// good fetch. Messages name lists only: a fetch error can hold the hub's and its
// resolver's addresses, so the error stays in the finding's feeds detail.
func judgeDomainFeeds(feeds []storage.DomainIntelFeed, statuses []threatintel.DomainFeedStatus, now time.Time, stale time.Duration) (severity, status int, message string) {
	if len(feeds) == 0 {
		return ocsfSevInformational, ocsfStatusResolved, "No bad-domain lists are set up"
	}
	byName := make(map[string]threatintel.DomainFeedStatus, len(statuses))
	for _, st := range statuses {
		byName[st.Name] = st
	}
	var needKey, failing, wobbling, retrying []string
	loaded, names, pending := 0, 0, 0
	for _, feed := range feeds {
		st, known := byName[feed.Name]
		switch {
		case !known:
			pending++
		case st.Error == "":
			loaded++
			names += st.Domains
		case st.NeedsKey && st.FetchedAt == nil:
			needKey = append(needKey, feed.Name)
		case st.FailingSince != nil && now.Sub(*st.FailingSince) >= stale:
			failing = append(failing, feed.Name)
		case st.FetchedAt != nil:
			wobbling = append(wobbling, feed.Name)
		default:
			retrying = append(retrying, feed.Name)
		}
	}
	switch {
	case len(failing) > 0:
		return ocsfSevMedium, ocsfStatusNew, fmt.Sprintf("%s not loading for over %d h: %s",
			plural(len(failing), "bad-domain list", "bad-domain lists"), int(stale.Hours()), strings.Join(failing, ", "))
	case len(needKey) > 0:
		return ocsfSevLow, ocsfStatusNew, fmt.Sprintf("%s can't load without an abuse.ch key on the hub, so those bad names aren't checked: %s",
			plural(len(needKey), "bad-domain list", "bad-domain lists"), strings.Join(needKey, ", "))
	case len(wobbling) > 0:
		return ocsfSevInformational, ocsfStatusResolved, fmt.Sprintf("%s failed its last fetch and is using its last good copy: %s",
			plural(len(wobbling), "bad-domain list", "bad-domain lists"), strings.Join(wobbling, ", "))
	case len(retrying) > 0:
		return ocsfSevInformational, ocsfStatusResolved, fmt.Sprintf("%s not loaded yet, so those names aren't checked; retrying: %s",
			plural(len(retrying), "bad-domain list", "bad-domain lists"), strings.Join(retrying, ", "))
	case pending > 0:
		return ocsfSevInformational, ocsfStatusResolved, fmt.Sprintf("%s still loading", plural(pending, "bad-domain list", "bad-domain lists"))
	}
	return ocsfSevInformational, ocsfStatusResolved, fmt.Sprintf("%s loaded, %d names", plural(loaded, "bad-domain list", "bad-domain lists"), names)
}

// unmatchedEndpointFinding names the agents whose host Aico has no machine for. Such an
// agent gets none of Aico's word on whether it should be up (agentWatch), so a renamed
// machine would be judged by its stored presence alone with nothing saying so. Windows
// machines are noted, not raised: Aico doesn't manage them. Only each host's newest
// endpoint counts, as for Aico's word itself.
func (s *Server) unmatchedEndpointFinding(now time.Time) (feedFinding, error) {
	const uid, title = "ominull.inventory.unmatched", "Agents Aico has no machine for"
	cfg := s.store.GetDetectionTuning()
	fleet, err := s.store.AicoFleet()
	if err != nil {
		return feedFinding{}, err
	}
	if len(fleet.Machines) == 0 || !fleet.Fresh(now, time.Duration(cfg.AicoFleetFreshMinutes)*time.Minute) {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"Not checked: no recent machine list from Aico", nil, nil), nil
	}
	list, err := s.store.ListEndpoints("")
	if err != nil {
		return feedFinding{}, err
	}
	machines := make(map[string]bool, len(fleet.Machines))
	for _, m := range fleet.Machines {
		machines[m.Machine] = true
	}
	var current []storage.Endpoint
	for _, ep := range list {
		if ep.Status != "retired" {
			current = append(current, ep)
		}
	}
	newest := storage.NewestEndpoints(current)
	var raised, noted []string
	for _, ep := range current {
		short := storage.ShortHost(ep.Hostname)
		if short == "" || newest[short] != ep.ID || machines[short] {
			continue
		}
		if strings.Contains(strings.ToLower(ep.OS), "windows") {
			noted = append(noted, ep.ID)
		} else {
			raised = append(raised, ep.ID)
		}
	}
	sort.Strings(raised)
	sort.Strings(noted)
	unmapped := map[string]any{"endpoints": raised, "windows": noted}
	if len(raised) > 0 {
		return s.feedFinding(now, uid, title, ocsfSevLow, ocsfStatusNew,
			fmt.Sprintf("%s no machine in Aico, so Aico can't say if they should be up", plural(len(raised), "agent has", "agents have")),
			nil, unmapped), nil
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
		fmt.Sprintf("Every Linux agent has a machine in Aico; %s outside it", plural(len(noted), "Windows agent is", "Windows agents are")),
		nil, unmapped), nil
}
