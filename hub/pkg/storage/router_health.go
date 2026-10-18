package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Router health.
//
// The gateway's own condition (WAN, uptime, memory, config storage, connection
// table, firmware, failed ssh logins, UPnP mappings) arrives in the same poll
// as the leases and flows. Only the latest reading is kept: the hub answers
// "how is the router now" and "did its firmware change", and Nightshift, which
// owns the history and the alerting, reads it. As with every router field, the
// reading is bounded and normalised before it is stored; a reading that does
// not parse is dropped and never costs the poll's other sections.

const (
	maxRouterStamps   = 50
	maxRouterUPnPMaps = 50
	maxHealthField    = 40
)

var (
	healthWord = regexp.MustCompile(`[^A-Za-z0-9._+-]`)
	// proto:external-port:<8 hex of the hashed internal side>
	upnpMapPattern = regexp.MustCompile(`^(tcp|udp):[0-9]{1,5}:[0-9a-f]{8}$`)
)

// RouterFirmware is what the gateway says it runs.
type RouterFirmware struct {
	GLVersion string `json:"glversion"`
	OpenWrt   string `json:"openwrt"`
	Kernel    string `json:"kernel"`
}

// String is the stable comparison form; empty when the gateway reported none.
func (f RouterFirmware) String() string {
	if f.GLVersion == "" && f.OpenWrt == "" && f.Kernel == "" {
		return ""
	}
	return fmt.Sprintf("GL %s / OpenWrt %s / kernel %s", f.GLVersion, f.OpenWrt, f.Kernel)
}

// RouterHealth is one gateway reading. Memory and storage are kilobytes as the
// kernel reports them; Auth* are the router's own clock stamps (epoch seconds)
// of failed logins and connections closed before login, newest 50.
type RouterHealth struct {
	UptimeS        int64          `json:"uptime_s"`
	MemTotalKB     int64          `json:"mem_total_kb"`
	MemAvailKB     int64          `json:"mem_avail_kb"`
	OverlayKB      int64          `json:"overlay_kb"`
	OverlayUsedKB  int64          `json:"overlay_used_kb"`
	ConntrackCount int64          `json:"conntrack_count"`
	ConntrackMax   int64          `json:"conntrack_max"`
	WANUp          bool           `json:"wan_up"`
	WANIPv4        bool           `json:"wan_ipv4"`
	Load1          float64        `json:"load1"`
	Firmware       RouterFirmware `json:"firmware"`
	AuthPW         []int64        `json:"auth_pw"`
	AuthPre        []int64        `json:"auth_pre"`
	UPnP           []int          `json:"upnp"`
	UPnPN          int64          `json:"upnp_n"`
	UPnPMaps       []string       `json:"upnp_maps"`
}

// RouterHealthRecord is a stored reading with the firmware history the hub
// derived from successive readings.
type RouterHealthRecord struct {
	RouterID          string       `json:"router_id"`
	Label             string       `json:"label"`
	LastSeenAt        time.Time    `json:"last_seen_at"`
	ReportedAt        time.Time    `json:"reported_at"`
	Health            RouterHealth `json:"health"`
	Firmware          string       `json:"firmware"`
	FirmwarePrevious  string       `json:"firmware_previous,omitempty"`
	FirmwareChangedAt *time.Time   `json:"firmware_changed_at,omitempty"`
}

func healthText(raw string) string {
	raw = healthWord.ReplaceAllString(raw, "")
	if len(raw) > maxHealthField {
		raw = raw[:maxHealthField]
	}
	return raw
}

func nonNegative(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func cleanStamps(in []int64) []int64 {
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if v > 0 {
			out = append(out, v)
		}
	}
	if len(out) > maxRouterStamps {
		out = out[len(out)-maxRouterStamps:]
	}
	return out
}

// NormaliseRouterHealth bounds one gateway reading. ok is false when raw is not
// a JSON object (the poller sends null when it could not read the gateway).
func NormaliseRouterHealth(raw json.RawMessage) (RouterHealth, bool) {
	var h RouterHealth
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed[0] != '{' {
		return h, false
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return RouterHealth{}, false
	}
	h.UptimeS, h.MemTotalKB, h.MemAvailKB = nonNegative(h.UptimeS), nonNegative(h.MemTotalKB), nonNegative(h.MemAvailKB)
	h.OverlayKB, h.OverlayUsedKB = nonNegative(h.OverlayKB), nonNegative(h.OverlayUsedKB)
	h.ConntrackCount, h.ConntrackMax, h.UPnPN = nonNegative(h.ConntrackCount), nonNegative(h.ConntrackMax), nonNegative(h.UPnPN)
	if !(h.Load1 >= 0 && h.Load1 < 100000) { // also rejects NaN
		h.Load1 = 0
	}
	h.Firmware = RouterFirmware{GLVersion: healthText(h.Firmware.GLVersion), OpenWrt: healthText(h.Firmware.OpenWrt), Kernel: healthText(h.Firmware.Kernel)}
	h.AuthPW, h.AuthPre = cleanStamps(h.AuthPW), cleanStamps(h.AuthPre)
	if len(h.UPnP) != 2 {
		h.UPnP = []int{0, 0}
	}
	for i := range h.UPnP {
		if h.UPnP[i] != 0 {
			h.UPnP[i] = 1
		}
	}
	maps := make([]string, 0, len(h.UPnPMaps))
	for _, m := range h.UPnPMaps {
		if upnpMapPattern.MatchString(m) && len(maps) < maxRouterUPnPMaps {
			maps = append(maps, m)
		}
	}
	h.UPnPMaps = maps
	return h, true
}

// RecordRouterHealth stores the latest reading and notes a firmware change when
// the version differs from the previous reading's. A reading with no firmware
// at all (the gateway would not say) never counts as a change.
func (s *Store) RecordRouterHealth(routerID string, h RouterHealth, now time.Time) error {
	id := clampField(routerID)
	body, err := json.Marshal(h)
	if err != nil {
		return err
	}
	fw := h.Firmware.String()
	var prevFW, older string
	var changed *time.Time
	switch err := s.db.QueryRow(`SELECT firmware, firmware_prev, firmware_changed_at FROM router_health WHERE router_id = ?`, id).
		Scan(&prevFW, &older, &changed); err {
	case nil, sql.ErrNoRows:
	default:
		return err
	}
	if fw == "" {
		fw = prevFW
	} else if prevFW != "" && prevFW != fw {
		at := now.UTC()
		older, changed = prevFW, &at
	}
	_, err = s.db.Exec(`INSERT INTO router_health (router_id, reported_at, health, firmware, firmware_prev, firmware_changed_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(router_id) DO UPDATE SET reported_at=excluded.reported_at, health=excluded.health,
			firmware=excluded.firmware, firmware_prev=excluded.firmware_prev, firmware_changed_at=excluded.firmware_changed_at`,
		id, now.UTC(), string(body), fw, older, changed)
	return err
}

// ListRouterHealth returns the latest reading of every gateway that sent one.
func (s *Store) ListRouterHealth() ([]RouterHealthRecord, error) {
	rows, err := s.db.Query(`SELECT h.router_id, COALESCE(r.label, ''), r.last_seen_at, h.reported_at, h.health,
			h.firmware, h.firmware_prev, h.firmware_changed_at
		FROM router_health h LEFT JOIN router_sources r ON r.id = h.router_id ORDER BY h.router_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouterHealthRecord
	for rows.Next() {
		var rec RouterHealthRecord
		var body string
		var seen *time.Time
		if err := rows.Scan(&rec.RouterID, &rec.Label, &seen, &rec.ReportedAt, &body, &rec.Firmware, &rec.FirmwarePrevious, &rec.FirmwareChangedAt); err != nil {
			return nil, err
		}
		if seen != nil {
			rec.LastSeenAt = *seen
		}
		if err := json.Unmarshal([]byte(body), &rec.Health); err != nil {
			continue // a row this version cannot read says nothing rather than something wrong
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
