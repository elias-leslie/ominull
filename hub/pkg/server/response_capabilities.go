package server

import (
	"encoding/json"
	"strings"
)

// responseCapabilities is what an agent reports it can carry out. It is the
// one place the hub learns whether an endpoint can be isolated, collected
// from or given a terminal, and which terminal programs its PTY backend
// (forkpty, ConPTY, ...) offers. OS names are labels; this is the contract.
type responseCapabilities struct {
	Isolate          bool     `json:"isolate"`
	Collect          bool     `json:"collect"`
	TerminalPrograms []string `json:"-"`
	NoResponseKey    bool     `json:"-"` // the agent pins no tenant response key, so it drops every grant
	reported         bool
}

type wireCapabilities struct {
	Isolate     bool  `json:"isolate"`
	Collect     bool  `json:"collect"`
	ResponseKey *bool `json:"response_key,omitempty"`
	Terminal    *struct {
		Programs []string `json:"programs"`
	} `json:"terminal,omitempty"`
}

func parseResponseCapabilities(raw string) responseCapabilities {
	var w wireCapabilities
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &w) != nil {
		return responseCapabilities{}
	}
	out := responseCapabilities{Isolate: w.Isolate, Collect: w.Collect, reported: true,
		NoResponseKey: w.ResponseKey != nil && !*w.ResponseKey}
	if w.Terminal != nil {
		for _, p := range w.Terminal.Programs {
			p = strings.TrimSpace(p)
			if p != "" && len(p) <= 260 && len(out.TerminalPrograms) < 8 {
				out.TerminalPrograms = append(out.TerminalPrograms, p)
			}
		}
	}
	return out
}

// normalizeResponseCapabilities keeps a bounded, re-encoded copy of what the
// agent sent; anything malformed is dropped (stored as "not reported").
func normalizeResponseCapabilities(raw json.RawMessage) string {
	if len(raw) == 0 || len(raw) > 4096 {
		return ""
	}
	c := parseResponseCapabilities(string(raw))
	if !c.reported {
		return ""
	}
	w := wireCapabilities{Isolate: c.Isolate, Collect: c.Collect}
	if c.NoResponseKey {
		f := false
		w.ResponseKey = &f
	}
	if c.TerminalPrograms != nil {
		w.Terminal = &struct {
			Programs []string `json:"programs"`
		}{Programs: c.TerminalPrograms}
	}
	b, _ := json.Marshal(w)
	return string(b)
}
