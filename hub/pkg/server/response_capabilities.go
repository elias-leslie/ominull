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
	AllowPrefixes    bool     `json:"-"` // the isolation allow list may hold address ranges
	Collect          bool     `json:"collect"`
	TerminalPrograms []string `json:"-"`
	// Screen: the agent can share its screen (a screen_session); ScreenInput:
	// and take mouse and keyboard input, so a control session is possible.
	Screen        bool `json:"-"`
	ScreenInput   bool `json:"-"`
	NoResponseKey bool `json:"-"` // the agent pins no tenant response key, so it drops every grant
	reported      bool
}

// screenAvailable says whether a screen session can be asked for on an
// endpoint, and if not, why (in the owner's words). control asks for input.
func (c responseCapabilities) screenAvailable(control bool) (bool, string) {
	switch {
	case !c.reported || !c.Screen:
		return false, "this endpoint reports no screen capability"
	case c.NoResponseKey:
		return false, "this endpoint has no tenant response key pinned, so it drops every signed grant and a screen session would never open; pin the key on the endpoint first"
	case control && !c.ScreenInput:
		return false, "this endpoint can share its screen to watch but does not take remote input; ask for a view-only session"
	}
	return true, ""
}

// wireScreen is the "screen" capability as stored: {"input":bool}. An agent
// may also report a bare true/false.
type wireScreen struct {
	Input bool `json:"input"`
}

type wireCapabilities struct {
	Isolate       bool  `json:"isolate"`
	AllowPrefixes bool  `json:"allow_prefixes,omitempty"`
	Collect       bool  `json:"collect"`
	ResponseKey   *bool `json:"response_key,omitempty"`
	Terminal      *struct {
		Programs []string `json:"programs"`
	} `json:"terminal,omitempty"`
	Screen json.RawMessage `json:"screen,omitempty"`
}

func parseResponseCapabilities(raw string) responseCapabilities {
	var w wireCapabilities
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &w) != nil {
		return responseCapabilities{}
	}
	out := responseCapabilities{Isolate: w.Isolate, AllowPrefixes: w.AllowPrefixes, Collect: w.Collect, reported: true,
		NoResponseKey: w.ResponseKey != nil && !*w.ResponseKey}
	if w.Terminal != nil {
		for _, p := range w.Terminal.Programs {
			p = strings.TrimSpace(p)
			if p != "" && len(p) <= 260 && len(out.TerminalPrograms) < 8 {
				out.TerminalPrograms = append(out.TerminalPrograms, p)
			}
		}
	}
	if len(w.Screen) > 0 {
		var on bool
		var ws wireScreen
		if json.Unmarshal(w.Screen, &on) == nil {
			out.Screen = on
		} else if json.Unmarshal(w.Screen, &ws) == nil {
			out.Screen, out.ScreenInput = true, ws.Input
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
	w := wireCapabilities{Isolate: c.Isolate, AllowPrefixes: c.AllowPrefixes, Collect: c.Collect}
	if c.NoResponseKey {
		f := false
		w.ResponseKey = &f
	}
	if c.TerminalPrograms != nil {
		w.Terminal = &struct {
			Programs []string `json:"programs"`
		}{Programs: c.TerminalPrograms}
	}
	if c.Screen {
		w.Screen, _ = json.Marshal(wireScreen{Input: c.ScreenInput})
	}
	b, _ := json.Marshal(w)
	return string(b)
}
