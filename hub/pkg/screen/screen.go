// Package screen is the remote screen session (docs/REMOTE_SCREEN.md): what
// differs from a terminal and nothing else. A screen session is a terminal
// session of its own kind - same manager, relay, tokens, caps, limits,
// sweeper and states - whose program is "screen:control" or "screen:view".
// This package supplies the kind: its frame policy (binary JPEG tiles pass
// through, input is dropped in view mode, quality is clamped), the one screen
// per endpoint cap on top of the shared caps, no recording, and pause/resume
// to the agent when the viewer detaches and comes back.
package screen

import (
	"errors"
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

const (
	// ProgramPrefix marks a screen session's program in the shared manager.
	ProgramPrefix = "screen:"
	// MaxPerEndpoint is how many screen sessions one endpoint may have live
	// at once, whatever the shell cap allows (a screen is heavier).
	MaxPerEndpoint = 1
	// MaxWatchers is how many watch (view-only) attachments a session may
	// have beside its control attachment.
	MaxWatchers = 3
	// MaxFPS is the frame rate the hub lets a viewer ask for (v1).
	MaxFPS = 10
	// DefaultJPEGQuality, MinJPEGQuality and MaxJPEGQuality bound the tile
	// quality a viewer may ask for (v1).
	DefaultJPEGQuality = 60
	MinJPEGQuality     = 30
	MaxJPEGQuality     = 85
)

var (
	pauseMessage  = []byte(`{"type":"pause"}`)
	resumeMessage = []byte(`{"type":"resume"}`)
)

func init() {
	terminal.RegisterKind(terminal.SessionKind{
		Prefix:         ProgramPrefix,
		Name:           "screen",
		NewPolicy:      newPolicy,
		MaxPerEndpoint: MaxPerEndpoint,
		MaxWatchers:    MaxWatchers,
		// No pixel recording by default (REMOTE_SCREEN.md section 7); the
		// audit still says who, when, how long and which mode.
		NoRecording: true,
		// Watching is using: a view-only viewer sends nothing for minutes.
		AttachedIsActivity: true,
		PauseMessage:       pauseMessage,
		ResumeMessage:      resumeMessage,
	})
}

// ValidMode reports whether m is a screen session mode.
func ValidMode(m string) bool {
	return m == response.ScreenModeControl || m == response.ScreenModeView
}

// Program is the shared manager's program for a screen session in mode.
func Program(mode string) string { return ProgramPrefix + mode }

// ModeOf returns the mode of a screen session's program.
func ModeOf(program string) (string, bool) {
	if !strings.HasPrefix(program, ProgramPrefix) {
		return "", false
	}
	m := strings.TrimPrefix(program, ProgramPrefix)
	return m, ValidMode(m)
}

// IsScreen reports whether a session program is a screen session's.
func IsScreen(program string) bool { return strings.HasPrefix(program, ProgramPrefix) }

// CreateSession opens a waiting screen session under an authority-signed grant
// for this endpoint. d is the session length (zero or less: the hub's
// maximum); the shared caps and the one-per-endpoint cap apply.
func CreateSession(tm *terminal.Manager, tenantID, endpointID, operatorID, mode string, grant *response.EndpointGrant, d time.Duration) (*terminal.TerminalSession, error) {
	if tm == nil {
		return nil, errors.New("terminal manager not initialized")
	}
	if !ValidMode(mode) {
		return nil, errors.New(`screen mode must be "control" or "view"`)
	}
	if grant == nil || grant.ActionKind != response.ActionKindScreenSession || grant.EndpointID != endpointID {
		return nil, errors.New("a screen session needs a screen_session grant for this endpoint")
	}
	return tm.CreateSessionFor(tenantID, endpointID, operatorID, Program(mode), grant, d)
}
