package screen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

// TestEveryHelperMessageIsAllowed reads the helper's agent->operator message
// list straight from the shared Rust wire crate and checks the hub forwards
// each type. The second live test died because the helper's "desktop" message
// was missing here: the relay closed the session with
// forbidden_agent_frame_type seconds after it opened.
func TestEveryHelperMessageIsAllowed(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "screen", "wire", "src", "proto.rs"))
	if err != nil {
		t.Fatalf("read the wire protocol: %v", err)
	}
	types := outMsgTypes(t, string(src))
	if len(types) < 7 || !contains(types, "desktop") || !contains(types, "hello") {
		t.Fatalf("parsed helper message types look wrong: %v", types)
	}
	for _, mode := range []string{response.ScreenModeControl, response.ScreenModeView} {
		p := newPolicy(Program(mode), "parity")
		for _, typ := range types {
			d := p.Agent(websocket.TextMessage, []byte(`{"type":"`+typ+`"}`))
			if typ == "bye" {
				if d.Action != terminal.FrameCloseSession || !strings.HasPrefix(d.Reason, "agent_bye") {
					t.Errorf("%s: bye should end the session as agent_bye, got %+v", mode, d)
				}
				continue
			}
			if d.Action != terminal.FrameForward {
				t.Errorf("%s: the helper sends %q but the hub does not forward it: %+v", mode, typ, d)
			}
		}
	}
	// A realistic desktop message, as the helper sends it after hello.
	d := newPolicy(Program(response.ScreenModeControl), "parity").Agent(websocket.TextMessage, []byte(`{"type":"desktop","name":"secure","signed_in":true}`))
	if d.Action != terminal.FrameForward {
		t.Fatalf("desktop message not forwarded: %+v", d)
	}
}

// outMsgTypes lists the serde tag of each OutMsg variant (snake_case), except
// the catch-all Unknown that only the viewer decodes.
func outMsgTypes(t *testing.T, src string) []string {
	t.Helper()
	start := strings.Index(src, "pub enum OutMsg {")
	if start < 0 {
		t.Fatal("pub enum OutMsg not found in proto.rs")
	}
	body := src[start:]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatal("end of OutMsg not found")
	}
	variant := regexp.MustCompile(`(?m)^    ([A-Z][A-Za-z0-9]*)\b`)
	var out []string
	for _, m := range variant.FindAllStringSubmatch(body[:end], -1) {
		if m[1] == "Unknown" {
			continue
		}
		out = append(out, snake(m[1]))
	}
	return out
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
