package server

import "testing"

// An agent without a pinned tenant response key drops every signed grant, so
// it says so and the hub must not offer it a terminal.
func TestCapabilitiesWithoutResponseKey(t *testing.T) {
	c := parseResponseCapabilities(`{"isolate":true,"response_key":false}`)
	if !c.reported || !c.NoResponseKey || len(c.TerminalPrograms) != 0 || !c.Isolate {
		t.Fatalf("parsed %+v", c)
	}
	if got := normalizeResponseCapabilities([]byte(`{"isolate":true,"response_key":false}`)); got != `{"isolate":true,"collect":false,"response_key":false}` {
		t.Fatalf("normalized %s", got)
	}
	full := parseResponseCapabilities(`{"isolate":true,"collect":true,"response_key":true,"terminal":{"programs":["/bin/bash"]}}`)
	if full.NoResponseKey || len(full.TerminalPrograms) != 1 {
		t.Fatalf("parsed %+v", full)
	}
	older := parseResponseCapabilities(`{"isolate":true,"collect":true,"terminal":{"programs":["/bin/bash"]}}`)
	if older.NoResponseKey {
		t.Fatal("an agent that does not report the field is not assumed keyless")
	}
}
