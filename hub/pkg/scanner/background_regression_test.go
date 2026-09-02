package scanner

import "testing"

func TestBackgroundStartupDoesNotBindDHCPPort(t *testing.T) {
	scanner := New(nil)

	// Use an unprivileged ephemeral port so lack of permission to bind the real
	// UDP/67 cannot make the default-off assertion pass for the wrong reason.
	scanner.dhcpSnooper = newDHCPSnooper(scanner, "127.0.0.1:0")

	scanner.StartBackground()
	t.Cleanup(scanner.StopBackground)
	if scanner.dhcpSnooper.IsServing() {
		t.Fatal("background scanner startup bound UDP/67 without an explicit DHCP-snoop opt-in")
	}
}

func TestDHCPSnoopingStartsOnlyWhenExplicitlyRequested(t *testing.T) {
	scanner := New(nil)
	scanner.dhcpSnooper = newDHCPSnooper(scanner, "127.0.0.1:0")
	t.Cleanup(scanner.StopBackground)

	if err := scanner.StartDHCPSnooping(); err != nil {
		t.Fatalf("start explicit DHCP snooping: %v", err)
	}
	if !scanner.DHCPSnooping() {
		t.Fatal("explicit DHCP-snoop opt-in did not start the listener")
	}
}
