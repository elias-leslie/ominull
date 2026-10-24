package testguard

import (
	"os"
	"os/exec"
	"testing"
)

func TestGuardBlocksAndRecords(t *testing.T) {
	cleanup := Install()
	defer cleanup()
	for _, c := range [][]string{{"systemd-run", "--unit=x", "true"}, {"sudo", "-n", "true"}, {"pkexec", "true"}, {"systemctl", "stop", "x.service"}, {"systemctl", "--no-ask-password", "restart", "x.service"}} {
		err := exec.Command(c[0], c[1:]...).Run()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 99 {
			t.Errorf("%v: want exit 99, got %v", c, err)
		}
	}
	if Finish(0) != 1 {
		t.Error("Finish did not fail after guarded calls")
	}
	if err := exec.Command("systemctl", "--version").Run(); err != nil {
		t.Skipf("no real systemctl to pass through: %v", err)
	}
	_ = os.Remove(hits)
	_ = exec.Command("systemctl", "--no-ask-password", "is-active", "--quiet", "nonexistent-testguard.service").Run()
	if Finish(0) != 0 {
		t.Error("a read-only systemctl verb was counted as a hit")
	}
}
