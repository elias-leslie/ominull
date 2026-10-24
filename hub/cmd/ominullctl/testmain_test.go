package main

import (
	"os"
	"testing"

	"ominull/hub/pkg/testguard"
)

// No test here may reach real systemd-run, pkexec or sudo.
func TestMain(m *testing.M) {
	removeGuard := testguard.Install()
	code := testguard.Finish(m.Run())
	removeGuard()
	os.Exit(code)
}
