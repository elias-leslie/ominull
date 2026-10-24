// Package testguard keeps tests off the machine's real privilege and service
// paths. A test that reaches systemd-run, a changing systemctl verb, pkexec,
// sudo, su, doas or run0 pops password dialogs on a workstation (and could
// change real units). Install puts look-alikes first in PATH: they record the
// call and exit 99. Read-only systemctl verbs (is-active, is-enabled, show,
// status, list-*), after any leading options, pass through to the real one.
// TestMain calls Install and then exits with Finish(code), which turns a
// recorded call into a failed run.
package testguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var blocked = []string{"systemd-run", "pkexec", "sudo", "su", "doas", "run0", "machinectl"}

var hits string

// Install prepends the guard directory to PATH and returns a function that
// removes it. Call it before running tests.
func Install() (cleanup func()) {
	dir, err := os.MkdirTemp("", "ominull-testguard-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "testguard:", err)
		os.Exit(1)
	}
	hits = filepath.Join(dir, "hits")
	shim := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "testguard:", err)
			os.Exit(1)
		}
	}
	deny := fmt.Sprintf("echo \"$(basename \"$0\") $*\" >>%q\nexit 99\n", hits)
	for _, name := range blocked {
		shim(name, deny)
	}
	realCtl, _ := exec.LookPath("systemctl")
	pass := ""
	if realCtl != "" {
		pass = fmt.Sprintf("verb=\"$1\"\nfor a in \"$@\"; do case \"$a\" in -*) ;; *) verb=\"$a\"; break ;; esac; done\ncase \"$verb\" in is-active|is-enabled|show|status|list-units|list-unit-files|list-timers|--version) exec %q \"$@\" ;; esac\n", realCtl)
	}
	shim("systemctl", pass+deny)
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() { _ = os.RemoveAll(dir) }
}

// Finish returns code, or 1 (after printing the calls) when a guarded command
// was reached during the run.
func Finish(code int) int {
	if b, err := os.ReadFile(hits); err == nil && len(b) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: tests reached a real privilege or service command:\n%s", strings.TrimSpace(string(b))+"\n")
		return 1
	}
	return code
}
