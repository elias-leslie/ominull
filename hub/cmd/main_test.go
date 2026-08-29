package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A key file is the alternative to putting the admin credential in the command
// line, where every local account can read it. It is only an improvement if the
// file itself is not readable by every local account, so a loose mode is
// refused rather than quietly accepted.
func TestAKeyFileMustNotBeReadableByAnyoneElse(t *testing.T) {
	dir := t.TempDir()

	tight := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(tight, []byte("s3cret-admin-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readKeyFile(tight)
	if err != nil {
		t.Fatalf("a 0600 key file should be accepted: %v", err)
	}
	if key != "s3cret-admin-key" {
		t.Fatalf("got %q, want the first line with no trailing newline", key)
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		loose := filepath.Join(dir, "loose.key")
		if err := os.WriteFile(loose, []byte("s3cret-admin-key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(loose, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readKeyFile(loose); err == nil {
			t.Fatalf("mode %04o lets another account read the admin key; it should be refused", mode)
		}
		os.Remove(loose)
	}
}

// An empty file is a misconfiguration that would otherwise start the hub with an
// empty admin key, which authenticates nothing and refuses everyone.
func TestAnEmptyKeyFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.key")
	if err := os.WriteFile(path, []byte("\n   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(path); err == nil {
		t.Fatal("an empty key file should be refused, not used as an empty key")
	}
}

// Only the first line is the credential: an operator who keeps the admin key on
// line 1 and a note or a second key below it must not get both.
func TestOnlyTheFirstLineIsTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.key")
	if err := os.WriteFile(path, []byte("first-line-key\nsecond-line-tenant-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if key != "first-line-key" {
		t.Fatalf("got %q, want only the first line", key)
	}
}
