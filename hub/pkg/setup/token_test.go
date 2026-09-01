package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenIsPrivateOneUseAndRotatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup.token")
	if err := Ensure(path); err != nil {
		t.Fatal(err)
	}
	if ok, err := Available(path); err != nil || !ok {
		t.Fatalf("new token availability = %v, %v", ok, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("token prefix = %q", token)
	}
	if mode := func() os.FileMode { info, _ := os.Stat(path); return info.Mode().Perm() }(); mode != 0600 {
		t.Fatalf("token mode = %04o", mode)
	}
	if ok, err := Consume(path, token); err != nil || !ok {
		t.Fatalf("consume = %v, %v", ok, err)
	}
	if ok, err := Available(path); err != nil || ok {
		t.Fatalf("consumed token availability = %v, %v", ok, err)
	}
	if ok, err := Consume(path, token); err != nil || ok {
		t.Fatalf("replay consume = %v, %v", ok, err)
	}
	rotated, err := Rotate(path)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == token || !strings.HasPrefix(rotated, TokenPrefix) {
		t.Fatalf("rotation returned bad token %q", rotated)
	}
}

func TestTokenRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "setup.token")
	if err := os.WriteFile(target, []byte("not-a-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(path); err == nil {
		t.Fatal("Ensure accepted a symlink")
	}
	if ok, err := Available(path); err == nil || ok {
		t.Fatalf("Available accepted a symlink: %v, %v", ok, err)
	}
}
