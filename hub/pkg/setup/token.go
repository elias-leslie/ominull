// Package setup contains first-run setup primitives shared by the hub and its
// package-owned control utility.
package setup

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const TokenPrefix = "oms_"

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return TokenPrefix + hex.EncodeToString(raw[:]), nil
}

func secureEqual(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func ensureParent(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("setup token path is required")
	}
	return os.MkdirAll(filepath.Dir(path), 0700)
}

// Ensure creates the local one-time token if it does not exist. Existing files
// are never replaced during package upgrade or service restart.
func Ensure(path string) error {
	if err := ensureParent(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("setup token path is a symlink: %s", path)
		}
		if info.IsDir() {
			return fmt.Errorf("setup token path is a directory: %s", path)
		}
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("setup token file %s is readable by group or other", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	return writeAtomic(path, token+"\n")
}

// Rotate creates a fresh token. It prints no value; callers choose whether to
// display the returned token on a local terminal.
func Rotate(path string) (string, error) {
	if err := ensureParent(path); err != nil {
		return "", err
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := writeAtomic(path, token+"\n"); err != nil {
		return "", err
	}
	return token, nil
}

// Consume validates and removes one token while holding an advisory file lock.
// The lock covers multiple ominull-hub workers or a control utility racing the
// first request; the in-process server also serializes setup sessions.
func Consume(path, presented string) (bool, error) {
	presented = strings.TrimSpace(presented)
	if presented == "" {
		return false, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return false, err
	}
	stored := strings.TrimSpace(string(raw))
	if !secureEqual(stored, presented) {
		return false, nil
	}
	if err := f.Truncate(0); err != nil {
		return false, err
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	return true, nil
}

func Available(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return false, fmt.Errorf("setup token file is not a private regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(raw)) != "", nil
}

func writeAtomic(path, contents string) error {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(contents); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
