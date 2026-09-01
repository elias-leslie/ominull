package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"ominull/hub/pkg/setup"
)

const defaultSetupTokenPath = "/var/lib/ominull/setup.token"

func main() {
	path := flag.String("path", envOr("OMINULL_SETUP_TOKEN_FILE", defaultSetupTokenPath), "private setup-token file")
	rotate := false
	args := make([]string, 0, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		if arg == "--rotate" {
			rotate = true
			continue
		}
		args = append(args, arg)
	}
	_ = flag.CommandLine.Parse(args)
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "setup-token":
		if rotate {
			token, err := setup.Rotate(*path)
			fatalIf(err)
			fmt.Println(token)
			return
		}
		token, err := currentToken(*path)
		if err != nil {
			if err := setup.Ensure(*path); err != nil {
				fatalIf(err)
			}
			token, err = currentToken(*path)
		}
		fatalIf(err)
		fmt.Println(token)
	case "setup-status":
		available, err := setup.Available(*path)
		fatalIf(err)
		if available {
			fmt.Println("pending")
		} else {
			fmt.Println("consumed-or-not-created")
		}
	default:
		usage()
		os.Exit(2)
	}
}

func currentToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%s must be a private regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ominullctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ominullctl [--path FILE] setup-token [--rotate] | setup-status")
}
