package releasesigner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// InstalledPath is the root-owned copy that the user half re-executes under sudo.
const InstalledPath = "/usr/local/sbin/ominull-release-signer"

const usage = `ominull-release-signer: the OMINULL_SIGNING_COMMAND for OmniNull releases
  pubkey                              PEM public key of the release key ($OMINULL_SIGNING_KEY: id or label)
  begin release VERSION NAME[=SHA]... open a signing session for one release; prints the token
  begin trust TENANT STATEMENT_FILE   the same for one trust bundle
  sign FILE                           DER ECDSA-SHA256 signature on stdout ($OMINULL_SIGNING_SESSION from begin)
  end                                 close the session (it also ends when everything is signed)
Paths: OMINULL_SIGNING_STORE, OMINULL_SIGNING_PUBLIC, OMINULL_SIGNING_RUN.
`

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Main runs the command and returns the exit status (64: usage).
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg := Config{Store: env("OMINULL_SIGNING_STORE", DefaultStore), Run: env("OMINULL_SIGNING_RUN", DefaultRun), Harden: Harden}
	err := run(cfg, args, stdin, stdout, stderr)
	var u usageErr
	switch {
	case err == nil:
		return 0
	case errors.As(err, &u):
		fmt.Fprint(stderr, usage)
		return 64
	}
	fmt.Fprintf(stderr, "ominull-release-signer: %v\n", err)
	return 1
}

type usageErr struct{}

func (usageErr) Error() string { return "usage" }

func run(cfg Config, a []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(a) == 0 {
		return usageErr{}
	}
	switch a[0] {
	case "pubkey":
		if len(a) == 1 {
			return pubkey(stdout, os.Getenv("OMINULL_SIGNING_KEY"))
		}
	case "begin":
		return userBegin(cfg, a[1:], stdout, stderr)
	case "sign":
		if len(a) == 2 {
			return userSign(cfg, a[1], stdout, stderr)
		}
	case "end":
		if len(a) == 1 {
			return sudo(cfg, nil, io.Discard, stderr, "root-end", os.Getenv("OMINULL_SIGNING_SESSION"))
		}
	// Root half, run through sudo by the user half: root-OP STORE RUN ARGS...
	case "root-begin":
		return rootBegin(cfg, a[1:], stdin, stdout)
	case "root-sign":
		return rootSign(cfg, a[1:], stdin, stdout)
	case "root-end":
		return rootEnd(cfg, a[1:])
	}
	return usageErr{}
}

// ---------------------------------------------------------------- user half

func publicFile() (map[string]any, error) {
	b, err := os.ReadFile(env("OMINULL_SIGNING_PUBLIC", DefaultPublic))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func pubkey(w io.Writer, want string) error {
	m, err := publicFile()
	if err != nil {
		return err
	}
	list, _ := m["keys"].([]any)
	var hit []string
	var names []string
	for _, e := range list {
		k, _ := e.(map[string]any)
		id, _ := k["id"].(string)
		label, _ := k["label"].(string)
		pem, _ := k["pubkey"].(string)
		names = append(names, id+" ("+label+")")
		if want == "" || strings.HasPrefix(id, want) || label == want || strings.HasPrefix(label, want+" ") {
			hit = append(hit, pem)
		}
	}
	if len(hit) != 1 {
		return fmt.Errorf("%d keys match %q; set OMINULL_SIGNING_KEY to one of: %s", len(hit), want, strings.Join(names, ", "))
	}
	_, err = io.WriteString(w, hit[0])
	return err
}

// sudo re-executes the installed binary as root: root-OP STORE RUN ARGS...
func sudo(cfg Config, stdin io.Reader, stdout, stderr io.Writer, op string, args ...string) error {
	bin := env("OMINULL_SIGNER_INSTALLED", InstalledPath)
	c := exec.Command("sudo", append([]string{"-n", bin, op, cfg.Store, cfg.Run}, args...)...)
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	if err := c.Run(); err != nil {
		return errors.New("signing failed (see the message above)")
	}
	return nil
}

func userBegin(cfg Config, a []string, stdout, stderr io.Writer) error {
	switch {
	case len(a) >= 3 && a[0] == "release":
		names := make([]string, 0, len(a)-2)
		for _, p := range a[2:] {
			n, sha, _ := strings.Cut(p, "=")
			p = filepath.Base(n)
			if sha != "" {
				p += "=" + sha
			}
			names = append(names, p)
		}
		return sudo(cfg, nil, stdout, stderr, "root-begin", append([]string{os.Getenv("OMINULL_SIGNING_KEY"), "release", a[1]}, names...)...)
	case len(a) == 3 && a[0] == "trust":
		f, err := os.Open(a[2])
		if err != nil {
			return err
		}
		defer f.Close()
		return sudo(cfg, io.LimitReader(f, maxText+1), stdout, stderr, "root-begin", os.Getenv("OMINULL_SIGNING_KEY"), "trust", a[1])
	}
	return usageErr{}
}

var stmtRe = regexp.MustCompile(`^OMINULL-RELEASE-V1\npackage=([^\n]+)\n`)

func userSign(cfg Config, path string, stdout, stderr io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	kind, name := "package", filepath.Base(path)
	if m := stmtRe.FindSubmatch(head); m != nil {
		kind, name = "statement", string(m[1])
	} else if strings.HasPrefix(string(head), "OMINULL-TRUST-BUNDLE-V1\n") {
		kind, name = "trust", "-"
	}
	return sudo(cfg, f, stdout, stderr, "root-sign", os.Getenv("OMINULL_SIGNING_SESSION"), kind, name, strconv.FormatInt(st.Size(), 10))
}

// ---------------------------------------------------------------- root half

// rootCfg applies the STORE and RUN the user half passed and requires root.
func rootCfg(base Config, a []string, need int) (Config, []string, error) {
	if os.Geteuid() != 0 && os.Getenv("OMINULL_SIGNER_ALLOW_NONROOT") != "1" {
		return base, nil, errors.New("the root half runs only as root (sudo)")
	}
	if len(a) < need+2 {
		return base, nil, usageErr{}
	}
	base.Store, base.Run = a[0], a[1]
	return base, a[2:], nil
}

func rootBegin(base Config, a []string, stdin io.Reader, stdout io.Writer) error {
	cfg, a, err := rootCfg(base, a, 2)
	if err != nil {
		return err
	}
	r := Request{Key: a[0], Op: a[1]}
	rest := a[2:]
	switch r.Op {
	case "release":
		if len(rest) < 1 {
			return usageErr{}
		}
		r.Version, r.Packages = rest[0], rest[1:]
	case "trust":
		if len(rest) != 1 {
			return usageErr{}
		}
		r.Tenant = rest[0]
		b, err := io.ReadAll(io.LimitReader(stdin, maxText+1))
		if err != nil {
			return err
		}
		r.Statement = string(b)
	default:
		return usageErr{}
	}
	id, err := cfg.Begin(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, id)
	return err
}

func rootSign(base Config, a []string, stdin io.Reader, stdout io.Writer) error {
	cfg, a, err := rootCfg(base, a, 4)
	if err != nil {
		return err
	}
	size, err := strconv.ParseInt(a[3], 10, 64)
	if err != nil {
		return usageErr{}
	}
	sig, err := cfg.Sign(a[0], a[1], a[2], size, stdin)
	if err != nil {
		return err
	}
	_, err = stdout.Write(sig)
	return err
}

func rootEnd(base Config, a []string) error {
	cfg, a, err := rootCfg(base, a, 1)
	if err != nil {
		return err
	}
	return cfg.End(a[0])
}
