package detector

import (
	"path/filepath"
	"strings"
)

// WorkloadOf names the program behind a connection finely enough to vouch for.
//
// For most programs that is the executable's path, lower-cased. For an
// interpreter it is not: on a developer machine every service, test run and one-off script is
// "python3.13", so the name alone cannot tell a market-data worker from a
// script an agent wrote a minute ago. The workload of an interpreter is its
// base name, what it was started as when that says more (a virtualenv's
// python names its project, "npm" names what node runs), and what it was asked to run: the script, the
// module after -m, the jar after -jar. Code that does not come from a named
// program - inline (-c, -e), from stdin or a /dev/fd pipe, preloaded beside
// the program (node -r, perl -M, ruby -r) - or a command line this parser
// cannot read for certain (an option it does not know) yields the workload
// "<interpreter> -c", which tuning never accepts as known. Failing closed is
// the point: a misread option must not turn its value into the "program".
//
// The command line is what the process says about itself. That is enough to
// stop one known service's identity covering every other program run by the
// same interpreter, which is the point; it is not proof of what the process
// is, which is why a known workload still answers to the volume, beacon and
// threat-intelligence detectors.
func WorkloadOf(processPath, commandLine string) string {
	path, base := executableOf(processPath)
	family := interpreterFamily(base)
	if family == "" {
		// Any other program is known by where it is installed, not by its name:
		// a copy of python named "chrome" in a home directory is not Chrome.
		return path
	}
	args := strings.Fields(commandLine)
	if len(args) == 0 {
		return base
	}
	// argv[0] is kept when it says more than the executable does: a
	// virtualenv's python names its project, and "npm" or a process title
	// names the tool a bare "node" is running.
	parts := []string{base}
	if strings.Contains(args[0], "/") || interpreterFamily(strings.ToLower(args[0])) != family {
		parts = append(parts, args[0])
	}
	if target := interpreterTarget(family, args[1:]); target != "" {
		parts = append(parts, target)
	}
	return strings.Join(parts, " ")
}

// executableOf is the reported executable path as WorkloadOf compares it -
// lower-cased, forward slashes, no " (deleted)" - and its base name.
func executableOf(processPath string) (path, base string) {
	path = strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(processPath, "\\", "/")), " (deleted)")
	base = filepath.Base(path)
	if base == "." || base == "/" {
		return "", ""
	}
	return path, base
}

// vouchedWorkload is the workload the known-workload entries are asked about
// for a process, given the attribution status its agent reported.
//
// An installed program is known by its path, and a path the agent could not
// match to the file that runs (path_mismatch) names nothing: a program
// bind-mounted over a listed path would otherwise borrow that path's entry,
// and an AnyOwner entry for a path reaches every destination. So such a
// process has no workload to vouch for it. An interpreter's workload is its
// base name and its own command line, which any process can already claim
// without forging a path - a copy of anything named python3 gets it - and the
// tuning gives it the narrower reach for that reason, so path_mismatch takes
// nothing further from it.
func vouchedWorkload(processPath, commandLine, attributionStatus string) string {
	if attributionStatus == pathMismatch {
		if _, base := executableOf(processPath); interpreterFamily(base) == "" {
			return ""
		}
	}
	return WorkloadOf(processPath, commandLine)
}

// interpreterFamily groups the interpreters whose command lines WorkloadOf can
// read. Network clients (curl, ssh, nc) and Windows hosts are not here: their
// arguments are destinations and commands, not a program, so they are known by
// name or not at all.
func interpreterFamily(base string) string {
	b := strings.TrimSuffix(base, ".exe")
	switch b {
	case "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh":
		return "shell"
	case "fish":
		return "fish"
	case "java":
		return "java"
	case "deno", "bun", "nodejs":
		return "node"
	}
	for _, f := range []string{"python", "node", "perl", "ruby", "php", "lua"} {
		if b == f {
			return f
		}
		if rest, ok := strings.CutPrefix(b, f); ok && isVersionSuffix(rest) {
			return f
		}
	}
	return ""
}

// inlineTarget is the one spelling every family's inline or stdin code gets,
// so tuning has one suffix to refuse (storage.isInlineWorkload).
const inlineTarget = "-c"

// interpreterSyntax is what WorkloadOf needs to know about one family's
// command line: which short flags carry inline code, which take a value, and
// whether the interpreter reads its program from stdin when given none.
type interpreterSyntax struct {
	inlineLetters string            // a short-flag cluster containing any of these runs inline or preloaded code (-c, -Ic, -pe, -r)
	inlineLong    []string          // long flags that carry or preload code, with or without "=value"
	valueLetters  string            // short flags whose value is attached or the next argument
	switchLetters string            // short flags that take no value; any other letter fails closed
	valueLong     []string          // long flags whose value is the next argument unless given with "="
	switchLong    []string          // long flags that take no value; any other long flag fails closed
	switchPrefix  []string          // families of long switches ("--no-", "--trace-")
	targetFlags   map[string]string // flags whose value is the program: "-m" -> module, "-jar" -> jar
	stdinIfNone   bool              // no program named means it reads one from stdin
}

var syntaxes = map[string]interpreterSyntax{
	"python": {inlineLetters: "c", valueLetters: "XWQ", switchLetters: "bBdEhiIOPqsSuvVx", valueLong: []string{"--check-hash-based-pycs"}, targetFlags: map[string]string{"-m": "-m "}, stdinIfNone: true},
	"node": {inlineLetters: "epr", valueLetters: "C", switchLetters: "hvci", inlineLong: []string{"--eval", "--print", "--require", "--import", "--loader", "--experimental-loader", "--experimental-default-type"},
		valueLong:    []string{"--env-file", "--title", "--input-type", "--max-old-space-size", "--stack-size", "--dns-result-order"},
		switchLong:   []string{"--enable-source-maps", "--preserve-symlinks", "--inspect", "--use-openssl-ca", "--use-bundled-ca", "--abort-on-uncaught-exception"},
		switchPrefix: []string{"--no-", "--trace-", "--experimental-vm-modules", "--expose-gc", "--throw-deprecation", "--pending-deprecation"}, stdinIfNone: true},
	"perl":  {inlineLetters: "eEMm", valueLetters: "IxilCdDF0", switchLetters: "acnpstTuUvWwXS", stdinIfNone: true},
	"ruby":  {inlineLetters: "er", valueLetters: "ICEFKTU0", switchLetters: "acdlnpsSvwWyh", valueLong: []string{"--encoding", "--external-encoding", "--internal-encoding"}, switchPrefix: []string{"--disable-", "--enable-", "--jit"}, stdinIfNone: true},
	"php":   {inlineLetters: "rBRE", valueLetters: "cdz", switchLetters: "aehilmnqsvwH", targetFlags: map[string]string{"-f": ""}, stdinIfNone: true},
	"lua":   {inlineLetters: "el", switchLetters: "ivEW", stdinIfNone: true},
	"shell": {inlineLetters: "cs", valueLetters: "oO", switchLetters: "abefhkmnptuvxBCEHPTilr", valueLong: []string{"--rcfile", "--init-file"}, switchLong: []string{"--norc", "--noprofile", "--login", "--posix", "--noediting", "--restricted"}, stdinIfNone: true},
	// fish reads -C as a command to run first, unlike every other shell.
	"fish": {inlineLetters: "cC", switchLetters: "ilnpPv", inlineLong: []string{"--init-command", "--command"}, switchLong: []string{"--login", "--interactive", "--private", "--no-execute", "--no-config"}, stdinIfNone: true},
	"java": {valueLong: []string{"-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-opens", "--add-exports", "--add-modules"},
		targetFlags: map[string]string{"-jar": "-jar "}},
}

// isPipeProgram reports a "script" that is a pipe or descriptor: code
// arriving that way (python3 <(curl ...)) is inline code under another name.
func isPipeProgram(a string) bool {
	return a == "/dev/stdin" || strings.HasPrefix(a, "/dev/fd/") || strings.HasPrefix(a, "/proc/self/fd/") || strings.HasPrefix(a, "/proc/thread-self/fd/")
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func interpreterTarget(family string, args []string) string {
	syn := syntaxes[family]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-":
			return inlineTarget // the program is read from stdin
		case a == "--":
			if i+1 < len(args) && !isPipeProgram(args[i+1]) {
				return args[i+1]
			}
			return inlineTarget
		case hasKey(syn.targetFlags, a):
			if i+1 < len(args) {
				return syn.targetFlags[a] + args[i+1]
			}
			return ""
		case family == "shell" && strings.HasPrefix(a, "+") && len(a) > 1:
			// "+x", "+o name": a shell option being unset.
			if last := a[len(a)-1]; last == 'o' || last == 'O' {
				i++ // the option's name is the next argument
			}
		case family == "java" && strings.HasPrefix(a, "-"):
			// The JVM's own options are -Xmx1g, -Dk=v, -server: values attached.
			name, _, attached := strings.Cut(a, "=")
			if contains(syn.valueLong, name) && !attached {
				i++
			}
		case strings.HasPrefix(a, "--"):
			name, _, attached := strings.Cut(a, "=")
			switch {
			case contains(syn.inlineLong, name):
				return inlineTarget
			case contains(syn.valueLong, name):
				if !attached {
					i++
				}
			case attached, contains(syn.switchLong, name), hasAnyPrefix(name, syn.switchPrefix):
			default:
				return inlineTarget // an option this parser does not know: fail closed
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// A short-flag cluster: -I, -Ic, -cCODE, -pe, -mmodule.
			for j := 1; j < len(a); j++ {
				c := a[j]
				if strings.IndexByte(syn.inlineLetters, c) >= 0 {
					return inlineTarget
				}
				if family == "python" && c == 'm' {
					if rest := a[j+1:]; rest != "" {
						return "-m " + rest
					}
					if i+1 < len(args) {
						return "-m " + args[i+1]
					}
					return ""
				}
				if strings.IndexByte(syn.valueLetters, c) >= 0 {
					if j == len(a)-1 {
						i++ // the value is the next argument
					}
					break // otherwise the rest of the cluster is the value
				}
				if strings.IndexByte(syn.switchLetters, c) < 0 {
					return inlineTarget // a letter this parser does not know: fail closed
				}
			}
		default:
			if isPipeProgram(a) {
				return inlineTarget
			}
			return a
		}
	}
	if syn.stdinIfNone {
		return inlineTarget
	}
	return ""
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
