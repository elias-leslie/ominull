package detector

import (
	"path/filepath"
	"strings"
)

// WorkloadOf names the program behind a connection finely enough to vouch for.
//
// For most programs that is the executable's base name. For an interpreter it
// is not: on a developer machine every service, test run and one-off script is
// "python3.13", so the name alone cannot tell a market-data worker from a
// script an agent wrote a minute ago. The workload of an interpreter is its
// base name, what it was started as when that says more (a virtualenv's
// python names its project, "npm" names what node runs), and what it was asked to run: the script, the
// module after -m, the jar after -jar. Code given inline (-c, -e) yields a
// workload ending in " -c" or " -e", which tuning never accepts as known.
//
// The command line is what the process says about itself. That is enough to
// stop one known service's identity covering every other program run by the
// same interpreter, which is the point; it is not proof of what the process
// is, which is why a known workload still answers to the volume, beacon and
// threat-intelligence detectors.
func WorkloadOf(processPath, commandLine string) string {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(processPath, "\\", "/")))
	base = strings.TrimSuffix(base, " (deleted)")
	if base == "." || base == "/" {
		base = ""
	}
	family := interpreterFamily(base)
	args := strings.Fields(commandLine)
	if family == "" || len(args) == 0 {
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

// interpreterFamily groups the interpreters whose command lines WorkloadOf can
// read. Network clients (curl, ssh, nc) and Windows hosts are not here: their
// arguments are destinations and commands, not a program, so they are known by
// name or not at all.
func interpreterFamily(base string) string {
	b := strings.TrimSuffix(base, ".exe")
	switch b {
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh":
		return "shell"
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

func interpreterTarget(family string, args []string) string {
	inline := map[string]string{"python": "-c", "shell": "-c", "node": "-e", "perl": "-e", "ruby": "-e", "php": "-r", "lua": "-e"}[family]
	withValue := map[string][]string{
		"python": {"-X", "-W", "-Q"},
		"node":   {"-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--title"},
		"java":   {"-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-opens", "--add-exports"},
		"ruby":   {"-I", "-r"},
		"perl":   {"-I", "-M"},
	}[family]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == inline || (family == "node" && (a == "--eval" || a == "-p" || a == "--print")):
			// One spelling for every family, so tuning has one suffix to refuse.
			if inline == "-r" {
				return "-e"
			}
			return inline
		case family == "python" && a == "-m" && i+1 < len(args):
			return "-m " + args[i+1]
		case family == "java" && a == "-jar" && i+1 < len(args):
			return "-jar " + args[i+1]
		case strings.HasPrefix(a, "-"):
			for _, v := range withValue {
				if a == v {
					i++
					break
				}
			}
		default:
			return a
		}
	}
	return ""
}
