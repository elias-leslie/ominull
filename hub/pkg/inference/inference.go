package inference

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/storage"
)

/*
Role inference from flow.

Some of the most important machines on a network are the ones nothing can see
directly: a domain controller answers no agent install, and a hardened one
answers no probe either. But every workstation on the network tells you where
it is, several hundred times a day, by authenticating against it.

Fan-in is identity. Many agented endpoints opening sessions to one static
address on 389/636, 88, 135 and 445, from lsass.exe and svchost.exe, with no
matching fan-out, is a domain controller. The same shape with 445 and heavy
sustained bytes is a file server; 9100 is a print server; 902 a hypervisor.

Three rules govern what this package is allowed to do:

  1. Every inference produces a rationale an operator can read and argue with.
  2. Every inference is correctable, and a correction outranks it permanently.
  3. An inference never overwrites agent or scan ground truth — it is stored
     as one more claim, and the merge decides.
*/

// Signature is one role's flow shape.
type Signature struct {
	Role  string
	Label string
	// AnyPorts are the service ports that identify the role. MinPorts of them
	// must be present in the fan-in.
	AnyPorts []int
	MinPorts int
	// ExcludePorts disqualify the match: a host answering Kerberos is a
	// domain controller, not the certificate authority next to it.
	ExcludePorts []int
	// MinSources is how many distinct agented endpoints must be reaching it.
	// One host talking to another is a conversation; thirty is a service.
	MinSources int
	// ProcessHints raise confidence when the sessions come from the processes
	// the role implies.
	ProcessHints []string
	// MinBytesPerFlow separates bulk transfer from control chatter.
	MinBytesPerFlow int64
	// RequireQuietOutbound demands the host not originate a comparable amount
	// of its own traffic.
	RequireQuietOutbound bool
}

// Signatures are evaluated in order; the highest-confidence match wins and
// order breaks ties, so the more specific shapes come first.
var Signatures = []Signature{
	{
		Role:                 "domain-controller",
		Label:                "Domain controller",
		AnyPorts:             []int{88, 389, 636, 135, 445, 464, 3268},
		MinPorts:             3,
		MinSources:           3,
		ProcessHints:         []string{"lsass.exe", "svchost.exe"},
		RequireQuietOutbound: true,
	},
	{
		Role:                 "certificate-authority",
		Label:                "Internal certificate authority",
		AnyPorts:             []int{135, 443},
		MinPorts:             2,
		ExcludePorts:         []int{88, 389},
		MinSources:           3,
		ProcessHints:         []string{"certutil.exe", "svchost.exe"},
		RequireQuietOutbound: true,
	},
	{
		Role:                 "file-server",
		Label:                "File server",
		AnyPorts:             []int{445, 139, 2049},
		MinPorts:             1,
		ExcludePorts:         []int{88},
		MinSources:           3,
		MinBytesPerFlow:      40000,
		RequireQuietOutbound: true,
	},
	{
		Role:       "print-server",
		Label:      "Print server",
		AnyPorts:   []int{9100, 631, 515},
		MinPorts:   1,
		MinSources: 2,
	},
	{
		Role:       "hypervisor",
		Label:      "Hypervisor",
		AnyPorts:   []int{902, 903, 8006},
		MinPorts:   1,
		MinSources: 2,
	},
	{
		Role:                 "dns-resolver",
		Label:                "DNS resolver",
		AnyPorts:             []int{53},
		MinPorts:             1,
		ExcludePorts:         []int{88, 389},
		MinSources:           3,
		RequireQuietOutbound: false,
	},
}

// maxConfidence caps what flow evidence alone is allowed to claim. An
// inference is never ground truth, so it never reaches the 1.0 an agent
// reports or an operator asserts.
const maxConfidence = 0.9

// Result is one inference, ready to be stored or rendered.
type Result struct {
	IP         string  `json:"ip"`
	Role       string  `json:"role"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// Engine runs inference on a schedule against the events table.
type Engine struct {
	store    *storage.Store
	window   time.Duration
	interval time.Duration

	mu      sync.RWMutex
	lastRun time.Time
	lastN   int
	lastErr string
	results []Result
}

func New(store *storage.Store) *Engine {
	return &Engine{
		store:    store,
		window:   24 * time.Hour,
		interval: 5 * time.Minute,
	}
}

// Start runs inference on its schedule until the context is cancelled. The
// first pass runs immediately so a freshly started hub does not wait a whole
// interval before naming anything.
func (e *Engine) Start(ctx context.Context) {
	if n, err := e.RunOnce(); err != nil {
		log.Printf("[-] Flow inference failed: %v", err)
	} else if n > 0 {
		log.Printf("[+] Flow inference: %d role(s) deduced from traffic", n)
	}

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := e.RunOnce(); err != nil {
				log.Printf("[-] Flow inference failed: %v", err)
			}
		}
	}
}

// RunOnce evaluates the window and writes a role claim for every match.
func (e *Engine) RunOnce() (int, error) {
	profiles, err := e.store.FlowProfiles(e.window)
	if err != nil {
		e.record(nil, err)
		return 0, err
	}

	// Which addresses in a subnet answer a given port at all. This is what
	// lets a rationale say "nothing else on this subnet answers 88", which is
	// the observation that makes the call convincing.
	subnetPortHolders := make(map[string]int)
	for _, p := range profiles {
		for _, ps := range p.Ports {
			subnetPortHolders[fmt.Sprintf("%s|%d", p.Subnet, ps.Port)]++
		}
	}

	results := make([]Result, 0)
	for _, p := range profiles {
		res, ok := Evaluate(p, subnetPortHolders)
		if !ok {
			continue
		}
		if err := e.store.UpsertInferredAsset(res.IP, res.Role, res.Confidence, res.Rationale, p.LastSeen); err != nil {
			e.record(nil, err)
			return 0, err
		}
		results = append(results, res)
	}

	sort.SliceStable(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	e.record(results, nil)
	return len(results), nil
}

func (e *Engine) record(results []Result, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastRun = time.Now().UTC()
	if err != nil {
		e.lastErr = err.Error()
		return
	}
	e.lastErr = ""
	e.results = results
	e.lastN = len(results)
}

// Status reports what the last scheduled pass concluded, for the console.
func (e *Engine) Status() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	results := make([]Result, len(e.results))
	copy(results, e.results)
	return map[string]interface{}{
		"last_run":       e.lastRun,
		"inferred_count": e.lastN,
		"window":         e.window.String(),
		"interval":       e.interval.String(),
		"last_error":     e.lastErr,
		"results":        results,
		"max_confidence": maxConfidence,
	}
}

// Evaluate scores one address against every signature and returns the best
// match. It is pure: the same profile always yields the same call and the
// same rationale, which is what makes an inference arguable.
func Evaluate(p storage.FlowProfile, subnetPortHolders map[string]int) (Result, bool) {
	// A host that talks outward as much as it is talked to is not answering
	// requests, it is making them.
	quiet := p.FanOutFlows*2 <= p.Flows

	best := Result{}
	found := false

	for _, sig := range Signatures {
		if p.SourceEndpoints < sig.MinSources {
			continue
		}
		if sig.RequireQuietOutbound && !quiet {
			continue
		}

		excluded := false
		for _, port := range sig.ExcludePorts {
			if p.HasPort(port) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Walk the observed ports, not the signature's list, so the rationale
		// names them in the order the traffic actually favours them.
		matched := make([]int, 0, len(sig.AnyPorts))
		var matchedFlows, matchedBytes int64
		for _, ps := range p.Ports {
			for _, port := range sig.AnyPorts {
				if ps.Port != port {
					continue
				}
				matched = append(matched, port)
				matchedFlows += ps.Flows
				matchedBytes += ps.Bytes
				break
			}
		}
		if len(matched) < sig.MinPorts {
			continue
		}
		if sig.MinBytesPerFlow > 0 {
			if matchedFlows == 0 || matchedBytes/matchedFlows < sig.MinBytesPerFlow {
				continue
			}
		}

		procs := matchingProcesses(p.Processes, sig.ProcessHints)

		// Confidence is built from what was actually observed, so a weak
		// match reads as weak rather than as a confident guess.
		conf := 0.55
		conf += 0.05 * float64(len(matched)-sig.MinPorts)
		if len(procs) > 0 {
			conf += 0.10
		}
		if p.SourceEndpoints >= sig.MinSources*3 {
			conf += 0.10
		} else if p.SourceEndpoints >= sig.MinSources*2 {
			conf += 0.05
		}
		if p.SourceLocations > 1 {
			conf += 0.05
		}
		if quiet && p.FanOutFlows == 0 {
			conf += 0.05
		}
		if conf > maxConfidence {
			conf = maxConfidence
		}

		if !found || conf > best.Confidence {
			best = Result{
				IP:         p.IP,
				Role:       sig.Role,
				Label:      sig.Label,
				Confidence: round2(conf),
				Rationale:  rationale(p, sig, matched, procs, quiet, subnetPortHolders),
			}
			found = true
		}
	}
	return best, found
}

func matchingProcesses(seen []string, hints []string) []string {
	out := make([]string, 0, len(hints))
	for _, hint := range hints {
		for _, proc := range seen {
			if strings.Contains(strings.ToLower(proc), strings.ToLower(hint)) {
				out = append(out, hint)
				break
			}
		}
	}
	return out
}

// rationale writes the sentence an operator reads in the expanded row. It
// only states things the profile actually contains: counts, ports, processes,
// and the absence of fan-out.
func rationale(p storage.FlowProfile, sig Signature, matched []int, procs []string, quiet bool, subnetPortHolders map[string]int) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%d agented endpoint%s", p.SourceEndpoints, plural(p.SourceEndpoints))
	if p.SourceLocations > 1 {
		fmt.Fprintf(&b, " across %d locations", p.SourceLocations)
	}
	if len(procs) > 0 {
		fmt.Fprintf(&b, ", from %s", joinWords(procs))
	}
	fmt.Fprintf(&b, ", on %s", joinPorts(matched))

	if quiet {
		if p.FanOutFlows == 0 {
			b.WriteString("; fan-in without any fan-out")
		} else {
			fmt.Fprintf(&b, "; fan-in %dx its own outbound", p.Flows/maxInt64(p.FanOutFlows, 1))
		}
	}

	// The uniqueness clause is the strongest part of the argument when it is
	// true, so state it only when it is.
	for _, port := range matched {
		if subnetPortHolders[fmt.Sprintf("%s|%d", p.Subnet, port)] == 1 && p.Subnet != "" {
			fmt.Fprintf(&b, "; nothing else on %s answers %d", p.Subnet, port)
			break
		}
	}

	if sig.MinBytesPerFlow > 0 {
		fmt.Fprintf(&b, "; %s across %d flows", humanBytes(p.Bytes), p.Flows)
	}

	b.WriteString(".")
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func joinWords(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, "/")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
