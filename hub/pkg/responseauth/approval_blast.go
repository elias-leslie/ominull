package responseauth

import (
	"encoding/json"
	"strings"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
)

// Blast verdicts (Nightshift's approvals model): safe changes nothing that
// matters, undoable can be put back, dangerous cannot easily be, and core is
// the protected core that asks the owner whatever the rows or the session
// say.
const (
	BlastSafe      = "safe"
	BlastUndoable  = "undoable"
	BlastDangerous = "dangerous"
	BlastCore      = "core"
)

// Blast is an ask's blast radius, decided from its payload alone and signed
// into its statement: Nightshift shows it as "Asked because" and keeps it for
// learning. Class is one of script, package, reboot, isolation, remote,
// capability, detection, enrol, agent_update, other.
type Blast struct {
	Class   string `json:"class"`
	Verdict string `json:"verdict"`
	Why     string `json:"why"`
}

// blastFor classes an ask. Core for OmniNull: isolating a host-locked machine
// (it could cut off access to the hosts the owner manages everything from),
// loosening capability, trust or lock, opening LAN self-enrolment, and
// anything the hub cannot read. No released package deletes data without an
// undo today; a careful package or step is dangerous, not core.
func (a *Authority) blastFor(in *ApprovalRequestInput, targets []string, ri RowInputs) Blast {
	locked := false
	if in.Facts != nil {
		set := map[string]bool{}
		for _, id := range in.Facts.Locked {
			set[id] = true
		}
		for _, t := range targets {
			locked = locked || set[t]
		}
	}
	remoteVerdict := func(class, what string) Blast {
		if ri.Lab {
			return Blast{class, BlastUndoable, what + " on a lab machine"}
		}
		return Blast{class, BlastDangerous, what + " on a person's machine"}
	}
	switch in.Kind {
	case ActionKindAgentUpdate:
		if _, _, err := a.rolloutRuleCovers(in, targets); err == nil {
			return Blast{"agent_update", BlastUndoable, "an owner-signed release, rolled out canaries first; agents can go back to the previous signed version"}
		}
		return Blast{"agent_update", BlastDangerous, "an agent build that is not an owner-signed release"}
	case response.ActionKindTerminalSession:
		return remoteVerdict("remote", "a terminal")
	case response.ActionKindScreenSession:
		return remoteVerdict("remote", "remote screen")
	case response.ActionKindScriptExec:
		return blastForRun(in, targets, remoteVerdict)
	case ActionKindIsolation, ActionKindMesh:
		var p routedPayload
		if json.Unmarshal(in.Payload, &p) == nil && p.Route == "/api/v1/endpoints/allow-isolation" {
			return Blast{"capability", BlastCore, "lets the hub isolate a machine it could not isolate before"}
		}
		if locked {
			return Blast{"isolation", BlastCore, "isolating a host-locked machine could cut off access to it"}
		}
		return Blast{"isolation", BlastUndoable, "the hub can release the isolation"}
	case ActionKindCapability:
		return Blast{"capability", BlastCore, "loosens what the hub may do on a machine"}
	case ActionKindDetection:
		var p detectionPolicyPayload
		if json.Unmarshal(in.Payload, &p) != nil {
			return Blast{"detection", BlastCore, "the hub cannot read this detection change"}
		}
		switch p.Policy {
		case "enrolment_window":
			return Blast{"enrol", BlastCore, "opening LAN self-enrolment lets a new agent onto a person's machine"}
		case "terminal_limits", "screen_ask_first", "remote_access":
			return Blast{"capability", BlastCore, "loosens remote access limits"}
		case "software_catalog":
			return Blast{"capability", BlastUndoable, "changes which programs maintenance may uninstall; saving the old list undoes it"}
		}
		if p.Drill != nil && len(*p.Drill) > 0 {
			return Blast{"detection", BlastDangerous, "the change blinds a detection floor case, or its drill could not run"}
		}
		return Blast{"detection", BlastUndoable, "a detection policy change; saving the previous policy undoes it"}
	}
	return Blast{"other", BlastDangerous, "an action the hub does not class"}
}

// blastForRun: released packages by their risk, careful steps and mode;
// anything else is code the owner has not released.
func blastForRun(in *ApprovalRequestInput, targets []string, remoteVerdict func(class, what string) Blast) Blast {
	if oneOffOf(in.Payload) != nil {
		return remoteVerdict("script", "a one-off script")
	}
	items, _, err := parsePackageRunPayload(in.Payload, targets)
	if err != nil || len(items) == 0 {
		return Blast{"package", BlastCore, "the hub cannot read this package run"}
	}
	var careful, names []string
	auditOnly, reboot := true, false
	for _, it := range items {
		if it.Header == nil {
			return remoteVerdict("script", "a script that is not a released package")
		}
		mode := it.Exec.Parameters["mode"]
		names = append(names, it.Header.Name+" ("+mode+")")
		if mode != "audit" {
			auditOnly = false
		}
		if mode == "audit" {
			continue
		}
		if it.Header.Role == scripts.RoleReboot {
			reboot = reboot || mode == "enforce"
			continue
		}
		if it.Risk == "careful" && mode == "enforce" {
			careful = append(careful, it.Header.Name)
		}
		for _, s := range it.Header.CarefulSteps(it.Exec.Parameters) {
			careful = append(careful, it.Header.Name+" step "+s)
		}
	}
	switch {
	case auditOnly:
		return Blast{"package", BlastSafe, "audit only: changes nothing"}
	case len(careful) > 0:
		return Blast{"package", BlastDangerous, "careful: " + strings.Join(careful, ", ")}
	case reboot:
		return Blast{"reboot", BlastUndoable, "restarts the machine after an on-screen warning; nothing lasting changes"}
	}
	return Blast{"package", BlastUndoable, "released safe packages: " + strings.Join(names, ", ")}
}
