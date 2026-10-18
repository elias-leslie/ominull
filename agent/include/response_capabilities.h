/*
 * What this agent can do when the hub asks, as one telemetry field. The hub
 * acts on these capabilities, never on the OS name, so a new platform (macOS
 * later) only has to report its own list. Each PTY backend (forkpty, ConPTY)
 * sits behind the same terminal protocol; the programs listed here are exactly
 * the ones that backend's allowlist accepts, first one the default.
 */
#ifndef OMINULL_RESPONSE_CAPABILITIES_H
#define OMINULL_RESPONSE_CAPABILITIES_H

/* "allow_prefixes": the isolation allow list may hold address ranges
 * (Trust_IsAllowEntry); an agent without it rejects a grant naming one, so
 * the hub sends ranges only to agents that report it. */
/* Collection and the terminal arrive as signed grants, verified against the
 * tenant response key pinned on this host. Without that key every grant is
 * dropped, so an agent without one reports only what needs no grant, and says
 * why: "response_key":false. */
#define OMINULL_CAPS_LINUX \
    "{\"isolate\":true,\"allow_prefixes\":true,\"collect\":true,\"response_key\":true,\"terminal\":{\"programs\":[\"/bin/bash\",\"/bin/sh\"]}}"
#define OMINULL_CAPS_NO_RESPONSE_KEY "{\"isolate\":true,\"response_key\":false}"

/* Screen capture/control is a separate signed grant (kind "screen_session"),
 * verified against the same pinned response key as the terminal. The agent
 * reports it as a sibling of "terminal"; "input":true says this backend can
 * inject (control mode), not only view. The hub's screenAvailable gate and
 * resolveScreen refuse an endpoint that does not report it. The screen object
 * rides inside _END so the single append site (hub_client.c) needs no change. */
#define OMINULL_CAPS_WINDOWS_BASE \
    "{\"isolate\":true,\"allow_prefixes\":true,\"collect\":true,\"response_key\":true,\"terminal\":{\"programs\":[\"cmd.exe\",\"powershell.exe\""
#define OMINULL_CAPS_WINDOWS_PWSH ",\"pwsh.exe\""
#define OMINULL_CAPS_WINDOWS_TERMINAL_CLOSE "]}"
#define OMINULL_CAPS_WINDOWS_SCREEN ",\"screen\":{\"input\":true}"
#define OMINULL_CAPS_WINDOWS_END OMINULL_CAPS_WINDOWS_TERMINAL_CLOSE OMINULL_CAPS_WINDOWS_SCREEN "}"

#endif
