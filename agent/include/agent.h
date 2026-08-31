#ifndef OMINULL_AGENT_H
#define OMINULL_AGENT_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define OMINULL_AGENT_VERSION "1.7.24"
#define OMINULL_MAX_PATH 260
#define SERVICE_NAME "ominulld"
#define SERVICE_DISPLAY_NAME "Ominull Threat Nullification Service"
#define OMINULL_DEFAULT_CONFIG_PATH "C:\\ProgramData\\Ominull\\agent.conf"
#define OMINULL_DEFAULT_KEY_PATH "C:\\ProgramData\\Ominull\\agent.key"

typedef struct _AGENT_CONFIG {
    char hub_url[256];
    char api_key[128];
    char endpoint_id[64];
    char hostname[128];
    char location_id[64];
    char role_tag[64];
    char cf_client_id[128];
    char cf_client_secret[128];
    char primary_ip[64];
    char primary_mac[32];
    char os_version[128];
    /* The hub's CA, planted by enrolment. Every hub connection is verified
     * against this file, so it lives beside the binary rather than under a
     * path an upgrade replaces. */
    char ca_path[260];
    char config_path[260];
    char install_type[16];
    char package_identifier[64];
    char registered_package_version[64];
    char provenance_status[16];
    /* Where api_key was read from, when it came from a file rather than the
     * command line. Set, it is what the service registration carries; empty,
     * the key is still inline and Service_MigrateKeyToFile will move it. */
    char key_path[260];
    /* This endpoint's own certificate and key as a PKCS#12 archive, planted by
     * enrolment. Presented on every hub connection so the hub can tell which
     * endpoint is reporting; the API key alone only proves tenant membership. */
    char client_pfx_path[260];
    bool is_service;
    bool verbose;
    /* Opt-in to a cleartext hub. Off by default: without it the agent refuses
     * an http:// hub rather than putting the API key on the wire. */
    bool allow_plaintext;
} AGENT_CONFIG;

/* Versioned user-mode collection record. It is shared by the Linux socket
 * collector and Windows socket-table collector; neither platform claims a
 * privileged event stream. */
#define OMINULL_EVENT_CONNECT_V4          1
#define OMINULL_EVENT_CONNECT_V6          2
#define OMINULL_EVENT_RECV_ACCEPT_V4      3
#define OMINULL_EVENT_RECV_ACCEPT_V6      4
#define OMINULL_EVENT_FLOW_ESTABLISHED_V4 5
#define OMINULL_EVENT_FLOW_ESTABLISHED_V6 6
#define OMINULL_EVENT_FLOW_CLOSED         7
#define OMINULL_EVENT_BLOCKED             8

#pragma pack(push, 1)
typedef struct _OMINULL_EVENT {
    UINT64 Timestamp;
    UINT32 EventType;
    UINT32 Action;
    UINT64 ProcessId;
    UINT8  IpVersion;
    UINT8  Protocol;
    UINT8  Direction;
    UINT8  Reserved;
    UINT16 LocalPort;
    UINT16 RemotePort;
    union {
        struct { UINT32 LocalIp; UINT32 RemoteIp; } Ipv4;
        struct { UINT8 LocalIp[16]; UINT8 RemoteIp[16]; } Ipv6;
    } Addr;
    UINT64 FlowId;
    WCHAR  ProcessPath[OMINULL_MAX_PATH];
    UINT64 BytesIn;
    UINT64 BytesOut;
} OMINULL_EVENT, *POMINULL_EVENT;
#pragma pack(pop)

/* The user-mode filtering engine, in agent/windows/wfp_user.c. It is what
 * enforces isolation in the user-mode Windows Filtering Platform. Linked into
 * the agent as well as built as the standalone ominull_wfp_user.exe recovery
 * tool. */
DWORD Wfp_Init(int dynamicSession);
void Wfp_Close(void);

/* The baseline isolation policy, as the hub resolves it for this endpoint: what
 * an isolated host is still permitted to reach, already expanded to destination,
 * protocol and remote port so nothing is left for an agent to interpret.
 *
 * It replaces two permits that used to be compiled in - DNS to any resolver and
 * DHCP to any server - which were holes with a justification attached, and were
 * invisible to whoever clicked Isolate. The hub pinhole and loopback stay
 * compiled in: they are what make an isolation reversible, and an allow-list
 * someone can empty by accident is a way to lose a host. */
#define OMINULL_MAX_BASELINE_RULES 64

typedef struct {
    char service[16];       /* dns, dhcp, ntp, custom - decides precedence only */
    char destination[64];
    char protocol[8];       /* udp or tcp */
    int  port;              /* the remote port, in both directions */
} OMINULL_BASELINE_RULE;

/* baselineKnown distinguishes a hub that sent no policy from a hub whose policy
 * is empty. The first keeps the compiled-in permits - tightening the floor under
 * a fleet whose hub never asked for it would cut hosts off during a hub upgrade.
 * The second means hub and loopback only, and is obeyed. */
DWORD Wfp_ApplyState(const char* hubIpStr, int isolate,
                     const char* const* blockedIPs, int blockedCount,
                     const char* const* allowIPs, int allowCount,
                     const OMINULL_BASELINE_RULE* baseline, int baselineCount,
                     int baselineKnown);

/* Agent_EnforcementStatus is "ok" or the reason this host could not apply
 * isolation rules if it were asked to. Reported on every heartbeat: the hub
 * refuses to isolate an endpoint that says it cannot enforce, because that
 * isolation would be a default-deny with nothing underneath it.
 *
 * Agent_LastAppliedNote carries anything the agent needs to say about the state
 * it is actually in - notably that the dead-man timer released an isolation the
 * hub had stopped answering for. */
const char* Agent_EnforcementStatus(void);
const char* Agent_LastAppliedNote(void);

/* Reduces the configured hub URL to an address literal. Shared rather than
 * copied: this is the address the pinhole is written for, and the readiness
 * report claims the same one - two implementations of it would eventually
 * disagree, and the disagreement would only show up on a host that had already
 * been cut off. Returns false when the URL will not reduce, which is the state
 * that makes an isolation irreversible and is reported as such. */
bool HubAddressLiteral(const AGENT_CONFIG* config, char* out, size_t cap);

// Hub communication & networking.
//
// The hub answers a telemetry POST with the agent_update descriptor, which is
// how the agent learns a release exists at all. respOut receives that response
// body (truncated to respCap) so the caller can act on it; pass NULL to ignore.
bool Hub_SendTelemetryBatch(const AGENT_CONFIG* config, const OMINULL_EVENT* events, size_t count,
                            char* respOut, size_t respCap);

// Fills primary_ip, primary_mac and os_version from the running system. Called
// once at startup: the hub keys asset identity on the hardware address, so
// these have to be observed rather than assumed. Any field that cannot be
// determined is left empty, which the hub treats as "unknown" instead of
// recording a guess as ground truth.
void Agent_DetectHostIdentity(AGENT_CONFIG* config);
void Agent_DetectInstallProvenance(AGENT_CONFIG* config);

// Self-update. Update_Apply verifies the signed MSI and delegates replacement
// and rollback to Windows Installer.
void Update_Apply(const AGENT_CONFIG* config, const char* respJson);
int Update_RunNativeInstaller(const char* packagePath);

/* Hub transport security. Hub_TransportReady gates every outbound request:
 * it refuses a cleartext hub, refuses a missing CA, and proves the peer really
 * is the hub before anything carrying the API key is sent. Hub_VerifyRequestPin
 * re-checks the certificate on a request that has already been answered, so a
 * response from anything but the enrolled hub is discarded rather than acted
 * on. Both are no-ops when a cleartext transport was explicitly allowed.
 * Rationale and the reason the check is a preflight: agent/src/hub_tls.c. */
bool Hub_TransportReady(const AGENT_CONFIG* config);
bool Hub_VerifyRequestPin(void* hRequest, const AGENT_CONFIG* config);
bool Hub_UsesTLS(const AGENT_CONFIG* config);
// Attaches this endpoint's client certificate to a request before it is sent.
// Returns false when there is none, which is not an error: the agent then
// reports under the API key alone and the hub decides whether to accept that.
bool Hub_AttachClientCert(void* hRequest, const AGENT_CONFIG* config);
// True once a client certificate has been loaded and attached to a request.
bool Hub_HasClientCert(void);
// Answers a certificate request that arrived after the send. Returns true when
// err was ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED and the request has been told
// there is no certificate, so the caller should send it once more.
bool Hub_RetryWithoutClientCert(void* hRequest, unsigned long err);
// Splits a hub URL into host, port and scheme. port is WinHTTP's INTERNET_PORT,
// spelled as the WORD it is so this header stays usable without winhttp.h.
void Hub_SplitURL(const char* hubUrl, char* host, size_t hostLen, WORD* port, BOOL* isHttps);

// Service dispatcher
void Service_Run(void);
void Service_SetConfig(const AGENT_CONFIG* config);
// Reads enrollment fields from stdin and writes package-owned configuration
// and private material without putting the tenant key in process arguments.
bool Service_ConfigureFromStdin(void);
// Installs the service with the full running configuration. It takes the whole
// config rather than a hub URL and key because the SCM command line is the only
// place the service's arguments exist: anything left out here - the role, the
// location, the pinned CA - is simply lost at the next start.
// Moves an inline --key out of the service command line into a file only
// SYSTEM and Administrators can read, and rewrites the registration to point at
// it. Called on every service start: the binPath is not rewritten by an
// upgrade, so an endpoint enrolled before this existed has to repair itself.
// No-op once config->key_path is set.
void Service_MigrateKeyToFile(const AGENT_CONFIG* config);
// Registers the package-owned service's SCM recovery actions. Idempotent, and
// applied on every start so an in-place upgrade is not left without them.
void Service_EnsureRecovery(void);
void RunAgentLoop(AGENT_CONFIG* config);

#endif // OMINULL_AGENT_H
