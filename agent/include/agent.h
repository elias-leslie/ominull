#ifndef OMINULL_AGENT_H
#define OMINULL_AGENT_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../driver/include/ominull_ioctl.h"

#define OMINULL_AGENT_VERSION "1.5.0"
#define SERVICE_NAME "ominulld"
#define SERVICE_DISPLAY_NAME "Ominull Threat Nullification Service"

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

// Driver communication interface
HANDLE Driver_Open(void);
void Driver_Close(HANDLE hDevice);
bool Driver_StreamEvents(HANDLE hDevice, OMINULL_EVENT* outEvent);
bool Driver_SetIsolation(HANDLE hDevice, bool enable, uint32_t allowHubIP, uint16_t allowHubPort);

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

// Self-update. Update_Apply installs a newer agent only after verifying it
// against the release key compiled into this binary; Update_CheckStartup runs
// once at startup and restores the previous binary if a new one keeps failing.
void Update_Apply(const AGENT_CONFIG* config, const char* respJson);
void Update_CheckStartup(const AGENT_CONFIG* config);

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
// Splits a hub URL into host, port and scheme. port is WinHTTP's INTERNET_PORT,
// spelled as the WORD it is so this header stays usable without winhttp.h.
void Hub_SplitURL(const char* hubUrl, char* host, size_t hostLen, WORD* port, BOOL* isHttps);

// Service dispatcher
void Service_Run(void);
void Service_SetConfig(const AGENT_CONFIG* config);
// Installs the service with the full running configuration. It takes the whole
// config rather than a hub URL and key because the SCM command line is the only
// place the service's arguments exist: anything left out here - the role, the
// location, the pinned CA - is simply lost at the next start.
bool Service_Install(const AGENT_CONFIG* config);
// Moves an inline --key out of the service command line into a file only
// SYSTEM and Administrators can read, and rewrites the registration to point at
// it. Called on every service start: the binPath is not rewritten by an
// upgrade, so an endpoint enrolled before this existed has to repair itself.
// No-op once config->key_path is set.
void Service_MigrateKeyToFile(const AGENT_CONFIG* config);
// Registers the SCM recovery actions and writes the script the last of them
// runs. Idempotent, and applied on every start so an in-place upgrade is not
// left without them.
void Service_EnsureRecovery(void);
// Self-update's restart path. A service cannot start itself, so the updater
// spawns a detached copy of the installed binary in --restart-service mode
// (Service_SpawnRestart) which waits for the SCM to report the service STOPPED
// and starts it again (Service_WaitStoppedAndStart, the mode's entry point).
// This exists because the SCM recovery actions cannot be relied on for it: the
// failure counter that selects them counts every abnormal exit on the host, so
// which action runs after an update is decided by unrelated history.
bool Service_SpawnRestart(void);
int Service_WaitStoppedAndStart(void);
bool Service_Uninstall(void);
void RunAgentLoop(AGENT_CONFIG* config);

#endif // OMINULL_AGENT_H
