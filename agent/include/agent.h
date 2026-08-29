#ifndef OMINULL_AGENT_H
#define OMINULL_AGENT_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../driver/include/ominull_ioctl.h"

#define OMINULL_AGENT_VERSION "1.3.3"
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
    bool is_service;
    bool verbose;
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

// Service dispatcher
void Service_Run(void);
void Service_SetConfig(const AGENT_CONFIG* config);
bool Service_Install(const char* hubUrl, const char* apiKey);
// Registers the SCM recovery actions self-update relies on. Idempotent, and
// applied on every start so an in-place upgrade is not left without them.
void Service_EnsureRecovery(void);
bool Service_Uninstall(void);
void RunAgentLoop(AGENT_CONFIG* config);

#endif // OMINULL_AGENT_H
