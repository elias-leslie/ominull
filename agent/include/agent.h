#ifndef OMINULL_AGENT_H
#define OMINULL_AGENT_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../driver/include/ominull_ioctl.h"

#define OMINULL_AGENT_VERSION "1.0.0"
#define SERVICE_NAME "ominulld"
#define SERVICE_DISPLAY_NAME "Ominull Threat Nullification Service"

typedef struct _AGENT_CONFIG {
    char hub_url[256];
    char api_key[128];
    char endpoint_id[64];
    char hostname[128];
    bool is_service;
    bool verbose;
} AGENT_CONFIG;

// Driver communication interface
HANDLE Driver_Open(void);
void Driver_Close(HANDLE hDevice);
bool Driver_StreamEvents(HANDLE hDevice, OMINULL_EVENT* outEvent);
bool Driver_SetIsolation(HANDLE hDevice, bool enable, uint32_t allowHubIP, uint16_t allowHubPort);

// Hub communication & networking
bool Hub_SendTelemetryBatch(const AGENT_CONFIG* config, const OMINULL_EVENT* events, size_t count);

// Service dispatcher
void Service_Run(void);
bool Service_Install(const char* hubUrl, const char* apiKey);
bool Service_Uninstall(void);

#endif // OMINULL_AGENT_H
