#include "../include/agent.h"

static SERVICE_STATUS g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE g_StopEvent = NULL;
static AGENT_CONFIG g_Config;

static void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            if (g_StopEvent) SetEvent(g_StopEvent);
            break;
        default:
            break;
    }
}

static void RunAgentLoop(AGENT_CONFIG* config) {
    HANDLE hDriver = Driver_Open();
    if (hDriver == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Agent could not connect to Ominull driver. Retrying...\n");
    }

    OMINULL_EVENT eventBatch[64];
    size_t batchCount = 0;
    DWORD lastFlush = GetTickCount();

    printf("[+] Ominull Agent running. Streaming kernel events to Hub: %s\n", config->hub_url);

    while (1) {
        if (g_StopEvent && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        if (hDriver == INVALID_HANDLE_VALUE) {
            Sleep(2000);
            hDriver = Driver_Open();
            continue;
        }

        OMINULL_EVENT ev;
        if (Driver_StreamEvents(hDriver, &ev)) {
            eventBatch[batchCount++] = ev;
            if (config->verbose) {
                printf("[EVENT] Type: 0x%X Action: %u PID: %llu\n", ev.EventType, ev.Action, (unsigned long long)ev.ProcessId);
            }
        }

        DWORD now = GetTickCount();
        if (batchCount >= 32 || (batchCount > 0 && (now - lastFlush > 1000))) {
            Hub_SendTelemetryBatch(config, eventBatch, batchCount);
            batchCount = 0;
            lastFlush = now;
        }

        Sleep(10); // Low-latency poll
    }

    if (batchCount > 0) {
        Hub_SendTelemetryBatch(config, eventBatch, batchCount);
    }

    if (hDriver != INVALID_HANDLE_VALUE) {
        Driver_Close(hDriver);
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    RunAgentLoop(&g_Config);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void Service_Run(void) {
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {(LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcherA(ServiceTable);
}

bool Service_Install(const char* hubUrl, const char* apiKey) {
    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) {
        return false;
    }

    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --service --hub %s --key %s", binaryPath, hubUrl, apiKey);

    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        fprintf(stderr, "[-] OpenSCManager failed (Error: %lu)\n", GetLastError());
        return false;
    }

    SC_HANDLE schService = CreateServiceA(
        schSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmdLine,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (!schService) {
        DWORD err = GetLastError();
        CloseServiceHandle(schSCManager);
        if (err == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already installed.\n");
            return true;
        }
        fprintf(stderr, "[-] CreateService failed (Error: %lu)\n", err);
        return false;
    }

    printf("[+] Service installed successfully: %s\n", SERVICE_NAME);
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

bool Service_Uninstall(void) {
    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) return false;

    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(schService, SERVICE_CONTROL_STOP, &status);
    BOOL deleted = DeleteService(schService);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    if (deleted) {
        printf("[+] Service uninstalled successfully.\n");
    }
    return deleted ? true : false;
}
