#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
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

static size_t PollActiveSocketFlows(OMINULL_EVENT* outEvents, size_t maxEvents) {
    size_t count = 0;
    DWORD dwSize = 0;

    DWORD ret = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
        PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pTcpTable) {
            if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries && count < maxEvents; i++) {
                    MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
                    if (row.dwRemoteAddr == 0 || row.dwRemotePort == 0) continue;

                    OMINULL_EVENT* ev = &outEvents[count];
                    memset(ev, 0, sizeof(OMINULL_EVENT));
                    ev->EventType = OMINULL_EVENT_FLOW_ESTABLISHED_V4;
                    ev->Action = 0; // Permit
                    ev->Direction = 1; // Outbound
                    ev->Protocol = IPPROTO_TCP;
                    ev->IpVersion = 4;
                    ev->ProcessId = row.dwOwningPid;
                    ev->LocalPort = ntohs((u_short)row.dwLocalPort);
                    ev->RemotePort = ntohs((u_short)row.dwRemotePort);
                    ev->Addr.Ipv4.LocalIp = ntohl(row.dwLocalAddr);
                    ev->Addr.Ipv4.RemoteIp = ntohl(row.dwRemoteAddr);

                    wcscpy(ev->ProcessPath, L"C:\\Windows\\System32\\ntoskrnl.exe");
                    if (row.dwOwningPid > 4) {
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.dwOwningPid);
                        if (hProc) {
                            DWORD pathLen = OMINULL_MAX_PATH;
                            if (QueryFullProcessImageNameW(hProc, 0, ev->ProcessPath, &pathLen)) {
                                ev->ProcessPath[OMINULL_MAX_PATH - 1] = L'\0';
                            }
                            CloseHandle(hProc);
                        }
                    }
                    count++;
                }
            }
            free(pTcpTable);
        }
    }
    return count;
}

void RunAgentLoop(AGENT_CONFIG* config) {
    HANDLE hDriver = Driver_Open();
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[*] Ominull kernel driver not present. Operating in User-Mode High-Fidelity Flow Mode.\n");
    } else {
        printf("[+] Connected to Ominull WFP kernel driver.\n");
    }

    OMINULL_EVENT eventBatch[64];
    size_t batchCount = 0;
    DWORD lastFlush = GetTickCount();

    printf("[+] Ominull Agent running. Streaming network flows to Hub: %s\n", config->hub_url);

    while (1) {
        if (g_StopEvent && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        // 1. Collect driver events if connected
        if (hDriver != INVALID_HANDLE_VALUE) {
            OMINULL_EVENT ev;
            while (Driver_StreamEvents(hDriver, &ev) && batchCount < 48) {
                eventBatch[batchCount++] = ev;
                if (config->verbose) {
                    printf("[DRIVER EVENT] Type: 0x%lX Action: %lu PID: %llu\n", (unsigned long)ev.EventType, (unsigned long)ev.Action, (unsigned long long)ev.ProcessId);
                }
            }
        }

        // 2. Poll live socket table flows
        DWORD now = GetTickCount();
        if (now - lastFlush >= 2500) {
            size_t socketCount = PollActiveSocketFlows(eventBatch + batchCount, 64 - batchCount);
            batchCount += socketCount;

            Hub_SendTelemetryBatch(config, eventBatch, batchCount);
            batchCount = 0;
            lastFlush = now;
        }

        Sleep(100);
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
