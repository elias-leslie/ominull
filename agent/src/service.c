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

            char hubResponse[4096];
            Hub_SendTelemetryBatch(config, eventBatch, batchCount, hubResponse, sizeof(hubResponse));
            batchCount = 0;
            lastFlush = now;

            // The hub answers with an agent_update descriptor when a newer
            // release is published. Update_Apply verifies it against the
            // pinned release key before anything is installed, and does not
            // return if the swap succeeds.
            Update_Apply(config, hubResponse);
        }

        Sleep(100);
    }

    if (batchCount > 0) {
        Hub_SendTelemetryBatch(config, eventBatch, batchCount, NULL, 0);
    }

    if (hDriver != INVALID_HANDLE_VALUE) {
        Driver_Close(hDriver);
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    // The SCM dispatch arguments are not the service's configuration; that was parsed
    // from the registered binPath in main() and handed over via Service_SetConfig.
    (void)argc;
    (void)argv;
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

// Service_SetConfig hands the command line main() parsed to the SCM entry point.
// ServiceMain cannot parse it itself: the arguments it receives come from the SCM, not
// from the registered binPath, so without this the service ran with an empty hub URL
// and key and could never report telemetry.
void Service_SetConfig(const AGENT_CONFIG* config) {
    // Repair the recovery configuration on every start, so a service that was
    // upgraded in place rather than reinstalled still has what self-update needs.
    Service_EnsureRecovery();
    if (config) {
        g_Config = *config;
        g_Config.is_service = true;
    }
}

void Service_Run(void) {
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {(LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcherA(ServiceTable);
}

// Service_EnsureRecovery registers the SCM recovery actions the self-update
// path depends on, and does it every time the agent starts rather than only at
// install.
//
// A service cannot synchronously stop and start itself, and spawning a detached
// "sc stop && sc start" makes the update depend on a process that is about to be
// killed. Instead the agent exits non-zero after swapping the binary and the SCM
// restarts it from the registered binPath - which still carries this endpoint's
// key and identity, so nothing re-registers the service.
//
// Registering this only at install time would have left every service upgraded
// in place without any of it: CreateService returns ERROR_SERVICE_EXISTS on an
// already-installed service, so --install never reaches the configuration. An
// agent that cannot restart itself cannot finish an update, so this is applied
// on every start and repairs itself.
void Service_EnsureRecovery(void) {
    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) return;

    char installDir[MAX_PATH];
    snprintf(installDir, sizeof(installDir), "%s", binaryPath);
    char* slash = strrchr(installDir, '\\');
    if (slash) *slash = '\0';

    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) return;
    // SERVICE_START is required alongside SERVICE_CHANGE_CONFIG, not optional:
    // the recovery actions include SC_ACTION_RESTART, and the SCM checks that
    // the caller may actually start the service before it will record an action
    // that starts it. Without it ChangeServiceConfig2 fails with
    // ERROR_ACCESS_DENIED even for LocalSystem - OpenService still hands back a
    // perfectly valid handle, so the failure surfaces only at the point of use.
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME,
                                        SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_CONFIG);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return;
    }

    // The third action is the outer safety net: if a new binary is so broken
    // the SCM cannot start it at all, no code of ours ever runs to notice, so
    // the rollback has to come from outside the process.
    char rollback[MAX_PATH * 2];
    snprintf(rollback, sizeof(rollback),
             "cmd.exe /c move /y \"%s\\ominulld.old\" \"%s\\ominulld.exe\"", installDir, installDir);

    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;     actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;     actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RUN_COMMAND; actions[2].Delay = 60000;

    SERVICE_FAILURE_ACTIONSA fa;
    ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 86400;
    fa.lpCommand = rollback;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
        fprintf(stderr, "[!] Could not register service recovery actions (Error: %lu); "
                        "self-update will install but not restart itself.\n", GetLastError());
    }

    // Without this flag the SCM applies recovery only to crashes, not to a
    // clean non-zero exit - which is exactly how the updater signals that the
    // binary has been replaced.
    SERVICE_FAILURE_ACTIONS_FLAG faFlag;
    faFlag.fFailureActionsOnNonCrashFailures = TRUE;
    ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &faFlag);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
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
            // Still apply the recovery configuration. Returning here without it
            // is how an in-place upgrade ends up with a service that installs
            // updates but can never restart into them.
            printf("[*] Service already installed.\n");
            Service_EnsureRecovery();
            return true;
        }
        fprintf(stderr, "[-] CreateService failed (Error: %lu)\n", err);
        return false;
    }

    Service_EnsureRecovery();

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
