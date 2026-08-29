#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <errno.h>
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

// Service_WriteRecoveryScript drops the script the SCM's last recovery action
// runs. It is generated on every start rather than shipped in the package, so a
// service upgraded in place gets it too, and it is written into the install
// directory because that is the one place only administrators can write - the
// SCM runs it as LocalSystem.
//
// Every line of it has to be safe to run when nothing is wrong. The SCM repeats
// the last configured action once the failure count runs past the end of the
// list, so an unconditional "put the previous binary back", which is what
// shipped through v1.4.1, turns any unrelated failure into a silent downgrade.
// The update.pending guard is what makes the rollback conditional on there
// actually being an update to roll back, and the trailing start is what makes
// the repeat useful rather than merely harmless.
static bool Service_WriteRecoveryScript(const char* installDir, char* outPath, size_t cap) {
    snprintf(outPath, cap, "%s\\ominull-recover.bat", installDir);
    /* Binary mode on purpose: the CRT's text mode would translate each \n in the
     * CRLF pairs below into a second \r, and cmd is not owed that. */
    FILE* f = fopen(outPath, "wb");
    if (!f) return false;
    fprintf(f,
            "@echo off\r\n"
            "rem Generated by the Ominull agent on every start; edits are overwritten.\r\n"
            "rem Run by the SCM as the last service recovery action.\r\n"
            "if exist \"%s\\update.pending\" if exist \"%s\\ominulld.old\" (\r\n"
            "  move /y \"%s\\ominulld.old\" \"%s\\ominulld.exe\"\r\n"
            "  del /q \"%s\\update.pending\"\r\n"
            ")\r\n"
            "\"%%SystemRoot%%\\System32\\sc.exe\" start %s\r\n",
            installDir, installDir, installDir, installDir, installDir, SERVICE_NAME);
    bool ok = (ferror(f) == 0);
    return (fclose(f) == 0) && ok;
}

// Service_EnsureRecovery registers the SCM recovery actions, and does it every
// time the agent starts rather than only at install.
//
// These are the outer net, not the mechanism. Self-update restarts the service
// itself (Service_SpawnRestart below); what the SCM is for here is the case no
// code of ours can cover, a binary so broken it never runs at all. Leaning on
// the SCM for the ordinary restart is what left endpoints stopped after both
// the 1.3.3 -> 1.4.0 and 1.4.0 -> 1.4.1 rolls: the counter these actions are
// indexed by counts every abnormal exit on the host, not just this update's, so
// which action fires is decided by unrelated history.
//
// The reset period is deliberately short for the same reason. At the shipped
// 86400s a single taskkill in the morning still counted against an update in
// the evening; at 900s the list is only ever walked by a service that is
// failing now, which is what it was meant to describe. A binary that cannot
// start walks all three actions in about seventy seconds, well inside it.
//
// Registering this only at install time would have left every service upgraded
// in place without any of it: CreateService returns ERROR_SERVICE_EXISTS on an
// already-installed service, so --install never reaches the configuration.
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

    char sysDir[MAX_PATH];
    if (!GetSystemDirectoryA(sysDir, MAX_PATH)) {
        snprintf(sysDir, sizeof(sysDir), "C:\\Windows\\System32");
    }

    // The last action recovers from outside the process. Both the script and
    // the interpreter are named by absolute path: this runs as LocalSystem, and
    // resolving either through PATH would be a place to plant something.
    char script[MAX_PATH], rollback[MAX_PATH * 2];
    if (!Service_WriteRecoveryScript(installDir, script, sizeof(script))) {
        fprintf(stderr, "[!] Could not write the recovery script in %s (errno %d); "
                        "a failed update will not roll itself back.\n", installDir, errno);
        script[0] = '\0';
    }
    snprintf(rollback, sizeof(rollback), "%s\\cmd.exe /c call \"%s\"", sysDir, script);

    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;     actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;     actions[1].Delay = 5000;
    actions[2].Type = script[0] ? SC_ACTION_RUN_COMMAND : SC_ACTION_RESTART;
    actions[2].Delay = script[0] ? 60000 : 30000;

    SERVICE_FAILURE_ACTIONSA fa;
    ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 900;
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

/* ------------------------------------------------------------------ restart
 *
 * A service cannot restart itself: the process that would issue the start is
 * the one exiting. Through v1.4.1 the agent left that to the SCM's recovery
 * actions, and that was the wrong mechanism for it. Which action the SCM runs
 * is chosen by a per-service failure counter that counts every abnormal exit on
 * the host - a crash, a taskkill, a hung stop - not just this update's, and once
 * it runs past the end of the action list the SCM repeats the last action rather
 * than starting over. On an endpoint with any earlier failure that day the
 * update's own exit landed past the end of the list, so the service installed
 * its new binary and then sat stopped until someone ran "sc start" by hand.
 * That is how both the 1.3.3 -> 1.4.0 and the 1.4.0 -> 1.4.1 rolls ended.
 *
 * The restart is explicit now. Before it exits, the updater launches a detached
 * copy of the installed binary in --restart-service mode; that process outlives
 * the service, waits for the SCM to report it STOPPED, and starts it again.
 * Nothing in that path consults, or is affected by, how many times the service
 * has failed today. The recovery actions stay registered for the one case this
 * cannot cover - a binary too broken to run the helper at all.
 */

#define RESTART_WAIT_MS     120000  /* how long a stop may take before we try anyway */
#define RESTART_POLL_MS     500
#define RESTART_ATTEMPTS    5
#define RESTART_RETRY_MS    3000

bool Service_SpawnRestart(void) {
    char self[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self, MAX_PATH)) return false;

    /* The path is taken from the running module, not built from the install
     * directory, so this restarts whatever binary is actually registered - and
     * after a swap that is the new one, which is the point. */
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof(cmd), "\"%s\" --restart-service", self);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* The helper has to outlive the process that spawned it. DETACHED_PROCESS
     * keeps it off the service's console and CREATE_BREAKAWAY_FROM_JOB keeps it
     * out of a job object that would tear it down with the parent. Not every
     * host puts services in a job, and CreateProcess fails outright when a job
     * forbids breakaway, so a plain detached spawn is the fallback rather than
     * the failure. Handles are not inherited: this process is about to exit and
     * anything it held open would stay open in the child. */
    DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "[!] Could not launch the restart helper (Error: %lu); "
                            "falling back to the SCM recovery actions.\n", GetLastError());
            return false;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[+] Restart helper launched; the service will come back on its own.\n");
    return true;
}

int Service_WaitStoppedAndStart(void) {
    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) {
        fprintf(stderr, "[-] Restart helper: OpenSCManager failed (Error: %lu)\n", GetLastError());
        return 1;
    }
    SC_HANDLE schService = OpenServiceA(schSCManager, SERVICE_NAME,
                                        SERVICE_QUERY_STATUS | SERVICE_START);
    if (!schService) {
        fprintf(stderr, "[-] Restart helper: OpenService failed (Error: %lu)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return 1;
    }

    /* Wait for the service that spawned this helper to actually be gone.
     * StartService against a STOP_PENDING service is refused outright, and a
     * refusal here would leave the endpoint in exactly the state being fixed. */
    SERVICE_STATUS status;
    DWORD waited = 0;
    while (QueryServiceStatus(schService, &status) &&
           status.dwCurrentState != SERVICE_STOPPED &&
           waited < RESTART_WAIT_MS) {
        Sleep(RESTART_POLL_MS);
        waited += RESTART_POLL_MS;
    }

    int rc = 1;
    for (int attempt = 1; attempt <= RESTART_ATTEMPTS; attempt++) {
        if (StartServiceA(schService, 0, NULL)) {
            rc = 0;
            break;
        }
        DWORD err = GetLastError();
        /* The SCM's own recovery restart won the race. That is the outcome we
         * wanted, so it is a success and not something to report as an error. */
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            rc = 0;
            break;
        }
        fprintf(stderr, "[!] Restart helper: start attempt %d of %d failed (Error: %lu)\n",
                attempt, RESTART_ATTEMPTS, err);
        Sleep(RESTART_RETRY_MS);
    }

    if (rc == 0) {
        printf("[+] Restart helper: %s is running again.\n", SERVICE_NAME);
    } else {
        fprintf(stderr, "[-] Restart helper: gave up after %d attempts; the SCM recovery "
                        "actions are the remaining path back.\n", RESTART_ATTEMPTS);
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return rc;
}

bool Service_Install(const AGENT_CONFIG* config) {
    if (!config) return false;

    char binaryPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, binaryPath, MAX_PATH)) {
        return false;
    }

    /* The SCM command line is the only place the service's configuration
     * exists - ServiceMain gets SCM's argv, not this one - so everything the
     * running agent needs has to be written here. It used to carry only the hub
     * URL and the key, which silently dropped the role and location an operator
     * enrolled with; the CA path would have gone the same way, leaving a
     * service that could not verify the hub it was installed to talk to.
     *
     * The quoting matters: a CA path under Program Files contains a space, and
     * an unquoted one would be parsed as two arguments. */
    char cmdLine[MAX_PATH * 4];
    int n = snprintf(cmdLine, sizeof(cmdLine),
                     "\"%s\" --service --hub %s --key %s --role %s --location %s --id %s --ca \"%s\"",
                     binaryPath, config->hub_url, config->api_key,
                     config->role_tag[0] ? config->role_tag : "workstation",
                     config->location_id[0] ? config->location_id : "loc-home",
                     config->endpoint_id, config->ca_path);
    if (n > 0 && (size_t)n < sizeof(cmdLine) &&
        config->cf_client_id[0] && config->cf_client_secret[0]) {
        snprintf(cmdLine + n, sizeof(cmdLine) - n, " --cf-id %s --cf-secret %s",
                 config->cf_client_id, config->cf_client_secret);
    }
    if (config->allow_plaintext) {
        strncat(cmdLine, " --allow-plaintext", sizeof(cmdLine) - strlen(cmdLine) - 1);
    }

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
