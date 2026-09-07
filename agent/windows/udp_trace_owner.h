#ifndef OMINULL_UDP_TRACE_OWNER_H
#define OMINULL_UDP_TRACE_OWNER_H
#include <sddl.h>
#include <bcrypt.h>
#ifndef OMINULL_UDP_OWNER
#define OMINULL_UDP_OWNER L"Agent"
#endif
/* ETW sessions survive a controller crash. A protected ownership record and
 * process creation time permit recovery of exactly our abandoned session.
 * A matching name alone never authorizes stopping somebody else's trace. */
typedef struct {
    DWORD version, pid;
    UINT64 created;
    GUID guid;
    WCHAR name[80];
} UDP_TRACE_OWNER;
static HANDLE g_UDPTraceMutex;
static HKEY g_UDPTraceKey;
static bool g_UDPTraceLocked, g_UDPTraceRecorded;
static UINT64 UDPTraceTime(FILETIME time) { return ((UINT64)time.dwHighDateTime << 32) | time.dwLowDateTime; }
static void UDPTraceRelease(bool stopped) {
    if (g_UDPTraceKey) {
        if (stopped && g_UDPTraceRecorded)
            RegDeleteValueW(g_UDPTraceKey, L"Session");
        RegCloseKey(g_UDPTraceKey);
        g_UDPTraceKey = NULL;
    }
    g_UDPTraceRecorded = false;
    if (g_UDPTraceMutex) {
        if (g_UDPTraceLocked)
            ReleaseMutex(g_UDPTraceMutex);
        CloseHandle(g_UDPTraceMutex);
        g_UDPTraceMutex = NULL;
        g_UDPTraceLocked = false;
    }
}
static DWORD UDPTraceClaim(EVENT_TRACE_PROPERTIES *properties, const WCHAR *name) {
    WCHAR mutexName[80], keyName[80];
    swprintf(mutexName, 80, L"Global\\Ominull-UDP-Owner-%ls", OMINULL_UDP_OWNER);
    swprintf(keyName, 80, L"SOFTWARE\\Ominull\\UDPTrace-%ls", OMINULL_UDP_OWNER);
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                              &descriptor, NULL))
        return GetLastError();
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    g_UDPTraceMutex = CreateMutexW(&security, FALSE, mutexName);
    if (!g_UDPTraceMutex) {
        DWORD error = GetLastError();
        LocalFree(descriptor);
        return error;
    }
    DWORD wait = WaitForSingleObject(g_UDPTraceMutex, 0);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        LocalFree(descriptor);
        return ERROR_ALREADY_EXISTS;
    }
    g_UDPTraceLocked = true;
    DWORD status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyName, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
                                   &security, &g_UDPTraceKey, NULL);
    LocalFree(descriptor);
    if (status != ERROR_SUCCESS)
        return status;
    UDP_TRACE_OWNER previous = {0};
    DWORD type = 0, length = sizeof(previous);
    status = RegQueryValueExW(g_UDPTraceKey, L"Session", NULL, &type, (BYTE *)&previous, &length);
    if (status == ERROR_SUCCESS) {
        if (type != REG_BINARY || length != sizeof(previous) || previous.version != 1 ||
            previous.name[79] != 0 || wcsncmp(previous.name, L"Ominull-UDP-", 12))
            return ERROR_INVALID_DATA;
        HANDLE controller = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, previous.pid);
        if (controller) {
            FILETIME created, exit, kernel, user;
            BOOL known = GetProcessTimes(controller, &created, &exit, &kernel, &user);
            DWORD state = WaitForSingleObject(controller, 0);
            CloseHandle(controller);
            if (!known || state == WAIT_FAILED ||
                (state != WAIT_OBJECT_0 && UDPTraceTime(created) == previous.created))
                return ERROR_ALREADY_EXISTS;
        } else if (GetLastError() != ERROR_INVALID_PARAMETER)
            return ERROR_ACCESS_DENIED;
        struct {
            EVENT_TRACE_PROPERTIES p;
            WCHAR strings[340];
        } old = {0};
        old.p.Wnode.BufferSize = sizeof(old);
        status = ControlTraceW(0, previous.name, &old.p, EVENT_TRACE_CONTROL_QUERY);
        if (status == ERROR_SUCCESS) {
            if (memcmp(&old.p.Wnode.Guid, &previous.guid, sizeof(GUID)))
                return ERROR_INVALID_DATA;
            status = ControlTraceW(0, previous.name, &old.p, EVENT_TRACE_CONTROL_STOP);
        }
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND)
            return status;
        RegDeleteValueW(g_UDPTraceKey, L"Session");
    } else if (status != ERROR_FILE_NOT_FOUND)
        return status;
    UDP_TRACE_OWNER owner = {0};
    owner.version = 1;
    owner.pid = GetCurrentProcessId();
    FILETIME created, exit, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exit, &kernel, &user))
        return GetLastError();
    owner.created = UDPTraceTime(created);
    if (BCryptGenRandom(NULL, (PUCHAR)&owner.guid, sizeof(owner.guid), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return ERROR_GEN_FAILURE;
    wcsncpy(owner.name, name, 79);
    properties->Wnode.Guid = owner.guid;
    status = RegSetValueExW(g_UDPTraceKey, L"Session", 0, REG_BINARY, (const BYTE *)&owner, sizeof(owner));
    if (status == ERROR_SUCCESS)
        g_UDPTraceRecorded = true;
    return status;
}
#endif
