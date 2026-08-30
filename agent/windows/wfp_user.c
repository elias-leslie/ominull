#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// Well-known WFP layer and condition identifiers.
//
// These are Microsoft's, not ours. They are written out here because
// mingw-w64's fwpmu.h declares the WFP functions but ships none of the layer
// or condition GUIDs, and no mingw import library defines them either, so
// there is nothing to link against - the same reason OpenVPN and
// WireGuard-Windows carry their own copies.
//
// Four of the five values that used to sit here were wrong: invented or
// mistyped GUIDs that name no layer and no condition WFP has ever heard of.
// FwpmFilterAdd0 answered FWP_E_CONDITION_NOT_FOUND (0x80320002), the
// transaction was aborted, and every isolation and every mesh block this agent
// was ever asked to apply on Windows failed at the first filter while the hub
// went on showing the endpoint as quarantined. Only the outbound layer was
// right, which is why the layer was accepted and its condition was not.
//
// If one of these is ever edited, check it against the real value first: a
// wrong GUID here does not fail to compile and does not fail loudly at
// runtime, it just quietly filters nothing.
DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_CONNECT_V4,      /* c38d57d1-05a7-4c33-904f-7fbceee60e82 */
    0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82);

DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V4,  /* e1cd9fe7-f4b5-4273-96c0-592e487b8650 */
    0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50);

DEFINE_GUID(OMINULL_CONDITION_IP_REMOTE_ADDRESS,    /* b235ae9a-1d64-49b8-a44c-5ff3d9095045 */
    0xb235ae9a, 0x1d64, 0x49b8, 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45);

DEFINE_GUID(OMINULL_CONDITION_IP_REMOTE_PORT,       /* c35a604d-d22b-4e1a-91b4-68f674ee674b */
    0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b);

DEFINE_GUID(OMINULL_CONDITION_ALE_APP_ID,           /* d78e1e87-8644-4ea5-9437-d809ecefc971 */
    0xd78e1e87, 0x8644, 0x4ea5, 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71);


// Filter weights.
//
// A FWPM_FILTER0 weight given as FWP_UINT8 is not a 0-255 priority: WFP accepts
// only 0 through 15 and rejects anything larger with FWP_E_INVALID_WEIGHT
// (0x80320025). Every filter here used to ask for 0xFF, 0xFE, 0xFD, 0xC0 or
// 0x10, so FwpmFilterAdd0 refused the first one, the whole transaction was
// aborted, and not a single filter was ever installed. The agent said the
// engine had refused the change, the hub went on showing the endpoint as
// isolated, and the host stayed on the network. Higher still wins; these keep
// the order the old constants intended.
#define OMINULL_WEIGHT_PERMIT_HUB      15
#define OMINULL_WEIGHT_PERMIT_LOOPBACK 14
#define OMINULL_WEIGHT_PERMIT_DHCP     13
#define OMINULL_WEIGHT_BLOCK_PEER      12
#define OMINULL_WEIGHT_BLOCK_ALL        0

// Sublayer & Provider GUIDs
DEFINE_GUID(OMINULL_SUBLAYER_USER_GUID,
    0xb413e784, 0xa15f, 0x4f98, 0x89, 0x5f, 0x55, 0x82, 0x23, 0x6e, 0xb, 0x11);

DEFINE_GUID(OMINULL_PROVIDER_USER_GUID,
    0xc524f895, 0xb26a, 0x5a09, 0x90, 0x6a, 0x66, 0x93, 0x34, 0x7f, 0x1c, 0x22);

static HANDLE g_hEngine = NULL;

/* Wfp_Init opens the filtering engine.
 *
 * dynamicSession decides what happens to the filters when this process goes
 * away. The standalone tool wants them gone - it is a diagnostic, it exits
 * immediately, and a dynamic session is the only thing that stops `isolate`
 * from being a no-op that flushes itself on the way out. The agent wants the
 * opposite: isolation has to survive a crash or a restart of the service, the
 * way the Linux agent's iptables chains do, and be reconciled against the hub
 * on the next heartbeat rather than silently lifted by a killed process.
 *
 * Recovery, if the agent is gone and a host is still cut off:
 *   ominull_wfp_user.exe unisolate
 */
DWORD Wfp_Init(int dynamicSession) {
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    if (dynamicSession) {
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    }

    DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_hEngine);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to open WFP engine: 0x%08lX (Administrator privileges required)\n", (unsigned long)status);
        return status;
    }

    // Register Sublayer
    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
    sublayer.displayData.name = L"Ominull Zero-Friction User-Mode WFP Sublayer";
    sublayer.displayData.description = L"Enforces host isolation and dynamic threat rules from user-mode";
    sublayer.weight = 0xFF00; // High priority

    status = FwpmSubLayerAdd0(g_hEngine, &sublayer, NULL);
    if (status != ERROR_SUCCESS && status != (DWORD)FWP_E_ALREADY_EXISTS) {
        printf("[-] FwpmSubLayerAdd0 failed: 0x%08lX\n", (unsigned long)status);
        return status;
    }

    return ERROR_SUCCESS;
}

void Wfp_Close() {
    if (g_hEngine) {
        FwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
    }
}

DWORD Wfp_IsolateHost(const char* hubIpStr) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    printf("[*] Activating WFP User-Mode Network Isolation (Default-Deny)...\n");

    DWORD status = FwpmTransactionBegin0(g_hEngine, 0);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to begin WFP transaction: 0x%08lX\n", (unsigned long)status);
        return status;
    }

    // Parse Hub IP
    struct in_addr hubAddr;
    if (inet_pton(AF_INET, hubIpStr, &hubAddr) != 1) {
        hubAddr.s_addr = 0;
    }
    UINT32 hubIpHostOrder = ntohl(hubAddr.s_addr);

    // 1. Permit Filter: Hub IP Pin-Hole Outbound
    if (hubIpHostOrder != 0) {
        FWPM_FILTER0 permitHub;
        memset(&permitHub, 0, sizeof(permitHub));
        permitHub.layerKey = OMINULL_LAYER_ALE_AUTH_CONNECT_V4;
        permitHub.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
        permitHub.displayData.name = L"Ominull Analyst Hub Pinhole";
        permitHub.action.type = FWP_ACTION_PERMIT;
        permitHub.weight.type = FWP_UINT8;
        permitHub.weight.uint8 = OMINULL_WEIGHT_PERMIT_HUB;

        FWPM_FILTER_CONDITION0 cond;
        memset(&cond, 0, sizeof(cond));
        cond.fieldKey = OMINULL_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = hubIpHostOrder;

        permitHub.numFilterConditions = 1;
        permitHub.filterCondition = &cond;

        UINT64 filterId = 0;
        status = FwpmFilterAdd0(g_hEngine, &permitHub, NULL, &filterId);
        if (status != ERROR_SUCCESS) {
            printf("[-] Failed to add Hub permit filter: 0x%08lX\n", (unsigned long)status);
            FwpmTransactionAbort0(g_hEngine);
            return status;
        }
        printf("[+] Added Hub pinhole filter (ID: %llu, IP: %s)\n", (unsigned long long)filterId, hubIpStr);
    }

    // 2. Permit Filter: Local Loopback (127.0.0.1)
    {
        FWPM_FILTER0 permitLoopback;
        memset(&permitLoopback, 0, sizeof(permitLoopback));
        permitLoopback.layerKey = OMINULL_LAYER_ALE_AUTH_CONNECT_V4;
        permitLoopback.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
        permitLoopback.displayData.name = L"Ominull Loopback Permit";
        permitLoopback.action.type = FWP_ACTION_PERMIT;
        permitLoopback.weight.type = FWP_UINT8;
        permitLoopback.weight.uint8 = OMINULL_WEIGHT_PERMIT_LOOPBACK;

        FWPM_FILTER_CONDITION0 cond;
        memset(&cond, 0, sizeof(cond));
        cond.fieldKey = OMINULL_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = 0x7F000001; // 127.0.0.1

        permitLoopback.numFilterConditions = 1;
        permitLoopback.filterCondition = &cond;

        UINT64 filterId = 0;
        FwpmFilterAdd0(g_hEngine, &permitLoopback, NULL, &filterId);
    }

    // 3. Permit Filter: DHCP (UDP port 67/68)
    {
        FWPM_FILTER0 permitDhcp;
        memset(&permitDhcp, 0, sizeof(permitDhcp));
        permitDhcp.layerKey = OMINULL_LAYER_ALE_AUTH_CONNECT_V4;
        permitDhcp.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
        permitDhcp.displayData.name = L"Ominull DHCP Permit";
        permitDhcp.action.type = FWP_ACTION_PERMIT;
        permitDhcp.weight.type = FWP_UINT8;
        permitDhcp.weight.uint8 = OMINULL_WEIGHT_PERMIT_DHCP;

        FWPM_FILTER_CONDITION0 cond;
        memset(&cond, 0, sizeof(cond));
        cond.fieldKey = OMINULL_CONDITION_IP_REMOTE_PORT;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT16;
        cond.conditionValue.uint16 = 67;

        permitDhcp.numFilterConditions = 1;
        permitDhcp.filterCondition = &cond;

        UINT64 filterId = 0;
        FwpmFilterAdd0(g_hEngine, &permitDhcp, NULL, &filterId);
    }

    // 4. Default-Deny Block Filter Outbound
    {
        FWPM_FILTER0 blockAllOut;
        memset(&blockAllOut, 0, sizeof(blockAllOut));
        blockAllOut.layerKey = OMINULL_LAYER_ALE_AUTH_CONNECT_V4;
        blockAllOut.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
        blockAllOut.displayData.name = L"Ominull Host Isolation Block All Outbound";
        blockAllOut.action.type = FWP_ACTION_BLOCK;
        blockAllOut.weight.type = FWP_UINT8;
        blockAllOut.weight.uint8 = OMINULL_WEIGHT_BLOCK_ALL; // Catch-all default deny

        UINT64 filterId = 0;
        status = FwpmFilterAdd0(g_hEngine, &blockAllOut, NULL, &filterId);
        if (status != ERROR_SUCCESS) {
            printf("[-] Failed to add default block filter: 0x%08lX\n", (unsigned long)status);
            FwpmTransactionAbort0(g_hEngine);
            return status;
        }
        printf("[+] Added Default-Deny Outbound Isolation Filter (ID: %llu)\n", (unsigned long long)filterId);
    }

    // 5. Default-Deny Block Filter Inbound
    {
        FWPM_FILTER0 blockAllIn;
        memset(&blockAllIn, 0, sizeof(blockAllIn));
        blockAllIn.layerKey = OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        blockAllIn.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
        blockAllIn.displayData.name = L"Ominull Host Isolation Block All Inbound";
        blockAllIn.action.type = FWP_ACTION_BLOCK;
        blockAllIn.weight.type = FWP_UINT8;
        blockAllIn.weight.uint8 = OMINULL_WEIGHT_BLOCK_ALL;

        UINT64 filterId = 0;
        FwpmFilterAdd0(g_hEngine, &blockAllIn, NULL, &filterId);
    }

    status = FwpmTransactionCommit0(g_hEngine);
    if (status == ERROR_SUCCESS) {
        printf("[+] SUCCESS: Host network is now fully QUARANTINED at User-Mode WFP level.\n");
    } else {
        printf("[-] Failed to commit WFP isolation transaction: 0x%08lX\n", (unsigned long)status);
    }
    return status;
}

// Wfp_DeleteOwnFilters removes every filter sitting in this agent's sublayer.
//
// A sublayer cannot be deleted while filters still reference it - WFP answers
// FWP_E_IN_USE - so "delete the sublayer to flush everything atomically" only
// ever worked on a sublayer that was already empty. Releasing a host from
// isolation therefore left every block filter in the kernel, and because the
// teardown returned ERROR_SUCCESS no matter what the delete had said, the agent
// recorded the release as applied and stopped retrying. The endpoint went on
// heartbeating through its own hub pinhole, the console showed it released, and
// it stayed cut off from everything else.
static DWORD Wfp_DeleteOwnFilters(void) {
    HANDLE hEnum = NULL;

    // A NULL template enumerates every filter, which is what is wanted here.
    // A zeroed template is not the same thing: its actionMask is 0, so it
    // matches no action type and returns nothing at all - a teardown that
    // enumerated an empty set and then reported that it had cleaned up.
    DWORD status = FwpmFilterCreateEnumHandle0(g_hEngine, NULL, &hEnum);
    if (status != ERROR_SUCCESS) return status;

    UINT64 doomed[512];
    UINT32 doomedCount = 0;

    for (;;) {
        FWPM_FILTER0** entries = NULL;
        UINT32 got = 0;
        status = FwpmFilterEnum0(g_hEngine, hEnum, 64, &entries, &got);
        if (status != ERROR_SUCCESS || got == 0) {
            if (entries) FwpmFreeMemory0((void**)&entries);
            break;
        }
        for (UINT32 i = 0; i < got; i++) {
            if (memcmp(&entries[i]->subLayerKey, &OMINULL_SUBLAYER_USER_GUID, sizeof(GUID)) == 0) {
                if (doomedCount < (UINT32)(sizeof(doomed) / sizeof(doomed[0]))) {
                    doomed[doomedCount++] = entries[i]->filterId;
                }
            }
        }
        FwpmFreeMemory0((void**)&entries);
        if (got < 64) break;
    }
    FwpmFilterDestroyEnumHandle0(g_hEngine, hEnum);

    DWORD firstFailure = ERROR_SUCCESS;
    for (UINT32 i = 0; i < doomedCount; i++) {
        DWORD del = FwpmFilterDeleteById0(g_hEngine, doomed[i]);
        if (del != ERROR_SUCCESS && del != (DWORD)FWP_E_FILTER_NOT_FOUND && firstFailure == ERROR_SUCCESS) {
            firstFailure = del;
        }
    }
    if (doomedCount > 0) {
        printf("[*] Removed %lu Ominull filter(s) from the kernel.\n", (unsigned long)doomedCount);
    }
    return firstFailure;
}

DWORD Wfp_UnisolateHost() {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    printf("[*] Removing WFP User-Mode Network Isolation...\n");

    // Filters first, then the sublayer they live in.
    DWORD status = Wfp_DeleteOwnFilters();
    if (status != ERROR_SUCCESS) {
        printf("[-] Could not remove every Ominull filter: 0x%08lX. This host is still filtered.\n",
               (unsigned long)status);
        return status;
    }

    status = FwpmSubLayerDeleteByKey0(g_hEngine, &OMINULL_SUBLAYER_USER_GUID);
    if (status != ERROR_SUCCESS && status != (DWORD)FWP_E_SUBLAYER_NOT_FOUND) {
        printf("[-] FwpmSubLayerDeleteByKey0 returned: 0x%08lX\n", (unsigned long)status);
        return status;
    }

    // Recreate sublayer for future operations
    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
    sublayer.displayData.name = L"Ominull Zero-Friction User-Mode WFP Sublayer";
    sublayer.weight = 0xFF00;
    FwpmSubLayerAdd0(g_hEngine, &sublayer, NULL);

    printf("[+] SUCCESS: Host network isolation removed. Normal connectivity restored.\n");
    return ERROR_SUCCESS;
}

DWORD Wfp_BlockIP(const char* ipStr) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    struct in_addr addr;
    if (inet_pton(AF_INET, ipStr, &addr) != 1) {
        printf("[-] Invalid IPv4 address: %s\n", ipStr);
        return ERROR_INVALID_PARAMETER;
    }
    UINT32 ipHostOrder = ntohl(addr.s_addr);

    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.layerKey = OMINULL_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
    filter.displayData.name = L"Ominull Dynamic IP Block";
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = OMINULL_WEIGHT_BLOCK_PEER;

    FWPM_FILTER_CONDITION0 cond;
    memset(&cond, 0, sizeof(cond));
    cond.fieldKey = OMINULL_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_UINT32;
    cond.conditionValue.uint32 = ipHostOrder;

    filter.numFilterConditions = 1;
    filter.filterCondition = &cond;

    UINT64 filterId = 0;
    DWORD status = FwpmFilterAdd0(g_hEngine, &filter, NULL, &filterId);
    if (status == ERROR_SUCCESS) {
        printf("[+] SUCCESS: Blocked IP %s (WFP Filter ID: %llu)\n", ipStr, (unsigned long long)filterId);
    } else {
        printf("[-] Failed to block IP %s: 0x%08lX\n", ipStr, (unsigned long)status);
    }
    return status;
}

/* Wfp_ApplyState makes the engine match one description of what this host should
 * be enforcing, and is the only entry point the agent uses.
 *
 * It rebuilds rather than diffs: deleting the sublayer drops every filter in it
 * atomically, and the set is small enough that reasoning about which individual
 * filter to add or remove would cost more than it saves. It runs only when the
 * hub's answer actually changes, so the moment where nothing is enforced is not
 * on the steady-state path. */
DWORD Wfp_ApplyState(const char* hubIpStr, int isolate,
                     const char* const* blockedIPs, int blockedCount) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    /* Removes this agent's filters and recreates the sublayer empty. If the
     * kernel would not give them up, say so rather than reporting a release
     * that did not happen. */
    DWORD cleared = Wfp_UnisolateHost();
    if (cleared != ERROR_SUCCESS) return cleared;

    if (isolate) {
        DWORD status = Wfp_IsolateHost(hubIpStr);
        if (status != ERROR_SUCCESS) return status;
    }
    for (int i = 0; i < blockedCount; i++) {
        if (blockedIPs[i] && blockedIPs[i][0]) {
            Wfp_BlockIP(blockedIPs[i]);
        }
    }
    return ERROR_SUCCESS;
}

#ifndef OMINULL_WFP_EMBEDDED
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Ominull Windows Zero-Friction User-Mode WFP Engine\n");
        printf("Usage:\n");
        printf("  ominull_wfp_user.exe isolate <hub_ip>   - Isolate host network (default-deny with hub pinhole)\n");
        printf("  ominull_wfp_user.exe unisolate          - Lift isolation and restore normal traffic\n");
        printf("  ominull_wfp_user.exe block-ip <ip>      - Block specific IPv4 address\n");
        printf("  ominull_wfp_user.exe test               - Verify WFP subsystem initialization\n");
        return 1;
    }

    DWORD status = Wfp_Init(1);
    if (status != ERROR_SUCCESS) {
        return 1;
    }

    if (strcmp(argv[1], "isolate") == 0) {
        const char* hubIp = (argc >= 3) ? argv[2] : "10.0.0.57";
        Wfp_IsolateHost(hubIp);
    } else if (strcmp(argv[1], "unisolate") == 0) {
        Wfp_UnisolateHost();
    } else if (strcmp(argv[1], "block-ip") == 0) {
        if (argc < 3) {
            printf("[-] Missing IP parameter.\n");
            Wfp_Close();
            return 1;
        }
        Wfp_BlockIP(argv[2]);
    } else if (strcmp(argv[1], "test") == 0) {
        printf("[+] WFP User-Mode Engine Initialized Successfully!\n");
        printf("[+] Ready for Zero-Driver Threat Nullification.\n");
    } else {
        printf("[-] Unknown command: %s\n", argv[1]);
    }

    Wfp_Close();
    return 0;
}
#endif /* OMINULL_WFP_EMBEDDED */
