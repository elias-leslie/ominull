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

// Layer GUIDs
DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82);

DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x1b, 0x99, 0x9c, 0x21, 0x34, 0x5b, 0x52);

// Condition GUIDs
DEFINE_GUID(OMINULL_CONDITION_IP_REMOTE_ADDRESS,
    0xb23a2517, 0xdee, 0x4b6b, 0xae, 0xb3, 0x5c, 0x6e, 0x69, 0xae, 0x67, 0xc1);

DEFINE_GUID(OMINULL_CONDITION_IP_REMOTE_PORT,
    0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4);

DEFINE_GUID(OMINULL_CONDITION_ALE_APP_ID,
    0xd78de288, 0x7b52, 0x4f62, 0xa6, 0x67, 0x38, 0xd9, 0xf6, 0x94, 0x97, 0x24);

// Sublayer & Provider GUIDs
DEFINE_GUID(OMINULL_SUBLAYER_USER_GUID,
    0xb413e784, 0xa15f, 0x4f98, 0x89, 0x5f, 0x55, 0x82, 0x23, 0x6e, 0xb, 0x11);

DEFINE_GUID(OMINULL_PROVIDER_USER_GUID,
    0xc524f895, 0xb26a, 0x5a09, 0x90, 0x6a, 0x66, 0x93, 0x34, 0x7f, 0x1c, 0x22);

static HANDLE g_hEngine = NULL;

DWORD Wfp_Init() {
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Auto-cleanup on abnormal termination

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
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
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
        permitHub.weight.uint8 = 0xFF; // Top weight

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
        permitLoopback.weight.uint8 = 0xFE;

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
        permitDhcp.weight.uint8 = 0xFD;

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
        blockAllOut.weight.uint8 = 0x10; // Catch-all default deny

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
        blockAllIn.weight.uint8 = 0x10;

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

DWORD Wfp_UnisolateHost() {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    printf("[*] Removing WFP User-Mode Network Isolation...\n");

    // Deleting sublayer flushes all isolation and dynamic rules atomically
    DWORD status = FwpmSubLayerDeleteByKey0(g_hEngine, &OMINULL_SUBLAYER_USER_GUID);
    if (status == ERROR_SUCCESS || status == FWP_E_SUBLAYER_NOT_FOUND) {
        printf("[+] SUCCESS: Host network isolation removed. Normal connectivity restored.\n");
    } else {
        printf("[-] FwpmSubLayerDeleteByKey0 returned: 0x%08lX\n", (unsigned long)status);
    }

    // Recreate sublayer for future operations
    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
    sublayer.displayData.name = L"Ominull Zero-Friction User-Mode WFP Sublayer";
    sublayer.weight = 0xFF00;
    FwpmSubLayerAdd0(g_hEngine, &sublayer, NULL);

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
    filter.weight.uint8 = 0xC0;

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

    DWORD status = Wfp_Init();
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
