#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* For OMINULL_BASELINE_RULE. The baseline policy crosses from the agent into
 * this engine, so the shape has to be declared in one place - a second copy here
 * would compile and link and then disagree the first time a field moved. */
#include "../include/agent.h"

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

DEFINE_GUID(OMINULL_CONDITION_IP_PROTOCOL,          /* 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7 */
    0x3971ef2b, 0x623e, 0x4f9a, 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7);

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
#define OMINULL_WEIGHT_PERMIT_DNS      11
#define OMINULL_WEIGHT_PERMIT_ALLOW    10
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

/* The four ALE layers every rule here is installed on: outbound and inbound,
 * IPv4 and IPv6.
 *
 * Only the two IPv4 layers were ever filtered. An isolated Windows host with
 * working IPv6 - which is every modern Windows host on a segment that answers a
 * router solicitation - kept full IPv6 connectivity while the console showed it
 * quarantined, and anything on the box could step around the quarantine by
 * preferring an AAAA record. The Linux agent has always built the same chains
 * under ip6tables as under iptables, and pf's `block drop all` is
 * address-family agnostic, so Windows was the one platform where isolation was
 * not isolation.
 *
 * The two IPv6 layer GUIDs come from WireGuard-Windows, whose four IPv4 values
 * are byte-for-byte the ones already verified here against Microsoft's
 * reference. */
DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_CONNECT_V6,      /* 4a72393b-319f-44bc-84c3-ba54dcb3b6b4 */
    0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4);

DEFINE_GUID(OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V6,  /* a3b42c97-9f04-4672-b87e-cee9c483257f */
    0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f);

#define OMINULL_FAMILY_V4    1
#define OMINULL_FAMILY_V6    2
#define OMINULL_FAMILY_BOTH  (OMINULL_FAMILY_V4 | OMINULL_FAMILY_V6)

/* Index order is [family][direction], and direction 0 is always outbound.
 * ALE_AUTH_CONNECT authorizes an outgoing connection (and the first packet of
 * outgoing non-TCP traffic); ALE_AUTH_RECV_ACCEPT authorizes an incoming one. */
static const GUID* const kOminullLayers[2][2] = {
    { &OMINULL_LAYER_ALE_AUTH_CONNECT_V4, &OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
    { &OMINULL_LAYER_ALE_AUTH_CONNECT_V6, &OMINULL_LAYER_ALE_AUTH_RECV_ACCEPT_V6 },
};

/* AddFilterEverywhere installs one rule on every layer the caller asks for.
 *
 * Every permit in the isolation floor used to go on ALE_AUTH_CONNECT_V4 alone,
 * while the default-deny went on both IPv4 layers. Outbound-only is not a
 * floor: a DHCP renewal is a request out and a reply in, and the reply arrives
 * as a new inbound flow rather than as part of the outbound one, so it met the
 * inbound block instead. The lease then expires, the host loses the address the
 * hub reaches it on, and an isolated endpoint that could have been released by
 * the hub falls off the network for good. The same hole dropped inbound
 * loopback, which is how local software talks to itself.
 *
 * Writing it once is the fix: a rule cannot now be added to one layer and
 * forgotten on the other three. */
static DWORD AddFilterEverywhere(const wchar_t* base, FWP_ACTION_TYPE action, UINT8 weight,
                                 FWPM_FILTER_CONDITION0* conds, UINT32 condCount,
                                 int families) {
    static const wchar_t* const famName[2] = { L"IPv4", L"IPv6" };
    static const wchar_t* const dirName[2] = { L"outbound", L"inbound" };

    for (int f = 0; f < 2; f++) {
        if (!(families & (f == 0 ? OMINULL_FAMILY_V4 : OMINULL_FAMILY_V6))) continue;
        for (int d = 0; d < 2; d++) {
            wchar_t name[192];
            _snwprintf(name, sizeof(name) / sizeof(name[0]) - 1,
                       L"%s (%s %s)", base, famName[f], dirName[d]);
            name[sizeof(name) / sizeof(name[0]) - 1] = L'\0';

            FWPM_FILTER0 filter;
            memset(&filter, 0, sizeof(filter));
            filter.layerKey = *kOminullLayers[f][d];
            filter.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
            filter.displayData.name = name;
            filter.action.type = action;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = weight;
            filter.numFilterConditions = condCount;
            filter.filterCondition = condCount ? conds : NULL;

            UINT64 filterId = 0;
            DWORD status = FwpmFilterAdd0(g_hEngine, &filter, NULL, &filterId);
            if (status != ERROR_SUCCESS) return status;
        }
    }
    return ERROR_SUCCESS;
}

/* AddressCondition fills in a remote-address match for whichever family the
 * literal turns out to be, and reports which one that was.
 *
 * The v6 form points conditionValue at storage the caller owns, so `store` has
 * to outlive the FwpmFilterAdd0 call - which is why it is a parameter rather
 * than a local here. Returns 0 for a literal that is neither. */
static int AddressCondition(const char* ipStr, FWPM_FILTER_CONDITION0* cond, FWP_BYTE_ARRAY16* store) {
    struct in_addr a4;
    struct in6_addr a6;

    memset(cond, 0, sizeof(*cond));
    cond->fieldKey = OMINULL_CONDITION_IP_REMOTE_ADDRESS;
    cond->matchType = FWP_MATCH_EQUAL;

    if (ipStr && ipStr[0] && inet_pton(AF_INET, ipStr, &a4) == 1) {
        cond->conditionValue.type = FWP_UINT32;
        cond->conditionValue.uint32 = ntohl(a4.s_addr);
        return OMINULL_FAMILY_V4;
    }
    if (ipStr && ipStr[0] && inet_pton(AF_INET6, ipStr, &a6) == 1) {
        memcpy(store->byteArray16, &a6, sizeof(store->byteArray16));
        cond->conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        cond->conditionValue.byteArray16 = store;
        return OMINULL_FAMILY_V6;
    }
    return 0;
}

/* UdpRemotePort builds the two conditions that name one UDP service.
 *
 * The port is the remote one in both directions on purpose: outbound it is the
 * server's port, and inbound - where the remote end is the server - it is the
 * source port of the reply. The protocol condition is not decoration; the port
 * alone would have permitted the TCP service on the same number as well. */
static void UdpRemotePort(FWPM_FILTER_CONDITION0* cond, UINT16 port) {
    memset(cond, 0, sizeof(cond[0]) * 2);
    cond[0].fieldKey = OMINULL_CONDITION_IP_PROTOCOL;
    cond[0].matchType = FWP_MATCH_EQUAL;
    cond[0].conditionValue.type = FWP_UINT8;
    cond[0].conditionValue.uint8 = 17;                 /* UDP */
    cond[1].fieldKey = OMINULL_CONDITION_IP_REMOTE_PORT;
    cond[1].matchType = FWP_MATCH_EQUAL;
    cond[1].conditionValue.type = FWP_UINT16;
    cond[1].conditionValue.uint16 = port;
}

/* ServiceCondition builds the three conditions that name one baseline rule: a
 * protocol, a remote port and a remote address.
 *
 * The port is the remote one in both directions for the same reason UdpRemotePort
 * uses it - outbound it is the server's port, and inbound, where the remote end
 * is the server, it is the source port of the reply. Returns the address family
 * the destination parsed as, or 0 if it did not parse. The byte array backing an
 * IPv6 condition has to outlive the FwpmFilterAdd0 call, which is why the caller
 * owns it. */
static int ServiceCondition(const OMINULL_BASELINE_RULE* rule,
                            FWPM_FILTER_CONDITION0* cond, FWP_BYTE_ARRAY16* store) {
    memset(cond, 0, sizeof(cond[0]) * 3);

    int family = AddressCondition(rule->destination, &cond[0], store);
    if (!family) return 0;

    cond[1].fieldKey = OMINULL_CONDITION_IP_PROTOCOL;
    cond[1].matchType = FWP_MATCH_EQUAL;
    cond[1].conditionValue.type = FWP_UINT8;
    cond[1].conditionValue.uint8 = (strcmp(rule->protocol, "tcp") == 0) ? 6 : 17;

    cond[2].fieldKey = OMINULL_CONDITION_IP_REMOTE_PORT;
    cond[2].matchType = FWP_MATCH_EQUAL;
    cond[2].conditionValue.type = FWP_UINT16;
    cond[2].conditionValue.uint16 = (UINT16)rule->port;
    return family;
}

/* AddBaselineRules installs the part of the policy that belongs at one rung of
 * the ladder. DHCP sits above the peer blocks - a quarantine must not be able to
 * cost this host the lease that carries the address the hub reaches it on - and
 * everything else sits below them, so quarantining a rogue resolver still beats
 * the rule that lets this host resolve names. */
static DWORD AddBaselineRules(const OMINULL_BASELINE_RULE* baseline, int baselineCount,
                              int wantDHCP, UINT8 weight) {
    FWPM_FILTER_CONDITION0 cond[3];
    FWP_BYTE_ARRAY16 store;

    for (int i = 0; i < baselineCount; i++) {
        int isDHCP = (strcmp(baseline[i].service, "dhcp") == 0);
        if (isDHCP != wantDHCP) continue;

        int family = ServiceCondition(&baseline[i], cond, &store);
        if (!family) continue;             /* not an address; the hub validated it, so this is defensive */

        DWORD status = AddFilterEverywhere(L"Ominull Baseline Permit", FWP_ACTION_PERMIT,
                                           weight, cond, 3, family);
        if (status != ERROR_SUCCESS) {
            printf("[-] Failed to add baseline filter for %s/%s:%d: 0x%08lX\n",
                   baseline[i].service, baseline[i].destination, baseline[i].port,
                   (unsigned long)status);
            return status;
        }
    }
    return ERROR_SUCCESS;
}

/* Wfp_IsolateHost builds the default-deny and the floor that has to survive it.
 *
 * The floor is loopback, the hub, DHCP and DNS - the same four the Linux chains
 * permit, so a quarantined host behaves the same whichever retained agent runs.
 * What sits above the floor is the hub's allow list, which is
 * the mechanism a scoped trust rule is delivered by.
 *
 * DNS and DHCP used to be permitted to *any* destination here. Both were holes
 * with a justification attached rather than policy, and neither was visible to
 * whoever clicked Isolate. They are now whatever the baseline policy names, and
 * the hub resolves that per endpoint. A hub too old to send one leaves
 * baselineKnown at 0 and the old permits stay, because tightening the floor
 * under a fleet whose hub never asked for it would cut hosts off. */
DWORD Wfp_IsolateHost(const char* hubIpStr, const char* const* allowIPs, int allowCount,
                      const OMINULL_BASELINE_RULE* baseline, int baselineCount,
                      int baselineKnown) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    printf("[*] Activating WFP User-Mode Network Isolation (Default-Deny)...\n");

    DWORD status = FwpmTransactionBegin0(g_hEngine, 0);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to begin WFP transaction: 0x%08lX\n", (unsigned long)status);
        return status;
    }

    FWPM_FILTER_CONDITION0 cond[2];
    FWP_BYTE_ARRAY16 store;

    /* 1. The hub. Highest weight of anything here: a peer block that happened
     *    to name the hub must not be what takes away the only way to release
     *    this host. */
    int hubFamily = AddressCondition(hubIpStr, &cond[0], &store);
    if (hubFamily) {
        status = AddFilterEverywhere(L"Ominull Analyst Hub Pinhole", FWP_ACTION_PERMIT,
                                     OMINULL_WEIGHT_PERMIT_HUB, cond, 1, hubFamily);
        if (status != ERROR_SUCCESS) {
            printf("[-] Failed to add Hub permit filter: 0x%08lX\n", (unsigned long)status);
            FwpmTransactionAbort0(g_hEngine);
            return status;
        }
        printf("[+] Added Hub pinhole filter (IP: %s)\n", hubIpStr);
    }

    /* 2. Loopback, in both families. */
    AddressCondition("127.0.0.1", &cond[0], &store);
    status = AddFilterEverywhere(L"Ominull Loopback Permit", FWP_ACTION_PERMIT,
                                 OMINULL_WEIGHT_PERMIT_LOOPBACK, cond, 1, OMINULL_FAMILY_V4);
    if (status == ERROR_SUCCESS) {
        AddressCondition("::1", &cond[0], &store);
        status = AddFilterEverywhere(L"Ominull Loopback Permit", FWP_ACTION_PERMIT,
                                     OMINULL_WEIGHT_PERMIT_LOOPBACK, cond, 1, OMINULL_FAMILY_V6);
    }
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to add loopback permit filter: 0x%08lX\n", (unsigned long)status);
        FwpmTransactionAbort0(g_hEngine);
        return status;
    }

    /* 3. The DHCP part of the baseline, above the peer blocks: a lease that
     *    expires because a quarantine named the DHCP server costs this host the
     *    address the hub reaches it on. */
    if (baselineKnown) {
        status = AddBaselineRules(baseline, baselineCount, 1, OMINULL_WEIGHT_PERMIT_DHCP);
    } else {
        /* No policy from this hub. DHCPv6 is a different pair of ports
         * (546/547) rather than the same two, so the two families get one rule
         * each rather than one rule on four layers. */
        UdpRemotePort(cond, 67);
        status = AddFilterEverywhere(L"Ominull DHCP Permit", FWP_ACTION_PERMIT,
                                     OMINULL_WEIGHT_PERMIT_DHCP, cond, 2, OMINULL_FAMILY_V4);
        if (status == ERROR_SUCCESS) {
            UdpRemotePort(cond, 547);
            status = AddFilterEverywhere(L"Ominull DHCPv6 Permit", FWP_ACTION_PERMIT,
                                         OMINULL_WEIGHT_PERMIT_DHCP, cond, 2, OMINULL_FAMILY_V6);
        }
    }
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to add DHCP permit filter: 0x%08lX\n", (unsigned long)status);
        FwpmTransactionAbort0(g_hEngine);
        return status;
    }

    /* 4. The rest of the baseline - DNS, NTP, whatever else the policy names.
     *    Below the peer block on purpose: quarantining a rogue resolver has to
     *    beat the rule that lets this host resolve names. */
    if (baselineKnown) {
        status = AddBaselineRules(baseline, baselineCount, 0, OMINULL_WEIGHT_PERMIT_DNS);
    } else {
        UdpRemotePort(cond, 53);
        status = AddFilterEverywhere(L"Ominull DNS Permit", FWP_ACTION_PERMIT,
                                     OMINULL_WEIGHT_PERMIT_DNS, cond, 2, OMINULL_FAMILY_BOTH);
    }
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to add DNS permit filter: 0x%08lX\n", (unsigned long)status);
        FwpmTransactionAbort0(g_hEngine);
        return status;
    }

    /* 5. The hub's allow list. Below a peer block, so a mesh quarantine of a
     *    rogue host still wins over a standing trust rule that named it.
     *
     *    The agent parsed this field and then told the operator it could not
     *    enforce it, which was honest and still meant a Windows endpoint was
     *    the one platform where a trust rule did nothing. */
    for (int i = 0; i < allowCount; i++) {
        int family = AddressCondition(allowIPs[i], &cond[0], &store);
        if (!family) continue;             /* a CIDR is not this filter's shape */
        status = AddFilterEverywhere(L"Ominull Isolation Allow", FWP_ACTION_PERMIT,
                                     OMINULL_WEIGHT_PERMIT_ALLOW, cond, 1, family);
        if (status != ERROR_SUCCESS) {
            printf("[-] Failed to add allow-list filter for %s: 0x%08lX\n",
                   allowIPs[i], (unsigned long)status);
            FwpmTransactionAbort0(g_hEngine);
            return status;
        }
    }

    /* 6. Default-deny on all four layers, weight zero so everything above it
     *    wins. */
    status = AddFilterEverywhere(L"Ominull Host Isolation Block All", FWP_ACTION_BLOCK,
                                 OMINULL_WEIGHT_BLOCK_ALL, NULL, 0, OMINULL_FAMILY_BOTH);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to add default block filter: 0x%08lX\n", (unsigned long)status);
        FwpmTransactionAbort0(g_hEngine);
        return status;
    }

    status = FwpmTransactionCommit0(g_hEngine);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to commit WFP transaction: 0x%08lX\n", (unsigned long)status);
        return status;
    }

    if (baselineKnown) {
        printf("[+] Host isolation active (IPv4 and IPv6). Permitted: hub %s, loopback, "
               "%d baseline rule(s), %d allow-list address(es).\n",
               hubIpStr && hubIpStr[0] ? hubIpStr : "(none)", baselineCount, allowCount);
    } else {
        printf("[+] Host isolation active (IPv4 and IPv6). This hub sends no baseline policy, so the "
               "built-in floor applies: hub %s, loopback, DHCP and DNS to any destination, "
               "%d allow-list address(es).\n",
               hubIpStr && hubIpStr[0] ? hubIpStr : "(none)", allowCount);
    }
    return ERROR_SUCCESS;
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

/* Wfp_BlockIP quarantines one peer, in both directions and in whichever address
 * family the literal is.
 *
 * It installs both directions, so a mesh block placed on a compromised machine
 * cannot leave the peer able to reach in. */
DWORD Wfp_BlockIP(const char* ipStr) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    FWPM_FILTER_CONDITION0 cond;
    FWP_BYTE_ARRAY16 store;
    int family = AddressCondition(ipStr, &cond, &store);
    if (!family) {
        printf("[-] Not an IP address: %s\n", ipStr ? ipStr : "(null)");
        return ERROR_INVALID_PARAMETER;
    }

    DWORD status = AddFilterEverywhere(L"Ominull Dynamic IP Block", FWP_ACTION_BLOCK,
                                       OMINULL_WEIGHT_BLOCK_PEER, &cond, 1, family);
    if (status == ERROR_SUCCESS) {
        printf("[+] SUCCESS: Blocked IP %s in both directions.\n", ipStr);
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
                     const char* const* blockedIPs, int blockedCount,
                     const char* const* allowIPs, int allowCount,
                     const OMINULL_BASELINE_RULE* baseline, int baselineCount,
                     int baselineKnown) {
    if (!g_hEngine) return ERROR_INVALID_HANDLE;

    /* Removes this agent's filters and recreates the sublayer empty. If the
     * kernel would not give them up, say so rather than reporting a release
     * that did not happen. */
    DWORD cleared = Wfp_UnisolateHost();
    if (cleared != ERROR_SUCCESS) return cleared;

    if (isolate) {
        DWORD status = Wfp_IsolateHost(hubIpStr, allowIPs, allowCount,
                                       baseline, baselineCount, baselineKnown);
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
static bool RemoveDirectoryFiles(const char* directory) {
    char pattern[MAX_PATH];
    int n = snprintf(pattern, sizeof(pattern), "%s\\*", directory);
    if (n < 0 || (size_t)n >= sizeof(pattern)) return false;

    WIN32_FIND_DATAA entry;
    HANDLE find = FindFirstFileA(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_PATH_NOT_FOUND;

    bool ok = true;
    do {
        if (strcmp(entry.cFileName, ".") == 0 || strcmp(entry.cFileName, "..") == 0) continue;
        char path[MAX_PATH];
        n = snprintf(path, sizeof(path), "%s\\%s", directory, entry.cFileName);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            ok = false;
            continue;
        }
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!RemoveDirectoryA(path) && GetLastError() != ERROR_PATH_NOT_FOUND) ok = false;
        } else if (!DeleteFileA(path) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            ok = false;
        }
    } while (FindNextFileA(find, &entry));
    FindClose(find);
    return ok;
}

static bool RemoveAgentData(void) {
    static const char* files[] = {
        "C:\\ProgramData\\Ominull\\agent.conf",
        "C:\\ProgramData\\Ominull\\agent.key",
        "C:\\ProgramData\\Ominull\\ca.crt",
        "C:\\ProgramData\\Ominull\\client.crt",
        "C:\\ProgramData\\Ominull\\client.pfx",
        "C:\\Program Files\\Ominull\\agent.conf",
        "C:\\Program Files\\Ominull\\agent.key",
        "C:\\Program Files\\Ominull\\ca.crt",
        "C:\\Program Files\\Ominull\\client.crt",
        "C:\\Program Files\\Ominull\\client.pfx",
        NULL,
    };
    bool ok = true;
    for (size_t i = 0; files[i]; i++) {
        if (!DeleteFileA(files[i]) && GetLastError() != ERROR_FILE_NOT_FOUND) ok = false;
    }
    if (!RemoveDirectoryFiles("C:\\ProgramData\\Ominull\\updates")) ok = false;
    if (!RemoveDirectoryA("C:\\ProgramData\\Ominull\\updates") &&
        GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_DIR_NOT_EMPTY) ok = false;
    if (!RemoveDirectoryA("C:\\ProgramData\\Ominull") &&
        GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_DIR_NOT_EMPTY) ok = false;
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Ominull Windows Zero-Friction User-Mode WFP Engine\n");
        printf("Usage:\n");
        printf("  ominull_wfp_user.exe isolate <hub_ip>   - Isolate host network (default-deny with hub pinhole)\n");
        printf("  ominull_wfp_user.exe unisolate          - Lift isolation and restore normal traffic\n");
        printf("  ominull_wfp_user.exe uninstall           - Lift isolation and remove agent identity\n");
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
        /* No hub connection here, so no baseline policy: this is the recovery
         * tool, and it applies the permissive built-in floor. An operator
         * isolating a host by hand from its own console wants the floor that
         * keeps DNS and DHCP working, not an empty policy they cannot see. */
        Wfp_IsolateHost(hubIp, NULL, 0, NULL, 0, 0);
    } else if (strcmp(argv[1], "unisolate") == 0) {
        Wfp_UnisolateHost();
    } else if (strcmp(argv[1], "uninstall") == 0) {
        status = Wfp_UnisolateHost();
        if (status == ERROR_SUCCESS && !RemoveAgentData()) {
            printf("[-] WFP was cleared but some package-owned agent data could not be removed.\n");
            status = ERROR_ACCESS_DENIED;
        }
    } else if (strcmp(argv[1], "block-ip") == 0) {
        if (argc < 3) {
            printf("[-] Missing IP parameter.\n");
            Wfp_Close();
            return 1;
        }
        Wfp_BlockIP(argv[2]);
    } else if (strcmp(argv[1], "test") == 0) {
        printf("[+] WFP User-Mode Engine Initialized Successfully!\n");
        printf("[+] Ready for user-mode WFP recovery.\n");
    } else {
        printf("[-] Unknown command: %s\n", argv[1]);
    }

    Wfp_Close();
    return 0;
}
#endif /* OMINULL_WFP_EMBEDDED */
