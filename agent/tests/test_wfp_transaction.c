/* Failure injection at the WFP API boundary. Never opens the real engine. */
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
static FWPM_FILTER0 existing;
static FWPM_FILTER0 *entry = &existing;
static unsigned live_count, saved_count, enum_calls, add_calls, fail_add;
static bool transaction;
static DWORD Begin(HANDLE h, UINT32 flags) {
    (void)h;
    (void)flags;
    assert(!transaction);
    transaction = true;
    saved_count = live_count;
    return 0;
}
static DWORD Commit(HANDLE h) {
    (void)h;
    assert(transaction);
    transaction = false;
    return 0;
}
static DWORD Abort(HANDLE h) {
    (void)h;
    assert(transaction);
    live_count = saved_count;
    transaction = false;
    return 0;
}
/* The range conditions Add was given, to check what the filter says. */
static FWP_V4_ADDR_AND_MASK seen_v4[8];
static FWP_V6_ADDR_AND_MASK seen_v6[8];
static unsigned seen_v4_n, seen_v6_n;
/* The app-limited filters Add was given, and the weight each carried. */
static unsigned seen_app, seen_app_weight, seen_plain_hub_weight;
static FWP_BYTE_BLOB self_app;
static DWORD Add(HANDLE h, const FWPM_FILTER0 *f, PSECURITY_DESCRIPTOR sd,
                 UINT64 *id) {
    (void)h;
    (void)sd;
    for (UINT32 i = 0; f && i < f->numFilterConditions; i++) {
        const FWP_CONDITION_VALUE0 *v = &f->filterCondition[i].conditionValue;
        if (v->type == FWP_V4_ADDR_MASK && seen_v4_n < 8)
            seen_v4[seen_v4_n++] = *v->v4AddrMask;
        if (v->type == FWP_V6_ADDR_MASK && seen_v6_n < 8)
            seen_v6[seen_v6_n++] = *v->v6AddrMask;
        if (v->type == FWP_BYTE_BLOB_TYPE && v->byteBlob == &self_app) {
            seen_app++;
            seen_app_weight = f->weight.uint8;
        }
    }
    if (f && f->displayData.name && wcsstr(f->displayData.name, L"Hub Pinhole") && f->numFilterConditions == 3)
        seen_plain_hub_weight = f->weight.uint8;
    (void)id;
    if (++add_calls == fail_add)
        return ERROR_ACCESS_DENIED;
    live_count++;
    return 0;
}
static DWORD Create(HANDLE h, const FWPM_FILTER_ENUM_TEMPLATE0 *t, HANDLE *e) {
    (void)h;
    (void)t;
    *e = (HANDLE)1;
    enum_calls = 0;
    return 0;
}
static DWORD Enum(HANDLE h, HANDLE e, UINT32 n, FWPM_FILTER0 ***rows,
                  UINT32 *count) {
    (void)h;
    (void)e;
    (void)n;
    *rows = &entry;
    *count = enum_calls++ == 0 && live_count ? 1 : 0;
    return 0;
}
static DWORD Delete(HANDLE h, UINT64 id) {
    (void)h;
    (void)id;
    live_count = 0;
    return 0;
}
static DWORD Destroy(HANDLE h, HANDLE e) {
    (void)h;
    (void)e;
    return 0;
}
static void Free(void **p) { (void)p; }
static DWORD SubAdd(HANDLE h, const FWPM_SUBLAYER0 *s, PSECURITY_DESCRIPTOR d) {
    (void)h;
    (void)s;
    (void)d;
    return 0;
}
static DWORD AppId(const wchar_t *path, FWP_BYTE_BLOB **id) {
    (void)path;
    *id = &self_app;
    return 0;
}
#define FwpmGetAppIdFromFileName0 AppId
#define FwpmTransactionBegin0 Begin
#define FwpmTransactionCommit0 Commit
#define FwpmTransactionAbort0 Abort
#define FwpmFilterAdd0 Add
#define FwpmFilterCreateEnumHandle0 Create
#define FwpmFilterEnum0 Enum
#define FwpmFilterDeleteById0 Delete
#define FwpmFilterDestroyEnumHandle0 Destroy
#define FwpmFreeMemory0 Free
#define FwpmSubLayerAdd0 SubAdd
#define OMINULL_WFP_EMBEDDED
#include "../windows/wfp_user.c"
int main(void) {
    g_hEngine = (HANDLE)1;
    existing.subLayerKey = OMINULL_SUBLAYER_USER_GUID;
    existing.filterId = 1;
    const char *blocked[] = {"2001:db8::42"};
    live_count = 5;
    fail_add = 2;
    DWORD result = Wfp_ApplyState(NULL, 0, blocked, 1, NULL, 0, NULL, 0, 0);
    if (result == 0 || live_count != 5 || transaction) {
        fprintf(stderr,
                "failed replacement lost previous filters or reported success: "
                "status=%lu count=%u\n",
                result, live_count);
        return 1;
    }
    add_calls = 0;
    fail_add = 0;
    assert(Wfp_ApplyState(NULL, 0, blocked, 1, NULL, 0, NULL, 0, 0) == 0);
    assert(live_count == 10 && !transaction);
    puts("WFP replacement commits both directions and preserves old state on "
         "failure");
    /* A range is an allow entry like an address: the agent used to drop these. */
    assert(Wfp_CanAllow("198.51.100.7") && Wfp_CanAllow("198.51.100.0/25"));
    assert(Wfp_CanAllow("2001:db8::7") && Wfp_CanAllow("2001:db8::/48"));
    assert(!Wfp_CanAllow("fe80::1%11") && !Wfp_CanAllow("fe80::/64"));
    assert(!Wfp_CanAllow("example.com") && !Wfp_CanAllow("198.51.100.0/99"));
    /* The filter has to say the range, in both directions: the IPv4 address and
     * mask in host order with host bits off, the IPv6 bytes and prefix length. */
    {
        const char *ranges[] = {"198.51.100.77/25", "2001:db8:1::/48"};
        const unsigned char want6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 1};
        add_calls = 0;
        seen_v4_n = seen_v6_n = 0;
        OMINULL_HUB_TARGETS hub = {.count = 1, .port = 9443, .addresses = {"203.0.113.1"}};
        assert(Wfp_ApplyState(&hub, 1, NULL, 0, ranges, 2, NULL, 0, 0) == 0);
        assert(seen_v4_n == 2 && seen_v6_n == 2);
        for (unsigned i = 0; i < 2; i++) {
            assert(seen_v4[i].addr == 0xC6336400u && seen_v4[i].mask == 0xFFFFFF80u);
            assert(seen_v6[i].prefixLength == 48);
            assert(memcmp(seen_v6[i].addr, want6, 16) == 0);
        }
    }
    /* A followed hub address is this program's alone and below the blocks; the old
     * hole stays as it was. */
    {
        OMINULL_HUB_TARGETS hub = {.count = 2, .port = 9443, .addresses = {"203.0.113.1", "203.0.113.2"}};
        seen_app = 0;
        assert(Wfp_ApplyState(&hub, 1, NULL, 0, NULL, 0, NULL, 0, 0) == 0);
        assert(seen_app == 0 && seen_plain_hub_weight == OMINULL_WEIGHT_PERMIT_HUB);
        hub.agent_only[1] = true;
        assert(Wfp_ApplyState(&hub, 1, NULL, 0, NULL, 0, NULL, 0, 0) == 0);
        assert(seen_app == 2 && seen_app_weight == OMINULL_WEIGHT_PERMIT_ALLOW);
        assert(seen_plain_hub_weight == OMINULL_WEIGHT_PERMIT_HUB);
        assert(OMINULL_WEIGHT_PERMIT_ALLOW < OMINULL_WEIGHT_BLOCK_PEER);
    }
    return 0;
}
