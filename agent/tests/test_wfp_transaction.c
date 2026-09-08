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
static DWORD Add(HANDLE h, const FWPM_FILTER0 *f, PSECURITY_DESCRIPTOR sd,
                 UINT64 *id) {
    (void)h;
    (void)f;
    (void)sd;
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
    DWORD result = Wfp_ApplyState(NULL, 0, blocked, 1, NULL, 0, NULL, 0, 1);
    if (result == 0 || live_count != 5 || transaction) {
        fprintf(stderr,
                "failed replacement lost previous filters or reported success: "
                "status=%lu count=%u\n",
                result, live_count);
        return 1;
    }
    add_calls = 0;
    fail_add = 0;
    assert(Wfp_ApplyState(NULL, 0, blocked, 1, NULL, 0, NULL, 0, 1) == 0);
    assert(live_count == 10 && !transaction);
    puts("WFP replacement commits both directions and preserves old state on "
         "failure");
    return 0;
}
