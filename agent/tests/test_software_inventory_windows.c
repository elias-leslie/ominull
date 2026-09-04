/*
 * Unit test suite for Windows Authoritative Software Inventory Collector (Slice 7A).
 */

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "software_inventory_windows.h"

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(expr) do { \
    g_tests_run++; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expr); \
        g_tests_failed++; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    g_tests_run++; \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s:%d: strings not equal:\n  got:  \"%s\"\n  want: \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        g_tests_failed++; \
    } \
} while (0)

static void test_vendor_normalization_win(void) {
    printf("[*] Testing Windows vendor normalization...\n");
    char vendor[128];

    SoftwareInvWin_NormalizeVendor("Microsoft Corporation", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "microsoft");

    SoftwareInvWin_NormalizeVendor("Google LLC", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "google");

    SoftwareInvWin_NormalizeVendor("Mozilla Corporation", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "mozilla");

    SoftwareInvWin_NormalizeVendor("Oracle America, Inc.", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "oracle");

    SoftwareInvWin_NormalizeVendor("Git for Windows", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "git");

    SoftwareInvWin_NormalizeVendor("Adobe Systems Incorporated", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "adobe");

    SoftwareInvWin_NormalizeVendor("Valve Corporation", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "valve");

    SoftwareInvWin_NormalizeVendor("Custom Vendor, LLC", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "custom vendor");

    SoftwareInvWin_NormalizeVendor("", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "unknown");

    SoftwareInvWin_NormalizeVendor(NULL, vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "unknown");
}

static void test_json_escaping_win(void) {
    printf("[*] Testing Windows JSON escaping...\n");
    char escaped[256];

    SoftwareInvWin_EscapeJson("C:\\Program Files\\Test\\app.exe \"arg\"", escaped, sizeof(escaped));
    ASSERT_STR_EQ(escaped, "C:\\\\Program Files\\\\Test\\\\app.exe \\\"arg\\\"");

    SoftwareInvWin_EscapeJson(NULL, escaped, sizeof(escaped));
    ASSERT_STR_EQ(escaped, "");
}

static void test_registry_collection_live(void) {
    printf("[*] Testing registry software collection with created HKCU fixture...\n");

    const char* testSubkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OminullTestPackage";
    HKEY hKey = NULL;
    DWORD disposition = 0;

    LONG res = RegCreateKeyExA(
        HKEY_CURRENT_USER, testSubkey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hKey, &disposition
    );
    ASSERT_TRUE(res == ERROR_SUCCESS);
    ASSERT_TRUE(hKey != NULL);

    const char* displayName = "Ominull Agent Test Suite";
    const char* displayVersion = "1.8.3.42";
    const char* publisher = "SummitFlow Engineering Corp.";
    DWORD winInstaller = 1;

    RegSetValueExA(hKey, "DisplayName", 0, REG_SZ, (const BYTE*)displayName, (DWORD)strlen(displayName) + 1);
    RegSetValueExA(hKey, "DisplayVersion", 0, REG_SZ, (const BYTE*)displayVersion, (DWORD)strlen(displayVersion) + 1);
    RegSetValueExA(hKey, "Publisher", 0, REG_SZ, (const BYTE*)publisher, (DWORD)strlen(publisher) + 1);
    RegSetValueExA(hKey, "WindowsInstaller", 0, REG_DWORD, (const BYTE*)&winInstaller, sizeof(winInstaller));

    RegCloseKey(hKey);

    /* Collect installed software via heap allocation to respect stack limits */
    SoftwareInventoryBatchWin* batch = (SoftwareInventoryBatchWin*)calloc(1, sizeof(SoftwareInventoryBatchWin));
    ASSERT_TRUE(batch != NULL);

    int collectRes = SoftwareInvWin_Collect(batch);
    ASSERT_TRUE(collectRes == 0);
    ASSERT_TRUE(batch->count > 0);

    /* Locate our test package */
    bool found = false;
    for (size_t i = 0; i < batch->count; i++) {
        if (strcmp(batch->items[i].product, "Ominull Agent Test Suite") == 0) {
            found = true;
            ASSERT_STR_EQ(batch->items[i].version, "1.8.3.42");
            ASSERT_STR_EQ(batch->items[i].source, "msi");
            ASSERT_STR_EQ(batch->items[i].install_scope, "user");
            ASSERT_STR_EQ(batch->items[i].confidence, "authoritative");
            ASSERT_STR_EQ(batch->items[i].raw_vendor, "SummitFlow Engineering Corp.");
            ASSERT_STR_EQ(batch->items[i].raw_product, "Ominull Agent Test Suite");
            ASSERT_STR_EQ(batch->items[i].raw_version, "1.8.3.42");
            ASSERT_TRUE(batch->items[i].observed_at > 0);
            break;
        }
    }
    ASSERT_TRUE(found);

    /* Serialize JSON */
    char json_buf[8192];
    size_t json_len = SoftwareInvWin_SerializeJSON("win-endpoint-test-01", batch, json_buf, sizeof(json_buf));
    ASSERT_TRUE(json_len > 0);
    ASSERT_TRUE(strstr(json_buf, "\"endpoint_id\":\"win-endpoint-test-01\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"source\":\"win_registry\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"product\":\"Ominull Agent Test Suite\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"version\":\"1.8.3.42\"") != NULL);

    /* Cleanup HKCU test fixture and batch */
    RegDeleteKeyA(HKEY_CURRENT_USER, testSubkey);
    free(batch);
}

int main(void) {
    printf("=== Running Ominull Windows Software Inventory Tests (Slice 7A) ===\n");
    test_vendor_normalization_win();
    test_json_escaping_win();
    test_registry_collection_live();

    printf("Summary: %d tests passed, %d tests failed.\n", g_tests_run - g_tests_failed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
