/*
 * Ominull Windows Endpoint Authoritative Software Inventory Collector
 *
 * Implements authoritative installed software inspection from Windows Uninstall registry keys:
 * - HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall (64-bit and 32-bit WoW64)
 * - HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall (per-user)
 *
 * Preserves raw DisplayName/Publisher/DisplayVersion alongside normalized fields.
 */

#ifndef OMINULL_SOFTWARE_INVENTORY_WINDOWS_H
#define OMINULL_SOFTWARE_INVENTORY_WINDOWS_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#define MAX_SOFTWARE_PACKAGES_WIN 4096
#define MAX_PKG_STR_LEN_WIN 128
#define MAX_PKG_RAW_LEN_WIN 256

typedef struct {
    char source[32];          /* "win_registry", "msi" */
    char vendor[MAX_PKG_STR_LEN_WIN];     /* Normalized publisher/vendor */
    char product[MAX_PKG_STR_LEN_WIN];    /* Normalized display name */
    char version[MAX_PKG_STR_LEN_WIN];    /* Normalized version string */
    char architecture[32];   /* "x64", "x86" */
    char install_scope[32];   /* "system", "user" */
    char confidence[32];      /* "authoritative", "inferred" */
    char raw_vendor[MAX_PKG_RAW_LEN_WIN]; /* Raw Publisher string */
    char raw_product[MAX_PKG_STR_LEN_WIN];/* Raw DisplayName */
    char raw_version[MAX_PKG_STR_LEN_WIN];/* Raw DisplayVersion */
    int64_t observed_at;
} SoftwarePackageItemWin;

typedef struct {
    SoftwarePackageItemWin items[MAX_SOFTWARE_PACKAGES_WIN];
    size_t count;
    bool truncated;
    char primary_source[32]; /* "win_registry" */
} SoftwareInventoryBatchWin;

/* ---------------------------------------------------------------------------
 * Safe String & JSON Escaping Helpers
 * ------------------------------------------------------------------------- */

static inline void SoftwareInvWin_SafeCopy(char* dst, size_t dst_cap, const char* src) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t len = strlen(src);
    if (len >= dst_cap) len = dst_cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static inline void SoftwareInvWin_Trim(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
    char* start = s;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
}

static inline void SoftwareInvWin_EscapeJson(const char* src, char* dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t out = 0;
    for (size_t in = 0; src[in] != '\0' && out + 2 < dst_cap; in++) {
        unsigned char c = (unsigned char)src[in];
        if (c == '"') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = '"';
        } else if (c == '\\') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = '\\';
        } else if (c == '\b') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'b';
        } else if (c == '\f') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'f';
        } else if (c == '\n') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'n';
        } else if (c == '\r') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 'r';
        } else if (c == '\t') {
            if (out + 2 >= dst_cap) break;
            dst[out++] = '\\'; dst[out++] = 't';
        } else if (c < 0x20) {
            if (out + 6 >= dst_cap) break;
            int written = snprintf(dst + out, dst_cap - out, "\\u%04x", c);
            if (written > 0) out += (size_t)written;
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

static inline void SoftwareInvWin_NormalizeVendor(const char* raw, char* vendor, size_t vendor_cap) {
    if (!vendor || vendor_cap == 0) return;
    vendor[0] = '\0';
    if (!raw || raw[0] == '\0') {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "unknown");
        return;
    }

    /* Common software publisher signatures */
    if (strstr(raw, "Microsoft") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "microsoft");
    } else if (strstr(raw, "Google") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "google");
    } else if (strstr(raw, "Mozilla") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "mozilla");
    } else if (strstr(raw, "Oracle") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "oracle");
    } else if (strstr(raw, "Git") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "git");
    } else if (strstr(raw, "Adobe") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "adobe");
    } else if (strstr(raw, "Apple") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "apple");
    } else if (strstr(raw, "Valve") != NULL) {
        SoftwareInvWin_SafeCopy(vendor, vendor_cap, "valve");
    } else {
        /* Take characters before comma or legal suffixes */
        size_t idx = 0;
        for (; raw[idx] != '\0' && raw[idx] != ',' && raw[idx] != '(' && idx + 1 < vendor_cap; idx++) {
            vendor[idx] = (char)tolower((unsigned char)raw[idx]);
        }
        vendor[idx] = '\0';
        SoftwareInvWin_Trim(vendor);
        if (vendor[0] == '\0') {
            SoftwareInvWin_SafeCopy(vendor, vendor_cap, "unknown");
        }
    }
}

/* ---------------------------------------------------------------------------
 * Registry Query Helper
 * ------------------------------------------------------------------------- */

static inline void SoftwareInvWin_QueryRegistryKey(
    HKEY hRootKey,
    const char* subkeyPath,
    REGSAM accessFlags,
    const char* arch,
    const char* scope,
    SoftwareInventoryBatchWin* batch
) {
    if (!batch) return;

    HKEY hUninstallKey = NULL;
    LONG res = RegOpenKeyExA(hRootKey, subkeyPath, 0, KEY_READ | accessFlags, &hUninstallKey);
    if (res != ERROR_SUCCESS || !hUninstallKey) {
        return;
    }

    DWORD subkeyCount = 0;
    DWORD maxSubkeyLen = 0;
    res = RegQueryInfoKeyA(
        hUninstallKey, NULL, NULL, NULL,
        &subkeyCount, &maxSubkeyLen, NULL, NULL, NULL, NULL, NULL, NULL
    );
    if (res != ERROR_SUCCESS || subkeyCount == 0) {
        RegCloseKey(hUninstallKey);
        return;
    }

    char subkeyName[256];
    for (DWORD i = 0; i < subkeyCount; i++) {
        DWORD nameLen = sizeof(subkeyName);
        res = RegEnumKeyExA(hUninstallKey, i, subkeyName, &nameLen, NULL, NULL, NULL, NULL);
        if (res != ERROR_SUCCESS) continue;

        HKEY hAppKey = NULL;
        res = RegOpenKeyExA(hUninstallKey, subkeyName, 0, KEY_READ | accessFlags, &hAppKey);
        if (res != ERROR_SUCCESS || !hAppKey) continue;

        /* Check SystemComponent */
        DWORD sysComp = 0;
        DWORD sysCompSize = sizeof(sysComp);
        if (RegQueryValueExA(hAppKey, "SystemComponent", NULL, NULL, (LPBYTE)&sysComp, &sysCompSize) == ERROR_SUCCESS) {
            if (sysComp == 1) {
                RegCloseKey(hAppKey);
                continue;
            }
        }

        /* Check ParentKeyName (child patch/component) */
        char parentKey[128] = {0};
        DWORD parentKeySize = sizeof(parentKey);
        if (RegQueryValueExA(hAppKey, "ParentKeyName", NULL, NULL, (LPBYTE)parentKey, &parentKeySize) == ERROR_SUCCESS) {
            SoftwareInvWin_Trim(parentKey);
            if (parentKey[0] != '\0') {
                RegCloseKey(hAppKey);
                continue;
            }
        }

        /* Read DisplayName */
        char displayName[MAX_PKG_RAW_LEN_WIN] = {0};
        DWORD nameSize = sizeof(displayName);
        res = RegQueryValueExA(hAppKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &nameSize);
        if (res != ERROR_SUCCESS || displayName[0] == '\0') {
            RegCloseKey(hAppKey);
            continue;
        }
        SoftwareInvWin_Trim(displayName);
        if (displayName[0] == '\0') {
            RegCloseKey(hAppKey);
            continue;
        }

        /* Read DisplayVersion */
        char displayVersion[MAX_PKG_RAW_LEN_WIN] = {0};
        DWORD verSize = sizeof(displayVersion);
        res = RegQueryValueExA(hAppKey, "DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &verSize);
        if (res != ERROR_SUCCESS || displayVersion[0] == '\0') {
            SoftwareInvWin_SafeCopy(displayVersion, sizeof(displayVersion), "1.0");
        }
        SoftwareInvWin_Trim(displayVersion);

        /* Read Publisher */
        char publisher[MAX_PKG_RAW_LEN_WIN] = {0};
        DWORD pubSize = sizeof(publisher);
        res = RegQueryValueExA(hAppKey, "Publisher", NULL, NULL, (LPBYTE)publisher, &pubSize);
        if (res != ERROR_SUCCESS || publisher[0] == '\0') {
            SoftwareInvWin_SafeCopy(publisher, sizeof(publisher), "unknown");
        }
        SoftwareInvWin_Trim(publisher);

        /* Read WindowsInstaller */
        DWORD winInstaller = 0;
        DWORD winInstSize = sizeof(winInstaller);
        bool isMsi = false;
        if (RegQueryValueExA(hAppKey, "WindowsInstaller", NULL, NULL, (LPBYTE)&winInstaller, &winInstSize) == ERROR_SUCCESS) {
            if (winInstaller == 1) {
                isMsi = true;
            }
        }

        RegCloseKey(hAppKey);

        /* Deduplicate against existing batch items */
        bool duplicate = false;
        for (size_t k = 0; k < batch->count; k++) {
            if (strcmp(batch->items[k].product, displayName) == 0 &&
                strcmp(batch->items[k].version, displayVersion) == 0 &&
                strcmp(batch->items[k].architecture, arch) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;

        if (batch->count < MAX_SOFTWARE_PACKAGES_WIN) {
            SoftwarePackageItemWin* it = &batch->items[batch->count];
            memset(it, 0, sizeof(*it));

            SoftwareInvWin_SafeCopy(it->source, sizeof(it->source), isMsi ? "msi" : "win_registry");
            SoftwareInvWin_SafeCopy(it->product, sizeof(it->product), displayName);
            SoftwareInvWin_SafeCopy(it->raw_product, sizeof(it->raw_product), displayName);

            SoftwareInvWin_SafeCopy(it->version, sizeof(it->version), displayVersion);
            SoftwareInvWin_SafeCopy(it->raw_version, sizeof(it->raw_version), displayVersion);

            SoftwareInvWin_SafeCopy(it->architecture, sizeof(it->architecture), arch);
            SoftwareInvWin_SafeCopy(it->install_scope, sizeof(it->install_scope), scope);
            SoftwareInvWin_SafeCopy(it->confidence, sizeof(it->confidence), "authoritative");

            SoftwareInvWin_SafeCopy(it->raw_vendor, sizeof(it->raw_vendor), publisher);
            SoftwareInvWin_NormalizeVendor(publisher, it->vendor, sizeof(it->vendor));

            it->observed_at = (int64_t)time(NULL);
            batch->count++;
        } else {
            batch->truncated = true;
        }
    }

    RegCloseKey(hUninstallKey);
}

/* ---------------------------------------------------------------------------
 * Primary Windows Collection Entrypoint
 * ------------------------------------------------------------------------- */

static inline int SoftwareInvWin_Collect(SoftwareInventoryBatchWin* batch) {
    if (!batch) return -1;
    memset(batch, 0, sizeof(*batch));
    SoftwareInvWin_SafeCopy(batch->primary_source, sizeof(batch->primary_source), "win_registry");

    const char* uninstallPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    /* 1. HKLM 64-bit hive (or native on 32-bit) */
    SoftwareInvWin_QueryRegistryKey(HKEY_LOCAL_MACHINE, uninstallPath, KEY_WOW64_64KEY, "x64", "system", batch);

    /* 2. HKLM 32-bit WoW64 hive */
    SoftwareInvWin_QueryRegistryKey(HKEY_LOCAL_MACHINE, uninstallPath, KEY_WOW64_32KEY, "x86", "system", batch);

    /* 3. HKCU (Per-user installations) */
    SoftwareInvWin_QueryRegistryKey(HKEY_CURRENT_USER, uninstallPath, 0, "x64", "user", batch);

    return 0;
}

/* ---------------------------------------------------------------------------
 * JSON Serialization for Hub Ingestion (/api/v1/software)
 * ------------------------------------------------------------------------- */

static inline size_t SoftwareInvWin_SerializeJSON(
    const char* endpoint_id,
    const SoftwareInventoryBatchWin* batch,
    char* out_buf,
    size_t out_cap
) {
    if (!out_buf || out_cap < 32 || !batch) return 0;

    char esc_ep[128] = {0};
    char esc_src[64] = {0};
    SoftwareInvWin_EscapeJson(endpoint_id ? endpoint_id : "unknown", esc_ep, sizeof(esc_ep));
    SoftwareInvWin_EscapeJson(batch->primary_source[0] ? batch->primary_source : "win_registry", esc_src, sizeof(esc_src));

    size_t written = 0;
    int n = snprintf(out_buf + written, out_cap - written,
                     "{\"endpoint_id\":\"%s\",\"source\":\"%s\",\"packages\":[",
                     esc_ep, esc_src);
    if (n < 0 || (size_t)n >= out_cap - written) return 0;
    written += (size_t)n;

    char esc_prod[MAX_PKG_STR_LEN_WIN * 2];
    char esc_ver[MAX_PKG_STR_LEN_WIN * 2];
    char esc_vend[MAX_PKG_STR_LEN_WIN * 2];
    char esc_arch[64];
    char esc_raw_prod[MAX_PKG_STR_LEN_WIN * 2];
    char esc_raw_ver[MAX_PKG_STR_LEN_WIN * 2];
    char esc_raw_vend[MAX_PKG_RAW_LEN_WIN * 2];

    for (size_t i = 0; i < batch->count; i++) {
        const SoftwarePackageItemWin* it = &batch->items[i];
        SoftwareInvWin_EscapeJson(it->product, esc_prod, sizeof(esc_prod));
        SoftwareInvWin_EscapeJson(it->version, esc_ver, sizeof(esc_ver));
        SoftwareInvWin_EscapeJson(it->vendor, esc_vend, sizeof(esc_vend));
        SoftwareInvWin_EscapeJson(it->architecture, esc_arch, sizeof(esc_arch));
        SoftwareInvWin_EscapeJson(it->raw_product, esc_raw_prod, sizeof(esc_raw_prod));
        SoftwareInvWin_EscapeJson(it->raw_version, esc_raw_ver, sizeof(esc_raw_ver));
        SoftwareInvWin_EscapeJson(it->raw_vendor, esc_raw_vend, sizeof(esc_raw_vend));

        n = snprintf(out_buf + written, out_cap - written,
                     "%s{\"source\":\"%s\",\"vendor\":\"%s\",\"product\":\"%s\",\"version\":\"%s\","
                     "\"architecture\":\"%s\",\"install_scope\":\"%s\",\"confidence\":\"%s\","
                     "\"raw_vendor\":\"%s\",\"raw_product\":\"%s\",\"raw_version\":\"%s\","
                     "\"observed_at\":\"%lld\"}",
                     (i > 0 ? "," : ""),
                     it->source, esc_vend, esc_prod, esc_ver,
                     esc_arch, it->install_scope, it->confidence,
                     esc_raw_vend, esc_raw_prod, esc_raw_ver,
                     (long long)it->observed_at);

        if (n < 0 || (size_t)n >= out_cap - written) {
            break;
        }
        written += (size_t)n;
    }

    if (written + 3 >= out_cap) return 0;
    out_buf[written++] = ']';
    out_buf[written++] = '}';
    out_buf[written] = '\0';

    return written;
}

#endif /* _WIN32 */

#endif /* OMINULL_SOFTWARE_INVENTORY_WINDOWS_H */
