/*
 * Ominull Linux Endpoint Authoritative Software Inventory Collector
 *
 * Implements bounded, authoritative package inspection from OS package systems
 * (Debian/Ubuntu /var/lib/dpkg/status, RPM rpmdb queries).
 * Preserves raw maintainer/vendor/version strings alongside normalized values.
 */

#ifndef OMINULL_SOFTWARE_INVENTORY_LINUX_H
#define OMINULL_SOFTWARE_INVENTORY_LINUX_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifndef DEFAULT_DPKG_STATUS_PATH
#define DEFAULT_DPKG_STATUS_PATH "/var/lib/dpkg/status"
#endif

#define MAX_SOFTWARE_PACKAGES 4096
#define MAX_PKG_STR_LEN 128
#define MAX_PKG_RAW_LEN 256

typedef struct {
    char source[32];          /* "dpkg", "rpm" */
    char vendor[MAX_PKG_STR_LEN];         /* Normalized vendor e.g. "ubuntu", "debian", "canonical" */
    char product[MAX_PKG_STR_LEN];        /* Normalized package name */
    char version[MAX_PKG_STR_LEN];        /* Normalized version string */
    char architecture[32];   /* e.g. "amd64", "all" */
    char install_scope[32];   /* "system", "user" */
    char confidence[32];      /* "authoritative", "inferred" */
    char raw_vendor[MAX_PKG_RAW_LEN];     /* Raw Maintainer / Vendor field */
    char raw_product[MAX_PKG_STR_LEN];    /* Raw package name */
    char raw_version[MAX_PKG_STR_LEN];    /* Raw version string */
    int64_t observed_at;
} SoftwarePackageItem;

typedef struct {
    SoftwarePackageItem items[MAX_SOFTWARE_PACKAGES];
    size_t count;
    bool truncated;
    char primary_source[32]; /* "dpkg", "rpm" */
} SoftwareInventoryBatch;

/* ---------------------------------------------------------------------------
 * Helpers: JSON Escaping & String Manipulation
 * ------------------------------------------------------------------------- */

static inline void SoftwareInv_EscapeJson(const char* src, char* dst, size_t dst_cap) {
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

static inline void SoftwareInv_SafeCopy(char* dst, size_t dst_cap, const char* src) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t len = strlen(src);
    if (len >= dst_cap) len = dst_cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static inline void SoftwareInv_Trim(char* s) {
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

static inline void SoftwareInv_NormalizeVendor(const char* raw, char* vendor, size_t vendor_cap) {
    if (!vendor || vendor_cap == 0) return;
    vendor[0] = '\0';
    if (!raw || raw[0] == '\0') {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "unknown");
        return;
    }

    /* Check common distribution / vendor signatures */
    if (strcasestr(raw, "Ubuntu") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "ubuntu");
    } else if (strcasestr(raw, "Debian") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "debian");
    } else if (strcasestr(raw, "Red Hat") != NULL || strcasestr(raw, "CentOS") != NULL || strcasestr(raw, "Fedora") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "redhat");
    } else if (strcasestr(raw, "Canonical") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "canonical");
    } else if (strcasestr(raw, "Microsoft") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "microsoft");
    } else if (strcasestr(raw, "Google") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "google");
    } else if (strcasestr(raw, "Mozilla") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "mozilla");
    } else if (strcasestr(raw, "Apache") != NULL) {
        SoftwareInv_SafeCopy(vendor, vendor_cap, "apache");
    } else {
        /* Take characters before '<' or '(' or first comma */
        size_t idx = 0;
        for (; raw[idx] != '\0' && raw[idx] != '<' && raw[idx] != '(' && raw[idx] != ',' && idx + 1 < vendor_cap; idx++) {
            vendor[idx] = (char)tolower((unsigned char)raw[idx]);
        }
        vendor[idx] = '\0';
        SoftwareInv_Trim(vendor);
        if (vendor[0] == '\0') {
            SoftwareInv_SafeCopy(vendor, vendor_cap, "unknown");
        }
    }
}

/* ---------------------------------------------------------------------------
 * Debian / Ubuntu Package Collector (/var/lib/dpkg/status)
 * ------------------------------------------------------------------------- */

static inline int SoftwareInv_CollectDpkgStatus(const char* status_path, SoftwareInventoryBatch* batch) {
    if (!batch) return -1;
    const char* path = status_path ? status_path : DEFAULT_DPKG_STATUS_PATH;

    FILE* fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    char line[1024];
    char cur_pkg[MAX_PKG_STR_LEN] = {0};
    char cur_ver[MAX_PKG_STR_LEN] = {0};
    char cur_arch[32] = {0};
    char cur_status[128] = {0};
    char cur_maint[MAX_PKG_RAW_LEN] = {0};
    bool in_block = false;

    SoftwareInv_SafeCopy(batch->primary_source, sizeof(batch->primary_source), "dpkg");

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Check for stanza boundary (empty line) */
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') {
            if (in_block && cur_pkg[0] != '\0' && cur_ver[0] != '\0') {
                /* Check status: must be installed and not deinstall/purge/not-installed */
                if (strstr(cur_status, "installed") != NULL &&
                    strstr(cur_status, "not-installed") == NULL &&
                    strstr(cur_status, "deinstall") == NULL &&
                    strstr(cur_status, "purge") == NULL) {

                    if (batch->count < MAX_SOFTWARE_PACKAGES) {
                        SoftwarePackageItem* it = &batch->items[batch->count];
                        memset(it, 0, sizeof(*it));

                        SoftwareInv_SafeCopy(it->source, sizeof(it->source), "dpkg");
                        SoftwareInv_SafeCopy(it->product, sizeof(it->product), cur_pkg);
                        SoftwareInv_SafeCopy(it->raw_product, sizeof(it->raw_product), cur_pkg);

                        SoftwareInv_SafeCopy(it->version, sizeof(it->version), cur_ver);
                        SoftwareInv_SafeCopy(it->raw_version, sizeof(it->raw_version), cur_ver);

                        SoftwareInv_SafeCopy(it->architecture, sizeof(it->architecture), cur_arch[0] ? cur_arch : "all");
                        SoftwareInv_SafeCopy(it->install_scope, sizeof(it->install_scope), "system");
                        SoftwareInv_SafeCopy(it->confidence, sizeof(it->confidence), "authoritative");

                        SoftwareInv_SafeCopy(it->raw_vendor, sizeof(it->raw_vendor), cur_maint);
                        SoftwareInv_NormalizeVendor(cur_maint, it->vendor, sizeof(it->vendor));

                        it->observed_at = (int64_t)time(NULL);
                        batch->count++;
                    } else {
                        batch->truncated = true;
                    }
                }
            }
            cur_pkg[0] = '\0';
            cur_ver[0] = '\0';
            cur_arch[0] = '\0';
            cur_status[0] = '\0';
            cur_maint[0] = '\0';
            in_block = false;
            continue;
        }

        in_block = true;
        if (strncmp(line, "Package: ", 9) == 0) {
            SoftwareInv_SafeCopy(cur_pkg, sizeof(cur_pkg), line + 9);
            SoftwareInv_Trim(cur_pkg);
        } else if (strncmp(line, "Status: ", 8) == 0) {
            SoftwareInv_SafeCopy(cur_status, sizeof(cur_status), line + 8);
            SoftwareInv_Trim(cur_status);
        } else if (strncmp(line, "Version: ", 9) == 0) {
            SoftwareInv_SafeCopy(cur_ver, sizeof(cur_ver), line + 9);
            SoftwareInv_Trim(cur_ver);
        } else if (strncmp(line, "Architecture: ", 14) == 0) {
            SoftwareInv_SafeCopy(cur_arch, sizeof(cur_arch), line + 14);
            SoftwareInv_Trim(cur_arch);
        } else if (strncmp(line, "Maintainer: ", 12) == 0) {
            SoftwareInv_SafeCopy(cur_maint, sizeof(cur_maint), line + 12);
            SoftwareInv_Trim(cur_maint);
        }
    }

    /* Flush trailing block if any */
    if (in_block && cur_pkg[0] != '\0' && cur_ver[0] != '\0') {
        if (strstr(cur_status, "installed") != NULL &&
            strstr(cur_status, "not-installed") == NULL &&
            strstr(cur_status, "deinstall") == NULL &&
            strstr(cur_status, "purge") == NULL) {

            if (batch->count < MAX_SOFTWARE_PACKAGES) {
                SoftwarePackageItem* it = &batch->items[batch->count];
                memset(it, 0, sizeof(*it));

                SoftwareInv_SafeCopy(it->source, sizeof(it->source), "dpkg");
                SoftwareInv_SafeCopy(it->product, sizeof(it->product), cur_pkg);
                SoftwareInv_SafeCopy(it->raw_product, sizeof(it->raw_product), cur_pkg);

                SoftwareInv_SafeCopy(it->version, sizeof(it->version), cur_ver);
                SoftwareInv_SafeCopy(it->raw_version, sizeof(it->raw_version), cur_ver);

                SoftwareInv_SafeCopy(it->architecture, sizeof(it->architecture), cur_arch[0] ? cur_arch : "all");
                SoftwareInv_SafeCopy(it->install_scope, sizeof(it->install_scope), "system");
                SoftwareInv_SafeCopy(it->confidence, sizeof(it->confidence), "authoritative");

                SoftwareInv_SafeCopy(it->raw_vendor, sizeof(it->raw_vendor), cur_maint);
                SoftwareInv_NormalizeVendor(cur_maint, it->vendor, sizeof(it->vendor));

                it->observed_at = (int64_t)time(NULL);
                batch->count++;
            } else {
                batch->truncated = true;
            }
        }
    }

    fclose(fp);
    return 0;
}

/* ---------------------------------------------------------------------------
 * RPM Package Collector (rpmdb / rpm query)
 * ------------------------------------------------------------------------- */

static inline int SoftwareInv_CollectRPM(SoftwareInventoryBatch* batch) {
    if (!batch) return -1;

    /* Check if RPM database path exists */
    struct stat st;
    if (stat("/var/lib/rpm", &st) != 0 && stat("/usr/lib/sysimage/rpm", &st) != 0) {
        return -1;
    }

    FILE* fp = popen("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n' 2>/dev/null", "r");
    if (!fp) {
        return -1;
    }

    SoftwareInv_SafeCopy(batch->primary_source, sizeof(batch->primary_source), "rpm");

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        SoftwareInv_Trim(line);
        if (line[0] == '\0') continue;

        char* name = line;
        char* tab1 = strchr(name, '\t');
        if (!tab1) continue;
        *tab1 = '\0';

        char* ver = tab1 + 1;
        char* tab2 = strchr(ver, '\t');
        if (!tab2) continue;
        *tab2 = '\0';

        char* arch = tab2 + 1;
        char* tab3 = strchr(arch, '\t');
        char* vendor = "unknown";
        if (tab3) {
            *tab3 = '\0';
            vendor = tab3 + 1;
            if (vendor[0] == '\0' || strcmp(vendor, "(none)") == 0) {
                vendor = "unknown";
            }
        }

        if (batch->count < MAX_SOFTWARE_PACKAGES) {
            SoftwarePackageItem* it = &batch->items[batch->count];
            memset(it, 0, sizeof(*it));

            SoftwareInv_SafeCopy(it->source, sizeof(it->source), "rpm");
            SoftwareInv_SafeCopy(it->product, sizeof(it->product), name);
            SoftwareInv_SafeCopy(it->raw_product, sizeof(it->raw_product), name);

            SoftwareInv_SafeCopy(it->version, sizeof(it->version), ver);
            SoftwareInv_SafeCopy(it->raw_version, sizeof(it->raw_version), ver);

            SoftwareInv_SafeCopy(it->architecture, sizeof(it->architecture), arch[0] ? arch : "all");
            SoftwareInv_SafeCopy(it->install_scope, sizeof(it->install_scope), "system");
            SoftwareInv_SafeCopy(it->confidence, sizeof(it->confidence), "authoritative");

            SoftwareInv_SafeCopy(it->raw_vendor, sizeof(it->raw_vendor), vendor);
            SoftwareInv_NormalizeVendor(vendor, it->vendor, sizeof(it->vendor));

            it->observed_at = (int64_t)time(NULL);
            batch->count++;
        } else {
            batch->truncated = true;
        }
    }

    pclose(fp);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Primary Linux Collection Entrypoint
 * ------------------------------------------------------------------------- */

static inline int SoftwareInv_CollectLinux(const char* dpkg_path_override, SoftwareInventoryBatch* batch) {
    if (!batch) return -1;
    memset(batch, 0, sizeof(*batch));

    /* Try Debian/dpkg first */
    if (dpkg_path_override != NULL) {
        return SoftwareInv_CollectDpkgStatus(dpkg_path_override, batch);
    }

    struct stat st;
    if (stat(DEFAULT_DPKG_STATUS_PATH, &st) == 0) {
        return SoftwareInv_CollectDpkgStatus(DEFAULT_DPKG_STATUS_PATH, batch);
    }

    /* Fallback to RPM */
    if (SoftwareInv_CollectRPM(batch) == 0) {
        return 0;
    }

    return -1;
}

/* ---------------------------------------------------------------------------
 * JSON Serialization for Hub Ingestion (/api/v1/software)
 * ------------------------------------------------------------------------- */

static inline size_t SoftwareInv_SerializeJSON(const char* endpoint_id, const SoftwareInventoryBatch* batch, char* out_buf, size_t out_cap) {
    if (!out_buf || out_cap < 32 || !batch) return 0;

    char esc_ep[128] = {0};
    char esc_src[64] = {0};
    SoftwareInv_EscapeJson(endpoint_id ? endpoint_id : "unknown", esc_ep, sizeof(esc_ep));
    SoftwareInv_EscapeJson(batch->primary_source[0] ? batch->primary_source : "dpkg", esc_src, sizeof(esc_src));

    size_t written = 0;
    int n = snprintf(out_buf + written, out_cap - written,
                     "{\"endpoint_id\":\"%s\",\"source\":\"%s\",\"packages\":[",
                     esc_ep, esc_src);
    if (n < 0 || (size_t)n >= out_cap - written) return 0;
    written += (size_t)n;

    char esc_prod[MAX_PKG_STR_LEN * 2];
    char esc_ver[MAX_PKG_STR_LEN * 2];
    char esc_vend[MAX_PKG_STR_LEN * 2];
    char esc_arch[64];
    char esc_raw_prod[MAX_PKG_STR_LEN * 2];
    char esc_raw_ver[MAX_PKG_STR_LEN * 2];
    char esc_raw_vend[MAX_PKG_RAW_LEN * 2];

    for (size_t i = 0; i < batch->count; i++) {
        const SoftwarePackageItem* it = &batch->items[i];
        SoftwareInv_EscapeJson(it->product, esc_prod, sizeof(esc_prod));
        SoftwareInv_EscapeJson(it->version, esc_ver, sizeof(esc_ver));
        SoftwareInv_EscapeJson(it->vendor, esc_vend, sizeof(esc_vend));
        SoftwareInv_EscapeJson(it->architecture, esc_arch, sizeof(esc_arch));
        SoftwareInv_EscapeJson(it->raw_product, esc_raw_prod, sizeof(esc_raw_prod));
        SoftwareInv_EscapeJson(it->raw_version, esc_raw_ver, sizeof(esc_raw_ver));
        SoftwareInv_EscapeJson(it->raw_vendor, esc_raw_vend, sizeof(esc_raw_vend));

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
            /* Out of space; gracefully truncate array */
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

#endif /* OMINULL_SOFTWARE_INVENTORY_LINUX_H */
