#ifndef OMINULL_HUB_SCRAPE_H
#define OMINULL_HUB_SCRAPE_H

/*
 * Plain-search field readers for the small flat parts of the hub's replies: the
 * update descriptor, the enrollment credential and the threat list. Nothing here
 * is a security decision on its own: a descriptor's values are checked against
 * the release statement, and a threat address against the address rules, by the
 * caller. Field values carry no escapes, so a value is everything up to the next
 * quote; one longer than the buffer is cut there and the checks downstream refuse it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "hub_input.h"

/* "key":"value" with nothing between. */
static inline bool Scrape_StringFlat(const char* json, const char* key, char* out, size_t outLen) {
#ifdef HI_SCRAPE
    return hi_scrape_string_flat(json, key, out, outLen);
#else
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);
    size_t idx = 0;
    while (*p && *p != '"' && idx < outLen - 1) {
        out[idx++] = *p++;
    }
    out[idx] = '\0';
    return idx > 0;
#endif
}

/* "key": then spaces or tabs, then a string. */
static inline bool Scrape_StringSpaced(const char* json, const char* key, char* out, size_t outLen) {
#ifdef HI_SCRAPE
    return hi_scrape_string_spaced(json, key, out, outLen);
#else
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* p = strstr(json, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outLen - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
#endif
}

/* The omd_ credential an enrolled endpoint receives: whole, and the right shape. */
static inline bool Scrape_DeviceCredential(const char* json, char* out, size_t outLen) {
#ifdef HI_SCRAPE
    return hi_scrape_device_credential(json, out, outLen);
#else
    const char* marker = strstr(json, "\"device_credential\":\"");
    if (!marker || outLen == 0) return false;
    marker += strlen("\"device_credential\":\"");
    size_t n = 0;
    while (marker[n] && marker[n] != '"' && n < outLen - 1) n++;
    if (marker[n] != '"') return false;
    memcpy(out, marker, n);
    out[n] = '\0';
    return n == 68 && strncmp(out, "omd_", 4) == 0;
#endif
}

/* Hands each token of the flat array "key":[...] to take. */
static inline void Scrape_AddressList(const char* json, const char* key, void (*take)(const char* ip, void* ctx), void* ctx) {
#ifdef HI_SCRAPE
    hi_scrape_address_list(json, key, take, ctx);
#else
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":[", key);
    const char* p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    while (*p && *p != ']') {
        while (*p && (*p == ' ' || *p == ',' || *p == '"' || *p == '\n' || *p == '\r')) p++;
        if (*p == ']' || !*p) break;
        char ip[64] = {0};
        int idx = 0;
        while (*p && *p != '"' && *p != ']' && *p != ',' && idx < (int)sizeof(ip) - 1) {
            ip[idx++] = *p++;
        }
        if (!ip[0]) continue;
        take(ip, ctx);
    }
#endif
}

#endif
