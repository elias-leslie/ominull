#ifndef OMINULL_HUB_ADDRESS_H
#define OMINULL_HUB_ADDRESS_H
/* Shared URL and complete A/AAAA resolution for transport and isolation. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif
#define OMINULL_MAX_HUB_ADDRESSES 16
typedef struct {
    char addresses[OMINULL_MAX_HUB_ADDRESSES][64];
    size_t count;
    uint16_t port;
} OMINULL_HUB_TARGETS;
static inline void OminullParseHubURL(const char *hubUrl, char *host,
                                      size_t hostLen, uint16_t *port,
                                      bool *isHttps) {
    if (!hostLen)
        return;
    host[0] = '\0';
    *port = 0;
    *isHttps = false;
    if (!hubUrl)
        return;
    const char *begin = hubUrl;
    uint16_t parsedPort = 80;
    bool tls = false;
    if (!strncmp(begin, "https://", 8)) {
        begin += 8;
        parsedPort = 443;
        tls = true;
    } else if (!strncmp(begin, "http://", 7))
        begin += 7;
    else
        return;
    const char *end = strpbrk(begin, "/?#");
    if (!end)
        end = begin + strlen(begin);
    if (end <= begin)
        return;
    const char *name = begin, *nameEnd = end, *portStart = NULL;
    if (begin < end && *begin == '[') {
        name = begin + 1;
        nameEnd = memchr(name, ']', (size_t)(end - name));
        if (!nameEnd)
            return;
        if (nameEnd + 1 < end) {
            if (nameEnd[1] != ':')
                return;
            portStart = nameEnd + 2;
        }
    } else {
        const char *colon = memchr(begin, ':', (size_t)(end - begin));
        if (colon) {
            nameEnd = colon;
            portStart = colon + 1;
        }
    }
    size_t length = (size_t)(nameEnd - name);
    if (!length || length >= hostLen)
        return;
    for (const char *p = name; p < nameEnd; p++)
        if ((unsigned char)*p <= 32 || *p == '@' || *p == '%' || *p == '[')
            return;
    if (portStart) {
        if (portStart == end)
            return;
        unsigned value = 0;
        for (const char *p = portStart; p < end; p++) {
            if (*p < '0' || *p > '9')
                return;
            value = value * 10 + (unsigned)(*p - '0');
            if (value > 65535)
                return;
        }
        if (!value)
            return;
        parsedPort = (uint16_t)value;
    }
    memcpy(host, name, length);
    host[length] = '\0';
    if (*begin == '[') {
        struct in6_addr address;
        if (inet_pton(AF_INET6, host, &address) != 1) {
            host[0] = '\0';
            return;
        }
    }
    *port = parsedPort;
    *isHttps = tls;
}
static inline bool OminullUnscopedPolicyIP(const char *s) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!s || !s[0])
        return false;
    if (inet_pton(AF_INET, s, &v4) == 1)
        return true;
    return inet_pton(AF_INET6, s, &v6) == 1 &&
           !(v6.s6_addr[0] == 0xfe && (v6.s6_addr[1] & 0xc0) == 0x80);
}

static inline bool OminullResolveHub(const char *url,
                                     OMINULL_HUB_TARGETS *targets) {
    memset(targets, 0, sizeof(*targets));
    char host[256];
    uint16_t port;
    bool tls;
    OminullParseHubURL(url, host, sizeof(host), &port, &tls);
    if (!host[0] || !port)
        return false;
    struct addrinfo hints = {0}, *results = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &results) != 0 || !results)
        return false;
    bool valid = true;
    for (struct addrinfo *r = results; r; r = r->ai_next) {
        const void *address = NULL;
        if (r->ai_family == AF_INET)
            address = &((struct sockaddr_in *)r->ai_addr)->sin_addr;
        else if (r->ai_family == AF_INET6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)r->ai_addr;
            if (a->sin6_scope_id) {
                valid = false;
                break;
            }
            address = &a->sin6_addr;
        } else
            continue;
        char literal[64];
        if (!inet_ntop(r->ai_family, address, literal, sizeof(literal)) ||
            !OminullUnscopedPolicyIP(literal)) {
            valid = false;
            break;
        }
        bool duplicate = false;
        for (size_t i = 0; i < targets->count; i++)
            if (!strcmp(literal, targets->addresses[i]))
                duplicate = true;
        if (duplicate)
            continue;
        if (targets->count == OMINULL_MAX_HUB_ADDRESSES) {
            valid = false;
            break;
        }
        strcpy(targets->addresses[targets->count++], literal);
    }
    freeaddrinfo(results);
    if (!valid || !targets->count) {
        memset(targets, 0, sizeof(*targets));
        return false;
    }
    targets->port = port;
    return true;
}

#endif
