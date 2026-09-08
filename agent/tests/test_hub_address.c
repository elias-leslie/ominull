#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
static int answers = 2, scoped;
static struct addrinfo records[17];
static struct sockaddr_in v4;
static struct sockaddr_in6 v6[17];
static int FixtureResolve(const char *host, const char *service,
                          const struct addrinfo *hints, struct addrinfo **out) {
    (void)service;
    assert(!strcmp(host, "hub.example") && hints->ai_family == AF_UNSPEC);
    memset(records, 0, sizeof(records));
    memset(v6, 0, sizeof(v6));
    for (int i = 0; i < answers; i++) {
        records[i].ai_family = AF_INET6;
        records[i].ai_addr = (void *)&v6[i];
        records[i].ai_addrlen = sizeof(v6[i]);
        inet_pton(AF_INET6, "2001:db8::1", &v6[i].sin6_addr);
        v6[i].sin6_addr.s6_addr[15] = i + 1;
        v6[i].sin6_family = AF_INET6;
        v6[i].sin6_scope_id = scoped ? 11 : 0;
        records[i].ai_next = i + 1 < answers ? &records[i + 1] : NULL;
    }
    v4.sin_family = AF_INET;
    inet_pton(AF_INET, "203.0.113.9", &v4.sin_addr);
    records[0].ai_family = AF_INET;
    records[0].ai_addr = (void *)&v4;
    records[0].ai_addrlen = sizeof(v4);
    *out = records;
    return 0;
}
static void FixtureFree(struct addrinfo *p) { assert(p == records); }
#define getaddrinfo FixtureResolve
#define freeaddrinfo FixtureFree
#include "../include/hub_address.h"
int main(void) {
    char host[256];
    uint16_t port;
    bool tls;
    OminullParseHubURL("https://[2001:db8::9]:9443/path", host, sizeof(host),
                       &port, &tls);
    assert(!strcmp(host, "2001:db8::9") && port == 9443 && tls);
    const char *bad[] = {"https://",
                         "https://[]:443",
                         "https://[fe80::1%11]:443",
                         "https://u@host:443",
                         "https://host:0",
                         "https://host:65536",
                         "https://host:999999999999999999999999",
                         "https://host:443junk",
                         "https://2001:db8::1",
                         "ftp://host"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        OminullParseHubURL(bad[i], host, sizeof(host), &port, &tls);
        assert(!host[0] && !port);
    }
    OMINULL_HUB_TARGETS targets;
    assert(OminullResolveHub("https://hub.example:9443", &targets));
    assert(targets.count == 2 && targets.port == 9443);
    assert(!strcmp(targets.addresses[0], "203.0.113.9") &&
           !strcmp(targets.addresses[1], "2001:db8::2"));
    answers = 17;
    assert(!OminullResolveHub("https://hub.example:9443", &targets) &&
           !targets.count);
    answers = 2;
    scoped = 1;
    assert(!OminullResolveHub("https://hub.example:9443", &targets) &&
           !targets.count);
    puts("Shared hub parser and complete A/AAAA resolver: port, bounds, scope "
         "rejection passed");
    return 0;
}
