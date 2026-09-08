/* Exercise the actual /proc socket collector, not a duplicate parser. */
#include "../include/forensics_linux.h"
#include <assert.h>
int main(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in6 address = {.sin6_family = AF_INET6};
    assert(inet_pton(AF_INET6, "::1", &address.sin6_addr) == 1);
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    char *data = NULL;
    size_t size = 0;
    ForensicCollectorStatus status;
    assert(
        Forensics_CollectSocketToProcess(&data, &size, &status, 1024 * 1024));
    assert(data && size > 0);
    char expected[128];
    snprintf(expected, sizeof(expected),
             "\"local_address\": \"::1\",\n      \"local_port\": %u",
             ntohs(address.sin6_port));
    bool found = strstr(data, expected) != NULL;
    free(data);
    close(fd);
    if (!found) {
        fprintf(stderr, "IPv6 socket address discarded\n");
        return 1;
    }
    puts("IPv6 forensic socket address and ephemeral port preserved");
    return 0;
}
