/* Shared helpers for the agent's libFuzzer harnesses (scripts/fuzz-agent.sh).
 * Each harness feeds hub-controlled bytes to one parser family under ASan and
 * UBSan; the parsers take NUL-terminated text, so input is copied and
 * terminated first (an embedded NUL just ends the text early, as on the wire). */
#ifndef OMINULL_FUZZ_COMMON_H
#define OMINULL_FUZZ_COMMON_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* Copies data into a fresh heap buffer of exactly size+1 bytes, so ASan sees
 * any read past the terminator. */
static inline char* Fuzz_Text(const uint8_t* data, size_t size) {
    char* s = (char*)malloc(size + 1);
    if (!s) abort();
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

/* The parsers log refusals to stdout; keep the fuzzer's output readable. */
static inline void Fuzz_QuietStdout(void) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) { dup2(fd, 1); close(fd); }
}
#endif
