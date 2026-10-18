/*
 * Release-key signature check for POSIX agents, through the openssl CLI the
 * updater already relies on (no library dependency). Used for the trust
 * bundle: the release key, compiled into the agent, vouches for the response
 * authority's public keys, so a hub cannot make an agent pin keys of its own.
 *
 * The message, signature and public key are written to a fresh 0700
 * directory under the agent's state directory, checked with
 * "openssl dgst -sha256 -verify", and removed.
 */
#ifndef OMINULL_RELEASE_VERIFY_POSIX_H
#define OMINULL_RELEASE_VERIFY_POSIX_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* g_ReleaseVerifyPem = NULL;      /* PEM public key; set before use */
static char g_ReleaseVerifyDir[200] = "/var/lib/ominull";

static inline bool ReleaseVerify_Write(const char* path, const void* data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    const uint8_t* p = (const uint8_t*)data;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    return close(fd) == 0;
}

/* ReleaseVerifyPosixKey checks the signature against the PEM public key pem. */
static inline bool ReleaseVerifyPosixKey(const char* pem, const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    if (!pem || !msg || !der || !derlen) return false;
    char dir[260], fm[300], fs[300], fp[300];
    snprintf(dir, sizeof(dir), "%.190s/.release-verify-XXXXXX", g_ReleaseVerifyDir);
    if (!mkdtemp(dir)) return false;
    snprintf(fm, sizeof(fm), "%s/msg", dir);
    snprintf(fs, sizeof(fs), "%s/sig", dir);
    snprintf(fp, sizeof(fp), "%s/release.pub", dir);
    bool ok = ReleaseVerify_Write(fm, msg, len) && ReleaseVerify_Write(fs, der, derlen) &&
              ReleaseVerify_Write(fp, pem, strlen(pem));
    if (ok) {
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, 0);
                dup2(devnull, 1);
                dup2(devnull, 2);
            }
            char* const argv[] = {(char*)"openssl", (char*)"dgst", (char*)"-sha256", (char*)"-verify", fp, (char*)"-signature", fs, fm, NULL};
            execvp("openssl", argv);
            _exit(127);
        }
        int status = 0;
        ok = false;
        if (pid > 0) {
            pid_t r;
            while ((r = waitpid(pid, &status, 0)) < 0 && errno == EINTR) {
            }
            ok = r == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
    }
    unlink(fm);
    unlink(fs);
    unlink(fp);
    rmdir(dir);
    return ok;
}

/* ReleaseVerifyPosix checks against the compiled-in release key only: the
 * verifier for trust bundles and routine-keys statements. */
static inline bool ReleaseVerifyPosix(const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    return ReleaseVerifyPosixKey(g_ReleaseVerifyPem, msg, len, der, derlen);
}

#ifdef OMINULL_AGENT_TRUST_H
/* ReleaseVerifyPosixXY is the Trust_KeyVerifier for agent updates: the
 * compiled-in key (xy NULL) or a pinned routine key. */
static inline bool ReleaseVerifyPosixXY(const uint8_t* xy, const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    if (!xy) return ReleaseVerifyPosix(msg, len, der, derlen);
    char pem[200];
    return Trust_P256PEM(xy, pem, sizeof(pem)) && ReleaseVerifyPosixKey(pem, msg, len, der, derlen);
}
#endif

#endif
