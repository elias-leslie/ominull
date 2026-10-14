#ifndef OMINULL_TERMINAL_LINUX_H
#define OMINULL_TERMINAL_LINUX_H

/*
 * Ominull Linux Pseudoterminal Worker (Slice 3B.1)
 *
 * Implements:
 * - Strict allowlist validation: /bin/sh and /bin/bash only.
 * - Pseudoterminal allocation via forkpty(3).
 * - Sanitized minimal execution environment (TERM, PATH, HOME, USER, SHELL).
 * - Safe working directory (/var/lib/ominull or /root).
 * - Full-duplex WebSocket relay over authenticated loopback via libcurl CONNECT_ONLY.
 * - Dynamic window resize propagation (TIOCSWINSZ).
 * - Fail-closed child-tree termination (SIGKILL to process group).
 *
 * WebSocket client (RFC 6455): random handshake key and frame masks from the
 * kernel CSPRNG; buffered, non-blocking frame reader that accepts 7/16/64-bit
 * lengths up to TERMINAL_MAX_MESSAGE, reassembles continuation frames, answers
 * pings and keeps bytes that arrived with the 101 response. Stdin is queued and
 * written to the pty as it drains, so a large paste never blocks shell output.
 */

#include <pty.h>
#include <utmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <curl/curl.h>

#include "terminal_frame.h"

#define TERMINAL_MAX_FRAME_SIZE 65536    /* largest frame the agent sends */
#define TERMINAL_MAX_MESSAGE 1048576     /* largest message the agent accepts */
#define TERMINAL_MAX_QUEUE 1048576
#define TERMINAL_STDOUT_CHUNK 32768      /* pty bytes coalesced into one stdout frame */
#define TERMINAL_STDIN_QUEUE_MAX (4 * 1048576)
#define TERMINAL_FRAMES_PER_TURN 64      /* incoming messages handled before draining the pty again */

/* ---------------------------------------------------------------------------
 * Allowlist Validation
 * ------------------------------------------------------------------------- */

static inline bool Terminal_IsAllowedProgram(const char* program) {
    if (!program || program[0] == '\0') return false;
    if (strcmp(program, "/bin/sh") == 0 || strcmp(program, "/bin/bash") == 0) {
        return (access(program, X_OK) == 0);
    }
    return false;
}

typedef struct {
    char session_id[64];
    char program[64];
    char connect_token[128];
} TerminalSessionParams;

static inline bool Terminal_ParsePayload(const char* json, TerminalSessionParams* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    if (!TermPayload_Parse(json, out->session_id, sizeof(out->session_id), out->program, sizeof(out->program),
                           out->connect_token, sizeof(out->connect_token))) {
        return false;
    }
    if (out->session_id[0] == '\0' || out->connect_token[0] == '\0') {
        return false;
    }
    if (out->program[0] == '\0') {
        strncpy(out->program, "/bin/bash", sizeof(out->program) - 1);
    }
    return Terminal_IsAllowedProgram(out->program);
}

/* ---------------------------------------------------------------------------
 * Base64 Encoding & Decoding
 * ------------------------------------------------------------------------- */

static inline size_t Terminal_Base64Encode(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    return TermB64_Encode(in, in_len, out, out_max);
}

static inline size_t Terminal_Base64Decode(const char* in, size_t in_len, unsigned char* out, size_t out_max) {
    return TermB64_Decode(in, in_len, out, out_max);
}

/* ---------------------------------------------------------------------------
 * CSPRNG
 * ------------------------------------------------------------------------- */

static inline bool Terminal_Random(unsigned char* out, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(out + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)n;
    }
    if (off == len) return true;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    while (off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    close(fd);
    return true;
}

/* ---------------------------------------------------------------------------
 * RFC 6455 WebSocket client connection
 * ------------------------------------------------------------------------- */

typedef struct {
    CURL* curl;            /* libcurl CONNECT_ONLY transport, or NULL */
    int fd;                /* raw socket transport (tests), used when curl is NULL */
    int poll_fd;           /* descriptor to poll for readiness */
    unsigned char* in;     /* received, not yet parsed bytes */
    size_t in_len;
    size_t in_cap;
    unsigned char* msg;    /* message being reassembled */
    size_t msg_len;
    size_t msg_cap;
    int msg_opcode;
    bool in_msg;
    bool msg_ready;        /* msg holds a delivered message to be dropped on the next call */
    unsigned char ctrl[126];
    unsigned char mask_pool[256];
    size_t mask_pos;
} TerminalWs;

static inline void TerminalWs_Init(TerminalWs* ws, CURL* curl, int fd, int poll_fd) {
    memset(ws, 0, sizeof(*ws));
    ws->curl = curl;
    ws->fd = fd;
    ws->poll_fd = poll_fd;
    ws->mask_pos = sizeof(ws->mask_pool);
}

static inline void TerminalWs_Free(TerminalWs* ws) {
    free(ws->in);
    free(ws->msg);
    ws->in = ws->msg = NULL;
    ws->in_len = ws->in_cap = ws->msg_len = ws->msg_cap = 0;
}

/* >0 bytes read, 0 would block, -1 closed or failed. */
static inline ssize_t TerminalWs_RawRecv(TerminalWs* ws, unsigned char* buf, size_t len) {
    if (ws->curl) {
        size_t n = 0;
        CURLcode res = curl_easy_recv(ws->curl, buf, len, &n);
        if (res == CURLE_AGAIN) return 0;
        if (res != CURLE_OK || n == 0) return -1;
        return (ssize_t)n;
    }
    ssize_t n = recv(ws->fd, buf, len, MSG_DONTWAIT);
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
    return n == 0 ? -1 : n;
}

/* >=0 bytes sent (0 would block), -1 failed. */
static inline ssize_t TerminalWs_RawSend(TerminalWs* ws, const unsigned char* buf, size_t len) {
    if (ws->curl) {
        size_t n = 0;
        CURLcode res = curl_easy_send(ws->curl, buf, len, &n);
        if (res == CURLE_AGAIN) return 0;
        if (res != CURLE_OK) return -1;
        return (ssize_t)n;
    }
    ssize_t n = send(ws->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
    return n;
}

static inline bool TerminalWs_SendAll(TerminalWs* ws, const unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = TerminalWs_RawSend(ws, buf + off, len - off);
        if (n < 0) return false;
        if (n == 0) {
            struct pollfd pfd = { .fd = ws->poll_fd, .events = POLLOUT, .revents = 0 };
            int pr = poll(&pfd, 1, 5000);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) return false;
            continue;
        }
        off += (size_t)n;
    }
    return true;
}

static inline bool TerminalWs_Mask(TerminalWs* ws, unsigned char mask[4]) {
    if (ws->mask_pos + 4 > sizeof(ws->mask_pool)) {
        if (!Terminal_Random(ws->mask_pool, sizeof(ws->mask_pool))) return false;
        ws->mask_pos = 0;
    }
    memcpy(mask, ws->mask_pool + ws->mask_pos, 4);
    ws->mask_pos += 4;
    return true;
}

static inline bool TerminalWs_SendFrame(TerminalWs* ws, int opcode, const unsigned char* payload, size_t payload_len) {
    if (payload_len > TERMINAL_MAX_FRAME_SIZE) return false;
    unsigned char hdr[14];
    size_t hl = 0;
    hdr[0] = 0x80 | (opcode & 0x0F);
    if (payload_len < 126) {
        hdr[1] = 0x80 | (uint8_t)payload_len;
        hl = 2;
    } else if (payload_len <= 65535) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (payload_len >> 8) & 0xFF;
        hdr[3] = payload_len & 0xFF;
        hl = 4;
    } else {
        hdr[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) hdr[2 + i] = (uint8_t)(((uint64_t)payload_len >> (56 - 8 * i)) & 0xFF);
        hl = 10;
    }
    unsigned char mask[4];
    if (!TerminalWs_Mask(ws, mask)) return false;
    memcpy(hdr + hl, mask, 4);
    hl += 4;

    unsigned char stackbuf[16384];
    size_t total = hl + payload_len;
    unsigned char* frame = total <= sizeof(stackbuf) ? stackbuf : (unsigned char*)malloc(total);
    if (!frame) return false;
    memcpy(frame, hdr, hl);
    for (size_t i = 0; i < payload_len; i++) frame[hl + i] = payload[i] ^ mask[i & 3];
    bool ok = TerminalWs_SendAll(ws, frame, total);
    if (frame != stackbuf) free(frame);
    return ok;
}

/* Back-compat wrapper used by older call sites and tests. */
static inline bool Terminal_SendWsFrame(CURL* curl, curl_socket_t sock, int opcode, const unsigned char* payload, size_t payload_len) {
    TerminalWs ws;
    TerminalWs_Init(&ws, curl, (int)sock, (int)sock);
    bool ok = TerminalWs_SendFrame(&ws, opcode, payload, payload_len);
    TerminalWs_Free(&ws);
    return ok;
}

static inline bool TerminalWs_Reserve(unsigned char** buf, size_t* cap, size_t need) {
    if (need <= *cap) return true;
    size_t ncap = *cap ? *cap : 16384;
    while (ncap < need) ncap *= 2;
    unsigned char* nb = (unsigned char*)realloc(*buf, ncap);
    if (!nb) return false;
    *buf = nb;
    *cap = ncap;
    return true;
}

/* Feeds bytes that arrived before the frame stream was handed over (the tail of
 * the HTTP 101 read). */
static inline bool TerminalWs_Prefill(TerminalWs* ws, const unsigned char* data, size_t len) {
    if (len == 0) return true;
    if (!TerminalWs_Reserve(&ws->in, &ws->in_cap, ws->in_len + len)) return false;
    memcpy(ws->in + ws->in_len, data, len);
    ws->in_len += len;
    return true;
}

/*
 * Next complete message, without blocking. Returns 1 and sets opcode/data/len
 * (data stays valid until the next call; it is NUL-terminated), 0 when more
 * bytes are needed, -1 on a protocol error, an oversized message or a closed
 * transport. Control frames (ping 9, pong 10, close 8) are returned as they
 * arrive, also in the middle of a fragmented message.
 */
static inline int TerminalWs_Next(TerminalWs* ws, int* opcode, unsigned char** data, size_t* len) {
    if (ws->msg_ready) {
        ws->msg_ready = false;
        ws->msg_len = 0;
    }
    for (;;) {
        /* Try to parse one frame from the buffer. */
        if (ws->in_len >= 2) {
            unsigned char* b = ws->in;
            bool fin = (b[0] & 0x80) != 0;
            int op = b[0] & 0x0F;
            bool masked = (b[1] & 0x80) != 0;
            uint64_t plen = b[1] & 0x7F;
            size_t hl = 2;
            bool have_header = true;
            if (plen == 126) {
                if (ws->in_len < 4) have_header = false;
                else {
                    plen = ((uint64_t)b[2] << 8) | b[3];
                    hl = 4;
                }
            } else if (plen == 127) {
                if (ws->in_len < 10) have_header = false;
                else {
                    plen = 0;
                    for (int i = 0; i < 8; i++) plen = (plen << 8) | b[2 + i];
                    hl = 10;
                }
            }
            if (have_header) {
                if ((b[0] & 0x70) != 0) return -1; /* no extensions negotiated */
                if (plen > TERMINAL_MAX_MESSAGE) return -1;
                if (op >= 8 && (plen > 125 || !fin)) return -1;
                size_t mask_off = hl;
                if (masked) hl += 4;
                if (ws->in_len >= hl + plen) {
                    unsigned char* p = b + hl;
                    if (masked) {
                        for (uint64_t i = 0; i < plen; i++) p[i] ^= b[mask_off + (i & 3)];
                    }
                    size_t consumed = hl + (size_t)plen;
                    int result = 0;
                    if (op >= 8) {
                        memcpy(ws->ctrl, p, (size_t)plen);
                        ws->ctrl[plen] = '\0';
                        *opcode = op;
                        *data = ws->ctrl;
                        *len = (size_t)plen;
                        result = 1;
                    } else {
                        if (op == 0) {
                            if (!ws->in_msg) return -1;
                        } else if (op == 1 || op == 2) {
                            if (ws->in_msg) return -1;
                            ws->in_msg = true;
                            ws->msg_opcode = op;
                            ws->msg_len = 0;
                        } else {
                            return -1;
                        }
                        if (ws->msg_len + plen > TERMINAL_MAX_MESSAGE) return -1;
                        if (!TerminalWs_Reserve(&ws->msg, &ws->msg_cap, ws->msg_len + (size_t)plen + 1)) return -1;
                        memcpy(ws->msg + ws->msg_len, p, (size_t)plen);
                        ws->msg_len += (size_t)plen;
                        if (fin) {
                            ws->in_msg = false;
                            ws->msg[ws->msg_len] = '\0';
                            ws->msg_ready = true;
                            *opcode = ws->msg_opcode;
                            *data = ws->msg;
                            *len = ws->msg_len;
                            result = 1;
                        }
                    }
                    memmove(ws->in, ws->in + consumed, ws->in_len - consumed);
                    ws->in_len -= consumed;
                    if (result) return 1;
                    continue;
                }
            }
        }
        /* Need more bytes. */
        if (!TerminalWs_Reserve(&ws->in, &ws->in_cap, ws->in_len + 16384)) return -1;
        ssize_t n = TerminalWs_RawRecv(ws, ws->in + ws->in_len, ws->in_cap - ws->in_len);
        if (n == 0) return 0;
        if (n < 0) return -1;
        ws->in_len += (size_t)n;
    }
}

/* ---------------------------------------------------------------------------
 * Pty stdin queue
 * ------------------------------------------------------------------------- */

typedef struct {
    unsigned char* buf;
    size_t len;
    size_t cap;
} TerminalStdinQueue;

static inline bool TerminalStdin_Push(TerminalStdinQueue* q, const unsigned char* data, size_t len) {
    if (q->len + len > TERMINAL_STDIN_QUEUE_MAX) return false;
    if (!TerminalWs_Reserve(&q->buf, &q->cap, q->len + len)) return false;
    memcpy(q->buf + q->len, data, len);
    q->len += len;
    return true;
}

/* Writes as much of the queue as the pty takes now. Returns false on a hard error. */
static inline bool TerminalStdin_Flush(TerminalStdinQueue* q, int fd) {
    size_t off = 0;
    while (off < q->len) {
        ssize_t n = write(fd, q->buf + off, q->len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return false;
    }
    if (off > 0) {
        memmove(q->buf, q->buf + off, q->len - off);
        q->len -= off;
    }
    return true;
}

/*
 * Applies one incoming text message to the pty. Returns false when the session
 * should end (close frame, malformed stdin that overflows the queue).
 * A lone Ctrl-C drops any paste still queued, as the tty line discipline flushes
 * its input queue on SIGINT, so an interrupt is never stuck behind a paste.
 */
static inline bool Terminal_HandleMessage(const char* json, size_t len, int master_fd, TerminalStdinQueue* q) {
    TermInFrame f;
    if (!TermFrame_Parse(json, len, &f)) return true; /* ignore what we do not understand */
    if (strcmp(f.type, "stdin") == 0) {
        if (f.data_len == 0) return true;
        size_t cap = f.data_len / 4 * 3 + 3;
        unsigned char small[4096];
        unsigned char* dec = cap <= sizeof(small) ? small : (unsigned char*)malloc(cap);
        if (!dec) return false;
        size_t n = TermB64_Decode(f.data, f.data_len, dec, cap);
        bool ok = true;
        if (n == 1 && dec[0] == 0x03) q->len = 0;
        if (n > 0) ok = TerminalStdin_Push(q, dec, n);
        if (dec != small) free(dec);
        if (ok) ok = TerminalStdin_Flush(q, master_fd);
        return ok;
    }
    if (strcmp(f.type, "resize") == 0) {
        if (f.rows > 0 && f.rows <= 500 && f.cols > 0 && f.cols <= 500) {
            struct winsize wsz;
            memset(&wsz, 0, sizeof(wsz));
            wsz.ws_row = (unsigned short)f.rows;
            wsz.ws_col = (unsigned short)f.cols;
            ioctl(master_fd, TIOCSWINSZ, &wsz);
        }
        return true;
    }
    if (strcmp(f.type, "close") == 0) return false;
    return true;
}

/* Reads up to TERMINAL_STDOUT_CHUNK bytes the pty has ready now and sends them as
 * one stdout frame. Returns 1 if data was sent, 0 if nothing was ready, -1 when
 * the pty is gone (any read bytes are sent first) or the send failed. */
static inline int Terminal_PumpStdout(TerminalWs* ws, int master_fd, unsigned char* raw, char* frame, size_t frame_cap) {
    size_t got = 0;
    bool gone = false;
    while (got < TERMINAL_STDOUT_CHUNK) {
        ssize_t n = read(master_fd, raw + got, TERMINAL_STDOUT_CHUNK - got);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        gone = true; /* 0 or EIO: the shell side closed */
        break;
    }
    if (got > 0) {
        static const char pre[] = "{\"type\":\"stdout\",\"data\":\"";
        size_t pl = sizeof(pre) - 1;
        memcpy(frame, pre, pl);
        size_t bl = TermB64_Encode(raw, got, frame + pl, frame_cap - pl - 3);
        if (bl == 0) return -1;
        frame[pl + bl] = '"';
        frame[pl + bl + 1] = '}';
        if (!TerminalWs_SendFrame(ws, 1, (const unsigned char*)frame, pl + bl + 2)) return -1;
    }
    if (gone) return -1;
    return got > 0 ? 1 : 0;
}

#define TERMINAL_STDOUT_FRAME_CAP (TERMINAL_STDOUT_CHUNK / 3 * 4 + 64)

/*
 * The relay loop, separated from connection setup so tests can drive it over a
 * socketpair. Returns 0 on a clean end.
 */
static inline int Terminal_Relay(TerminalWs* ws, int master_fd, pid_t child_pid) {
    int flags = fcntl(master_fd, F_GETFL, 0);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    unsigned char* raw = (unsigned char*)malloc(TERMINAL_STDOUT_CHUNK);
    char* frame = (char*)malloc(TERMINAL_STDOUT_FRAME_CAP);
    TerminalStdinQueue q = {0};
    if (!raw || !frame) {
        free(raw);
        free(frame);
        return -1;
    }

    bool running = true;
    int rc = 0;
    while (running) {
        if (child_pid > 0) {
            int status = 0;
            if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
                /* Send what the shell printed last before ending. */
                while (Terminal_PumpStdout(ws, master_fd, raw, frame, TERMINAL_STDOUT_FRAME_CAP) == 1) {}
                break;
            }
        }

        struct pollfd pfds[2];
        pfds[0].fd = master_fd;
        pfds[0].events = POLLIN | (q.len > 0 ? POLLOUT : 0);
        pfds[0].revents = 0;
        pfds[1].fd = ws->poll_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        int pr = poll(pfds, 2, 50);
        if (pr < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }

        /* 1. One chunk of shell output. */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int r = Terminal_PumpStdout(ws, master_fd, raw, frame, TERMINAL_STDOUT_FRAME_CAP);
            if (r < 0) break;
        }

        /* 2. Incoming messages (always tried: TLS may hold decrypted bytes poll cannot see). */
        for (int i = 0; i < TERMINAL_FRAMES_PER_TURN && running; i++) {
            int op = 0;
            unsigned char* data = NULL;
            size_t len = 0;
            int fr = TerminalWs_Next(ws, &op, &data, &len);
            if (fr == 0) break;
            if (fr < 0) {
                running = false;
                break;
            }
            if (op == 9) {
                if (!TerminalWs_SendFrame(ws, 10, data, len)) running = false;
            } else if (op == 8) {
                running = false;
            } else if (op == 1) {
                if (!Terminal_HandleMessage((const char*)data, len, master_fd, &q)) running = false;
            }
        }

        /* 3. Queued stdin. */
        if (running && q.len > 0 && !TerminalStdin_Flush(&q, master_fd)) break;

        if ((pfds[1].revents & (POLLHUP | POLLERR)) && !(pfds[1].revents & POLLIN)) break;
    }

    free(q.buf);
    free(raw);
    free(frame);
    return rc;
}

/* Reads the HTTP upgrade response until the header ends; any bytes after it are
 * frames and go to the connection buffer. Returns true for a 101. */
static inline bool TerminalWs_ReadUpgrade(TerminalWs* ws, int timeout_ms) {
    char resp[4096];
    size_t have = 0;
    while (have < sizeof(resp) - 1) {
        ssize_t n = TerminalWs_RawRecv(ws, (unsigned char*)resp + have, sizeof(resp) - 1 - have);
        if (n < 0) return false;
        if (n == 0) {
            struct pollfd pfd = { .fd = ws->poll_fd, .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) return false;
            continue;
        }
        have += (size_t)n;
        resp[have] = '\0';
        char* end = strstr(resp, "\r\n\r\n");
        if (end) {
            size_t hdr_len = (size_t)(end - resp) + 4;
            if (strncmp(resp, "HTTP/1.1 101", 12) != 0 && strncmp(resp, "HTTP/1.0 101", 12) != 0) return false;
            return TerminalWs_Prefill(ws, (const unsigned char*)resp + hdr_len, have - hdr_len);
        }
    }
    return false;
}


/* ---------------------------------------------------------------------------
 * Child Process Tree Termination
 * ------------------------------------------------------------------------- */

/* Signal every process in the pseudoterminal's session, not only the shell's
 * own process group. forkpty(3) makes the shell a session leader, and an
 * interactive shell puts each job it starts into a *separate* process group
 * inside that session - so "sleep 900 &" survived a terminate that killed the
 * shell, while the console promised the operator that everything started in
 * that shell was gone. /proc is the only way to enumerate a session. */
static inline void Terminal_SignalSession(pid_t sid, int sig) {
    DIR* proc = opendir("/proc");
    if (!proc) return;
    struct dirent* ent;
    while ((ent = readdir(proc)) != NULL) {
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid <= 1 || pid == sid) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char line[512];
        size_t n = fread(line, 1, sizeof(line) - 1, f);
        fclose(f);
        if (n == 0) continue;
        line[n] = '\0';

        /* Field 2 is the executable name in parentheses and may itself contain
         * spaces and parentheses, so the fields are read after the last ')'. */
        char* after = strrchr(line, ')');
        if (!after) continue;
        int state = 0;
        int ppid = 0, pgrp = 0, session = 0;
        if (sscanf(after + 1, " %c %d %d %d", (char*)&state, &ppid, &pgrp, &session) != 4) continue;
        if (session == (int)sid) kill(pid, sig);
    }
    closedir(proc);
}

static inline void Terminal_KillChildTree(pid_t child_pid) {
    if (child_pid <= 1) return;

    // Send SIGTERM to child process group
    kill(-child_pid, SIGTERM);
    Terminal_SignalSession(child_pid, SIGTERM);
    usleep(50000); // 50ms grace period

    // Enforce unconditional SIGKILL to full child process group
    kill(-child_pid, SIGKILL);
    Terminal_SignalSession(child_pid, SIGKILL);

    // Reap child to avoid zombies
    int status = 0;
    waitpid(child_pid, &status, 0);
}

/* ---------------------------------------------------------------------------
 * Full-Duplex Relay Worker
 * ------------------------------------------------------------------------- */

static inline int Terminal_RunLinuxWorker(
    const char* hub_url,
    bool use_tls,
    const char* ca_path,
    bool pin_ca,
    const char* client_cert,
    const char* client_key,
    const char* endpoint_id,
    const char* session_id,
    const char* token,
    const char* program
) {
    if (!Terminal_IsAllowedProgram(program)) {
        return -1;
    }

    // 1. Fork pseudoterminal
    int master_fd = -1;
    pid_t child_pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (child_pid < 0) {
        return -1;
    }

    if (child_pid == 0) {
        // Child: shell process
        setpgid(0, 0); // Establish dedicated process group for tree-kill containment

        // Close inherited file descriptors above stderr
        for (int fd = 3; fd < 1024; fd++) {
            close(fd);
        }

        // Full color sanitized environment
        clearenv();
        setenv("TERM", "xterm-256color", 1);
        setenv("COLORTERM", "truecolor", 1);
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        setenv("LOGNAME", "root", 1);
        setenv("SHELL", program, 1);
        setenv("LS_COLORS", "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.zip=01;31:*.gz=01;31:*.deb=01;31:*.rpm=01;31:*.sh=01;32:", 1);
        setenv("CLICOLOR", "1", 1);
        setenv("CLICOLOR_FORCE", "1", 1);
        setenv("LANG", "en_US.UTF-8", 1);
        setenv("LC_CTYPE", "C.UTF-8", 1);

        // Explicit safe working directory
        if (chdir("/var/lib/ominull") != 0) {
            if (chdir("/root") != 0) {
                if (chdir("/") != 0) {}
            }
        }

        // Establish colored shell environment & prompt
        const char* rc_path = "/var/lib/ominull/.bashrc_terminal";
        FILE* f_rc = fopen(rc_path, "w");
        if (f_rc) {
            fputs("if [ -f /etc/bash.bashrc ]; then . /etc/bash.bashrc; fi\n"
                  "if [ -f /etc/profile ]; then . /etc/profile; fi\n"
                  "if [ -f /root/.bashrc ]; then . /root/.bashrc; fi\n"
                  "alias ls='ls --color=auto'\n"
                  "alias ll='ls -la --color=auto'\n"
                  "alias grep='grep --color=auto'\n"
                  "export PS1='\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n", f_rc);
            fclose(f_rc);
        }

        if (strcmp(program, "/bin/bash") == 0) {
            if (access(rc_path, R_OK) == 0) {
                execl(program, "bash", "--rcfile", rc_path, "-i", (char*)NULL);
            } else {
                execl(program, "bash", "-l", "-i", (char*)NULL);
            }
        } else if (strcmp(program, "/bin/sh") == 0) {
            execl(program, "sh", "-i", (char*)NULL);
        } else {
            execl(program, program, "-i", (char*)NULL);
        }
        _exit(127);
    }

    // Parent worker: establish authenticated WebSocket to hub relay
    CURL* curl = curl_easy_init();
    if (!curl) {
        Terminal_KillChildTree(child_pid);
        close(master_fd);
        return -1;
    }

    // Parse host and port from hub_url
    char host[128] = {0};
    int port = use_tls ? 443 : 80;
    const char* p = hub_url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        port = 80;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        port = 443;
    }
    const char* slash = strchr(p, '/');
    size_t host_len = slash ? (size_t)(slash - p) : strlen(p);
    if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
    strncpy(host, p, host_len);
    host[host_len] = '\0';

    char* colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    char connect_url[512];
    snprintf(connect_url, sizeof(connect_url), "%s://%s:%d", use_tls ? "https" : "http", host, port);

    curl_easy_setopt(curl, CURLOPT_URL, connect_url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (use_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (pin_ca && ca_path && ca_path[0] && access(ca_path, R_OK) == 0) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
        }
        if (client_cert && client_key && client_cert[0] && client_key[0] &&
            access(client_cert, R_OK) == 0 && access(client_key, R_OK) == 0) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
            curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
        }
    }

    CURLcode c_res = curl_easy_perform(curl);
    if (c_res != CURLE_OK) {
        curl_easy_cleanup(curl);
        Terminal_KillChildTree(child_pid);
        close(master_fd);
        return -1;
    }

    curl_socket_t ws_sock;
    curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &ws_sock);


    TerminalWs ws;
    TerminalWs_Init(&ws, curl, -1, (int)ws_sock);

    // Random 16-byte handshake key (RFC 6455 4.1)
    unsigned char raw_key[16];
    char ws_key[32] = {0};
    if (!Terminal_Random(raw_key, sizeof(raw_key))) {
        curl_easy_cleanup(curl);
        Terminal_KillChildTree(child_pid);
        close(master_fd);
        return -1;
    }
    Terminal_Base64Encode(raw_key, sizeof(raw_key), ws_key, sizeof(ws_key));

    // Send HTTP WebSocket Upgrade request
    char upgrade_req[1024];
    int req_len = snprintf(upgrade_req, sizeof(upgrade_req),
        "GET /api/v1/terminal/ws/agent?session_id=%s&endpoint_id=%s&token=%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "X-Device-Endpoint-ID: %s\r\n"
        "X-Terminal-Token: %s\r\n\r\n",
        session_id, endpoint_id, token,
        host, port, ws_key, endpoint_id, token);

    if (req_len <= 0 || (size_t)req_len >= sizeof(upgrade_req) ||
        !TerminalWs_SendAll(&ws, (const unsigned char*)upgrade_req, (size_t)req_len) ||
        !TerminalWs_ReadUpgrade(&ws, 5000)) {
        TerminalWs_Free(&ws);
        curl_easy_cleanup(curl);
        Terminal_KillChildTree(child_pid);
        close(master_fd);
        return -1;
    }

    Terminal_Relay(&ws, master_fd, child_pid);

    // Teardown & Child-Tree Kill
    Terminal_KillChildTree(child_pid);
    close(master_fd);

    // Send final close frame
    const char* close_msg = "{\"type\":\"close\"}";
    TerminalWs_SendFrame(&ws, 1, (const unsigned char*)close_msg, strlen(close_msg));

    TerminalWs_Free(&ws);
    curl_easy_cleanup(curl);
    return 0;
}

#endif /* OMINULL_TERMINAL_LINUX_H */
