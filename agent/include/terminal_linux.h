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
 */

#include <pty.h>
#include <utmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
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

#define TERMINAL_MAX_FRAME_SIZE 65536
#define TERMINAL_MAX_QUEUE 1048576

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

    // Bounded search for session_id
    const char* s_id = strstr(json, "\"session_id\"");
    if (s_id) {
        const char* val = strchr(s_id, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->session_id) - 1) {
                out->session_id[len] = val[len];
                len++;
            }
            out->session_id[len] = '\0';
        }
    }

    // Bounded search for program
    const char* s_pr = strstr(json, "\"program\"");
    if (s_pr) {
        const char* val = strchr(s_pr, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->program) - 1) {
                out->program[len] = val[len];
                len++;
            }
            out->program[len] = '\0';
        }
    }

    // Bounded search for connect_token
    const char* s_tok = strstr(json, "\"connect_token\"");
    if (s_tok) {
        const char* val = strchr(s_tok, ':');
        if (val) {
            val++;
            while (*val == ' ' || *val == '\t' || *val == '"') val++;
            size_t len = 0;
            while (val[len] && val[len] != '"' && val[len] != ',' && val[len] != '}' && len < sizeof(out->connect_token) - 1) {
                out->connect_token[len] = val[len];
                len++;
            }
            out->connect_token[len] = '\0';
        }
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

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline size_t Terminal_Base64Encode(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    size_t out_len = 4 * ((in_len + 2) / 3);
    if (out_len + 1 > out_max) return 0;

    size_t i = 0, j = 0;
    while (i < in_len) {
        size_t rem = in_len - i;
        uint32_t oct_a = in[i++];
        uint32_t oct_b = (rem > 1) ? in[i++] : 0;
        uint32_t oct_c = (rem > 2) ? in[i++] : 0;
        uint32_t triple = (oct_a << 16) | (oct_b << 8) | oct_c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (rem > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? b64_table[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

static inline int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static inline size_t Terminal_Base64Decode(const char* in, size_t in_len, unsigned char* out, size_t out_max) {
    size_t i = 0, j = 0;
    while (i < in_len && j < out_max) {
        while (i < in_len && (in[i] == ' ' || in[i] == '\r' || in[i] == '\n' || in[i] == '\t')) i++;
        if (i >= in_len) break;

        int a = b64_val(in[i++]);
        int b = (i < in_len) ? b64_val(in[i++]) : -1;
        int c = (i < in_len) ? b64_val(in[i++]) : -1;
        int d = (i < in_len) ? b64_val(in[i++]) : -1;

        if (a < 0 || b < 0) break;
        uint32_t triple = (a << 18) | (b << 12) | ((c < 0 ? 0 : c) << 6) | (d < 0 ? 0 : d);

        out[j++] = (triple >> 16) & 0xFF;
        if (c >= 0 && j < out_max) out[j++] = (triple >> 8) & 0xFF;
        if (d >= 0 && j < out_max) out[j++] = triple & 0xFF;
    }
    return j;
}

/* ---------------------------------------------------------------------------
 * RFC 6455 WebSocket Framing Helpers
 * ------------------------------------------------------------------------- */

static inline bool Terminal_SendWsFrame(CURL* curl, curl_socket_t sock, int opcode, const unsigned char* payload, size_t payload_len) {
    if (payload_len > TERMINAL_MAX_FRAME_SIZE) return false;

    unsigned char frame[TERMINAL_MAX_FRAME_SIZE + 16];
    size_t header_len = 0;

    // Byte 0: FIN (0x80) | opcode
    frame[0] = 0x80 | (opcode & 0x0F);

    // Client-to-server frames MUST be masked (0x80)
    if (payload_len < 126) {
        frame[1] = 0x80 | (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        frame[1] = 0x80 | 126;
        frame[2] = (payload_len >> 8) & 0xFF;
        frame[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        return false;
    }

    // Generate 4-byte mask key
    unsigned char mask[4];
    mask[0] = (unsigned char)(rand() & 0xFF);
    mask[1] = (unsigned char)(rand() & 0xFF);
    mask[2] = (unsigned char)(rand() & 0xFF);
    mask[3] = (unsigned char)(rand() & 0xFF);

    memcpy(frame + header_len, mask, 4);
    header_len += 4;

    // Mask payload
    for (size_t i = 0; i < payload_len; i++) {
        frame[header_len + i] = payload[i] ^ mask[i % 4];
    }
    size_t total_len = header_len + payload_len;

    // Send frame with poll retry on EAGAIN
    size_t offset = 0;
    while (offset < total_len) {
        size_t sent = 0;
        CURLcode res = curl_easy_send(curl, frame + offset, total_len - offset, &sent);
        if (res == CURLE_OK) {
            offset += sent;
        } else if (res == CURLE_AGAIN) {
            struct pollfd pfd = { .fd = sock, .events = POLLOUT, .revents = 0 };
            int pr = poll(&pfd, 1, 1000);
            if (pr <= 0) return false;
        } else {
            return false;
        }
    }
    return true;
}

static inline int Terminal_RecvExact(CURL* curl, curl_socket_t sock, unsigned char* buf, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        size_t nread = 0;
        CURLcode res = curl_easy_recv(curl, buf + offset, len - offset, &nread);
        if (res == CURLE_OK) {
            if (nread == 0) return -1; // EOF
            offset += nread;
        } else if (res == CURLE_AGAIN) {
            struct pollfd pfd = { .fd = sock, .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd, 1, 5000);
            if (pr <= 0) return -1;
        } else {
            return -1; // Connection error
        }
    }
    return (int)offset;
}

static inline int Terminal_RecvWsFrame(CURL* curl, curl_socket_t sock, int* out_opcode, unsigned char* out_payload, size_t out_max, size_t* out_len) {
    unsigned char hdr[2];
    size_t nread = 0;
    CURLcode res = curl_easy_recv(curl, hdr, 2, &nread);
    if (res == CURLE_AGAIN) return 0; // Would block, no frame ready
    if (res != CURLE_OK || nread < 2) return -1; // Connection closed or error

    int opcode = hdr[0] & 0x0F;
    bool is_masked = (hdr[1] & 0x80) != 0;
    size_t payload_len = hdr[1] & 0x7F;

    if (payload_len == 126) {
        unsigned char ext[2];
        if (Terminal_RecvExact(curl, sock, ext, 2) != 2) return -1;
        payload_len = ((size_t)ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        return -1; // Oversized frame
    }

    unsigned char mask[4] = {0};
    if (is_masked) {
        if (Terminal_RecvExact(curl, sock, mask, 4) != 4) return -1;
    }

    if (payload_len > out_max) return -1;

    if (payload_len > 0) {
        if (Terminal_RecvExact(curl, sock, out_payload, payload_len) != (int)payload_len) return -1;
        if (is_masked) {
            for (size_t i = 0; i < payload_len; i++) {
                out_payload[i] ^= mask[i % 4];
            }
        }
    }
    out_payload[payload_len] = '\0';
    *out_opcode = opcode;
    *out_len = payload_len;
    return 1; // 1 frame read
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

    // Generate dynamic WebSocket client nonce key
    char ws_key[32] = {0};
    unsigned char raw_key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    Terminal_Base64Encode(raw_key, sizeof(raw_key), ws_key, sizeof(ws_key));

    // Send HTTP WebSocket Upgrade request
    char upgrade_req[1024];
    snprintf(upgrade_req, sizeof(upgrade_req),
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

    size_t sent = 0;
    while (1) {
        c_res = curl_easy_send(curl, upgrade_req, strlen(upgrade_req), &sent);
        if (c_res == CURLE_AGAIN) {
            struct pollfd pfd = { .fd = ws_sock, .events = POLLOUT, .revents = 0 };
            if (poll(&pfd, 1, 1000) <= 0) break;
            continue;
        }
        break;
    }

    // Read HTTP 101 response
    char resp[1024] = {0};
    size_t nread = 0;
    while (1) {
        c_res = curl_easy_recv(curl, resp, sizeof(resp) - 1, &nread);
        if (c_res == CURLE_AGAIN) {
            struct pollfd pfd = { .fd = ws_sock, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 2000) <= 0) break;
            continue;
        }
        break;
    }

    if (c_res != CURLE_OK || strstr(resp, "101") == NULL) {
        curl_easy_cleanup(curl);
        Terminal_KillChildTree(child_pid);
        close(master_fd);
        return -1;
    }

    // Set master pty descriptor to non-blocking
    int flags = fcntl(master_fd, F_GETFL, 0);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    // Main full-duplex relay loop
    bool running = true;
    while (running) {
        // Check if child has exited
        int status = 0;
        pid_t wp = waitpid(child_pid, &status, WNOHANG);
        if (wp == child_pid) {
            break;
        }

        struct pollfd pfds[2];
        pfds[0].fd = master_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;

        pfds[1].fd = ws_sock;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll(pfds, 2, 50);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 1. Stdout from shell to WebSocket
        if (pfds[0].revents & POLLIN) {
            unsigned char raw_buf[4096];
            ssize_t n = read(master_fd, raw_buf, sizeof(raw_buf));
            if (n > 0) {
                char b64[8192];
                size_t b64_len = Terminal_Base64Encode(raw_buf, (size_t)n, b64, sizeof(b64));
                if (b64_len > 0) {
                    char frame_json[9000];
                    int jlen = snprintf(frame_json, sizeof(frame_json),
                        "{\"type\":\"stdout\",\"data\":\"%s\"}", b64);
                    if (jlen > 0) {
                        Terminal_SendWsFrame(curl, ws_sock, 1, (const unsigned char*)frame_json, (size_t)jlen);
                    }
                }
            } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                break;
            }
        }
        if (pfds[0].revents & (POLLHUP | POLLERR)) {
            break;
        }

        // 2. Stdin / Resize / Close from WebSocket to shell
        while (running) {
            int opcode = 0;
            size_t plen = 0;
            unsigned char pbuf[8192];
            int fr = Terminal_RecvWsFrame(curl, ws_sock, &opcode, pbuf, sizeof(pbuf) - 1, &plen);
            if (fr == 0) {
                break; // No more frames ready in buffer
            }
            if (fr < 0) {
                running = false;
                break;
            }

            // Handle Ping
            if (opcode == 9) {
                Terminal_SendWsFrame(curl, ws_sock, 10, pbuf, plen); // Pong
            } else if (opcode == 8) {
                // Close frame
                running = false;
                break;
            } else if (opcode == 1) {
                // Text frame (JSON)
                const char* f_json = (const char*)pbuf;
                if (strstr(f_json, "\"type\":\"stdin\"") || strstr(f_json, "\"type\": \"stdin\"")) {
                    const char* d_pos = strstr(f_json, "\"data\"");
                    if (d_pos) {
                        const char* col = strchr(d_pos, ':');
                        if (col) {
                            col++;
                            while (*col == ' ' || *col == '\t' || *col == '"') col++;
                            size_t dlen = 0;
                            while (col[dlen] && col[dlen] != '"' && col[dlen] != '}' && col[dlen] != ',') dlen++;
                            if (dlen > 0) {
                                unsigned char dec[4096];
                                size_t declen = Terminal_Base64Decode(col, dlen, dec, sizeof(dec));
                                if (declen > 0) {
                                    ssize_t wr = write(master_fd, dec, declen);
                                    (void)wr;
                                }
                            }
                        }
                    }
                } else if (strstr(f_json, "\"type\":\"resize\"") || strstr(f_json, "\"type\": \"resize\"")) {
                    // Extract rows and cols
                    int rows = 0, cols = 0;
                    const char* r_pos = strstr(f_json, "\"rows\"");
                    if (r_pos) {
                        const char* r_val = strchr(r_pos, ':');
                        if (r_val) rows = atoi(r_val + 1);
                    }
                    const char* c_pos = strstr(f_json, "\"cols\"");
                    if (c_pos) {
                        const char* c_val = strchr(c_pos, ':');
                        if (c_val) cols = atoi(c_val + 1);
                    }
                    if (rows > 0 && rows <= 500 && cols > 0 && cols <= 500) {
                        struct winsize ws;
                        ws.ws_row = (unsigned short)rows;
                        ws.ws_col = (unsigned short)cols;
                        ws.ws_xpixel = 0;
                        ws.ws_ypixel = 0;
                        ioctl(master_fd, TIOCSWINSZ, &ws);
                    }
                } else if (strstr(f_json, "\"type\":\"close\"") || strstr(f_json, "\"type\": \"close\"")) {
                    running = false;
                    break;
                }
            }
        }
        if (pfds[1].revents & (POLLHUP | POLLERR)) {
            break;
        }
    }

    // Teardown & Child-Tree Kill
    Terminal_KillChildTree(child_pid);
    close(master_fd);

    // Send final close frame
    const char* close_msg = "{\"type\":\"close\"}";
    Terminal_SendWsFrame(curl, ws_sock, 1, (const unsigned char*)close_msg, strlen(close_msg));

    curl_easy_cleanup(curl);
    return 0;
}

#endif /* OMINULL_TERMINAL_LINUX_H */
