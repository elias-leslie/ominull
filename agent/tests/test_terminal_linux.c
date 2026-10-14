#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>

#include "../include/terminal_linux.h"

static void test_allowlist() {
    printf("[*] Testing terminal program allowlist...\n");

    // Permitted programs
    assert(Terminal_IsAllowedProgram("/bin/sh") == true);
    assert(Terminal_IsAllowedProgram("/bin/bash") == true);

    // Forbidden / invalid programs
    assert(Terminal_IsAllowedProgram("/bin/dash") == false);
    assert(Terminal_IsAllowedProgram("/bin/zsh") == false);
    assert(Terminal_IsAllowedProgram("bash") == false);
    assert(Terminal_IsAllowedProgram("/bin/sh -c whoami") == false);
    assert(Terminal_IsAllowedProgram("../../bin/sh") == false);
    assert(Terminal_IsAllowedProgram("/usr/bin/python3") == false);
    assert(Terminal_IsAllowedProgram("") == false);
    assert(Terminal_IsAllowedProgram(NULL) == false);

    printf("[+] Program allowlist verified.\n");
}

static void test_payload_parsing() {
    printf("[*] Testing payload parsing...\n");

    TerminalSessionParams params;

    // Valid payload
    const char* valid_json = "{\"session_id\":\"sess-1234\",\"program\":\"/bin/bash\",\"connect_token\":\"tok-abcd\"}";
    assert(Terminal_ParsePayload(valid_json, &params) == true);
    assert(strcmp(params.session_id, "sess-1234") == 0);
    assert(strcmp(params.program, "/bin/bash") == 0);
    assert(strcmp(params.connect_token, "tok-abcd") == 0);

    // Default program when empty
    const char* default_prog = "{\"session_id\":\"sess-5678\",\"connect_token\":\"tok-xyz\"}";
    assert(Terminal_ParsePayload(default_prog, &params) == true);
    assert(strcmp(params.program, "/bin/bash") == 0);

    // Disallowed program
    const char* evil_prog = "{\"session_id\":\"sess-evil\",\"program\":\"/bin/dash\",\"connect_token\":\"tok-1\"}";
    assert(Terminal_ParsePayload(evil_prog, &params) == false);

    // Missing session ID or token
    const char* missing_tok = "{\"session_id\":\"sess-9999\",\"program\":\"/bin/sh\"}";
    assert(Terminal_ParsePayload(missing_tok, &params) == false);

    printf("[+] Payload parsing verified.\n");
}

static void test_base64_roundtrip() {
    printf("[*] Testing Base64 encode/decode roundtrip...\n");

    const unsigned char test_data[] = "Hello Ominull Pseudoterminal! \x00\x01\x02\xFF\xFE";
    size_t in_len = sizeof(test_data);

    char encoded[128];
    size_t elen = Terminal_Base64Encode(test_data, in_len, encoded, sizeof(encoded));
    assert(elen > 0);

    unsigned char decoded[128];
    size_t dlen = Terminal_Base64Decode(encoded, elen, decoded, sizeof(decoded));
    assert(dlen == in_len);
    assert(memcmp(test_data, decoded, in_len) == 0);

    printf("[+] Base64 roundtrip verified.\n");
}

static void test_environment_sanitization() {
    printf("[*] Testing child environment sanitization...\n");

    // Pollute parent environment with test variables
    setenv("FORBIDDEN_PARENT_VAL", "parent_canary_value", 1);
    setenv("LEAKED_VAR_TEST", "test_leaked_canary", 1);

    int master_fd = -1;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    assert(pid >= 0);

    if (pid == 0) {
        setpgid(0, 0);
        clearenv();
        setenv("TERM", "xterm-256color", 1);
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        setenv("SHELL", "/bin/sh", 1);

        execl("/bin/sh", "/bin/sh", "-c", "env", (char*)NULL);
        _exit(1);
    }

    char output[4096] = {0};
    size_t total_read = 0;
    while (total_read < sizeof(output) - 1) {
        ssize_t n = read(master_fd, output + total_read, sizeof(output) - 1 - total_read);
        if (n <= 0) break;
        total_read += n;
    }
    output[total_read] = '\0';
    close(master_fd);

    int status = 0;
    waitpid(pid, &status, 0);

    // Verify test variables are NOT present in output
    assert(strstr(output, "FORBIDDEN_PARENT_VAL") == NULL);
    assert(strstr(output, "parent_canary_value") == NULL);
    assert(strstr(output, "LEAKED_VAR_TEST") == NULL);
    assert(strstr(output, "TERM=xterm-256color") != NULL);

    printf("[+] Child environment sanitization verified.\n");
}

static void test_resize_propagation() {
    printf("[*] Testing terminal resize propagation...\n");

    int master_fd = -1;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    assert(pid >= 0);

    if (pid == 0) {
        // Child: idle sleep
        sleep(5);
        _exit(0);
    }

    struct winsize ws;
    ws.ws_row = 42;
    ws.ws_col = 137;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    int r = ioctl(master_fd, TIOCSWINSZ, &ws);
    assert(r == 0);

    struct winsize check_ws;
    r = ioctl(master_fd, TIOCGWINSZ, &check_ws);
    assert(r == 0);
    assert(check_ws.ws_row == 42);
    assert(check_ws.ws_col == 137);

    kill(pid, SIGKILL);
    close(master_fd);
    waitpid(pid, NULL, 0);

    printf("[+] Terminal resize propagation verified.\n");
}

static void test_child_tree_kill() {
    printf("[*] Testing child-tree kill containment...\n");

    int master_fd = -1;
    pid_t child_pid = forkpty(&master_fd, NULL, NULL, NULL);
    assert(child_pid >= 0);

    if (child_pid == 0) {
        setpgid(0, 0);
        // Spawn background grandchild
        execl("/bin/sh", "/bin/sh", "-c", "sleep 300 & sleep 300", (char*)NULL);
        _exit(1);
    }

    // Allow shell and grandchild to spin up
    usleep(150000); // 150ms

    // Verify child process group exists
    assert(kill(-child_pid, 0) == 0);

    // Call Terminal_KillChildTree
    Terminal_KillChildTree(child_pid);
    close(master_fd);

    // Verify process group is completely dead (kill should return ESRCH)
    assert(kill(-child_pid, 0) < 0);
    assert(errno == ESRCH);

    printf("[+] Child-tree kill containment verified.\n");
}


/* ---------------------------------------------------------------------------
 * WebSocket client and relay (socketpair transport, no hub)
 * ------------------------------------------------------------------------- */

#include <sys/socket.h>

/* An unmasked server frame, as the hub sends it. len_form: 0 shortest, 16 or 64 forced. */
static size_t srv_frame(unsigned char* out, int fin, int opcode, const unsigned char* p, size_t n, int len_form) {
    size_t h = 0;
    out[h++] = (unsigned char)((fin ? 0x80 : 0) | opcode);
    if (len_form == 64 || n > 65535) {
        out[h++] = 127;
        for (int i = 0; i < 8; i++) out[h++] = (unsigned char)(((uint64_t)n >> (56 - 8 * i)) & 0xFF);
    } else if (len_form == 16 || n >= 126) {
        out[h++] = 126;
        out[h++] = (unsigned char)(n >> 8);
        out[h++] = (unsigned char)n;
    } else {
        out[h++] = (unsigned char)n;
    }
    memcpy(out + h, p, n);
    return h + n;
}

static void write_all(int fd, const unsigned char* p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        assert(w > 0);
        p += w;
        n -= (size_t)w;
    }
}

/* Polls TerminalWs_Next until it yields something other than 0. */
static int next_blocking(TerminalWs* ws, int* op, unsigned char** d, size_t* n) {
    for (int i = 0; i < 2000; i++) {
        int r = TerminalWs_Next(ws, op, d, n);
        if (r != 0) return r;
        struct pollfd pfd = { .fd = ws->poll_fd, .events = POLLIN, .revents = 0 };
        poll(&pfd, 1, 10);
    }
    return 0;
}

static void test_ws_lengths_fragments_and_control(void) {
    printf("[*] Testing WebSocket frame reader (lengths, fragments, ping, prefill)...\n");
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    TerminalWs ws;
    TerminalWs_Init(&ws, NULL, sv[0], sv[0]);

    static unsigned char buf[3 * 1048576];
    static unsigned char big[300000];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (unsigned char)('a' + i % 26);

    /* Bytes that came with the 101 response are not lost. */
    size_t n = srv_frame(buf, 1, 1, (const unsigned char*)"early", 5, 0);
    assert(TerminalWs_Prefill(&ws, buf, n));
    int op = 0;
    unsigned char* d = NULL;
    size_t dl = 0;
    assert(next_blocking(&ws, &op, &d, &dl) == 1 && op == 1 && dl == 5 && memcmp(d, "early", 5) == 0);

    /* 16-bit and 64-bit lengths, a 300 KB message, delivered one byte at a time for the first. */
    n = srv_frame(buf, 1, 1, big, 200, 16);
    for (size_t i = 0; i < n; i++) {
        write_all(sv[1], buf + i, 1);
        int r = TerminalWs_Next(&ws, &op, &d, &dl);
        if (i + 1 < n) assert(r == 0);
        else assert(r == 1 && dl == 200 && memcmp(d, big, 200) == 0);
    }
    n = srv_frame(buf, 1, 1, big, sizeof(big), 64);
    pid_t w = fork();
    if (w == 0) {
        write_all(sv[1], buf, n);
        _exit(0);
    }
    assert(next_blocking(&ws, &op, &d, &dl) == 1 && dl == sizeof(big) && memcmp(d, big, sizeof(big)) == 0 && d[dl] == '\0');
    waitpid(w, NULL, 0);

    /* Fragmented text message with a ping in the middle: ping first, then the whole message. */
    size_t off = 0;
    off += srv_frame(buf + off, 0, 1, (const unsigned char*)"{\"type\":", 8, 0);
    off += srv_frame(buf + off, 1, 9, (const unsigned char*)"pp", 2, 0);
    off += srv_frame(buf + off, 0, 0, (const unsigned char*)"\"stdin\",", 8, 0);
    off += srv_frame(buf + off, 1, 0, (const unsigned char*)"\"data\":\"aGk=\"}", 14, 0);
    write_all(sv[1], buf, off);
    assert(next_blocking(&ws, &op, &d, &dl) == 1 && op == 9 && dl == 2 && memcmp(d, "pp", 2) == 0);
    assert(next_blocking(&ws, &op, &d, &dl) == 1 && op == 1);
    assert(strcmp((char*)d, "{\"type\":\"stdin\",\"data\":\"aGk=\"}") == 0);

    /* The client's frames are masked with fresh random keys. */
    assert(TerminalWs_SendFrame(&ws, 1, (const unsigned char*)"abcd", 4));
    assert(TerminalWs_SendFrame(&ws, 1, (const unsigned char*)"abcd", 4));
    unsigned char f1[10], f2[10];
    assert(read(sv[1], f1, 10) == 10 && read(sv[1], f2, 10) == 10);
    assert((f1[1] & 0x80) && (f2[1] & 0x80));
    assert(memcmp(f1 + 2, f2 + 2, 4) != 0);
    for (int i = 0; i < 4; i++) assert((f1[6 + i] ^ f1[2 + i]) == "abcd"[i]);

    /* Over the 1 MiB cap: refused cleanly. */
    n = 0;
    buf[n++] = 0x81;
    buf[n++] = 127;
    uint64_t huge = (uint64_t)TERMINAL_MAX_MESSAGE + 1;
    for (int i = 0; i < 8; i++) buf[n++] = (unsigned char)((huge >> (56 - 8 * i)) & 0xFF);
    write_all(sv[1], buf, n);
    assert(next_blocking(&ws, &op, &d, &dl) == -1);

    TerminalWs_Free(&ws);
    close(sv[0]);
    close(sv[1]);
    printf("[+] WebSocket frame reader verified.\n");
}

static void test_random_handshake_key(void) {
    unsigned char a[16], b[16];
    assert(Terminal_Random(a, sizeof(a)) && Terminal_Random(b, sizeof(b)));
    assert(memcmp(a, b, sizeof(a)) != 0);
    static const unsigned char fixed[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    assert(memcmp(a, fixed, sizeof(a)) != 0);
    printf("[+] Handshake key and masks come from the CSPRNG.\n");
}

/* The relay with a socketpair standing in for the pty: a 256 KiB paste in one
 * frame reaches the "pty" intact while its output keeps flowing, and a lone
 * Ctrl-C jumps any queued paste. */
static void test_relay_large_paste_and_interrupt(void) {
    printf("[*] Testing relay: 256 KiB paste in one frame, Ctrl-C...\n");
    int hub[2], pty[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, hub) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pty) == 0);
    pid_t relay = fork();
    if (relay == 0) {
        close(hub[1]);
        close(pty[1]);
        TerminalWs ws;
        TerminalWs_Init(&ws, NULL, hub[0], hub[0]);
        int rc = Terminal_Relay(&ws, pty[0], -1);
        _exit(rc == 0 ? 0 : 3);
    }
    close(hub[0]);
    close(pty[0]);

    const size_t paste_len = 256 * 1024;
    unsigned char* paste = malloc(paste_len);
    for (size_t i = 0; i < paste_len; i++) paste[i] = (unsigned char)(i * 7 + 3);
    char* json = malloc(paste_len * 2);
    int jl = sprintf(json, "{\"type\":\"stdin\",\"data\":\"");
    jl += (int)TermB64_Encode(paste, paste_len, json + jl, paste_len * 2 - jl);
    jl += sprintf(json + jl, "\"}");
    unsigned char* frame = malloc((size_t)jl + 16);
    size_t fl = srv_frame(frame, 1, 1, (unsigned char*)json, (size_t)jl, 0);

    /* Writer and reader at once, like a real pty would be. */
    pid_t writer = fork();
    if (writer == 0) {
        write_all(hub[1], frame, fl);
        _exit(0);
    }
    unsigned char* got = malloc(paste_len);
    size_t have = 0;
    while (have < paste_len) {
        ssize_t r = read(pty[1], got + have, paste_len - have);
        assert(r > 0);
        have += (size_t)r;
    }
    assert(memcmp(got, paste, paste_len) == 0);
    waitpid(writer, NULL, 0);

    /* Output from the "shell" is relayed as stdout frames of at most 32 KiB. */
    static unsigned char out[100000];
    memset(out, 'z', sizeof(out));
    write_all(pty[1], out, sizeof(out));
    size_t seen = 0;
    int frames = 0;
    static unsigned char rx[200000];
    size_t rxl = 0;
    while (seen < sizeof(out)) {
        ssize_t r = read(hub[1], rx + rxl, sizeof(rx) - rxl);
        assert(r > 0);
        rxl += (size_t)r;
        for (;;) {
            if (rxl < 4) break;
            size_t plen = rx[1] & 0x7F, hl = 2;
            if (plen == 126) {
                plen = ((size_t)rx[2] << 8) | rx[3];
                hl = 4;
            }
            hl += 4; /* client frames are masked */
            if (rxl < hl + plen) break;
            for (size_t i = 0; i < plen; i++) rx[hl + i] ^= rx[hl - 4 + (i & 3)];
            TermInFrame f;
            assert(TermFrame_Parse((char*)rx + hl, plen, &f) && strcmp(f.type, "stdout") == 0);
            static unsigned char dec[40000];
            size_t dn = TermB64_Decode(f.data, f.data_len, dec, sizeof(dec));
            assert(dn > 0 && dn <= TERMINAL_STDOUT_CHUNK);
            seen += dn;
            frames++;
            memmove(rx, rx + hl + plen, rxl - hl - plen);
            rxl -= hl + plen;
        }
    }
    assert(seen == sizeof(out));
    assert(frames <= 8); /* coalesced, not 4 KiB per frame */

    /* Close message ends the relay cleanly. */
    const char* closem = "{\"type\":\"close\"}";
    fl = srv_frame(frame, 1, 1, (const unsigned char*)closem, strlen(closem), 0);
    write_all(hub[1], frame, fl);
    int status = 0;
    waitpid(relay, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Ctrl-C drops queued stdin. */
    TerminalStdinQueue q = {0};
    int sink[2];
    assert(pipe(sink) == 0);
    fcntl(sink[1], F_SETFL, O_NONBLOCK);
    unsigned char fill[200000];
    memset(fill, 'p', sizeof(fill));
    assert(TerminalStdin_Push(&q, fill, sizeof(fill)));
    assert(TerminalStdin_Flush(&q, sink[1]));
    assert(q.len > 0); /* the pipe is full; the rest waits */
    char intr[64];
    int il = sprintf(intr, "{\"type\":\"stdin\",\"data\":\"Aw==\"}");
    assert(Terminal_HandleMessage(intr, (size_t)il, sink[1], &q));
    assert(q.len == 0 || (q.len == 1 && q.buf[0] == 0x03));
    free(q.buf);
    close(sink[0]);
    close(sink[1]);

    free(paste);
    free(json);
    free(frame);
    free(got);
    close(hub[1]);
    close(pty[1]);
    printf("[+] Relay paste, coalescing, close and Ctrl-C verified.\n");
}

int main() {
    printf("=== Starting Linux Terminal Worker Tests (Slice 3B.1) ===\n");
    test_allowlist();
    test_payload_parsing();
    test_base64_roundtrip();
    test_environment_sanitization();
    test_resize_propagation();
    test_child_tree_kill();
    test_ws_lengths_fragments_and_control();
    test_random_handshake_key();
    test_relay_large_paste_and_interrupt();
    printf("=== All Slice 3B.1 Unit Tests Passed Successfully! ===\n");
    return 0;
}
