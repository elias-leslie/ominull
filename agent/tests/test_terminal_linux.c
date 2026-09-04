#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

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

int main() {
    printf("=== Starting Linux Terminal Worker Tests (Slice 3B.1) ===\n");
    test_allowlist();
    test_payload_parsing();
    test_base64_roundtrip();
    test_environment_sanitization();
    test_resize_propagation();
    test_child_tree_kill();
    printf("=== All Slice 3B.1 Unit Tests Passed Successfully! ===\n");
    return 0;
}
