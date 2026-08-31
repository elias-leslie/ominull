/* Red-capable regression benchmark for Linux process attribution.
 *
 * It compiles the production collector against a fixture proc root, creates
 * many processes with many descriptors and 64 sockets, then asserts that one
 * collection stays within one descriptor-index walk. The pre-refactor
 * collector called FindProcessForInode once per socket and failed this budget. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* g_fixture_root;
#define OMINULL_PROC_ROOT g_fixture_root
#define main ominull_linux_agent_main_unused
#include "../linux/main.c"
#undef main

#define FIXTURE_PROCESSES 128
#define FIXTURE_FDS 32
#define FIXTURE_SOCKETS 64

static int failures;

static void check(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "[-] %s\n", message);
        failures++;
    }
}

static void mkdir_or_die(const char* path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        perror(path);
        exit(1);
    }
}

static void link_or_die(const char* target, const char* path) {
    if (symlink(target, path) != 0) {
        perror(path);
        exit(1);
    }
}

static void join_path(char* out, size_t out_len, const char* base, const char* suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);
    if (base_len + 1 + suffix_len >= out_len) {
        fprintf(stderr, "path too long\n");
        exit(1);
    }
    memcpy(out, base, base_len);
    out[base_len] = '/';
    memcpy(out + base_len + 1, suffix, suffix_len + 1);
}

static int remove_tree_entry(const char* path, const struct stat* st, int type, struct FTW* state) {
    (void)st;
    (void)type;
    (void)state;
    return remove(path);
}

static void make_fixture(void) {
    char template_path[] = "/tmp/ominull-linux-collector.XXXXXX";
    g_fixture_root = mkdtemp(template_path);
    if (!g_fixture_root) {
        perror("mkdtemp");
        exit(1);
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/net", g_fixture_root);
    mkdir_or_die(path);
    snprintf(path, sizeof(path), "%s/net/tcp", g_fixture_root);
    FILE* tcp = fopen(path, "w");
    if (!tcp) {
        perror(path);
        exit(1);
    }
    fputs("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n", tcp);
    for (int i = 0; i < FIXTURE_SOCKETS / 2; i++) {
        fprintf(tcp, "%d: 0100000A:%04X 0300000A:0050 01 00000000:%08X 00:00000000 0 1000 0 %lu\n",
                i, 4000 + i, i, 50000UL + (unsigned long)i);
    }
    fclose(tcp);

    snprintf(path, sizeof(path), "%s/net/tcp6", g_fixture_root);
    FILE* tcp6 = fopen(path, "w");
    if (!tcp6) {
        perror(path);
        exit(1);
    }
    fputs("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n", tcp6);
    for (int i = FIXTURE_SOCKETS / 2; i < FIXTURE_SOCKETS; i++) {
        fprintf(tcp6, "%d: 00000000000000000000000002000000:%04X B80D0120000000000000000001000000:0050 01 00000000:%08X 00:00000000 0 1000 0 %lu\n",
                i, 4000 + i, i, 50000UL + (unsigned long)i);
    }
    fclose(tcp6);

    for (int process = 0; process < FIXTURE_PROCESSES; process++) {
        unsigned int pid = 1000U + (unsigned int)process;
        snprintf(path, sizeof(path), "%s/%u", g_fixture_root, pid);
        mkdir_or_die(path);
        char fd_dir[PATH_MAX];
        join_path(fd_dir, sizeof(fd_dir), path, "fd");
        mkdir_or_die(fd_dir);
        for (int fd = 0; fd < FIXTURE_FDS; fd++) {
            char fd_path[PATH_MAX];
            char fd_name[32];
            snprintf(fd_name, sizeof(fd_name), "%d", fd);
            join_path(fd_path, sizeof(fd_path), fd_dir, fd_name);
            char target[64];
            if (process < FIXTURE_SOCKETS && fd == FIXTURE_FDS - 1) {
                snprintf(target, sizeof(target), "socket:[%lu]", 50000UL + (unsigned long)process);
            } else {
                snprintf(target, sizeof(target), "pipe:[%u]", process * FIXTURE_FDS + fd + 1);
            }
            link_or_die(target, fd_path);
        }
        char exe_path[PATH_MAX];
        join_path(exe_path, sizeof(exe_path), path, "exe");
        link_or_die("/usr/bin/fixture-process", exe_path);
    }
}

static void test_legacy_config(void) {
    char path[] = "/tmp/ominull-linux-config.XXXXXX";
    int fd = mkstemp(path);
    check(fd >= 0, "could not create legacy config fixture");
    if (fd < 0) return;

    FILE* config_file = fdopen(fd, "w");
    check(config_file != NULL, "could not open legacy config fixture");
    if (!config_file) {
        close(fd);
        unlink(path);
        return;
    }
    fputs("OMINULL_ARGS=--hub https://hub.example.test --key-file /etc/ominull/agent.key "
          "--role workstation --location loc-home --id linux-target --ca /etc/ominull/ca.crt "
          "--client-cert /etc/ominull/client.crt --client-key /etc/ominull/client.key "
          "--cf-id client-id --cf-secret client-secret\n", config_file);
    fclose(config_file);

    LINUX_AGENT_CONFIG config;
    memset(&config, 0, sizeof(config));
    check(LoadConfigFile(&config, path), "legacy config fixture was not readable");
    check(strcmp(config.hub_url, "https://hub.example.test") == 0,
          "legacy config did not preserve hub URL");
    check(strcmp(config.key_path, "/etc/ominull/agent.key") == 0,
          "legacy config did not preserve key path");
    check(strcmp(config.endpoint_id, "linux-target") == 0,
          "legacy config did not preserve endpoint ID");
    check(strcmp(config.ca_path, "/etc/ominull/ca.crt") == 0,
          "legacy config did not preserve CA path");
    check(strcmp(config.client_key_path, "/etc/ominull/client.key") == 0,
          "legacy config did not preserve client key path");
    check(strcmp(config.cf_client_secret, "client-secret") == 0,
          "legacy config did not preserve Cloudflare secret");
    unlink(path);
}

int main(void) {
    test_legacy_config();
    make_fixture();

    LINUX_FLOW_EVENT events[FIXTURE_SOCKETS];
    g_ProcDescriptorWalks = 0;
    size_t got = CollectActiveFlows(events, FIXTURE_SOCKETS);

    char message[256];
    snprintf(message, sizeof(message), "fixture produced %d active flows, expected %d", (int)got, FIXTURE_SOCKETS);
    check(got == FIXTURE_SOCKETS, message);
    check(strcmp(events[FIXTURE_SOCKETS / 2].src_ip, "::2") == 0,
          "IPv6 local address was not decoded from tcp6");
    check(strcmp(events[FIXTURE_SOCKETS / 2].dst_ip, "2001:db8::1") == 0,
          "IPv6 remote address was not decoded from tcp6");

    unsigned long one_index_walk = (unsigned long)FIXTURE_PROCESSES * FIXTURE_FDS;
    unsigned long allowed = one_index_walk + (unsigned long)FIXTURE_SOCKETS * 4UL;
    snprintf(message, sizeof(message), "collector performed %lu descriptor reads, budget is %lu",
             g_ProcDescriptorWalks, allowed);
    check(g_ProcDescriptorWalks <= allowed, message);

    nftw(g_fixture_root, remove_tree_entry, 16, FTW_DEPTH | FTW_PHYS);
    if (failures) {
        fprintf(stderr, "[-] Linux collector feedback loop failed\n");
        return 1;
    }
    printf("[+] Linux collector feedback loop passed: %lu descriptor reads\n", g_ProcDescriptorWalks);
    return 0;
}
