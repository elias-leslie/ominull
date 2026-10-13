/*
 * Data inventory module (agent/include/data_inventory_linux.h): rules,
 * parsers, the walk, the cursor and verdict cache, canary skipping, and the
 * sandbox - the seccomp filter must kill the scanning child on any write,
 * create, symlink-following open, foreign write or exec.
 *
 * Runs unprivileged; nothing outside a mkdtemp directory is written.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "data_inventory_linux.h"

static int g_run = 0, g_failed = 0;
#define CHECK(expr) do { g_run++; if (!(expr)) { g_failed++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); } } while (0)

static uint64_t rules_of(const char* text) { return DataInv_ContentRules((const unsigned char*)text, strlen(text)); }
static bool has(uint64_t r, int bit) { return (r & DI_BIT(bit)) != 0; }

/* Test fixtures are assembled at run time so no literal in this file looks
 * like a credential to a repository scanner. */
static void join(char* out, size_t cap, const char* a, const char* b) { snprintf(out, cap, "%s%s", a, b); }

static void test_content_rules(void) {
    char t[512];
    join(t, sizeof(t), "aws_key = AKIA", "IOSFODNN7EXAMPLQ\n");
    CHECK(has(rules_of(t), DI_R_AWS_ACCESS_KEY));
    join(t, sizeof(t), "xAKIA", "IOSFODNN7EXAMPLQ");
    CHECK(!has(rules_of(t), DI_R_AWS_ACCESS_KEY)); /* no boundary */
    join(t, sizeof(t), "AKIA", "IOSFODNN7EXAMPL"); /* 15 chars */
    CHECK(!has(rules_of(t), DI_R_AWS_ACCESS_KEY));
    join(t, sizeof(t), "token: gh", "p_abcdefghijklmnopqrstuvwxyz0123456789\n");
    CHECK(has(rules_of(t), DI_R_GITHUB_TOKEN));
    join(t, sizeof(t), "key=sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz012345\n");
    CHECK(has(rules_of(t), DI_R_ANTHROPIC_KEY));
    join(t, sizeof(t), "xox", "b-1234567890-abcdefghij");
    CHECK(has(rules_of(t), DI_R_SLACK_TOKEN));
    join(t, sizeof(t), "sk_li", "ve_abcdefghijklmnopqrstuvwx");
    CHECK(has(rules_of(t), DI_R_STRIPE_KEY));
    join(t, sizeof(t), "AIza", "SyA-abcdefghijklmnopqrstuvwxyz01234");
    CHECK(has(rules_of(t), DI_R_GOOGLE_API_KEY));
    join(t, sizeof(t), "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
    CHECK(has(rules_of(t), DI_R_JWT));
    join(t, sizeof(t), "-----BEGIN RSA PRIVATE", " KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n");
    CHECK(has(rules_of(t), DI_R_PRIVATE_KEY));
    join(t, sizeof(t), "-----BEGIN ENCRYPTED PRIVATE", " KEY-----\nMIIE\n");
    CHECK(has(rules_of(t), DI_R_PRIVATE_KEY_ENCRYPTED) && !has(rules_of(t), DI_R_PRIVATE_KEY));
    join(t, sizeof(t), "-----BEGIN OPENSSH PRIVATE", " KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n");
    CHECK(has(rules_of(t), DI_R_PRIVATE_KEY));
    join(t, sizeof(t), "-----BEGIN OPENSSH PRIVATE", " KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI\n");
    CHECK(has(rules_of(t), DI_R_PRIVATE_KEY_ENCRYPTED));
    join(t, sizeof(t), "DATABASE_URL=postgres://app:Zq8vT", "3kLm2@db.internal:5432/app\n");
    CHECK(has(rules_of(t), DI_R_URL_CREDENTIALS));
    CHECK(!has(rules_of("url=https://user:${PASSWORD}@host/x"), DI_R_URL_CREDENTIALS));
    CHECK(!has(rules_of("see https://example.com:8080/path"), DI_R_URL_CREDENTIALS));
    join(t, sizeof(t), "DB_PASSWORD=\"Xk9mQ2vL7p", "R4zWt8Yb\"\n");
    CHECK(has(rules_of(t), DI_R_GENERIC_ASSIGNMENT));
    join(t, sizeof(t), "pass" "word: Xk9mQ2v", "L7pR4zWt8Yb\n");
    CHECK(has(rules_of(t), DI_R_GENERIC_ASSIGNMENT));
    /* placeholders, references and code are not secrets */
    CHECK(!has(rules_of("password = \"changeme-please-1234\"\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("API_KEY=${API_KEY}\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("token = os.environ['TOKEN_VALUE_X']\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("secret = get_secret_from_vault(name)\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("password_file = /run/secrets/db-password-file\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("if token == expected_token_value_x:\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("token = aaaaaaaaaaaaaaaaaaaa\n"), DI_R_GENERIC_ASSIGNMENT)); /* low entropy */
    /* code and prose, not secrets */
    CHECK(!has(rules_of("    secret_or_key = excluded.secret_or_key,\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("    token = uuid.uuid4().hex[:8]\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("    s.OperatorTokenHash = operatorTokenHash\n"), DI_R_GENERIC_ASSIGNMENT));
    join(t, sizeof(t), "{\"api_", "key\":\"attacker-chosen-value\"}\n");
    CHECK(!has(rules_of(t), DI_R_GENERIC_ASSIGNMENT));
    CHECK(!has(rules_of("<c publicKeyToken=\"31bf3856ad364e35\"/>\n"), DI_R_GENERIC_ASSIGNMENT));
    CHECK(rules_of("plain prose with no secrets at all, only words.") == 0);
    /* binary content: only magic */
    unsigned char bin[64] = {0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0};
    memcpy(bin + 20, "AKIA", 4);
    memcpy(bin + 24, "IOSFODNN7EXAMPLQ", 16);
    uint64_t br = DataInv_ContentRules(bin, sizeof(bin));
    CHECK(has(br, DI_C_KEEPASS) && !has(br, DI_R_AWS_ACCESS_KEY));
    unsigned char luks[16] = {'L', 'U', 'K', 'S', 0xBA, 0xBE, 0, 2};
    CHECK(has(DataInv_ContentRules(luks, sizeof(luks)), DI_C_LUKS));
    CHECK(has(rules_of("$ANSIBLE_VAULT;1.1;AES256\n3132\n"), DI_C_ANSIBLE_VAULT));
}

static void test_name_rules(void) {
    CHECK(has(DataInv_NameRules("id_ed25519", ".ssh"), DI_K_SSH_PRIVATE));
    CHECK(DataInv_NameRules("id_ed25519.pub", ".ssh") == 0);
    CHECK(has(DataInv_NameRules("credentials", ".aws"), DI_K_CREDENTIALS_FILE));
    CHECK(!has(DataInv_NameRules("credentials", "docs"), DI_K_CREDENTIALS_FILE));
    CHECK(has(DataInv_NameRules(".env", "app"), DI_K_ENV_FILE));
    CHECK(has(DataInv_NameRules(".env.production", "app"), DI_K_ENV_FILE));
    CHECK(!has(DataInv_NameRules(".env.example", "app"), DI_K_ENV_FILE));
    CHECK(has(DataInv_NameRules("vault.kdbx", "x"), DI_C_KEEPASS));
    CHECK(has(DataInv_NameRules("server.p12", "x"), DI_K_PKCS12));
    CHECK(has(DataInv_NameRules("config", ".kube"), DI_K_CREDENTIALS_FILE));
    CHECK(strcmp(DataInv_ItemKind(DI_BIT(DI_K_ENV_FILE) | DI_BIT(DI_R_AWS_ACCESS_KEY)), "secret_candidate") == 0);
    CHECK(strcmp(DataInv_ItemKind(DI_BIT(DI_R_PRIVATE_KEY)), "private_key") == 0);
    CHECK(strcmp(DataInv_ItemKind(DI_BIT(DI_C_LUKS)), "encrypted_container") == 0);
    CHECK(strcmp(DataInv_ItemKind(DI_BIT(DI_K_PKCS12)), "key_file") == 0);
}

static void test_json_and_paths(void) {
    char buf[128];
    DataInvBuf b = {buf, sizeof(buf), 0, true};
    DataInv_PutJSONString(&b, "a\"b\\c\n\xff\xc3\xa9");
    CHECK(b.ok && strcmp(buf, "\"a\\\"b\\\\c\\u000a\\u00ff\xc3\xa9\"") == 0);
    CHECK(DataInv_PathCmp("/a", "/a/b") < 0);
    CHECK(DataInv_PathCmp("/a/b", "/a-c") < 0); /* walk order, not strcmp order */
    CHECK(strcmp("/a/b", "/a-c") > 0);
    CHECK(DataInv_PathCmp("/a/b", "/a/b") == 0);
    CHECK(DataInv_Under("/a/b/c", "/a/b") && DataInv_Under("/a/b", "/a/b") && !DataInv_Under("/a/bc", "/a/b"));
    char sp[64];
    DataInvBuf sb = {sp, sizeof(sp), 0, true};
    DataInv_PutStatePath(&sb, "/x y/%\tz\n");
    CHECK(strcmp(sp, "/x%20y/%25%09z%0A") == 0);
    CHECK(DataInv_DecodeStatePath(sp) && strcmp(sp, "/x y/%\tz\n") == 0);
    char bad[] = "/x%0";
    CHECK(!DataInv_DecodeStatePath(bad));
    char nul[] = "/x%00";
    CHECK(!DataInv_DecodeStatePath(nul));
    /* contract path encoding: printable valid UTF-8 kept, the rest %XX */
    char pb[160];
    DataInvBuf pj = {pb, sizeof(pb), 0, true};
    DataInv_PutJSONPath(&pj, "/a b/100%/\x01\x7f/\xc2\x85/\xc2\xa0/\xff/caf\xc3\xa9/\"q\"");
    CHECK(pj.ok && strcmp(pb, "\"/a b/100%25/%01%7F/%C2%85/\xc2\xa0/%FF/caf\xc3\xa9/\\\"q\\\"\"") == 0);
}

static void test_policy(void) {
    DataInvPolicy p;
    char why[128];
    const char* ok = DI_POLICY_HEADER "\nversion 7\nenabled 1\nroot /home\nroot /srv/workspaces\nexclude /srv/scratch*\n"
                     "canary /home/u/.aws/credentials\nstore_depth 2\nmax_files 50000\nfuture_key whatever\nend\n";
    CHECK(DataInv_ParsePolicy(ok, &p, why, sizeof(why)));
    CHECK(p.version == 7 && p.enabled && p.nroots == 2 && p.ncanaries == 1 && p.nexcludes == 1 && p.max_files == 50000);
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nenabled 1\nroot /home\n", &p, why, sizeof(why))); /* no end */
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nroot home\nend\n", &p, why, sizeof(why)));
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nroot /home/../etc\nend\n", &p, why, sizeof(why)));
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nmax_files 1\nend\n", &p, why, sizeof(why)));
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nenabled 1\nend\n", &p, why, sizeof(why))); /* no roots */
    CHECK(!DataInv_ParsePolicy("something else\nend\n", &p, why, sizeof(why)));
    CHECK(!DataInv_ParsePolicy(DI_POLICY_HEADER "\nend\nroot /x\n", &p, why, sizeof(why)));
    CHECK(DataInv_ParsePolicy(DI_POLICY_HEADER "\nenabled 0\nend\n", &p, why, sizeof(why)) && !p.enabled);
}

static void test_state(void) {
    const char* text = DI_STATE_HEADER "\ncycle 0123456789abcdef 1000 1 0 3 1\ncursor /r/a%20b\nlast_run 5\nlast_done 4\nlast_full 3\n"
                       "wm 900 0123456789abcdef /r/a%20b\nv 1 2 30 40 4 0123456789abcdef /r/a%20b /r/a%20b/.env\nend\n";
    DataInvState s;
    CHECK(DataInv_ParseState(text, &s));
    CHECK(s.has_cycle && s.cycle_full && !s.cycle_done && s.cycle_policy == 3 && s.has_cursor && !strcmp(s.cursor, "/r/a b"));
    CHECK(s.nmarks == 1 && s.nverdicts == 1 && s.verdicts[0].rules == 4 && !strcmp(s.verdicts[0].store, "/r/a b"));
    CHECK(DataInv_FindVerdict(&s, "/r/a b/.env") != NULL && DataInv_FindMark(&s, "/r/a b") != NULL);
    DataInv_StateFree(&s);
    CHECK(!DataInv_ParseState(DI_STATE_HEADER "\ncursor relative\nend\n", &s));
    CHECK(!DataInv_ParseState(DI_STATE_HEADER "\nlast_run 5\n", &s)); /* no end */
    CHECK(!DataInv_ParseState(DI_STATE_HEADER "\nbogus 1\nend\n", &s));
    DataInvPolicy p;
    DataInv_PolicyDefaults(&p);
    p.enabled = true;
    p.nroots = 1;
    p.version = 3;
    memset(&s, 0, sizeof(s));
    CHECK(DataInv_Due(&p, &s, 1000)); /* never ran */
    s.has_cycle = true;
    s.cycle_policy = 3;
    s.cycle_rules = DI_RULES_VERSION;
    s.cycle_done = true;
    s.last_done = 0;
    CHECK(!DataInv_Due(&p, &s, 3600000LL));
    CHECK(DataInv_Due(&p, &s, 24LL * 3600000));
    s.cycle_policy = 4;
    CHECK(DataInv_Due(&p, &s, 1)); /* policy changed */
    s.cycle_policy = 3;
    s.cycle_done = false;
    s.last_run = 0;
    CHECK(!DataInv_Due(&p, &s, 59 * 60000LL) && DataInv_Due(&p, &s, 60 * 60000LL));
}

/* ------------------------------------------------------------------ tree fixture */

static char g_root[256];

static void put(const char* rel, const char* content, mode_t mode) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_root, rel);
    for (char* p = path + strlen(g_root) + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(path, 0755); *p = '/'; }
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    assert(fd >= 0);
    assert(write(fd, content, strlen(content)) == (ssize_t)strlen(content));
    close(fd);
    chmod(path, mode);
}

static char g_aws[64], g_pw[64], g_urlpw[64];

static void make_tree(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/ominull-di-test-XXXXXX");
    assert(mkdtemp(g_root));
    join(g_aws, sizeof(g_aws), "AKIA", "QZXCVBNMASDFGHJK");
    join(g_pw, sizeof(g_pw), "Xk9mQ2vL7p", "R4zWt8Yb");
    join(g_urlpw, sizeof(g_urlpw), "s3cr3tPa", "ssw0rdQ");
    char t[512];
    put("topfile.txt", "hello\n", 0644);
    snprintf(t, sizeof(t), "AWS_ACCESS_KEY_ID=%s\n", g_aws);
    put("proj/app/.env", t, 0644);
    snprintf(t, sizeof(t), "db:\n  password: %s\n", g_pw);
    put("proj/app/config.yaml", t, 0640);
    snprintf(t, sizeof(t), "[remote \"origin\"]\n\turl = https://bob:%s@git.example.org/r.git\n", g_urlpw);
    put("proj/app/.git/config", t, 0644);
    put("proj/app/.git/HEAD", "ref: refs/heads/main\n", 0644);
    join(t, sizeof(t), "-----BEGIN OPENSSH PRIVATE", " KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n");
    put("proj/app/id_ed25519", t, 0600);
    snprintf(t, sizeof(t), "k=%s\n", g_aws);
    put("proj/app/node_modules/pkg/index.js", t, 0644);
    put("proj/app/build/CACHEDIR.TAG", "Signature: 8a477f597d28d172789f06886806bc55\n", 0644);
    put("proj/app/build/leak.env", t, 0644);
    put("proj/app/venv/pyvenv.cfg", "home = /usr/bin\n", 0644);
    put("proj/app/venv/lib/x.py", t, 0644);
    put("proj/docs/readme.md", "token = example_token_here\n", 0644);
    put("proj/docs/cert.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", 0644);
    put("proj/docs/sub/deep/notes.txt", "nothing here\n", 0644);
    snprintf(t, sizeof(t), "[default]\naws_access_key_id = %s\n", g_aws);
    put("home/alice/.aws/credentials", t, 0600);
    unsigned char kdbx[32] = {0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    char kpath[512];
    snprintf(kpath, sizeof(kpath), "%s/home/alice/vault.kdbx", g_root);
    int fd = open(kpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, kdbx, sizeof(kdbx)) == (ssize_t)sizeof(kdbx));
    close(fd);
    put("home/alice/notes.txt", "shopping list\n", 0644);
    put("canarydir/inside.env", t, 0644);
    char link[512];
    snprintf(link, sizeof(link), "%s/proj/app/passwd-link", g_root);
    assert(symlink("/etc/passwd", link) == 0);
}

static void rm_tree(const char* path) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    assert(system(cmd) == 0);
}

static void tree_policy(DataInvPolicy* p) {
    DataInv_PolicyDefaults(p);
    p->enabled = true;
    p->version = 1;
    p->nroots = 1;
    snprintf(p->roots[0], DI_PATH_CAP, "%s", g_root);
    p->ncanaries = 2;
    snprintf(p->canaries[0], DI_PATH_CAP, "%s/home/alice/.aws/credentials", g_root);
    snprintf(p->canaries[1], DI_PATH_CAP, "%s/canarydir", g_root);
    p->store_depth = 2;
}

/* Runs the child in-process (no sandbox) into a temp file; returns the output. */
static char* run_inproc(const DataInvPolicy* p, const char* state, const char* cycle, long long now) {
    char tmpl[] = "/tmp/ominull-di-out-XXXXXX";
    int fd = mkstemp(tmpl);
    assert(fd >= 0);
    unlink(tmpl);
    int rc = DataInv_ChildRun(fd, p, state, "ep-test", cycle, now, false);
    CHECK(rc == 0);
    off_t len = lseek(fd, 0, SEEK_END);
    char* buf = (char*)malloc((size_t)len + 1);
    assert(buf);
    assert(pread(fd, buf, (size_t)len, 0) == len);
    buf[len] = '\0';
    close(fd);
    return buf;
}

static int count_of(const char* hay, const char* needle) {
    int n = 0;
    for (const char* p = strstr(hay, needle); p; p = strstr(p + 1, needle)) n++;
    return n;
}

static long long num_after(const char* doc, const char* key) {
    const char* p = strstr(doc, key);
    return p ? atoll(p + strlen(key)) : -1;
}

static void no_secret_text(const char* out) {
    CHECK(strstr(out, g_aws) == NULL);
    CHECK(strstr(out, g_pw) == NULL);
    CHECK(strstr(out, g_urlpw) == NULL);
    CHECK(strstr(out, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU") == NULL);
}

static void test_walk(void) {
    DataInvPolicy p;
    tree_policy(&p);
    long long t0 = DataInv_NowMs();
    char* out = run_inproc(&p, NULL, "00000000000000a1", t0);
    no_secret_text(out);
    char* doc = NULL;
    char* state = NULL;
    char why[128];
    size_t len = strlen(out);
    CHECK(DataInv_SplitOutput(out, len, &doc, &state, why, sizeof(why)));
    if (!doc) { free(out); return; }
    char item[700];
    snprintf(item, sizeof(item), "\"path\":\"%s/proj/app/.env\"", g_root);
    CHECK(strstr(doc, item) != NULL);
    CHECK(strstr(doc, "\"rules\":[\"aws_access_key\",\"env_file\"]") != NULL);
    snprintf(item, sizeof(item), "\"path\":\"%s/proj/app/config.yaml\"", g_root);
    CHECK(strstr(doc, item) != NULL);
    snprintf(item, sizeof(item), "\"path\":\"%s/proj/app/.git/config\"", g_root);
    CHECK(strstr(doc, item) != NULL);
    CHECK(strstr(doc, "\"kind\":\"private_key\",\"rules\":[\"private_key\",\"ssh_private_key_file\"]") != NULL);
    CHECK(strstr(doc, "\"rules\":[\"keepass\"]") != NULL);
    CHECK(count_of(doc, "\"kind\":") == 5); /* .env, config.yaml, .git/config, id_ed25519, vault.kdbx */
    /* skipped: canaries (never named), caches, venv, symlinks, certificates, placeholders */
    CHECK(strstr(out, "canarydir") == NULL && strstr(out, ".aws") == NULL);
    CHECK(num_after(doc, "\"skipped_canary\":") == 2);
    CHECK(strstr(doc, "node_modules") == NULL && strstr(doc, "leak.env") == NULL && strstr(doc, "x.py") == NULL);
    CHECK(strstr(doc, "cert.pem") == NULL && strstr(doc, "readme.md") == NULL);
    CHECK(num_after(doc, "\"skipped_regenerable\":") == 3);
    CHECK(strstr(doc, "\"symlinks\":1") != NULL);
    CHECK(strstr(doc, "\"cycle_complete\":true") != NULL && strstr(doc, "\"mode\":\"full\"") != NULL);
    /* stores: shallow root (topfile), proj/app, proj/docs, home/alice */
    CHECK(num_after(doc, "\"stores\":") == 4);
    CHECK(strstr(doc, "\"shallow\":true") != NULL);
    CHECK(strstr(doc, "\"hints\":[\"git\"") != NULL);
    CHECK(strstr(state, "cursor ") == NULL);
    CHECK(count_of(state, "\nwm ") == 4);
    CHECK(count_of(state, "\nv ") == 5); /* content verdicts: .env, config.yaml, .git/config, id_ed25519, vault.kdbx */

    /* Second cycle a day later: incremental, nothing changed, nothing re-read,
     * same items from the cache. */
    char* out2 = run_inproc(&p, state, "00000000000000a2", t0 + 86400000LL);
    char* doc2 = NULL;
    char* state2 = NULL;
    CHECK(DataInv_SplitOutput(out2, strlen(out2), &doc2, &state2, why, sizeof(why)));
    if (doc2) {
        CHECK(strstr(doc2, "\"mode\":\"incremental\"") != NULL);
        CHECK(num_after(doc2, "\"content_files\":") == 0);
        CHECK(count_of(doc2, "\"kind\":") == 5);
        CHECK(strstr(doc2, "\"rules\":[\"aws_access_key\",\"env_file\"]") != NULL);
        /* A changed file is re-read; its old verdict is not trusted. */
        put("proj/app/.env", "NOTHING=here\n", 0644);
        char* out3 = run_inproc(&p, state2, "00000000000000a3", t0 + 2 * 86400000LL);
        char* doc3 = NULL;
        char* state3 = NULL;
        CHECK(DataInv_SplitOutput(out3, strlen(out3), &doc3, &state3, why, sizeof(why)));
        if (doc3) {
            CHECK(num_after(doc3, "\"content_files\":") >= 1);
            CHECK(strstr(doc3, "\"rules\":[\"env_file\"]") != NULL);
            CHECK(strstr(doc3, "\"rules\":[\"aws_access_key\",\"env_file\"]") == NULL);
            CHECK(count_of(state3, "\nv ") == 4);
        }
        free(out3);
        char t[256];
        snprintf(t, sizeof(t), "AWS_ACCESS_KEY_ID=%s\n", g_aws);
        put("proj/app/.env", t, 0644);
    }
    free(out2);
    free(out);
}

static void test_cursor(void) {
    DataInvPolicy p;
    tree_policy(&p);
    p.max_files = 2;
    char* state = NULL;
    int runs = 0, stores = 0, partial = 0;
    bool complete = false;
    char cycle[17] = "00000000000000b1";
    while (!complete && runs < 20) {
        char* out = run_inproc(&p, state, cycle, DataInv_NowMs() + runs);
        char* doc = NULL;
        char* st = NULL;
        char why[128];
        CHECK(DataInv_SplitOutput(out, strlen(out), &doc, &st, why, sizeof(why)));
        if (!doc) { free(out); break; }
        no_secret_text(out);
        stores += (int)num_after(doc, "\"stores\":");
        partial += count_of(doc, "\"partial\":true");
        complete = strstr(doc, "\"cycle_complete\":true") != NULL;
        if (!complete) CHECK(strstr(st, "\ncursor ") != NULL);
        if (runs > 0) CHECK(strstr(doc, "\"resumed_from\":null") == NULL);
        free(state);
        state = strdup(st);
        free(out);
        runs++;
    }
    CHECK(complete);
    CHECK(runs >= 2);
    CHECK(stores == 4); /* every store reported exactly once over the cycle */
    CHECK(partial >= 1); /* proj/app has more files than the per-run budget */
    free(state);
}

/* ------------------------------------------------------------------ sandbox */

/* Forks a child that sandboxes itself and then runs op; returns the wait status. */
static int sandboxed(int (*op)(int outfd, const char* root)) {
    int fds[2];
    assert(pipe(fds) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        if (!DataInv_DropCapabilities() || !DataInv_InstallSeccomp(fds[1])) _exit(90);
        int rc = op(fds[1], g_root);
        _exit(rc);
    }
    close(fds[1]);
    char tmp[256];
    while (read(fds[0], tmp, sizeof(tmp)) > 0) {}
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

static bool killed_by_seccomp(int status) { return WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS; }

static int op_read_ok(int outfd, const char* root) {
    char path[512];
    snprintf(path, sizeof(path), "%s/topfile.txt", root);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 2;
    char b[8];
    if (read(fd, b, sizeof(b)) <= 0) return 3;
    close(fd);
    return write(outfd, "ok", 2) == 2 ? 0 : 4;
}
static int op_create(int outfd, const char* root) {
    (void)outfd;
    char path[512];
    snprintf(path, sizeof(path), "%s/created-by-scan", root);
    return open(path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600) >= 0 ? 0 : 1;
}
static int op_rdwr(int outfd, const char* root) {
    (void)outfd;
    char path[512];
    snprintf(path, sizeof(path), "%s/topfile.txt", root);
    return open(path, O_RDWR | O_NOFOLLOW) >= 0 ? 0 : 1;
}
static int op_follow(int outfd, const char* root) {
    (void)outfd;
    char path[512];
    snprintf(path, sizeof(path), "%s/proj/app/passwd-link", root);
    return open(path, O_RDONLY) >= 0 ? 0 : 1; /* no O_NOFOLLOW */
}
static int op_write_stdout(int outfd, const char* root) {
    (void)outfd;
    (void)root;
    return write(1, "x", 1) == 1 ? 0 : 1;
}
static int op_unlink(int outfd, const char* root) {
    (void)outfd;
    char path[512];
    snprintf(path, sizeof(path), "%s/topfile.txt", root);
    return unlink(path) == 0 ? 0 : 1;
}
static int op_exec(int outfd, const char* root) {
    (void)outfd;
    (void)root;
    char* argv[] = {(char*)"/bin/true", NULL};
    execv("/bin/true", argv);
    return 1;
}
static int op_socket(int outfd, const char* root) {
    (void)outfd;
    (void)root;
    return socket(AF_INET, SOCK_STREAM, 0) >= 0 ? 0 : 1;
}
static int op_fork(int outfd, const char* root) {
    (void)outfd;
    (void)root;
    return syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0) >= 0 ? 0 : 1;
}
static int op_chmod(int outfd, const char* root) {
    (void)outfd;
    char path[512];
    snprintf(path, sizeof(path), "%s/topfile.txt", root);
    return chmod(path, 0777) == 0 ? 0 : 1;
}

static void test_sandbox(void) {
    int st = sandboxed(op_read_ok);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(killed_by_seccomp(sandboxed(op_create)));
    CHECK(killed_by_seccomp(sandboxed(op_rdwr)));
    CHECK(killed_by_seccomp(sandboxed(op_follow)));
    CHECK(killed_by_seccomp(sandboxed(op_write_stdout)));
    CHECK(killed_by_seccomp(sandboxed(op_unlink)));
    CHECK(killed_by_seccomp(sandboxed(op_exec)));
    CHECK(killed_by_seccomp(sandboxed(op_socket)));
    CHECK(killed_by_seccomp(sandboxed(op_fork)));
    CHECK(killed_by_seccomp(sandboxed(op_chmod)));
    char path[512];
    snprintf(path, sizeof(path), "%s/created-by-scan", g_root);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/topfile.txt", g_root);
    struct stat sb;
    CHECK(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0644);
}

/* The whole scan, sandboxed, through the parent's start/drain/split path. */
static void test_sandboxed_scan(void) {
    DataInvPolicy p;
    tree_policy(&p);
    char state_path[512];
    snprintf(state_path, sizeof(state_path), "%s.state", g_root);
    DataInvRun run;
    memset(&run, 0, sizeof(run));
    run.fd = -1;
    CHECK(DataInv_Start(&run, &p, state_path, "ep-test"));
    bool done = false;
    for (int i = 0; i < 3000 && !done; i++) {
        done = DataInv_Drain(&run);
        if (!done) usleep(10000);
    }
    CHECK(done);
    char* doc = NULL;
    char* state = NULL;
    char why[160] = {0};
    bool ok = DataInv_SplitOutput(run.buf, run.len, &doc, &state, why, sizeof(why));
    if (!ok) fprintf(stderr, "sandboxed scan: %s\n", why);
    CHECK(ok);
    if (ok) {
        CHECK(strstr(doc, "\"sandboxed\":true") != NULL);
        CHECK(count_of(doc, "\"kind\":") == 5);
        no_secret_text(doc);
        CHECK(DataInv_WriteState(state_path, state));
        DataInvState s;
        char* text = DataInv_ReadSmallFile(state_path, DI_STATE_CAP);
        CHECK(text && DataInv_ParseState(text, &s) && s.cycle_done);
        struct stat sb;
        CHECK(stat(state_path, &sb) == 0 && (sb.st_mode & 0777) == 0600);
        free(text);
        DataInv_StateFree(&s);
    }
    DataInv_Reset(&run);
    unlink(state_path);
}

/* Review 1 #2/#4: a run that runs out of content budget keeps the verdicts of
 * the files it could not read, and times before 1970 are reported as 0. */
static void test_budget_keeps_verdicts(void) {
    char rp[600];
    snprintf(rp, sizeof(rp), "%s/proj/docs/readme.md", g_root);
    struct timespec old[2] = {{-315619200, 0}, {-315619200, 0}};
    CHECK(utimensat(AT_FDCWD, rp, old, 0) == 0);
    DataInvPolicy p;
    tree_policy(&p);
    p.version = 41;
    char* out = run_inproc(&p, NULL, "00000000000000c1", DataInv_NowMs());
    char *doc = NULL, *st = NULL, why[128];
    CHECK(DataInv_SplitOutput(out, strlen(out), &doc, &st, why, sizeof(why)) && doc && st);
    CHECK(doc && strstr(doc, "proj/app/config.yaml") != NULL);
    CHECK(doc && strstr(doc, "mtime\":-") == NULL && strstr(doc, "\"oldest_mtime\":0") != NULL);
    char* state = strdup(st ? st : "");
    free(out);
    /* policy change: a full cycle, with no content budget at all */
    p.version = 42;
    p.content_budget_bytes = 1;
    out = run_inproc(&p, state, "00000000000000c2", DataInv_NowMs() + 1000);
    CHECK(DataInv_SplitOutput(out, strlen(out), &doc, &st, why, sizeof(why)) && doc && st);
    CHECK(doc && strstr(doc, "\"content_partial\":true") != NULL);
    CHECK(doc && strstr(doc, "proj/app/config.yaml") != NULL); /* carried, not lost */
    free(state);
    state = strdup(st ? st : "");
    free(out);
    /* incremental with an ample budget: still there */
    p.content_budget_bytes = 256 << 20;
    out = run_inproc(&p, state, "00000000000000c3", DataInv_NowMs() + 2000);
    CHECK(DataInv_SplitOutput(out, strlen(out), &doc, &st, why, sizeof(why)) && doc);
    CHECK(doc && strstr(doc, "proj/app/config.yaml") != NULL);
    free(state);
    free(out);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_content_rules();
    test_name_rules();
    test_json_and_paths();
    test_policy();
    test_state();
    make_tree();
    test_walk();
    test_cursor();
    test_budget_keeps_verdicts();
    test_sandbox();
    test_sandboxed_scan();
    rm_tree(g_root);
    printf("data inventory: %d checks, %d failed\n", g_run, g_failed);
    return g_failed ? 1 : 0;
}
