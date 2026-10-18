/*
 * The self-updater's install script, run against stand-in curl, openssl,
 * dpkg, systemctl and install: a new binary that cannot start, one that
 * crash-loops and one that is not active are rolled back to the previous
 * binary and marked failed; a healthy one stays.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "../include/agent_update_linux.h"

static int failures = 0;
static char root[256];

static void check(const char* name, bool ok) {
    printf("  [%c] %s\n", ok ? '+' : '-', name);
    if (!ok) failures++;
}

/* Runs a shell command with every %s replaced by a (no format string). */
static int sh(const char* tmpl, const char* a) {
    char cmd[4096];
    size_t o = 0, alen = strlen(a);
    for (const char* p = tmpl; *p && o + alen + 1 < sizeof(cmd); p++) {
        if (p[0] == '%' && p[1] == 's') { memcpy(cmd + o, a, alen); o += alen; p++; }
        else cmd[o++] = *p;
    }
    cmd[o] = 0;
    return system(cmd);
}

static bool fileHas(const char* rel, const char* want) {
    char path[512], buf[256] = {0};
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE* f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, want) != NULL;
}

static bool exists(const char* rel) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    return access(path, F_OK) == 0;
}

/* newBinary: shell body of the installed binary; active: is-active exit code;
 * bump: restarts counted by systemd after the update's restart. */
static int run(const char* newBinary, int active, bool bump) {
    sh("rm -rf %s && mkdir -p %s/D %s/fake %s/bin", root);
    sh("printf '#!/bin/sh\\necho old\\n' > %s/bin/ominulld && chmod 755 %s/bin/ominulld && printf 'c2ln\\n' > %s/D/release.sig.b64", root);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "printf '#!/bin/sh\\n%s\\n' > %s/new && chmod 755 %s/new", newBinary, root, root);
    if (system(cmd) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "echo 3 > %s/nrestarts; echo %d > %s/active", root, active, root);
    if (system(cmd) != 0) return -1;
    if (bump) sh("touch %s/bump", root);
    /* Stand-ins. curl writes its -o file; dpkg installs %s/new as the binary. */
    sh("printf '#!/bin/sh\\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && : > \"$2\"; shift; done\\n' > %s/fake/curl", root);
    sh("printf '#!/bin/sh\\ncat >/dev/null\\n' > %s/fake/sha256sum; printf '#!/bin/sh\\nexit 0\\n' > %s/fake/openssl; printf '#!/bin/sh\\nexit 0\\n' > %s/fake/sleep", root);
    sh("printf '#!/bin/sh\\ncp %s/new %s/bin/ominulld\\n' > %s/fake/dpkg", root);
    sh("printf '#!/bin/sh\\nfor a; do s=$d; d=$a; done; cp \"$s\" \"$d\"\\n' > %s/fake/install", root);
    sh("printf '#!/bin/sh\\nR=%s\\necho \"$*\" >> $R/systemctl.log\\n"
       "case \"$1\" in show) cat $R/nrestarts;; is-active) exit $(cat $R/active);;"
       " restart) [ -f $R/bump ] && echo 9 > $R/nrestarts; true;; esac\\n' > %s/fake/systemctl", root);
    sh("chmod 755 %s/fake/*", root);

    char d[300], b[300], l[300];
    snprintf(d, sizeof(d), "%s/D", root);
    snprintf(b, sizeof(b), "%s/bin/ominulld", root);
    snprintf(l, sizeof(l), "%s/update.log", root);
    AgentUpdateScript s = {
        .dir = d, .binary = b, .log_path = l, .unit = "ominull-agent.service", .version = "9.9.9",
        .curl_args = "--cacert x", .hub_url = "https://hub.invalid", .pkg_path = "/download/a.deb",
        .sig_path = "/download/a.deb.sig", .sha256 = "00", .settle_seconds = 0,
    };
    char script[8192];
    if (AgentUpdate_BuildScript(&s, script, sizeof(script)) < 0) return -1;
    char path[300];
    snprintf(path, sizeof(path), "%s/apply.sh", root);
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    fputs(script, f);
    fclose(f);
    snprintf(cmd, sizeof(cmd), "PATH=%s/fake:/usr/bin:/bin sh %s", root, path);
    return system(cmd);
}

int main(void) {
    snprintf(root, sizeof(root), "%s/ominull-update-test.%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    printf("[*] Agent self-update install script\n");

    int rc = run("[ \"$1\" = --version ] && exit 127; echo new", 0, false);
    check("binary that cannot start: script fails", rc != 0);
    check("binary that cannot start: previous binary restored", fileHas("bin/ominulld", "echo old"));
    check("binary that cannot start: version marked failed", exists("D/failed-9.9.9"));
    check("binary that cannot start: log says why", fileHas("update.log", "does not start on this host"));

    rc = run("echo new", 0, false);
    check("healthy binary: script succeeds", rc == 0);
    check("healthy binary: new binary stays", fileHas("bin/ominulld", "echo new"));
    check("healthy binary: not marked failed", !exists("D/failed-9.9.9"));
    check("healthy binary: no previous copy left", !exists("D/ominulld.previous"));
    check("healthy binary: log names the key that verified it", fileHas("update.log", "verified against release key main"));

    rc = run("echo new", 0, true);
    check("crash-looping binary: rolled back", rc != 0 && fileHas("bin/ominulld", "echo old") && exists("D/failed-9.9.9"));

    rc = run("echo new", 3, false);
    check("inactive unit: rolled back", rc != 0 && fileHas("bin/ominulld", "echo old") && exists("D/failed-9.9.9"));

    AgentUpdateScript tiny = {0};
    char small[64];
    tiny.dir = tiny.binary = tiny.log_path = tiny.unit = tiny.version = tiny.curl_args = "x";
    tiny.hub_url = tiny.pkg_path = tiny.sig_path = tiny.sha256 = "x";
    check("script that does not fit is refused", AgentUpdate_BuildScript(&tiny, small, sizeof(small)) < 0);

    sh("rm -rf %s", root);
    if (failures) { printf("[-] %d failure(s)\n", failures); return 1; }
    printf("[+] All self-update script checks passed\n");
    return 0;
}
