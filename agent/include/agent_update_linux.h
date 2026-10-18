/*
 * The Linux self-updater's install script, built here so a test can run it
 * against stand-in tools. ApplyAgentUpdate writes it to the staging directory
 * and runs it detached (dpkg's prerm stops the daemon that started it).
 *
 * `set -e` stops a failed download, a wrong digest or a bad signature before
 * dpkg is reached. After the install the new binary must start (--version) and
 * then stay running; otherwise the previous binary is put back and the version
 * is marked failed (DIR/failed-VERSION), which the daemon checks before trying
 * that version again. A package that installs but cannot run here (a newer
 * libc, a crash at start) therefore costs one restart, not the endpoint.
 */
#ifndef OMINULL_AGENT_UPDATE_LINUX_H
#define OMINULL_AGENT_UPDATE_LINUX_H

#include <stdio.h>
#include <stddef.h>

typedef struct {
    const char* dir;         /* root-only staging directory */
    const char* binary;      /* installed agent binary */
    const char* log_path;
    const char* unit;        /* systemd unit */
    const char* version;
    const char* curl_args;   /* TLS pinning arguments for curl */
    const char* hub_url;
    const char* pkg_path;
    const char* sig_path;
    const char* sha256;
    int settle_seconds;      /* how long the new agent must stay up */
    const char* key_name;    /* which key signed the release statement: main or routine:<id> (NULL: main) */
} AgentUpdateScript;

/* Returns the script length, or -1 when it does not fit. */
static inline int AgentUpdate_BuildScript(const AgentUpdateScript* s, char* out, size_t cap) {
    int n = snprintf(out, cap,
        "#!/bin/sh\n"
        "set -e\n"
        "D=%s\n"
        "B=%s\n"
        "U=%s\n"
        "exec >>%s 2>&1\n"
        "echo \"=== $(date -u '+%%Y-%%m-%%dT%%H:%%M:%%SZ') updating to v%s ===\"\n"
        "rm -f \"$D/agent.deb\" \"$D/agent.deb.sig\"\n"
        "curl -fsSL %s -m 300 -o \"$D/agent.deb\" \"%s%s\"\n"
        "curl -fsSL %s -m 60 -o \"$D/agent.deb.sig\" \"%s%s\"\n"
        "echo \"%s  $D/agent.deb\" | sha256sum -c -\n"
        "openssl dgst -sha256 -verify \"$D/release.pub\" -signature \"$D/agent.deb.sig\" \"$D/agent.deb\"\n"
        "base64 -d \"$D/release.sig.b64\" > \"$D/release.sig\"\n"
        "openssl dgst -sha256 -verify \"$D/release.pub\" -signature \"$D/release.sig\" \"$D/release.statement\"\n"
        "echo \"[+] v%s verified against release key %s; installing\"\n"
        "cp -p \"$B\" \"$D/ominulld.previous\"\n"
        "R0=$(systemctl show -p NRestarts --value \"$U\" 2>/dev/null || echo 0)\n"
        "rollback() {\n"
        "  echo \"[!] v%s $1; restoring the previous agent binary\"\n"
        "  install -o root -g root -m 0755 \"$D/ominulld.previous\" \"$B\"\n"
        "  : > \"$D/failed-%s\"\n"
        "  systemctl reset-failed \"$U\" || true\n"
        "  systemctl restart \"$U\"\n"
        "  exit 1\n"
        "}\n"
        "dpkg -i \"$D/agent.deb\"\n"
        "rm -f \"$D/agent.deb\" \"$D/agent.deb.sig\"\n"
        "\"$B\" --version >/dev/null 2>&1 || rollback \"does not start on this host\"\n"
        "systemctl restart \"$U\"\n"
        "sleep %d\n"
        "R1=$(systemctl show -p NRestarts --value \"$U\" 2>/dev/null || echo 0)\n"
        "if ! systemctl is-active --quiet \"$U\" || [ \"$R1\" != \"$R0\" ]; then rollback \"did not stay running\"; fi\n"
        "rm -f \"$D/ominulld.previous\"\n"
        "echo \"[+] v%s is running\"\n",
        s->dir, s->binary, s->unit, s->log_path, s->version,
        s->curl_args, s->hub_url, s->pkg_path,
        s->curl_args, s->hub_url, s->sig_path,
        s->sha256, s->version, s->key_name ? s->key_name : "main", s->version, s->version,
        s->settle_seconds, s->version);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

#endif
