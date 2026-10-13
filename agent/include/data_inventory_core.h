/*
 * Ominull data inventory: platform-neutral detection core.
 *
 * The data inventory module walks hub-configured roots and reports metadata
 * only: per-store counts, sizes, times, modes and extension histograms, and
 * per-file verdicts for secret candidates, private keys, key/credential files
 * and encrypted containers. This header holds the parts that do not touch the
 * filesystem, so the Linux walker (data_inventory_linux.h) and a Windows
 * walker can share them and the tests can drive them directly.
 *
 * Secret detection runs here, on the endpoint, over a buffer the walker has
 * already read. A verdict is a set of rule ids. The matched text never leaves
 * this file: no function here copies, returns or logs it.
 */

#ifndef OMINULL_DATA_INVENTORY_CORE_H
#define OMINULL_DATA_INVENTORY_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Bumped whenever a rule is added or changed: a new rule set re-reads every
 * candidate file once (a full cycle) instead of trusting cached verdicts. */
#define DI_RULES_VERSION 1

/* Rule ids. Order is the wire order of names; never renumber, append only. */
enum {
    /* secrets found in content */
    DI_R_PRIVATE_KEY = 0,
    DI_R_PRIVATE_KEY_ENCRYPTED,
    DI_R_AWS_ACCESS_KEY,
    DI_R_GITHUB_TOKEN,
    DI_R_GITLAB_TOKEN,
    DI_R_SLACK_TOKEN,
    DI_R_SLACK_WEBHOOK,
    DI_R_DISCORD_WEBHOOK,
    DI_R_ANTHROPIC_KEY,
    DI_R_OPENAI_KEY,
    DI_R_STRIPE_KEY,
    DI_R_GOOGLE_API_KEY,
    DI_R_JWT,
    DI_R_NPM_TOKEN,
    DI_R_PYPI_TOKEN,
    DI_R_HF_TOKEN,
    DI_R_TELEGRAM_BOT,
    DI_R_AGE_SECRET_KEY,
    DI_R_URL_CREDENTIALS,
    DI_R_GENERIC_ASSIGNMENT,
    /* encrypted containers (content magic or extension) */
    DI_C_LUKS,
    DI_C_KEEPASS,
    DI_C_AGE,
    DI_C_PGP_MESSAGE,
    DI_C_ANSIBLE_VAULT,
    DI_C_GPG_FILE,
    DI_C_VERACRYPT_FILE,
    /* key and credential files (by name) */
    DI_K_SSH_PRIVATE,
    DI_K_KEY_FILE,
    DI_K_PKCS12,
    DI_K_KEYSTORE,
    DI_K_PUTTY_KEY,
    DI_K_CREDENTIALS_FILE,
    DI_K_ENV_FILE,
    DI_RULE_COUNT
};

#define DI_BIT(r) ((uint64_t)1 << (r))
#define DI_SECRET_MASK  ((DI_BIT(DI_C_LUKS)) - 1)
#define DI_CONTAINER_MASK (DI_BIT(DI_C_LUKS) | DI_BIT(DI_C_KEEPASS) | DI_BIT(DI_C_AGE) | DI_BIT(DI_C_PGP_MESSAGE) | \
                           DI_BIT(DI_C_ANSIBLE_VAULT) | DI_BIT(DI_C_GPG_FILE) | DI_BIT(DI_C_VERACRYPT_FILE))
#define DI_KEYFILE_MASK (DI_BIT(DI_K_SSH_PRIVATE) | DI_BIT(DI_K_KEY_FILE) | DI_BIT(DI_K_PKCS12) | DI_BIT(DI_K_KEYSTORE) | \
                         DI_BIT(DI_K_PUTTY_KEY) | DI_BIT(DI_K_CREDENTIALS_FILE) | DI_BIT(DI_K_ENV_FILE))

static const char* const DI_RULE_NAMES[DI_RULE_COUNT] = {
    "private_key", "private_key_encrypted", "aws_access_key", "github_token", "gitlab_token", "slack_token",
    "slack_webhook", "discord_webhook", "anthropic_key", "openai_key", "stripe_key", "google_api_key", "jwt",
    "npm_token", "pypi_token", "hf_token", "telegram_bot_token", "age_secret_key", "url_credentials",
    "generic_assignment",
    "luks", "keepass", "age", "pgp_message", "ansible_vault", "gpg_file", "veracrypt_file",
    "ssh_private_key_file", "key_file", "pkcs12", "keystore", "putty_key", "credentials_file", "env_file",
};

/* Kind of an item, from its rule bits: a secret in content outranks a
 * container, which outranks a name-only key file. */
static inline const char* DataInv_ItemKind(uint64_t rules) {
    if (rules & (DI_BIT(DI_R_PRIVATE_KEY) | DI_BIT(DI_R_PRIVATE_KEY_ENCRYPTED))) return "private_key";
    if (rules & DI_SECRET_MASK) return "secret_candidate";
    if (rules & DI_CONTAINER_MASK) return "encrypted_container";
    return "key_file";
}

/* ---------------------------------------------------------------------------
 * Small string helpers
 * ------------------------------------------------------------------------- */

static inline char DataInv_Lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }
static inline bool DataInv_IsAlnum(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static inline bool DataInv_IsUpperNum(unsigned char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'); }
static inline bool DataInv_IsB64Url(unsigned char c) { return DataInv_IsAlnum(c) || c == '_' || c == '-'; }
static inline bool DataInv_IsTokenChar(unsigned char c) { return DataInv_IsAlnum(c) || c == '_'; }

static inline bool DataInv_EndsWithCI(const char* s, const char* suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    if (m > n) return false;
    for (size_t i = 0; i < m; i++) {
        if (DataInv_Lower(s[n - m + i]) != DataInv_Lower(suffix[i])) return false;
    }
    return true;
}

static inline bool DataInv_EqualsCI(const char* a, const char* b) {
    for (; *a && *b; a++, b++) {
        if (DataInv_Lower(*a) != DataInv_Lower(*b)) return false;
    }
    return *a == *b;
}

static inline bool DataInv_StartsWith(const char* s, const char* prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* Length of the run of characters starting at p (bounded by end) that pass f. */
static inline size_t DataInv_Run(const unsigned char* p, const unsigned char* end, bool (*f)(unsigned char)) {
    size_t n = 0;
    while (p + n < end && f(p[n])) n++;
    return n;
}

/* Lower-case extension of a file name ("" when there is none or the name is a
 * dotfile without another dot), at most cap-1 bytes. */
static inline void DataInv_Extension(const char* name, char* out, size_t cap) {
    out[0] = '\0';
    const char* dot = strrchr(name, '.');
    if (!dot || dot == name || dot[1] == '\0') return;
    size_t len = strlen(dot + 1);
    if (len >= cap || len > 12) return; /* a long "extension" is a name, not a type */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)dot[1 + i];
        if (!DataInv_IsAlnum(c) && c != '_' && c != '-') { out[0] = '\0'; return; }
        out[i] = DataInv_Lower((char)c);
    }
    out[len] = '\0';
}

/* ---------------------------------------------------------------------------
 * Name rules: key and credential files, encrypted containers by extension.
 * parent is the containing directory's last component ("" when unknown).
 * ------------------------------------------------------------------------- */

static inline uint64_t DataInv_NameRules(const char* name, const char* parent) {
    uint64_t r = 0;
    char ext[16];
    DataInv_Extension(name, ext, sizeof(ext));
    if (DataInv_StartsWith(name, "id_") && !DataInv_EndsWithCI(name, ".pub") &&
        (DataInv_StartsWith(name, "id_rsa") || DataInv_StartsWith(name, "id_dsa") || DataInv_StartsWith(name, "id_ecdsa") ||
         DataInv_StartsWith(name, "id_ed25519"))) {
        r |= DI_BIT(DI_K_SSH_PRIVATE);
    }
    if (!strcmp(ext, "key") || !strcmp(ext, "pem")) r |= DI_BIT(DI_K_KEY_FILE);
    if (!strcmp(ext, "p12") || !strcmp(ext, "pfx")) r |= DI_BIT(DI_K_PKCS12);
    if (!strcmp(ext, "jks") || !strcmp(ext, "keystore") || !strcmp(ext, "bks")) r |= DI_BIT(DI_K_KEYSTORE);
    if (!strcmp(ext, "ppk")) r |= DI_BIT(DI_K_PUTTY_KEY);
    if (!strcmp(ext, "kdbx") || !strcmp(ext, "kdb")) r |= DI_BIT(DI_C_KEEPASS);
    if (!strcmp(ext, "gpg") || !strcmp(ext, "pgp")) r |= DI_BIT(DI_C_GPG_FILE);
    if (!strcmp(ext, "hc") || !strcmp(ext, "tc")) r |= DI_BIT(DI_C_VERACRYPT_FILE);
    if (!strcmp(ext, "age")) r |= DI_BIT(DI_C_AGE);
    if (!strcmp(name, ".netrc") || !strcmp(name, "_netrc") || !strcmp(name, ".pgpass") || !strcmp(name, ".git-credentials") ||
        !strcmp(name, ".npmrc") || !strcmp(name, ".pypirc") || !strcmp(name, ".boto") || !strcmp(name, ".s3cfg") ||
        (!strcmp(name, "credentials") && (!strcmp(parent, ".aws") || !strcmp(parent, "gcloud") || !strcmp(parent, ".docker"))) ||
        (!strcmp(name, "config.json") && !strcmp(parent, ".docker")) ||
        (!strcmp(name, "config") && !strcmp(parent, ".kube")) ||
        !strcmp(name, "application_default_credentials.json") || !strcmp(name, "credentials.db") ||
        !strcmp(name, "access_tokens.db")) {
        r |= DI_BIT(DI_K_CREDENTIALS_FILE);
    }
    if (!strcmp(name, ".env") ||
        (DataInv_StartsWith(name, ".env.") && !DataInv_EndsWithCI(name, ".example") && !DataInv_EndsWithCI(name, ".sample") &&
         !DataInv_EndsWithCI(name, ".template") && !DataInv_EndsWithCI(name, ".dist")) ||
        DataInv_EndsWithCI(name, ".env")) {
        r |= DI_BIT(DI_K_ENV_FILE);
    }
    return r;
}

/* Whether a file's content is worth reading for secrets. Text-like types,
 * names without an extension (config files) and every name rule hit. */
static inline bool DataInv_ContentCandidate(const char* name, uint64_t name_rules) {
    if (name_rules) return true;
    static const char* const exts[] = {
        "env", "ini", "conf", "cfg", "cnf", "config", "properties", "yaml", "yml", "toml", "json", "xml", "txt", "md",
        "sh", "bash", "zsh", "fish", "ps1", "psm1", "bat", "cmd", "py", "js", "mjs", "cjs", "ts", "rb", "go", "php",
        "java", "kt", "cs", "rs", "tf", "tfvars", "hcl", "sql", "pem", "key", "crt", "asc", "service", "desktop",
        "csv", "log", "pgpass", "netrc", "npmrc", "rc", "secret", "secrets", "tokens", "creds", "credentials", NULL,
    };
    char ext[16];
    DataInv_Extension(name, ext, sizeof(ext));
    if (!ext[0]) return true;
    for (size_t i = 0; exts[i]; i++) {
        if (!strcmp(ext, exts[i])) return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Content rules. buf holds the first bytes of a regular file. Returns the
 * rule bits found; never the matched text.
 * ------------------------------------------------------------------------- */

static inline bool DataInv_MemEq(const unsigned char* p, const unsigned char* end, const char* lit) {
    size_t n = strlen(lit);
    return (size_t)(end - p) >= n && memcmp(p, lit, n) == 0;
}

static inline bool DataInv_LooksBinary(const unsigned char* buf, size_t len) {
    size_t n = len < 4096 ? len : 4096;
    return memchr(buf, '\0', n) != NULL;
}

/* Magic bytes of encrypted containers. */
static inline uint64_t DataInv_MagicRules(const unsigned char* buf, size_t len) {
    uint64_t r = 0;
    const unsigned char* end = buf + len;
    static const unsigned char luks[6] = {'L', 'U', 'K', 'S', 0xBA, 0xBE};
    static const unsigned char kdbx[4] = {0x03, 0xD9, 0xA2, 0x9A};
    if (len >= 6 && memcmp(buf, luks, 6) == 0) r |= DI_BIT(DI_C_LUKS);
    if (len >= 4 && memcmp(buf, kdbx, 4) == 0) r |= DI_BIT(DI_C_KEEPASS);
    if (DataInv_MemEq(buf, end, "age-encryption.org/v1") || DataInv_MemEq(buf, end, "-----BEGIN AGE ENCRYPTED FILE-----"))
        r |= DI_BIT(DI_C_AGE);
    if (DataInv_MemEq(buf, end, "-----BEGIN PGP MESSAGE-----")) r |= DI_BIT(DI_C_PGP_MESSAGE);
    if (DataInv_MemEq(buf, end, "$ANSIBLE_VAULT;")) r |= DI_BIT(DI_C_ANSIBLE_VAULT);
    return r;
}

/* log2 without libm (the agent does not link it): exponent plus a short
 * atanh series for the mantissa, accurate to well under 0.001. */
static inline double DataInv_Log2(double x) {
    union { double d; uint64_t u; } v;
    v.d = x;
    int e = (int)((v.u >> 52) & 0x7ff) - 1023;
    v.u = (v.u & 0x000fffffffffffffULL) | 0x3ff0000000000000ULL;
    double m = v.d;
    double t = (m - 1.0) / (m + 1.0), t2 = t * t;
    double ln = 2.0 * t * (1.0 + t2 / 3.0 + t2 * t2 / 5.0 + t2 * t2 * t2 / 7.0 + t2 * t2 * t2 * t2 / 9.0);
    return (double)e + ln * 1.4426950408889634;
}

/* Shannon entropy in bits per character. */
static inline double DataInv_Entropy(const unsigned char* p, size_t n) {
    if (n == 0) return 0.0;
    unsigned counts[256] = {0};
    for (size_t i = 0; i < n; i++) counts[p[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i]) {
            double q = (double)counts[i] / (double)n;
            h -= q * DataInv_Log2(q);
        }
    }
    return h;
}

/* A value that is a placeholder, a reference or code, not a literal secret. */
static inline bool DataInv_Placeholder(const unsigned char* v, size_t n) {
    if (n == 0) return true;
    if (v[0] == '$' || v[0] == '%' || v[0] == '{' || v[0] == '<' || v[0] == '[' || v[0] == '@') return true;
    static const char* const words[] = {"example", "changeme", "change_me", "placeholder", "your", "xxxx", "****",
                                        "redacted", "dummy", "sample", "test", "secret_here", "token_here",
                                        "process.env", "os.environ", "getenv", "env(", "none", "null", "undefined",
                                        "password", "{{", "${", NULL};
    char low[96];
    size_t m = n < sizeof(low) - 1 ? n : sizeof(low) - 1;
    for (size_t i = 0; i < m; i++) low[i] = DataInv_Lower((char)v[i]);
    low[m] = '\0';
    for (size_t i = 0; words[i]; i++) {
        if (strstr(low, words[i])) return true;
    }
    for (size_t i = 0; i < n; i++) {
        if (v[i] == '(' || v[i] == ')' || v[i] == '+' || v[i] == '>' || v[i] == ' ') return true;
    }
    int classes = 0;
    bool lo = false, up = false, dg = false, sy = false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = v[i];
        if (c >= 'a' && c <= 'z') lo = true;
        else if (c >= 'A' && c <= 'Z') up = true;
        else if (c >= '0' && c <= '9') dg = true;
        else sy = true;
    }
    classes = lo + up + dg + sy;
    return classes < 2;
}

static const char* const DI_SECRET_NAMES[] = {"password", "passwd", "passphrase", "secret", "token", "apikey", "api_key",
                                              "api-key", "access_key", "accesskey", "private_key", "client_secret",
                                              "auth_key", "credential", NULL};

/* key = value / key: value with a secret-looking key name and a literal,
 * high-entropy value. at points at the '=' or ':' separator. */
static inline bool DataInv_GenericAt(const unsigned char* buf, const unsigned char* at, const unsigned char* end) {
    if (*at == ':' && at + 2 < end && at[1] == '/' && at[2] == '/') return false; /* a URL scheme */
    const unsigned char* k = at;
    while (k > buf && (k[-1] == ' ' || k[-1] == '\t' || k[-1] == '"' || k[-1] == '\'')) k--;
    const unsigned char* kend = k;
    while (k > buf && (DataInv_IsTokenChar(k[-1]) || k[-1] == '-' || k[-1] == '.')) k--;
    size_t klen = (size_t)(kend - k);
    if (klen < 3 || klen > 64) return false;
    char key[65];
    for (size_t i = 0; i < klen; i++) key[i] = DataInv_Lower((char)k[i]);
    key[klen] = '\0';
    bool named = false;
    for (size_t i = 0; DI_SECRET_NAMES[i]; i++) {
        if (strstr(key, DI_SECRET_NAMES[i])) { named = true; break; }
    }
    if (!named) return false;
    /* key names that describe a secret without holding one */
    if (strstr(key, "_file") || strstr(key, "_path") || strstr(key, "_env") || strstr(key, "_name") ||
        strstr(key, "_url") || strstr(key, "_len") || strstr(key, "_type") || strstr(key, "expir") || strstr(key, "public")) {
        return false;
    }
    const unsigned char* v = at + 1;
    if (*at == '=' && v < end && *v == '=') return false; /* comparison, not assignment */
    while (v < end && (*v == ' ' || *v == '\t')) v++;
    bool quoted = v < end && (*v == '"' || *v == '\'');
    unsigned char q = quoted ? *v : 0;
    if (quoted) v++;
    const unsigned char* ve = v;
    while (ve < end && ve - v < 256) {
        unsigned char c = *ve;
        if (quoted ? c == q : (c == ' ' || c == '\t' || c == ',' || c == ';' || c == '#')) break;
        if (c == '\n' || c == '\r' || c < 0x20) break;
        ve++;
    }
    size_t n = (size_t)(ve - v);
    if (n < 12 || n > 200) return false;
    if (DataInv_Placeholder(v, n)) return false;
    /* Generated secrets carry digits; words joined by - _ . or spaces
     * ("attacker-chosen", "fixture-secret-in-diagnostics") and identifiers
     * (operatorTokenHash) do not. */
    size_t digits = 0;
    for (size_t i = 0; i < n; i++) digits += v[i] >= '0' && v[i] <= '9';
    if (digits == 0) return false;
    /* Unquoted code references: excluded.private_key, cookie.Value, f(x). */
    if (!quoted) {
        bool ref = DataInv_IsTokenChar(v[0]) && !(v[0] >= '0' && v[0] <= '9');
        bool dot = false;
        for (size_t i = 0; i < n && ref; i++) {
            if (v[i] == '(' || v[i] == '[') break; /* a call or index: code */
            if (v[i] == '.') dot = true;
            else if (!DataInv_IsTokenChar(v[i])) ref = false;
        }
        if (ref && (dot || memchr(v, '(', n) || memchr(v, '[', n))) return false;
    }
    return DataInv_Entropy(v, n) >= 3.2;
}

/* scheme://user:password@host with a literal password. at points at "://". */
static inline bool DataInv_UrlCredentialsAt(const unsigned char* at, const unsigned char* end) {
    const unsigned char* u = at + 3;
    const unsigned char* colon = NULL;
    const unsigned char* p = u;
    while (p < end && p - u < 256) {
        unsigned char c = *p;
        if (c == '@') break;
        if (c == '/' || c == ' ' || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == '\t' || c == '<' || c == '>') return false;
        if (c == ':' && !colon) colon = p;
        p++;
    }
    if (p >= end || *p != '@' || !colon || colon == u) return false;
    const unsigned char* pw = colon + 1;
    size_t n = (size_t)(p - pw);
    if (n < 6) return false;
    if (DataInv_Placeholder(pw, n)) return false;
    return true;
}

static inline uint64_t DataInv_ContentRules(const unsigned char* buf, size_t len) {
    uint64_t r = DataInv_MagicRules(buf, len);
    if (DataInv_LooksBinary(buf, len)) return r;
    const unsigned char* end = buf + len;
    for (const unsigned char* p = buf; p < end; p++) {
        unsigned char c = *p;
        bool boundary = p == buf || !DataInv_IsTokenChar(p[-1]);
        switch (c) {
        case '-':
            if (DataInv_MemEq(p, end, "-----BEGIN ")) {
                const unsigned char* q = p + 11;
                const unsigned char* stop = end - q > 40 ? q + 40 : end;
                const unsigned char* hit = NULL;
                for (const unsigned char* s = q; s + 16 <= stop; s++) {
                    if (memcmp(s, "PRIVATE KEY-----", 16) == 0) { hit = s; break; }
                }
                if (hit) {
                    bool enc = (hit - q >= 10 && memcmp(q, "ENCRYPTED ", 10) == 0);
                    const unsigned char* body = hit + 16;
                    const unsigned char* look = end - body > 400 ? body + 400 : end;
                    for (const unsigned char* s = body; !enc && s + 9 <= look; s++) {
                        if (memcmp(s, "ENCRYPTED", 9) == 0) enc = true;
                    }
                    /* OpenSSH keys carry their cipher name base64-encoded: "none" means unencrypted. */
                    if (!enc && hit - q >= 8 && memcmp(q, "OPENSSH ", 8) == 0) {
                        const unsigned char* s = body;
                        while (s < look && (*s == '\r' || *s == '\n')) s++;
                        /* base64 of "openssh-key-v1\0\0\0\0\x04none" starts b3BlbnNzaC1rZXktdjEAAAAABG5vbmU */
                        if (!DataInv_MemEq(s, end, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU")) enc = true;
                    }
                    r |= DI_BIT(enc ? DI_R_PRIVATE_KEY_ENCRYPTED : DI_R_PRIVATE_KEY);
                }
                if (DataInv_MemEq(p, end, "-----BEGIN PGP PRIVATE" " KEY BLOCK-----")) r |= DI_BIT(DI_R_PRIVATE_KEY_ENCRYPTED);
            }
            break;
        case 'A':
            if (boundary && (DataInv_MemEq(p, end, "AKIA") || DataInv_MemEq(p, end, "ASIA"))) {
                size_t n = DataInv_Run(p + 4, end, DataInv_IsUpperNum);
                if (n == 16) r |= DI_BIT(DI_R_AWS_ACCESS_KEY);
            }
            if (boundary && DataInv_MemEq(p, end, "AIza") && DataInv_Run(p + 4, end, DataInv_IsB64Url) == 35)
                r |= DI_BIT(DI_R_GOOGLE_API_KEY);
            if (boundary && DataInv_MemEq(p, end, "AGE-SECRET-KEY-1") && DataInv_Run(p + 16, end, DataInv_IsUpperNum) >= 58)
                r |= DI_BIT(DI_R_AGE_SECRET_KEY);
            break;
        case 'g':
            if (boundary && p + 4 < end && p[1] == 'h' && (p[2] == 'p' || p[2] == 'o' || p[2] == 'u' || p[2] == 's' || p[2] == 'r') &&
                p[3] == '_' && DataInv_Run(p + 4, end, DataInv_IsAlnum) >= 36)
                r |= DI_BIT(DI_R_GITHUB_TOKEN);
            if (boundary && DataInv_MemEq(p, end, "github_pat_") && DataInv_Run(p + 11, end, DataInv_IsTokenChar) >= 70)
                r |= DI_BIT(DI_R_GITHUB_TOKEN);
            if (boundary && DataInv_MemEq(p, end, "glpat-") && DataInv_Run(p + 6, end, DataInv_IsB64Url) >= 20)
                r |= DI_BIT(DI_R_GITLAB_TOKEN);
            break;
        case 'x':
            if (boundary && p + 5 < end && p[1] == 'o' && p[2] == 'x' &&
                (p[3] == 'a' || p[3] == 'b' || p[3] == 'p' || p[3] == 'o' || p[3] == 's' || p[3] == 'r') && p[4] == '-') {
                size_t n = 0;
                while (p + 5 + n < end && (DataInv_IsAlnum(p[5 + n]) || p[5 + n] == '-')) n++;
                if (n >= 10) r |= DI_BIT(DI_R_SLACK_TOKEN);
            }
            break;
        case 'h':
            if (DataInv_MemEq(p, end, "hooks.slack.com/services/T")) r |= DI_BIT(DI_R_SLACK_WEBHOOK);
            if (boundary && DataInv_MemEq(p, end, "hf_") && DataInv_Run(p + 3, end, DataInv_IsAlnum) >= 34)
                r |= DI_BIT(DI_R_HF_TOKEN);
            break;
        case 'd':
            if (DataInv_MemEq(p, end, "discord.com/api/webhooks/") || DataInv_MemEq(p, end, "discordapp.com/api/webhooks/"))
                r |= DI_BIT(DI_R_DISCORD_WEBHOOK);
            break;
        case 's':
            if (boundary && DataInv_MemEq(p, end, "sk-ant-") && DataInv_Run(p + 7, end, DataInv_IsB64Url) >= 32)
                r |= DI_BIT(DI_R_ANTHROPIC_KEY);
            else if (boundary && DataInv_MemEq(p, end, "sk-proj-") && DataInv_Run(p + 8, end, DataInv_IsB64Url) >= 40)
                r |= DI_BIT(DI_R_OPENAI_KEY);
            else if (boundary && DataInv_MemEq(p, end, "sk-") && DataInv_Run(p + 3, end, DataInv_IsAlnum) == 48)
                r |= DI_BIT(DI_R_OPENAI_KEY);
            if (boundary && (DataInv_MemEq(p, end, "sk_live_")) && DataInv_Run(p + 8, end, DataInv_IsAlnum) >= 20)
                r |= DI_BIT(DI_R_STRIPE_KEY);
            break;
        case 'r':
            if (boundary && DataInv_MemEq(p, end, "rk_live_") && DataInv_Run(p + 8, end, DataInv_IsAlnum) >= 20)
                r |= DI_BIT(DI_R_STRIPE_KEY);
            break;
        case 'e':
            if (boundary && DataInv_MemEq(p, end, "eyJ")) {
                size_t a = DataInv_Run(p + 3, end, DataInv_IsB64Url);
                const unsigned char* q = p + 3 + a;
                if (a >= 10 && q + 4 < end && *q == '.' && DataInv_MemEq(q + 1, end, "eyJ")) {
                    size_t b = DataInv_Run(q + 4, end, DataInv_IsB64Url);
                    const unsigned char* s = q + 4 + b;
                    if (b >= 10 && s + 1 < end && *s == '.' && DataInv_Run(s + 1, end, DataInv_IsB64Url) >= 10)
                        r |= DI_BIT(DI_R_JWT);
                }
            }
            break;
        case 'n':
            if (boundary && DataInv_MemEq(p, end, "npm_") && DataInv_Run(p + 4, end, DataInv_IsAlnum) == 36)
                r |= DI_BIT(DI_R_NPM_TOKEN);
            break;
        case 'p':
            if (boundary && DataInv_MemEq(p, end, "pypi-AgEIcHlwaS5vcmc") && DataInv_Run(p + 20, end, DataInv_IsB64Url) >= 50)
                r |= DI_BIT(DI_R_PYPI_TOKEN);
            break;
        case ':':
            if (DataInv_MemEq(p, end, "://")) {
                if (DataInv_UrlCredentialsAt(p, end)) r |= DI_BIT(DI_R_URL_CREDENTIALS);
            } else if (p - buf >= 8 && end - p > 2 && p[1] == 'A' && p[2] == 'A') {
                /* Telegram bot token: 8-10 digits ':' AA + 33 */
                const unsigned char* d = p;
                size_t digits = 0;
                while (d > buf && d[-1] >= '0' && d[-1] <= '9' && digits < 11) { d--; digits++; }
                if (digits >= 8 && digits <= 10 && (d == buf || !DataInv_IsTokenChar(d[-1])) &&
                    DataInv_Run(p + 1, end, DataInv_IsB64Url) == 35)
                    r |= DI_BIT(DI_R_TELEGRAM_BOT);
            }
            if (!(r & DI_BIT(DI_R_GENERIC_ASSIGNMENT)) && DataInv_GenericAt(buf, p, end)) r |= DI_BIT(DI_R_GENERIC_ASSIGNMENT);
            break;
        case '=':
            if (!(r & DI_BIT(DI_R_GENERIC_ASSIGNMENT)) && DataInv_GenericAt(buf, p, end)) r |= DI_BIT(DI_R_GENERIC_ASSIGNMENT);
            break;
        default:
            break;
        }
    }
    return r;
}

/* ---------------------------------------------------------------------------
 * JSON and path helpers
 * ------------------------------------------------------------------------- */

/* Appends to a bounded buffer; sets *ok false (and keeps the buffer
 * NUL-terminated) once anything does not fit. */
typedef struct {
    char* data;
    size_t cap;
    size_t len;
    bool ok;
} DataInvBuf;

static inline void DataInv_Put(DataInvBuf* b, const char* s, size_t n) {
    if (!b->ok) return;
    if (b->len + n + 1 > b->cap) { b->ok = false; return; }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static inline void DataInv_PutS(DataInvBuf* b, const char* s) { DataInv_Put(b, s, strlen(s)); }

/* A formatted number; a macro so the literal format is type-checked. */
#define DataInv_PutF(b, fmt, v)                                                   \
    do {                                                                          \
        char di_tmp_[64];                                                         \
        int di_n_ = snprintf(di_tmp_, sizeof(di_tmp_), fmt, (long long)(v));      \
        if (di_n_ > 0 && (size_t)di_n_ < sizeof(di_tmp_)) DataInv_Put((b), di_tmp_, (size_t)di_n_); \
        else (b)->ok = false;                                                     \
    } while (0)

/* JSON string. Bytes that are not valid printable ASCII or valid UTF-8 are
 * written as \u00XX of the byte so a file name can never break the document
 * (the hub rejects invalid UTF-8). */
static inline void DataInv_PutJSONString(DataInvBuf* b, const char* s) {
    DataInv_Put(b, "\"", 1);
    const unsigned char* p = (const unsigned char*)s;
    while (*p && b->ok) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', (char)c};
            DataInv_Put(b, e, 2);
            p++;
        } else if (c >= 0x20 && c < 0x7f) {
            DataInv_Put(b, (const char*)p, 1);
            p++;
        } else {
            size_t n = 0;
            if (c >= 0xC2 && c <= 0xDF) n = 2;
            else if (c >= 0xE0 && c <= 0xEF) n = 3;
            else if (c >= 0xF0 && c <= 0xF4) n = 4;
            bool valid = n > 0;
            for (size_t i = 1; valid && i < n; i++) {
                if ((p[i] & 0xC0) != 0x80) valid = false;
            }
            if (valid && n == 3 && ((c == 0xE0 && p[1] < 0xA0) || (c == 0xED && p[1] >= 0xA0))) valid = false;
            if (valid && n == 4 && ((c == 0xF0 && p[1] < 0x90) || (c == 0xF4 && p[1] >= 0x90))) valid = false;
            if (valid) {
                DataInv_Put(b, (const char*)p, n);
                p += n;
            } else {
                char e[8];
                snprintf(e, sizeof(e), "\\u%04x", c);
                DataInv_Put(b, e, 6);
                p++;
            }
        }
    }
    DataInv_Put(b, "\"", 1);
}

/* JSON string of a file path, in the contract's path encoding: '%', C0
 * controls, DEL, C1 controls (U+0080..U+009F) and bytes that are not valid
 * UTF-8 are written as %XX of each byte, so every real name gives a printable,
 * valid string the hub and Nightshift accept, and distinct names stay distinct.
 * Canary paths are compared in this form (hub dataPathEncode, Nightshift
 * ingest.encode_data_path). */
static inline void DataInv_PutJSONPath(DataInvBuf* b, const char* s) {
    static const char hex[] = "0123456789ABCDEF";
    DataInv_Put(b, "\"", 1);
    const unsigned char* p = (const unsigned char*)s;
    while (*p && b->ok) {
        unsigned char c = *p;
        size_t n = 1;
        bool escape;
        if (c == '%' || c < 0x20 || c == 0x7f) {
            escape = true;
        } else if (c < 0x80) {
            escape = false;
        } else {
            n = 0;
            if (c >= 0xC2 && c <= 0xDF) n = 2;
            else if (c >= 0xE0 && c <= 0xEF) n = 3;
            else if (c >= 0xF0 && c <= 0xF4) n = 4;
            bool valid = n > 0;
            for (size_t i = 1; valid && i < n; i++) {
                if ((p[i] & 0xC0) != 0x80) valid = false;
            }
            if (valid && n == 3 && ((c == 0xE0 && p[1] < 0xA0) || (c == 0xED && p[1] >= 0xA0))) valid = false;
            if (valid && n == 4 && ((c == 0xF0 && p[1] < 0x90) || (c == 0xF4 && p[1] >= 0x90))) valid = false;
            if (!valid) n = 1;
            escape = !valid || (n == 2 && c == 0xC2 && p[1] <= 0x9F);
        }
        for (size_t i = 0; i < n; i++) {
            if (escape) {
                char e[3] = {'%', hex[p[i] >> 4], hex[p[i] & 15]};
                DataInv_Put(b, e, 3);
            } else if (p[i] == '"' || p[i] == '\\') {
                char e[2] = {'\\', (char)p[i]};
                DataInv_Put(b, e, 2);
            } else {
                DataInv_Put(b, (const char*)&p[i], 1);
            }
        }
        p += n;
    }
    DataInv_Put(b, "\"", 1);
}

/* Component-wise path order: the order a depth-first walk with each
 * directory's entries sorted by strcmp visits paths in. Returns <0, 0, >0. */
static inline int DataInv_PathCmp(const char* a, const char* b) {
    for (;;) {
        while (*a == '/') a++;
        while (*b == '/') b++;
        if (!*a || !*b) return (*a != '\0') - (*b != '\0');
        size_t la = strcspn(a, "/"), lb = strcspn(b, "/");
        size_t n = la < lb ? la : lb;
        int c = memcmp(a, b, n);
        if (c) return c;
        if (la != lb) return la < lb ? -1 : 1;
        a += la;
        b += lb;
    }
}

/* Whether path equals prefix or lies beneath it. */
static inline bool DataInv_Under(const char* path, const char* prefix) {
    size_t n = strlen(prefix);
    while (n > 1 && prefix[n - 1] == '/') n--;
    if (strncmp(path, prefix, n) != 0) return false;
    return path[n] == '\0' || path[n] == '/' || (n == 1 && prefix[0] == '/');
}

/* State-file path encoding: % and every byte outside 0x21..0x7e become %XX,
 * so a path with a tab or newline in its name stays one field. */
static inline void DataInv_PutStatePath(DataInvBuf* b, const char* s) {
    for (const unsigned char* p = (const unsigned char*)s; *p && b->ok; p++) {
        if (*p > 0x20 && *p < 0x7f && *p != '%') {
            DataInv_Put(b, (const char*)p, 1);
        } else {
            char e[4];
            snprintf(e, sizeof(e), "%%%02X", *p);
            DataInv_Put(b, e, 3);
        }
    }
}

static inline int DataInv_Hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Decodes a state-file path field in place; false on a malformed escape. */
static inline bool DataInv_DecodeStatePath(char* s) {
    char* w = s;
    for (char* r = s; *r; r++) {
        if (*r == '%') {
            int h = DataInv_Hex(r[1]), l = h < 0 ? -1 : DataInv_Hex(r[2]);
            if (h < 0 || l < 0) return false;
            unsigned char v = (unsigned char)(h * 16 + l);
            if (v == 0) return false;
            *w++ = (char)v;
            r += 2;
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
    return true;
}

#endif /* OMINULL_DATA_INVENTORY_CORE_H */
