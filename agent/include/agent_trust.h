/*
 * Agent trust: one verification path for everything the hub may ask this
 * endpoint to do to itself.
 *
 * The hub is not trusted to change this host's state. It carries signed
 * statements from the response authority (a separate service holding the
 * keys) and this file decides, on the endpoint, whether each one is genuine,
 * meant for this host, current, and inside what this host is allowed to do.
 *
 *   keys       three ed25519 public keys, pinned on first contact (or at
 *              enrollment) and never replaced silently afterwards:
 *                response     owner-approved grants (isolation, release,
 *                             agent update, mesh quarantine, terminal, ...)
 *                auto_isolate the detector's narrow key: isolate only
 *                policy       capability manifests
 *   manifest   which actions this endpoint accepts at all (monitor, respond,
 *              engagement), signed by the policy key, sequence-numbered
 *   grants     EndpointGrant V2 over a typed payload (route, body, targets),
 *              the same bytes the owner approved; per-slot monotonic
 *   state      what this host is authorized to enforce right now, durable,
 *              so a restart or a hub that changes its mind does not move it
 *
 * Everything here is OS-neutral C with no allocation on the hot path; file
 * access and the "is this file really ours" check sit behind the two
 * platform blocks below (POSIX, Win32). A future macOS agent uses the POSIX
 * block as it is.
 */
#ifndef OMINULL_AGENT_TRUST_H
#define OMINULL_AGENT_TRUST_H

#include "response_dispatcher.h"
#include <strings.h>
#include <stdarg.h>

#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#define TRUST_DEFAULT_KEY_DIR   "C:\\ProgramData\\Ominull"
#define TRUST_DEFAULT_STATE_DIR "C:\\ProgramData\\Ominull"
#define TRUST_SEP "\\"
#else
#define TRUST_DEFAULT_KEY_DIR   "/etc/ominull"
#define TRUST_DEFAULT_STATE_DIR "/var/lib/ominull"
#define TRUST_SEP "/"
#endif

#define TRUST_MAX_ALLOW 32
#define TRUST_MAX_MESH 64
#define TRUST_MAX_CAPS 12
#define TRUST_MAX_MFLOOR 8      /* policy keys whose manifest floor is remembered */
typedef struct { uint8_t key[32]; int64_t seq; } TrustFloor;
#define TRUST_MAX_PAYLOAD 8192
#define TRUST_MAX_GRANTS 8
#define TRUST_MAX_RULES 64
#define TRUST_SKEW_SECONDS 60
/* Host authority (docs/HOST_AUTHORITY.md): keys an administrator pins on the
 * host itself, outside the hub's trust bundle. The agent never writes these
 * files and a re-pin leaves them alone. */
#define TRUST_HOST_KEYS_FILE  "host_authority.json"
#define TRUST_HOST_ALLOW_FILE "host_auto_allow.json"
#define TRUST_MAX_HOST_KEYS   4
#define TRUST_MAX_HOST_ALLOW  16
#define TRUST_MAX_HOST_MODES  4
/* A released mesh slot is remembered this long so an older quarantine grant
 * that is still inside its validity window cannot be replayed over it. */
#define TRUST_MESH_FORGET_SECONDS (25 * 3600)

enum { TRUST_KEY_RESPONSE = 0, TRUST_KEY_AUTO = 1, TRUST_KEY_POLICY = 2, TRUST_KEY_COUNT = 3 };

static const char* const TRUST_KEY_FILES[TRUST_KEY_COUNT] = {"response.pub", "auto_isolate.pub", "policy.pub"};
static const char* const TRUST_KEY_FIELDS[TRUST_KEY_COUNT] = {"response_key", "auto_isolate_key", "policy_key"};

/* The tenant this agent belongs to (every agent reports "default"). A trust
 * bundle, manifest or grant for any other tenant is refused. */
#ifndef TRUST_TENANT
#define TRUST_TENANT "default"
#endif
/* The lowest trust bundle epoch this build accepts. Raised in a release after
 * the authority's keys are rotated, so even a fresh install cannot be handed an
 * older, still validly signed bundle. */
#ifndef TRUST_MIN_EPOCH
#define TRUST_MIN_EPOCH 1
#endif

/* ---------------------------------------------------------------------------
 * Strict, bounded JSON reading.
 *
 * The payload an agent acts on is the payload the owner approved, and the
 * authority read it with Go's decoder. Two readers that disagree about what a
 * document says are an attack surface: duplicate keys (Go keeps the last),
 * escaped keys ("rout\u0065" is "route" to Go) and case variants (Go matches
 * struct fields case-insensitively). At every object level read here, keys
 * must be plain and unique ignoring case, so whatever this reader accepts,
 * Go read the same way.
 * ------------------------------------------------------------------------- */

static inline const char* TJ_Ws(const char* p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static inline const char* TJ_SkipString(const char* p, const char* end) {
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        if (*p == '\\') {
            if (end - p < 2) return NULL;   /* an escape needs its byte */
            p += 2;
            continue;
        }
        if (*p == '"') return p + 1;
        if ((unsigned char)*p < 0x20) return NULL;
        p++;
    }
    return NULL;
}

static inline const char* TJ_SkipValue(const char* p, const char* end, int depth) {
    p = TJ_Ws(p, end);
    if (p >= end || depth > 16) return NULL;
    if (*p == '"') return TJ_SkipString(p, end);
    if (*p == '{' || *p == '[') {
        char close = (*p == '{') ? '}' : ']';
        bool object = (*p == '{');
        p = TJ_Ws(p + 1, end);
        if (p < end && *p == close) return p + 1;
        for (;;) {
            if (object) {
                p = TJ_SkipString(TJ_Ws(p, end), end);
                if (!p) return NULL;
                p = TJ_Ws(p, end);
                if (p >= end || *p != ':') return NULL;
                p++;
            }
            p = TJ_SkipValue(p, end, depth + 1);
            if (!p) return NULL;
            p = TJ_Ws(p, end);
            if (p >= end) return NULL;
            if (*p == ',') { p++; continue; }
            if (*p == close) return p + 1;
            return NULL;
        }
    }
    /* number, true, false, null */
    const char* s = p;
    while (p < end && (isalnum((unsigned char)*p) || *p == '-' || *p == '+' || *p == '.')) p++;
    return p > s ? p : NULL;
}

/* TJ_Member finds key in the object starting at obj (which must point at '{').
 * Returns 1 and the value span when found, 0 when absent, -1 when the object
 * is malformed or breaks the key rules above. */
static inline int TJ_Member(const char* obj, const char* end, const char* key, const char** v, const char** vend) {
    const char* p = TJ_Ws(obj, end);
    if (p >= end || *p != '{') return -1;
    p = TJ_Ws(p + 1, end);
    if (p < end && *p == '}') return 0;
    const char* keys[48];
    size_t keyLens[48];
    int nkeys = 0, found = 0;
    for (;;) {
        p = TJ_Ws(p, end);
        const char* ks = p;
        const char* ke = TJ_SkipString(p, end);
        if (!ke) return -1;
        ks++;                       /* inside the quotes */
        size_t klen = (size_t)(ke - 1 - ks);
        if (memchr(ks, '\\', klen)) return -1;
        for (int i = 0; i < nkeys; i++) {
            if (keyLens[i] == klen && strncasecmp(keys[i], ks, klen) == 0) return -1;
        }
        if (nkeys >= 48) return -1;
        keys[nkeys] = ks;
        keyLens[nkeys++] = klen;
        p = TJ_Ws(ke, end);
        if (p >= end || *p != ':') return -1;
        p = TJ_Ws(p + 1, end);
        const char* ve = TJ_SkipValue(p, end, 1);
        if (!ve) return -1;
        if (strlen(key) == klen && strncmp(ks, key, klen) == 0) {
            *v = p;
            *vend = ve;
            found = 1;
        }
        p = TJ_Ws(ve, end);
        if (p >= end) return -1;
        if (*p == ',') { p++; continue; }
        if (*p == '}') return found;
        return -1;
    }
}

/* A string with no escapes, copied out; false for anything else. */
static inline bool TJ_Plain(const char* v, const char* vend, char* out, size_t cap) {
    if (!v || v >= vend || *v != '"') return false;
    const char* e = TJ_SkipString(v, vend);
    if (!e) return false;
    size_t len = (size_t)(e - v - 2);
    if (len + 1 > cap || memchr(v + 1, '\\', len)) return false;
    memcpy(out, v + 1, len);
    out[len] = '\0';
    return true;
}

/* An array of plain strings; null reads as empty. Returns the count or -1. */
static inline int TJ_PlainArray(const char* v, const char* vend, char out[][64], int cap) {
    const char* p = TJ_Ws(v, vend);
    if (vend - p >= 4 && strncmp(p, "null", 4) == 0) return 0;
    if (p >= vend || *p != '[') return -1;
    p = TJ_Ws(p + 1, vend);
    if (p < vend && *p == ']') return 0;
    int n = 0;
    for (;;) {
        p = TJ_Ws(p, vend);
        const char* e = TJ_SkipString(p, vend);
        if (!e || n >= cap || !TJ_Plain(p, e, out[n], 64)) return -1;
        n++;
        p = TJ_Ws(e, vend);
        if (p >= vend) return -1;
        if (*p == ',') { p++; continue; }
        if (*p == ']') return n;
        return -1;
    }
}

static inline bool TJ_Int(const char* v, const char* vend, int64_t* out) {
    const char* p = TJ_Ws(v, vend);
    bool neg = false;
    if (p < vend && *p == '-') { neg = true; p++; }
    if (p >= vend || !isdigit((unsigned char)*p)) return false;
    int64_t x = 0;
    while (p < vend && isdigit((unsigned char)*p)) {
        if (x > (INT64_MAX - 9) / 10) return false;
        x = x * 10 + (*p++ - '0');
    }
    *out = neg ? -x : x;
    return true;
}

static inline bool TJ_MemberPlain(const char* obj, const char* end, const char* key, char* out, size_t cap) {
    const char *v, *ve;
    return TJ_Member(obj, end, key, &v, &ve) == 1 && TJ_Plain(v, ve, out, cap);
}

/* ---------------------------------------------------------------------------
 * Small helpers.
 * ------------------------------------------------------------------------- */

/* Trust_CompareVersions orders dotted numeric versions: <0, 0, >0. A part
 * that is not a number makes the whole comparison "not newer" (returns -2),
 * so a malformed version is never treated as an upgrade. */
static inline int Trust_CompareVersions(const char* a, const char* b) {
    if (!a || !b || !*a || !*b) return -2;
    for (;;) {
        if (!isdigit((unsigned char)*a) || !isdigit((unsigned char)*b)) return -2;
        long x = 0, y = 0;
        int dx = 0, dy = 0;
        while (isdigit((unsigned char)*a)) { if (++dx > 9) return -2; x = x * 10 + (*a++ - '0'); }
        while (isdigit((unsigned char)*b)) { if (++dy > 9) return -2; y = y * 10 + (*b++ - '0'); }
        if (x != y) return x < y ? -1 : 1;
        if (*a == '\0' && *b == '\0') return 0;
        if (*a == '\0') { /* 1.2 vs 1.2.0 / 1.2.1 */
            for (; *b; b++) if (*b != '.' && *b != '0') return -1;
            return 0;
        }
        if (*b == '\0') {
            for (; *a; a++) if (*a != '.' && *a != '0') return 1;
            return 0;
        }
        if (*a != '.' || *b != '.') return -2;
        a++;
        b++;
    }
}

/* Trust_AgentArtifactName is the one package this agent installs for a
 * version. The release key signs the hub package too; the name, computed
 * here and never taken from the hub, keeps an approved update from
 * installing some other genuinely signed package. */
static inline bool Trust_AgentArtifactName(const char* version, char* out, size_t cap) {
#ifdef _WIN32
    int n = snprintf(out, cap, "ominull-agent-windows-%s.msi", version);
#else
    int n = snprintf(out, cap, "ominull-agent_%s_amd64.deb", version);
#endif
    return n > 0 && (size_t)n < cap;
}

/* An update is admissible only to a strictly newer, well-formed version. */
static inline bool Trust_UpdateVersionAdmissible(const char* offered, const char* running) {
    return Trust_CompareVersions(offered, running) == 1;
}

static inline bool Trust_IsIPLiteral(const char* s) {
    if (!s || !*s || strlen(s) >= 64) return false;
    bool colon = strchr(s, ':') != NULL;
    for (const char* p = s; *p; p++) {
        if (isxdigit((unsigned char)*p) || *p == '.' || *p == ':') continue;
        return false;
    }
    if (!colon) {
        int parts = 0, val = -1, digits = 0;
        for (const char* p = s;; p++) {
            if (*p == '.' || *p == '\0') {
                if (val < 0 || val > 255 || digits == 0) return false;
                parts++;
                val = -1;
                digits = 0;
                if (*p == '\0') break;
                continue;
            }
            if (!isdigit((unsigned char)*p) || ++digits > 3) return false;
            val = (val < 0 ? 0 : val) * 10 + (*p - '0');
        }
        return parts == 4;
    }
    /* IPv6: up to eight groups of at most four hex digits, "::" at most once. */
    int colons = 0, groupLen = 0, doubles = 0;
    for (const char* p = s; *p; p++) {
        if (*p == ':') {
            colons++;
            groupLen = 0;
            if (p[1] == ':') {
                if (++doubles > 1 || p[2] == ':') return false;
            }
        } else if (*p == '.' || ++groupLen > 4) {
            return false;
        }
    }
    return colons >= 2 && colons <= 7 && (doubles == 1 || colons == 7);
}

/* Trust_IsAllowEntry: one isolation allow-list entry, an address or an
 * address range "addr/len". A range may not be wider than /8 (IPv4) or /32
 * (IPv6): the allow list is a pinhole through a default deny, never a way to
 * switch the deny off. An IPv6 range must be global unicast (2000::/3) or
 * unique local (fc00::/7) and not Teredo (2001::/32) or 6to4 (2002::/16), so
 * neither link-local nor a translation prefix such as 64:ff9b::/96 (which
 * reaches all of IPv4 through NAT64) can be opened. The hub refuses the same. */
#define TRUST_ALLOW_MIN_V4 8
#define TRUST_ALLOW_MIN_V6 32
static inline bool Trust_IsAllowEntry(const char* s) {
    if (!s || !*s || strlen(s) >= 64) return false;
    const char* slash = strchr(s, '/');
    if (!slash) return Trust_IsIPLiteral(s);
    char addr[64];
    size_t n = (size_t)(slash - s);
    if (n == 0 || n >= sizeof(addr)) return false;
    memcpy(addr, s, n);
    addr[n] = '\0';
    if (!Trust_IsIPLiteral(addr)) return false;
    const char* p = slash + 1;
    int len = 0, digits = 0;
    for (; *p; p++) {
        if (!isdigit((unsigned char)*p) || ++digits > 3) return false;
        len = len * 10 + (*p - '0');
    }
    if (digits == 0 || (digits > 1 && slash[1] == '0')) return false;
    bool v6 = strchr(addr, ':') != NULL;
    if (!v6) return len >= TRUST_ALLOW_MIN_V4 && len <= 32;
    if (len < TRUST_ALLOW_MIN_V6 || len > 128) return false;
    /* The first two groups decide; "::" in front means they are zero. */
    unsigned g0 = 0, g1 = 0;
    if (addr[0] != ':') {
        g0 = (unsigned)strtoul(addr, NULL, 16);
        const char* c = strchr(addr, ':');
        if (c && c[1] != ':') g1 = (unsigned)strtoul(c + 1, NULL, 16);
    }
    bool global = (g0 & 0xe000) == 0x2000, ula = (g0 & 0xfe00) == 0xfc00;
    if (!global && !ula) return false;
    if (g0 == 0x2002 || (g0 == 0x2001 && g1 == 0)) return false;
    return true;
}

/* Trust_PublicAddress: a globally routable unicast address. Threat
 * indicators are not signed (they come from the hub's feeds), so an agent
 * drops traffic only to public addresses: never to private, loopback,
 * link-local, CGNAT, multicast or reserved ranges, where a hub could cut a
 * host off its own LAN, gateway or resolver. */
static inline bool Trust_PublicAddress(const char* s) {
    if (!Trust_IsIPLiteral(s)) return false;
    if (!strchr(s, ':')) {
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
        if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
        if (a == 100 && (b & 0xc0) == 64) return false;          /* 100.64/10 */
        if (a == 169 && b == 254) return false;
        if (a == 172 && (b & 0xf0) == 16) return false;
        if (a == 192 && b == 168) return false;
        if (a == 192 && b == 0 && (c == 0 || c == 2)) return false;
        if (a == 198 && (b & 0xfe) == 18) return false;          /* 198.18/15 */
        if (a == 198 && b == 51 && c == 100) return false;
        if (a == 203 && b == 0 && c == 113) return false;
        return true;
    }
    if (s[0] == ':') return false;                               /* ::, ::1, ::/8 */
    unsigned g = 0, g2 = 0;
    const char* p = s;
    for (; *p && *p != ':'; p++) g = g * 16 + (unsigned)(isdigit((unsigned char)*p) ? *p - '0' : (tolower((unsigned char)*p) - 'a' + 10));
    if (*p == ':' && p[1] != ':')
        for (p++; *p && *p != ':'; p++) g2 = g2 * 16 + (unsigned)(isdigit((unsigned char)*p) ? *p - '0' : (tolower((unsigned char)*p) - 'a' + 10));
    if ((g & 0xe000) != 0x2000) return false;                    /* only 2000::/3 is global unicast */
    if (g == 0x2001 && g2 == 0x0db8) return false;               /* documentation */
    return true;
}

static inline bool Trust_HexKey(const char* hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return false;
    for (int i = 0; i < 64; i++) if (!isxdigit((unsigned char)hex[i])) return false;
    return Response_HexToBytes(hex, out, 32);
}

/* ---------------------------------------------------------------------------
 * Context: where things live, what is pinned, what was refused.
 * ------------------------------------------------------------------------- */

typedef struct {
    bool  have;
    char  tenant_id[64];
    char  endpoint_id[64];
    char  profile[24];
    char  caps[TRUST_MAX_CAPS][24];
    int   capCount;
    int64_t seq;
    int64_t issued_at;
    char  signer_key_id[65];
    char  signature[129];
} TrustManifest;

typedef struct {
    char    ip[64];
    bool    on;
    int64_t at;
} TrustMeshSlot;

/* One isolation exception (a baseline permit): the same shape the hub's
 * baseline policy resolves to, bound into the isolation the owner approved. */
typedef struct {
    char service[16];
    char destination[64];
    char protocol[8];
    int  port;
} TrustRule;

/* One pinned host-authority key. role tap: any script_exec; auto: only
 * packages on the host's allow-list, in an allowed mode. */
typedef struct {
    char    id[65];          /* signer_key_id: lowercase hex sha256 of the key */
    uint8_t key[32];
    bool    autoRole;
} TrustHostKey;

/* One allow-listed package for auto grants. */
typedef struct {
    char name[64];
    char sha256[65];         /* sha256 of the package source (script_digest) */
    char modes[TRUST_MAX_HOST_MODES][16];
    int  modeCount;
} TrustHostAllow;

/* Trust_ReleaseVerifier checks a DER ECDSA-P256/SHA-256 signature over msg
 * against the release key compiled into this agent (openssl on Linux, CNG on
 * Windows). It is the trust root for pinning the authority's keys. */
typedef bool (*Trust_ReleaseVerifier)(const char* msg, size_t len, const uint8_t* der, size_t derlen);

typedef struct {
    bool    exists;          /* a state file was found or written */
    bool    isolated;
    char    source[12];      /* owner | auto | bootstrap | local | none */
    int64_t iso_at;
    char    iso_grant[64];
    char    allow[TRUST_MAX_ALLOW][64];
    int     allowCount;
    TrustMeshSlot mesh[TRUST_MAX_MESH];
    int     meshCount;
    TrustRule rules[TRUST_MAX_RULES];   /* the isolation's exceptions, fixed when it was applied */
    int     ruleCount;
    int64_t iso_seen;        /* newest isolation grant processed (applied or refused) */
    int64_t mesh_seen;       /* newest mesh grant processed */
} TrustState;

typedef struct {
    char key_dir[200];
    char state_dir[200];
    bool check_owner;        /* false only in tests that do not run as root/SYSTEM */
    char endpoint_id[64];
    uint8_t keys[TRUST_KEY_COUNT][32];
    bool    have_key[TRUST_KEY_COUNT];
    bool    mismatch[TRUST_KEY_COUNT];
    char    tenant[64];          /* of the pinned bundle */
    int64_t epoch;               /* of the pinned bundle */
    int64_t epoch_floor;         /* highest epoch ever pinned here, or one above a revoked pin (survives --repin-trust) */
    char    ceiling[32];         /* local capability ceiling (capability.ceiling), "" = none */
    /* Host authority: host_present once host_authority.json exists (then
     * script_exec takes only host-authority grants, even when the file is
     * unreadable and no key loaded: it fails closed). */
    bool    host_present;
    TrustHostKey host_keys[TRUST_MAX_HOST_KEYS];
    int     hostKeyCount;
    TrustHostAllow host_allow[TRUST_MAX_HOST_ALLOW];
    int     hostAllowCount;
    char    host_error[96];      /* why a host file was not used; reported, never secret */
    /* manifest.floor: the highest manifest seq taken under each recent policy
     * key, kept across --repin-trust (a manifest only verifies under its own
     * key, so a key that comes back keeps its floor). Oldest entry first. */
    TrustFloor mfloor[TRUST_MAX_MFLOOR];
    int     mfloorCount;
    bool    mfloor_dirty;        /* raised from manifest.state at start; written before the next manifest is taken */
    TrustManifest manifest;
    TrustState state;
    Trust_ReleaseVerifier verify_release;   /* set by the platform after Trust_Init */
    bool untrusted;                         /* the key/state directory is not ours: read and write nothing */
    uint8_t failed_bundle[32];              /* last trust offer that did not verify */
    char refused[200];       /* last refusal, reported to the hub; never secrets */
    int64_t refused_at;
    bool loaded;
} TrustContext;

#if defined(__GNUC__)
__attribute__((format(printf, 3, 4)))
#endif
static inline void Trust_Refuse(TrustContext* t, int64_t now, const char* fmt, ...) {
    char msg[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (strcmp(msg, t->refused) != 0) {
        printf("[!] Refused: %s\n", msg);
        fflush(stdout);
    }
    snprintf(t->refused, sizeof(t->refused), "%s", msg);
    t->refused_at = now;
}

static inline void Trust_Path(const TrustContext* t, bool state, const char* leaf, char* out, size_t cap) {
    snprintf(out, cap, "%s" TRUST_SEP "%s", state ? t->state_dir : t->key_dir, leaf);
}

/* ---------------------------------------------------------------------------
 * Platform file backends.
 * ------------------------------------------------------------------------- */

#ifdef _WIN32
/* A pinned file counts only if SYSTEM or Administrators own it. ProgramData
 * lets ordinary users create files, so a file a user planted before the
 * agent wrote its own must never be read as a trust anchor. */
static inline bool Trust_FileIsOurs(const TrustContext* t, const char* path) {
    if (!t->check_owner) return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    if (GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd) != ERROR_SUCCESS)
        return false;
    bool ok = owner && (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
    LocalFree(sd);
    return ok;
}

static inline bool Trust_WriteFile(const TrustContext* t, const char* path, const char* data, bool secret) {
    (void)secret;
    if (t->untrusted) return false;
    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%.280s.tmp", path);
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    if (t->check_owner) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", SDDL_REVISION_1, &sd, NULL))
            return false;
        sa.lpSecurityDescriptor = sd;
    }
    DeleteFileA(tmp);
    HANDLE h = CreateFileA(tmp, GENERIC_WRITE, 0, t->check_owner ? &sa : NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (sd) LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD len = (DWORD)strlen(data), wrote = 0;
    BOOL ok = WriteFile(h, data, len, &wrote, NULL) && wrote == len && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || !MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp);
        return false;
    }
    return true;
}

static inline bool Trust_RemoveFile(const char* path) {
    return DeleteFileA(path) || GetLastError() == ERROR_FILE_NOT_FOUND;
}
static inline bool Trust_PathExists(const char* path) { return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }
#else
static inline bool Trust_FileIsOurs(const TrustContext* t, const char* path) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    if (!t->check_owner) return true;
    return st.st_uid == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static inline bool Trust_WriteFile(const TrustContext* t, const char* path, const char* data, bool secret) {
    if (t->untrusted) return false;
    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%.280s.tmp", path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, secret ? 0600 : 0644);
    if (fd < 0) return false;
    size_t len = strlen(data);
    ssize_t n = write(fd, data, len);
    bool ok = n >= 0 && (size_t)n == len && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    /* The rename is durable only once the directory is. */
    char dir[300];
    snprintf(dir, sizeof(dir), "%s", path);
    char* slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) slash[1] = '\0';
        else *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY);
        if (dfd < 0) return false;
        ok = fsync(dfd) == 0;
        close(dfd);
    }
    return ok;
}

static inline bool Trust_RemoveFile(const char* path) { return unlink(path) == 0 || errno == ENOENT; }
static inline bool Trust_PathExists(const char* path) {
    struct stat st;
    return lstat(path, &st) == 0;
}
#endif

static inline bool Trust_ReadSmallFile(const TrustContext* t, const char* path, char* out, size_t cap) {
    if (!Trust_FileIsOurs(t, path)) return false;
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(out, 1, cap - 1, f);
    bool whole = feof(f) != 0;
    fclose(f);
    out[n] = '\0';
    return whole && n > 0;
}

/* ---------------------------------------------------------------------------
 * Capability manifest.
 * ------------------------------------------------------------------------- */

static inline size_t Trust_ManifestCanonical(const TrustManifest* m, uint8_t* out, size_t cap) {
    ResponseCanonicalBuffer b;
    CanonicalBuf_Init(&b, out, cap);
    const char* caps[TRUST_MAX_CAPS];
    for (int i = 0; i < m->capCount; i++) caps[i] = m->caps[i];
    if (!CanonicalBuf_WriteString(&b, "OMINULL-CAPABILITY-MANIFEST-V1")) return 0;
    if (!CanonicalBuf_WriteUint32(&b, 1)) return 0;
    if (!CanonicalBuf_WriteString(&b, m->tenant_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, m->endpoint_id)) return 0;
    if (!CanonicalBuf_WriteString(&b, m->profile)) return 0;
    if (!CanonicalBuf_WriteStringSlice(&b, caps, (size_t)m->capCount)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, m->seq)) return 0;
    if (!CanonicalBuf_WriteInt64(&b, m->issued_at)) return 0;
    if (!CanonicalBuf_WriteHexNormalized(&b, m->signer_key_id)) return 0;
    return b.overflow ? 0 : b.len;
}

static inline bool Trust_ManifestVerify(const TrustContext* t, const TrustManifest* m) {
    if (!t->have_key[TRUST_KEY_POLICY] || m->seq <= 0 || strcmp(m->endpoint_id, t->endpoint_id) != 0 ||
        strcmp(m->tenant_id, t->tenant) != 0)
        return false;
    for (int i = 1; i < m->capCount; i++) {
        if (strcmp(m->caps[i - 1], m->caps[i]) >= 0) return false;   /* sorted, unique */
    }
    uint8_t canon[1024], sig[64];
    size_t len = Trust_ManifestCanonical(m, canon, sizeof(canon));
    if (!len || strlen(m->signature) != 128 || !Response_HexToBytes(m->signature, sig, 64)) return false;
    return Ed25519_Verify(sig, canon, len, t->keys[TRUST_KEY_POLICY]);
}

/* Trust_ParseManifest reads the wire object (heartbeat "capability_manifest"
 * or the pinned copy, which is the same JSON). */
static inline bool Trust_ParseManifest(const char* v, const char* ve, TrustManifest* m) {
    memset(m, 0, sizeof(*m));
    const char *cv, *cve, *x, *xe;
    int64_t ver = 0;
    if (TJ_Member(v, ve, "v", &x, &xe) != 1 || !TJ_Int(x, xe, &ver) || ver != 1) return false;
    if (!TJ_MemberPlain(v, ve, "tenant_id", m->tenant_id, sizeof(m->tenant_id))) return false;
    if (!TJ_MemberPlain(v, ve, "endpoint_id", m->endpoint_id, sizeof(m->endpoint_id))) return false;
    if (!TJ_MemberPlain(v, ve, "profile", m->profile, sizeof(m->profile))) return false;
    if (!TJ_MemberPlain(v, ve, "signer_key_id", m->signer_key_id, sizeof(m->signer_key_id))) return false;
    if (!TJ_MemberPlain(v, ve, "signature", m->signature, sizeof(m->signature))) return false;
    if (TJ_Member(v, ve, "seq", &x, &xe) != 1 || !TJ_Int(x, xe, &m->seq)) return false;
    if (TJ_Member(v, ve, "issued_at", &x, &xe) != 1 || !TJ_Int(x, xe, &m->issued_at)) return false;
    if (TJ_Member(v, ve, "caps", &cv, &cve) != 1) return false;
    char caps[TRUST_MAX_CAPS][64];
    int n = TJ_PlainArray(cv, cve, caps, TRUST_MAX_CAPS);
    if (n < 0) return false;
    for (int i = 0; i < n; i++) {
        if (strlen(caps[i]) >= sizeof(m->caps[0])) return false;
        snprintf(m->caps[i], sizeof(m->caps[0]), "%s", caps[i]);
    }
    m->capCount = n;
    m->have = true;
    return true;
}

static inline void Trust_ManifestJSON(const TrustManifest* m, char* out, size_t cap) {
    char caps[TRUST_MAX_CAPS * 28] = {0};
    size_t off = 0;
    for (int i = 0; i < m->capCount && off < sizeof(caps); i++) {
        int n = snprintf(caps + off, sizeof(caps) - off, "%s\"%s\"", i ? "," : "", m->caps[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    snprintf(out, cap,
             "{\"v\":1,\"tenant_id\":\"%s\",\"endpoint_id\":\"%s\",\"profile\":\"%s\",\"caps\":[%s],"
             "\"seq\":%lld,\"issued_at\":%lld,\"signer_key_id\":\"%s\",\"signature\":\"%s\"}\n",
             m->tenant_id, m->endpoint_id, m->profile, caps, (long long)m->seq, (long long)m->issued_at,
             m->signer_key_id, m->signature);
}

/* Which manifest capability an action needs. Agent updates are allowed with
 * no manifest at all: a monitor-only host still has to be patchable. */
static inline const char* Trust_CapabilityFor(const char* kind) {
    if (!kind) return NULL;
    if (strcmp(kind, "isolation_change") == 0 || strcmp(kind, "auto_isolate") == 0) return "isolate";
    if (strcmp(kind, "mesh_quarantine") == 0) return "mesh";
    if (strcmp(kind, "agent_update") == 0) return "update";
    if (strcmp(kind, "forensic_collection") == 0) return "collect";
    if (strcmp(kind, "script_exec") == 0) return "script";
    if (strcmp(kind, "terminal_session") == 0) return "terminal";
    if (strcmp(kind, "screen_session") == 0) return "screen";
    return NULL;
}

static inline bool Trust_ManifestHas(const TrustManifest* m, const char* cap) {
    if (!cap) return false;
    if (strcmp(cap, "update") == 0 && !m->have) return true;
    if (!m->have) return false;
    for (int i = 0; i < m->capCount; i++) if (strcmp(m->caps[i], cap) == 0) return true;
    return false;
}

/* Trust_CeilingHas: the local ceiling, set by an administrator on the host
 * (--capability-ceiling), caps what any manifest can grant. A hub cannot
 * raise it; an unreadable ceiling reads as monitor. Levels
 * (docs/HOST_AUTHORITY.md):
 *   monitor         updates only
 *   isolate         isolation, mesh quarantine, evidence collection, updates
 *   signed-scripts  isolate plus scripts, and those only with a pinned host
 *                   authority key (Trust_Allows)
 *   monitor-signed-scripts  evidence collection, updates and scripts (only
 *                   with a pinned host authority key); no isolation: for a
 *                   hypervisor, where isolating cuts its management only
 *   respond         everything but scripts
 *   engagement      everything */
static inline bool Trust_CeilingHas(const char* ceiling, const char* cap) {
    if (!ceiling || !ceiling[0]) return true;
    if (!cap) return false;
    if (strcmp(cap, "update") == 0) return true;
    if (strcmp(ceiling, "engagement") == 0) return true;
    if (strcmp(ceiling, "respond") == 0) return strcmp(cap, "script") != 0;
    bool isolateLevel = strcmp(cap, "isolate") == 0 || strcmp(cap, "mesh") == 0 || strcmp(cap, "collect") == 0;
    if (strcmp(ceiling, "isolate") == 0) return isolateLevel;
    if (strcmp(ceiling, "signed-scripts") == 0) return isolateLevel || strcmp(cap, "script") == 0;
    if (strcmp(ceiling, "monitor-signed-scripts") == 0) return strcmp(cap, "collect") == 0 || strcmp(cap, "script") == 0;
    return false;
}

/* Ceilings under which scripts run only on host-authority grants. */
static inline bool Trust_CeilingSignedOnly(const char* ceiling) {
    return ceiling && (strcmp(ceiling, "signed-scripts") == 0 || strcmp(ceiling, "monitor-signed-scripts") == 0);
}

/* Manifest profiles (signed by the authority). */
static inline bool Trust_ProfileName(const char* p) {
    return p && (strcmp(p, "monitor") == 0 || strcmp(p, "respond") == 0 || strcmp(p, "engagement") == 0);
}

/* Ceiling levels (set on the host): the profiles plus isolate,
 * signed-scripts and monitor-signed-scripts. */
static inline bool Trust_CeilingName(const char* p) {
    return Trust_ProfileName(p) || (p && (strcmp(p, "isolate") == 0 || Trust_CeilingSignedOnly(p)));
}

static inline bool Trust_Allows(const TrustContext* t, const char* kind) {
    const char* cap = Trust_CapabilityFor(kind);
    if (!Trust_ManifestHas(&t->manifest, cap) || !Trust_CeilingHas(t->ceiling, cap)) return false;
    /* (monitor-)signed-scripts: scripts only where a host authority key is pinned. */
    if (cap && strcmp(cap, "script") == 0 && Trust_CeilingSignedOnly(t->ceiling) && t->hostKeyCount == 0) return false;
    return true;
}

/* ---------------------------------------------------------------------------
 * Host authority files (docs/HOST_AUTHORITY.md). Root/SYSTEM-owned, read at
 * start, never written by the agent.
 *   host_authority.json  {"v":1,"keys":[{"id":"<sha256 hex of key>","role":"tap"|"auto","ed25519":"<64 hex>"}]}
 *   host_auto_allow.json {"v":1,"packages":[{"name":"..","sha256":"<64 hex>","modes":["audit","enforce"]}]}
 * ------------------------------------------------------------------------- */

static inline bool Trust_Hex64(const char* s) {
    if (!s || strlen(s) != 64) return false;
    for (const char* c = s; *c; c++) if (!isxdigit((unsigned char)*c)) return false;
    return true;
}

static inline void Trust_Lower(char* s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* Trust_EachElement walks a JSON array: calls fn on each element's span.
 * Returns the count, or -1 when the array is malformed, longer than cap, or
 * fn refuses an element. */
typedef bool (*Trust_ElementFn)(const char* v, const char* ve, void* ctx, int i);
static inline int Trust_EachElement(const char* v, const char* vend, int cap, Trust_ElementFn fn, void* ctx) {
    const char* p = TJ_Ws(v, vend);
    if (p >= vend || *p != '[') return -1;
    p = TJ_Ws(p + 1, vend);
    if (p < vend && *p == ']') return 0;
    int n = 0;
    for (;;) {
        p = TJ_Ws(p, vend);
        const char* e = TJ_SkipValue(p, vend, 1);
        if (!e || n >= cap || !fn(p, e, ctx, n)) return -1;
        n++;
        p = TJ_Ws(e, vend);
        if (p >= vend) return -1;
        if (*p == ',') { p++; continue; }
        if (*p == ']') return n;
        return -1;
    }
}

static inline bool Trust_HostKeyElement(const char* v, const char* ve, void* ctx, int i) {
    TrustHostKey* keys = (TrustHostKey*)ctx;
    TrustHostKey* k = &keys[i];
    char role[8], hex[80];
    memset(k, 0, sizeof(*k));
    if (!TJ_MemberPlain(v, ve, "id", k->id, sizeof(k->id)) || !Trust_Hex64(k->id)) return false;
    if (!TJ_MemberPlain(v, ve, "role", role, sizeof(role))) return false;
    if (strcmp(role, "tap") == 0) k->autoRole = false;
    else if (strcmp(role, "auto") == 0) k->autoRole = true;
    else return false;
    if (!TJ_MemberPlain(v, ve, "ed25519", hex, sizeof(hex)) || !Trust_Hex64(hex) || !Trust_HexKey(hex, k->key)) return false;
    /* The id is the key's fingerprint, as the grant's signer_key_id carries it. */
    uint8_t fp[32];
    char fphex[65];
    Response_SHA256_Sum(k->key, 32, fp);
    Response_BytesToHex(fp, 32, fphex);
    Trust_Lower(k->id);
    if (strcasecmp(fphex, k->id) != 0) return false;
    for (int j = 0; j < i; j++) if (strcmp(keys[j].id, k->id) == 0) return false;
    return true;
}

static inline bool Trust_HostAllowElement(const char* v, const char* ve, void* ctx, int i) {
    TrustHostAllow* a = &((TrustHostAllow*)ctx)[i];
    memset(a, 0, sizeof(*a));
    if (!TJ_MemberPlain(v, ve, "name", a->name, sizeof(a->name)) || !a->name[0]) return false;
    if (!TJ_MemberPlain(v, ve, "sha256", a->sha256, sizeof(a->sha256)) || !Trust_Hex64(a->sha256)) return false;
    Trust_Lower(a->sha256);
    const char *mv, *mve;
    char modes[TRUST_MAX_HOST_MODES][64];
    if (TJ_Member(v, ve, "modes", &mv, &mve) != 1) return false;
    int n = TJ_PlainArray(mv, mve, modes, TRUST_MAX_HOST_MODES);
    if (n <= 0) return false;
    for (int j = 0; j < n; j++) {
        size_t l = strlen(modes[j]);
        if (l == 0 || l >= sizeof(a->modes[0])) return false;
        for (const char* c = modes[j]; *c; c++) if (!(islower((unsigned char)*c) || *c == '_' || *c == '-')) return false;
        snprintf(a->modes[j], sizeof(a->modes[j]), "%s", modes[j]);
    }
    a->modeCount = n;
    return true;
}

/* Trust_HostVersion1: the document is an object whose "v" is 1. */
static inline bool Trust_HostVersion1(const char* buf, const char* end) {
    const char *v, *ve;
    int64_t ver = 0;
    return TJ_Member(buf, end, "v", &v, &ve) == 1 && TJ_Int(v, ve, &ver) && ver == 1;
}

static inline void Trust_LoadHostAuthority(TrustContext* t) {
    char path[260], buf[8192];
    t->hostKeyCount = 0;
    t->hostAllowCount = 0;
    t->host_error[0] = '\0';
    Trust_Path(t, false, TRUST_HOST_KEYS_FILE, path, sizeof(path));
    t->host_present = Trust_PathExists(path);
    if (!t->host_present) return;
    const char *v, *ve;
    if (!Trust_ReadSmallFile(t, path, buf, sizeof(buf))) {
        snprintf(t->host_error, sizeof(t->host_error), "host_authority.json is not root-owned, too big, or unreadable");
        return;
    }
    const char* end = buf + strlen(buf);
    TrustHostKey keys[TRUST_MAX_HOST_KEYS];
    int n = -1;
    if (Trust_HostVersion1(buf, end) && TJ_Member(buf, end, "keys", &v, &ve) == 1)
        n = Trust_EachElement(v, ve, TRUST_MAX_HOST_KEYS, Trust_HostKeyElement, keys);
    if (n <= 0) {
        snprintf(t->host_error, sizeof(t->host_error), "host_authority.json is malformed or has no valid key");
        return;
    }
    memcpy(t->host_keys, keys, sizeof(keys));
    t->hostKeyCount = n;

    Trust_Path(t, false, TRUST_HOST_ALLOW_FILE, path, sizeof(path));
    if (!Trust_PathExists(path)) return;
    TrustHostAllow allow[TRUST_MAX_HOST_ALLOW];
    n = -1;
    if (Trust_ReadSmallFile(t, path, buf, sizeof(buf))) {
        end = buf + strlen(buf);
        if (Trust_HostVersion1(buf, end) && TJ_Member(buf, end, "packages", &v, &ve) == 1)
            n = Trust_EachElement(v, ve, TRUST_MAX_HOST_ALLOW, Trust_HostAllowElement, allow);
    }
    if (n < 0) {
        snprintf(t->host_error, sizeof(t->host_error), "host_auto_allow.json is not root-owned or malformed; auto grants are refused");
        return;
    }
    memcpy(t->host_allow, allow, sizeof(allow));
    t->hostAllowCount = n;
}

/* ---------------------------------------------------------------------------
 * Enforcement state file.
 * ------------------------------------------------------------------------- */

static inline bool Trust_RuleValid(const TrustRule* r) {
    if (!r->service[0]) return false;
    for (const char* c = r->service; *c; c++)
        if (!(islower((unsigned char)*c) || isdigit((unsigned char)*c) || *c == '-' || *c == '_')) return false;
    if (!Trust_IsIPLiteral(r->destination)) return false;
    if (strcmp(r->protocol, "udp") != 0 && strcmp(r->protocol, "tcp") != 0) return false;
    return r->port >= 1 && r->port <= 65535;
}

/* Trust_ParseRules reads [{"destination","port","protocol","service"},...].
 * Returns the count, or -1 when anything in it is unreadable or invalid: an
 * exception list is taken whole or not at all. */
static inline int Trust_ParseRules(const char* v, const char* ve, TrustRule* out, int cap) {
    const char* p = TJ_Ws(v, ve);
    if (p >= ve || *p != '[') return -1;
    p = TJ_Ws(p + 1, ve);
    if (p < ve && *p == ']') return 0;
    int n = 0;
    for (;;) {
        const char* e = TJ_SkipValue(p, ve, 1);
        if (!e || n >= cap) return -1;
        TrustRule r;
        memset(&r, 0, sizeof(r));
        const char *x, *xe;
        int64_t port = 0;
        if (!TJ_MemberPlain(p, e, "service", r.service, sizeof(r.service)) ||
            !TJ_MemberPlain(p, e, "destination", r.destination, sizeof(r.destination)) ||
            !TJ_MemberPlain(p, e, "protocol", r.protocol, sizeof(r.protocol)) ||
            TJ_Member(p, e, "port", &x, &xe) != 1 || !TJ_Int(x, xe, &port) || port < 1 || port > 65535)
            return -1;
        r.port = (int)port;
        if (!Trust_RuleValid(&r)) return -1;
        out[n++] = r;
        p = TJ_Ws(e, ve);
        if (p >= ve) return -1;
        if (*p == ',') { p = TJ_Ws(p + 1, ve); continue; }
        if (*p == ']') return n;
        return -1;
    }
}

static inline bool Trust_SaveStateFrom(TrustContext* t, TrustState* s) {
    static char buf[16384];
    int off = snprintf(buf, sizeof(buf), "ominull-enforcement 1\niso %d %s %lld %s\nseen %lld %lld\n",
                       s->isolated ? 1 : 0, s->source[0] ? s->source : "none", (long long)s->iso_at,
                       s->iso_grant[0] ? s->iso_grant : "-", (long long)s->iso_seen, (long long)s->mesh_seen);
    for (int i = 0; i < s->allowCount && off > 0 && (size_t)off < sizeof(buf); i++)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "allow %s\n", s->allow[i]);
    for (int i = 0; i < s->meshCount && off > 0 && (size_t)off < sizeof(buf); i++)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "mesh %s %d %lld\n", s->mesh[i].ip, s->mesh[i].on ? 1 : 0,
                        (long long)s->mesh[i].at);
    for (int i = 0; i < s->ruleCount && off > 0 && (size_t)off < sizeof(buf); i++)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "rule %s %s %s %d\n", s->rules[i].service, s->rules[i].destination,
                        s->rules[i].protocol, s->rules[i].port);
    if (off <= 0 || (size_t)off >= sizeof(buf)) return false;
    char path[260];
    Trust_Path(t, true, "enforcement.state", path, sizeof(path));
    if (!Trust_WriteFile(t, path, buf, true)) {
        printf("[!] The authorized enforcement state could not be written to %s.\n", path);
        return false;
    }
    s->exists = true;
    return true;
}

static inline bool Trust_SaveState(TrustContext* t) { return Trust_SaveStateFrom(t, &t->state); }

static inline void Trust_LoadState(TrustContext* t) {
    TrustState* s = &t->state;
    memset(s, 0, sizeof(*s));
    snprintf(s->source, sizeof(s->source), "none");
    static char buf[16384];
    char path[260];
    Trust_Path(t, true, "enforcement.state", path, sizeof(path));
    if (!Trust_ReadSmallFile(t, path, buf, sizeof(buf))) return;
    if (strncmp(buf, "ominull-enforcement 1\n", 22) != 0) return;
    for (char* line = buf + 22; line && *line;) {
        char* next = strpbrk(line, "\r\n");
        if (next) {
            *next++ = '\0';
            while (*next == '\r' || *next == '\n') next++;
        }
        char a[64] = {0}, b[64] = {0};
        long long x = 0, y = 0;
        int on = 0;
        TrustRule r;
        memset(&r, 0, sizeof(r));
        if (sscanf(line, "rule %15s %63s %7s %d", r.service, r.destination, r.protocol, &r.port) == 4) {
            if (s->ruleCount < TRUST_MAX_RULES && Trust_RuleValid(&r)) s->rules[s->ruleCount++] = r;
        } else if (sscanf(line, "iso %d %11s %lld %63s", &on, a, &x, b) == 4) {
            s->isolated = on == 1;
            snprintf(s->source, sizeof(s->source), "%.11s", a);
            s->iso_at = x;
            snprintf(s->iso_grant, sizeof(s->iso_grant), "%s", strcmp(b, "-") == 0 ? "" : b);
        } else if (sscanf(line, "seen %lld %lld", &x, &y) == 2) {
            s->iso_seen = x;
            s->mesh_seen = y;
        } else if (sscanf(line, "allow %63s", a) == 1 && s->allowCount < TRUST_MAX_ALLOW && Trust_IsAllowEntry(a)) {
            snprintf(s->allow[s->allowCount++], 64, "%s", a);
        } else if (sscanf(line, "mesh %63s %d %lld", a, &on, &x) == 3 && s->meshCount < TRUST_MAX_MESH && Trust_IsIPLiteral(a)) {
            TrustMeshSlot* m = &s->mesh[s->meshCount++];
            snprintf(m->ip, sizeof(m->ip), "%s", a);
            m->on = on == 1;
            m->at = x;
        }
        line = next;
    }
    s->exists = true;
}

/* ---------------------------------------------------------------------------
 * Loading the pinned material.
 *
 * trust.pin holds the whole pinned bundle (tenant, epoch, three keys) and is
 * written in one atomic step, so a host never holds keys of two generations.
 * trust.epoch is the highest epoch ever pinned; --repin-trust keeps it, so an
 * older bundle cannot be pinned again after a rotation. Everything verifies
 * against the keys loaded from trust.pin (no per-key file is trusted).
 * ------------------------------------------------------------------------- */

static inline bool Trust_ParsePin(const char* buf, char tenant[64], int64_t* epoch, uint8_t keys[TRUST_KEY_COUNT][32],
                                  char hex[TRUST_KEY_COUNT][80]) {
    char t0[64] = "", h[TRUST_KEY_COUNT][80];
    long long e = 0;
    if (sscanf(buf, "ominull-trust 1\ntenant=%63[^\n]\nepoch=%lld\nresponse_key=%79[^\n]\nauto_isolate_key=%79[^\n]\npolicy_key=%79[^\n]", t0, &e,
               h[0], h[1], h[2]) != 5)
        return false;
    if (e < 1 || !t0[0]) return false;
    for (int i = 0; i < TRUST_KEY_COUNT; i++) {
        if (!Trust_HexKey(h[i], keys[i])) return false;
        if (hex) snprintf(hex[i], 80, "%s", h[i]);
    }
    snprintf(tenant, 64, "%s", t0);
    *epoch = e;
    return true;
}

static inline void Trust_LoadPin(TrustContext* t) {
    char path[260], buf[600];
    Trust_Path(t, false, "trust.epoch", path, sizeof(path));
    long long floor = 0;
    if (Trust_ReadSmallFile(t, path, buf, sizeof(buf)) && sscanf(buf, "%lld", &floor) == 1 && floor > 0) t->epoch_floor = floor;
    if (t->epoch_floor < TRUST_MIN_EPOCH) t->epoch_floor = TRUST_MIN_EPOCH;
    Trust_Path(t, false, "trust.pin", path, sizeof(path));
    char hex[TRUST_KEY_COUNT][80];
    if (!Trust_ReadSmallFile(t, path, buf, sizeof(buf)) || !Trust_ParsePin(buf, t->tenant, &t->epoch, t->keys, hex)) {
        t->tenant[0] = '\0';
        return;
    }
    if (strcmp(t->tenant, TRUST_TENANT) != 0 || t->epoch < t->epoch_floor) {
        printf("[!] The pinned trust bundle (tenant %s, epoch %lld) is not acceptable here; nothing is trusted until re-pinned.\n", t->tenant,
               (long long)t->epoch);
        t->tenant[0] = '\0';
        return;
    }
    for (int i = 0; i < TRUST_KEY_COUNT; i++) t->have_key[i] = true;
}

/* Trust_ManifestFloored: the manifest's seq is not above the highest one taken
 * under the pinned policy key. */
static inline bool Trust_ManifestFloored(const TrustContext* t, int64_t seq) {
    if (!t->have_key[TRUST_KEY_POLICY]) return false;
    for (int i = 0; i < t->mfloorCount; i++)
        if (memcmp(t->mfloor[i].key, t->keys[TRUST_KEY_POLICY], 32) == 0) return seq <= t->mfloor[i].seq;
    return false;
}

/* Trust_FloorInsert raises key's floor in a list: the key moves to the newest
 * slot and the oldest key is forgotten when the list is full. */
static inline void Trust_FloorInsert(TrustFloor* list, int* count, const uint8_t key[32], int64_t seq) {
    int i = 0;
    while (i < *count && memcmp(list[i].key, key, 32) != 0) i++;
    if (i == *count && *count == TRUST_MAX_MFLOOR) i = 0;   /* evict the oldest */
    else if (i == *count) (*count)++;
    for (; i + 1 < *count; i++) list[i] = list[i + 1];
    memcpy(list[*count - 1].key, key, 32);
    list[*count - 1].seq = seq;
}

static inline bool Trust_WriteFloors(const TrustContext* t, const TrustFloor* list, int count) {
    char fl[TRUST_MAX_MFLOOR * 90 + 1], path[260];
    size_t off = 0;
    fl[0] = '\0';
    for (int i = 0; i < count; i++) {
        char kh[65];
        Response_BytesToHex(list[i].key, 32, kh);
        off += (size_t)snprintf(fl + off, sizeof(fl) - off, "%s %lld\n", kh, (long long)list[i].seq);
    }
    Trust_Path(t, false, "manifest.floor", path, sizeof(path));
    return Trust_WriteFile(t, path, fl, false);
}

/* Trust_RaiseManifestFloor records seq as taken under the pinned policy key:
 * the next list is written first and only then put in force. */
static inline bool Trust_RaiseManifestFloor(TrustContext* t, int64_t seq) {
    if (!t->have_key[TRUST_KEY_POLICY]) return true;
    if (Trust_ManifestFloored(t, seq) && !t->mfloor_dirty) return true;
    TrustFloor next[TRUST_MAX_MFLOOR];
    int n = t->mfloorCount;
    memcpy(next, t->mfloor, sizeof(next));
    if (!Trust_ManifestFloored(t, seq)) Trust_FloorInsert(next, &n, t->keys[TRUST_KEY_POLICY], seq);
    if (!Trust_WriteFloors(t, next, n)) return false;
    memcpy(t->mfloor, next, sizeof(next));
    t->mfloorCount = n;
    t->mfloor_dirty = false;
    return true;
}

/* Trust_LoadManifestState takes the stored manifest when it verifies against
 * the pinned policy key (at start, and again once a bundle is pinned after a
 * re-pin), and raises the floor to it: the manifest is written before the
 * floor, so a stop between the two leaves the floor behind, never ahead. */
static inline void Trust_LoadManifestState(TrustContext* t) {
    char path[260], buf[2048];
    Trust_Path(t, true, "manifest.state", path, sizeof(path));
    if (!Trust_ReadSmallFile(t, path, buf, sizeof(buf))) return;
    TrustManifest m;
    if (!Trust_ParseManifest(buf, buf + strlen(buf), &m) || !Trust_ManifestVerify(t, &m)) return;
    if (t->manifest.have && m.seq <= t->manifest.seq) return;
    t->manifest = m;
    if (!Trust_ManifestFloored(t, m.seq)) {
        /* In memory now (Init may run before the directory is checked); made
         * durable on the next heartbeat, before any manifest is taken. */
        Trust_FloorInsert(t->mfloor, &t->mfloorCount, t->keys[TRUST_KEY_POLICY], m.seq);
        t->mfloor_dirty = true;
    }
}

static inline void Trust_Init(TrustContext* t, const char* endpoint_id, const char* key_dir, const char* state_dir, bool check_owner) {
    memset(t, 0, sizeof(*t));
    snprintf(t->endpoint_id, sizeof(t->endpoint_id), "%s", endpoint_id ? endpoint_id : "");
    snprintf(t->key_dir, sizeof(t->key_dir), "%.199s", key_dir ? key_dir : TRUST_DEFAULT_KEY_DIR);
    snprintf(t->state_dir, sizeof(t->state_dir), "%.199s", state_dir ? state_dir : TRUST_DEFAULT_STATE_DIR);
    t->check_owner = check_owner;
    Trust_LoadPin(t);
    char path[260], buf[2048];
    Trust_Path(t, false, "capability.ceiling", path, sizeof(path));
    if (Trust_PathExists(path)) {
        char c[32] = "";
        if (!Trust_ReadSmallFile(t, path, buf, sizeof(buf)) || sscanf(buf, "%31s", c) != 1 || !Trust_CeilingName(c))
            snprintf(c, sizeof(c), "monitor");
        snprintf(t->ceiling, sizeof(t->ceiling), "%s", c);
    }
    Trust_Path(t, false, "manifest.floor", path, sizeof(path));
    if (Trust_ReadSmallFile(t, path, buf, sizeof(buf))) {
        const char* line = buf;
        while (*line && t->mfloorCount < TRUST_MAX_MFLOOR) {
            char kh[80] = "";
            long long fs = 0;
            if (sscanf(line, "%79s %lld", kh, &fs) == 2 && fs > 0 && Trust_HexKey(kh, t->mfloor[t->mfloorCount].key))
                t->mfloor[t->mfloorCount++].seq = fs;
            const char* nl = strchr(line, '\n');
            if (!nl) break;
            line = nl + 1;
        }
    }
    Trust_LoadHostAuthority(t);
    Trust_LoadManifestState(t);
    Trust_LoadState(t);
    t->loaded = true;
}

/* Trust_Distrust drops everything loaded from a directory the platform could
 * not secure: no key, manifest or enforcement state from it is used, and
 * nothing is written there. */
static inline void Trust_Distrust(TrustContext* t) {
    memset(t->keys, 0, sizeof(t->keys));
    memset(t->have_key, 0, sizeof(t->have_key));
    t->tenant[0] = '\0';
    memset(&t->manifest, 0, sizeof(t->manifest));
    memset(&t->state, 0, sizeof(t->state));
    memset(t->host_keys, 0, sizeof(t->host_keys));   /* host_present stays: scripts stay refused */
    t->hostKeyCount = 0;
    t->hostAllowCount = 0;
    t->state.exists = true;   /* nothing to adopt into */
    snprintf(t->state.source, sizeof(t->state.source), "none");
    t->untrusted = true;
    Trust_Refuse(t, 0, "the trust directory is not protected; no pinned key, manifest or state is used%s", "");
}

/* The trust bundle: the authority's three public keys for a tenant, signed by
 * the release key. The release key is compiled into this agent and kept off
 * the hub, so a hub cannot make an agent pin keys of its own choosing. */
static inline int Trust_BundleStatement(const char* tenant, int64_t epoch, char hex[TRUST_KEY_COUNT][80], char* out, size_t cap) {
    return snprintf(out, cap, "OMINULL-TRUST-BUNDLE-V1\ntenant=%s\nepoch=%lld\nresponse_key=%s\nauto_isolate_key=%s\npolicy_key=%s\n", tenant,
                    (long long)epoch, hex[TRUST_KEY_RESPONSE], hex[TRUST_KEY_AUTO], hex[TRUST_KEY_POLICY]);
}

/* Trust_PinKeys pins a trust offer as a whole, only when this host has no
 * pin, the offer is for this agent's tenant at an epoch no lower than any
 * ever pinned here, and its bundle signature verifies against the release
 * key. A pinned set that differs from the offer is never replaced or mixed:
 * that is reported as a mismatch, and only a local administrator can re-pin
 * (--repin-trust). */
static inline void Trust_PinKeys(TrustContext* t, const char* obj, const char* end, int64_t now) {
    char hex[TRUST_KEY_COUNT][80];
    uint8_t key[TRUST_KEY_COUNT][32];
    char tenant[64], sigB64[256];
    for (int i = 0; i < TRUST_KEY_COUNT; i++) {
        if (!TJ_MemberPlain(obj, end, TRUST_KEY_FIELDS[i], hex[i], sizeof(hex[i])) || !Trust_HexKey(hex[i], key[i])) {
            Trust_Refuse(t, now, "the hub's trust offer is incomplete%s", "");
            return;
        }
        for (char* c = hex[i]; *c; c++) *c = (char)tolower((unsigned char)*c);
    }
    bool pinned = t->have_key[TRUST_KEY_RESPONSE] && t->have_key[TRUST_KEY_AUTO] && t->have_key[TRUST_KEY_POLICY];
    if (pinned) {
        bool any = false, was = false;
        for (int i = 0; i < TRUST_KEY_COUNT; i++) {
            was = was || t->mismatch[i];
            t->mismatch[i] = memcmp(key[i], t->keys[i], 32) != 0;
            any = any || t->mismatch[i];
        }
        if (any && !was) Trust_Refuse(t, now, "the hub offers authority keys other than the ones pinned here; re-pin locally if the rotation is intended%s", "");
        return;
    }
    if (t->untrusted) return;

    const char *ev, *eve;
    int64_t epoch = 0;
    if (!TJ_MemberPlain(obj, end, "tenant_id", tenant, sizeof(tenant)) || !tenant[0] ||
        !TJ_MemberPlain(obj, end, "bundle_sig", sigB64, sizeof(sigB64)) || !sigB64[0] ||
        TJ_Member(obj, end, "epoch", &ev, &eve) != 1 || !TJ_Int(ev, eve, &epoch)) {
        Trust_Refuse(t, now, "the hub's trust offer is not signed by the release key; nothing pinned%s", "");
        return;
    }
    if (strcmp(tenant, TRUST_TENANT) != 0) {
        Trust_Refuse(t, now, "the hub offers another tenant's trust bundle; nothing pinned%s", "");
        return;
    }
    if (epoch < t->epoch_floor) {
        Trust_Refuse(t, now, "the hub offers a trust bundle older than one already pinned here; nothing pinned%s", "");
        return;
    }
    char stmt[512];
    int sn = Trust_BundleStatement(tenant, epoch, hex, stmt, sizeof(stmt));
    if (sn <= 0 || sn >= (int)sizeof(stmt)) return;
    /* Checking a signature costs a process on Linux: an offer that failed is
     * not checked again until it changes. */
    uint8_t h[32];
    {
        char both[800];
        int bn = snprintf(both, sizeof(both), "%s|%s", stmt, sigB64);
        if (bn <= 0 || bn >= (int)sizeof(both)) return;
        Response_SHA256_Sum((const uint8_t*)both, (size_t)bn, h);
    }
    if (memcmp(h, t->failed_bundle, 32) == 0) return;
    uint8_t der[160];
    size_t dl = Response_Base64Decode(sigB64, strlen(sigB64), der, sizeof(der));
    if (!t->verify_release || dl == 0 || !t->verify_release(stmt, (size_t)sn, der, dl)) {
        memcpy(t->failed_bundle, h, 32);
        Trust_Refuse(t, now, "the hub's trust offer does not verify against the release key; nothing pinned%s", "");
        return;
    }
    /* The epoch floor first, then the pin in one atomic write. */
    char path[260], buf[600];
    {
        snprintf(buf, sizeof(buf), "%lld\n", (long long)epoch);
        Trust_Path(t, false, "trust.epoch", path, sizeof(path));
        if (!Trust_WriteFile(t, path, buf, false)) {
            Trust_Refuse(t, now, "the trust epoch could not be written; nothing pinned%s", "");
            return;
        }
        t->epoch_floor = epoch;
    }
    snprintf(buf, sizeof(buf), "ominull-trust 1\ntenant=%s\nepoch=%lld\nresponse_key=%s\nauto_isolate_key=%s\npolicy_key=%s\n", tenant,
             (long long)epoch, hex[0], hex[1], hex[2]);
    Trust_Path(t, false, "trust.pin", path, sizeof(path));
    if (!Trust_WriteFile(t, path, buf, false)) {
        Trust_Refuse(t, now, "the trust bundle could not be written; nothing pinned%s", "");
        return;
    }
    for (int i = 0; i < TRUST_KEY_COUNT; i++) {
        memcpy(t->keys[i], key[i], 32);
        t->have_key[i] = true;
        t->mismatch[i] = false;
    }
    snprintf(t->tenant, sizeof(t->tenant), "%s", tenant);
    t->epoch = epoch;
    Trust_LoadManifestState(t);
    printf("[+] Pinned the authority keys for tenant %s (epoch %lld, response %.16s...), signed by the release key.\n", tenant, (long long)epoch, hex[0]);
    fflush(stdout);
}

static inline void Trust_AcceptManifest(TrustContext* t, const char* v, const char* ve, int64_t now) {
    TrustManifest m;
    if (!Trust_ParseManifest(v, ve, &m)) {
        Trust_Refuse(t, now, "unreadable capability manifest%s", "");
        return;
    }
    if (t->manifest.have && m.seq == t->manifest.seq && strcmp(m.signature, t->manifest.signature) == 0) return;
    if (t->manifest.have && m.seq <= t->manifest.seq) {
        Trust_Refuse(t, now, "capability manifest older than the pinned one%s", "");
        return;
    }
    if (Trust_ManifestFloored(t, m.seq)) {
        /* After a re-pin the manifest file may be gone; this floor is not. */
        Trust_Refuse(t, now, "capability manifest older than one already taken under this policy key%s", "");
        return;
    }
    if (!Trust_ManifestVerify(t, &m)) {
        Trust_Refuse(t, now, "capability manifest does not verify against the pinned policy key%s", "");
        return;
    }
    /* The manifest first, then its floor: a failed write leaves the floor
     * behind (the same manifest is taken again on retry or at start), never
     * ahead of the manifest in force. */
    char path[260], json[1024];
    Trust_ManifestJSON(&m, json, sizeof(json));
    Trust_Path(t, true, "manifest.state", path, sizeof(path));
    if (!Trust_WriteFile(t, path, json, false)) {
        Trust_Refuse(t, now, "the capability manifest could not be written; not taken%s", "");
        return;
    }
    t->manifest = m;
    if (!Trust_RaiseManifestFloor(t, m.seq)) Trust_Refuse(t, now, "the manifest floor could not be written; it is raised again at start%s", "");
    printf("[+] Capability manifest %lld pinned: profile %s.\n", (long long)m.seq, m.profile);
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * Grants and the typed action they authorize.
 * ------------------------------------------------------------------------- */

enum { TRUST_OP_NONE = 0, TRUST_OP_ISOLATE, TRUST_OP_RELEASE, TRUST_OP_AUTO_ISOLATE, TRUST_OP_MESH_ON, TRUST_OP_MESH_OFF, TRUST_OP_UPDATE };

typedef struct {
    int  op;
    char allow[TRUST_MAX_ALLOW][64];
    int  allowCount;
    TrustRule rules[TRUST_MAX_RULES];
    int  ruleCount;
    char ip[64];
    char version[64];
} TrustAction;

/* Trust_ParseBaselines finds this host's isolation exceptions in the signed
 * payload: "baselines":[{"endpoints":[...],"rules":[...]}]. The hub binds them
 * when it asks for the approval, so the owner approves exactly these holes and
 * the heartbeat's copy is never used for a signed isolation. No entry for this
 * host means none: hub and loopback only. */
static inline const char* Trust_ParseBaselines(const char* payload, const char* end, const char* self, TrustAction* a) {
    const char *v, *ve;
    int r = TJ_Member(payload, end, "baselines", &v, &ve);
    if (r < 0) return "payload unreadable";
    if (r == 0) return NULL;
    const char* p = TJ_Ws(v, ve);
    if (p >= ve || *p != '[') return "isolation exceptions unreadable";
    p = TJ_Ws(p + 1, ve);
    if (p < ve && *p == ']') return NULL;
    bool found = false;
    for (;;) {
        const char* e = TJ_SkipValue(p, ve, 1);
        if (!e) return "isolation exceptions unreadable";
        const char *ev, *eve, *rv, *rve;
        static char eps[64][64];
        if (TJ_Member(p, e, "endpoints", &ev, &eve) != 1 || TJ_Member(p, e, "rules", &rv, &rve) != 1) return "isolation exceptions unreadable";
        int ne = TJ_PlainArray(ev, eve, eps, 64);
        if (ne < 0) return "isolation exceptions unreadable";
        static TrustRule rules[TRUST_MAX_RULES];
        int nr = Trust_ParseRules(rv, rve, rules, TRUST_MAX_RULES);
        if (nr < 0) return "isolation exceptions unreadable or too many";
        for (int i = 0; i < ne; i++) {
            if (strcmp(eps[i], self) != 0) continue;
            if (found) return "isolation exceptions name this host twice";
            found = true;
            memcpy(a->rules, rules, sizeof(TrustRule) * (size_t)nr);
            a->ruleCount = nr;
        }
        p = TJ_Ws(e, ve);
        if (p >= ve) return "isolation exceptions unreadable";
        if (*p == ',') { p = TJ_Ws(p + 1, ve); continue; }
        if (*p == ']') return NULL;
        return "isolation exceptions unreadable";
    }
}

/* Trust_ParseAction reads the payload the owner approved and works out what it
 * does to this host. kind is the grant's signed action kind; the route must
 * belong to it, so a grant for one kind can never carry another's action. */
static inline const char* Trust_ParseAction(const char* payload, size_t len, const char* kind, const char* grantEndpoint,
                                            const char* self, TrustAction* a) {
    memset(a, 0, sizeof(*a));
    const char* end = payload + len;
    const char *bv, *bve, *tv, *tve;
    char route[64];
    if (!TJ_MemberPlain(payload, end, "route", route, sizeof(route))) return "payload has no readable route";
    if (TJ_Member(payload, end, "body", &bv, &bve) != 1) return "payload has no body";
    if (TJ_Member(payload, end, "targets", &tv, &tve) != 1) return "payload has no targets";
    char targets[64][64];
    int nt = TJ_PlainArray(tv, tve, targets, 64);
    if (nt <= 0) return "payload targets unreadable";
    /* The body must itself be a strictly readable object. */
    const char *dv, *dve;
    if (TJ_Member(bv, bve, "\x01", &dv, &dve) < 0) return "payload body unreadable";

    bool mesh = strcmp(kind, "mesh_quarantine") == 0;
    if (mesh) {
        if (strcmp(route, "/api/v1/mesh/quarantine") == 0) a->op = TRUST_OP_MESH_ON;
        else if (strcmp(route, "/api/v1/mesh/unquarantine") == 0) a->op = TRUST_OP_MESH_OFF;
        else return "mesh grant over a non-mesh route";
        if (!TJ_MemberPlain(bv, bve, "target_ip", a->ip, sizeof(a->ip)) || !Trust_IsIPLiteral(a->ip)) return "mesh body has no address";
        char want[80];
        snprintf(want, sizeof(want), "mesh:%s", a->ip);
        if (nt != 1 || strcmp(targets[0], want) != 0 || strcmp(grantEndpoint, want) != 0) return "mesh grant and body disagree on the address";
        return NULL;
    }

    bool listed = false;
    for (int i = 0; i < nt; i++) if (strcmp(targets[i], self) == 0) listed = true;
    if (!listed || strcmp(grantEndpoint, self) != 0) return "grant is for another endpoint";

    if (strcmp(kind, "auto_isolate") == 0) {
        if (strcmp(route, "auto-isolate") != 0) return "auto-isolation key used for something other than isolating";
        char ep[64];
        if (!TJ_MemberPlain(bv, bve, "endpoint_id", ep, sizeof(ep)) || strcmp(ep, self) != 0 || nt != 1) return "auto-isolation body names another endpoint";
        a->op = TRUST_OP_AUTO_ISOLATE;
        return Trust_ParseBaselines(payload, end, self, a);
    }
    if (strcmp(kind, "agent_update") == 0) {
        if (strcmp(route, "/api/v1/agents/update") != 0) return "update grant over a non-update route";
        if (!TJ_MemberPlain(bv, bve, "version", a->version, sizeof(a->version))) return "update body names no version";
        a->op = TRUST_OP_UPDATE;
        return NULL;
    }
    if (strcmp(kind, "isolation_change") != 0) return "unsupported grant kind";
    bool single = false;
    if (strcmp(route, "/api/v1/endpoints/isolate") == 0) { a->op = TRUST_OP_ISOLATE; single = true; }
    else if (strcmp(route, "/api/v1/endpoints/isolate-bulk") == 0) a->op = TRUST_OP_ISOLATE;
    else if (strcmp(route, "/api/v1/endpoints/unisolate") == 0) { a->op = TRUST_OP_RELEASE; single = true; }
    else if (strcmp(route, "/api/v1/endpoints/unisolate-bulk") == 0) a->op = TRUST_OP_RELEASE;
    else return "isolation grant over an unknown route";
    if (single) {
        char ep[64];
        if (nt != 1 || !TJ_MemberPlain(bv, bve, "endpoint_id", ep, sizeof(ep)) || strcmp(ep, self) != 0) return "isolation body names another endpoint";
    }
    if (a->op == TRUST_OP_ISOLATE) {
        const char *av, *ave;
        int r = TJ_Member(bv, bve, "allow_ips", &av, &ave);
        if (r < 0) return "isolation body unreadable";
        if (r == 1) {
            a->allowCount = TJ_PlainArray(av, ave, a->allow, TRUST_MAX_ALLOW);
            if (a->allowCount < 0) return "isolation allow list unreadable or too long";
            for (int i = 0; i < a->allowCount; i++) if (!Trust_IsAllowEntry(a->allow[i])) return "isolation allow list holds a non-address or too wide a range";
        }
        return Trust_ParseBaselines(payload, end, self, a);
    }
    return NULL;
}

/* Trust_VerifyGrantCore checks one grant against its payload bytes and the key
 * its kind requires. Returns NULL when valid, else why not. *genuine (when
 * given) says whether the signature verified, whatever else is wrong: only a
 * genuine grant may move a watermark, so a forged grant with a far-future
 * issue time cannot make this host ignore every real one after it. */
static inline const char* Trust_VerifyGrantCore(const TrustContext* t, const ResponseGrant* g, const uint8_t* payload, size_t len, int64_t now,
                                                bool* genuine) {
    if (genuine) *genuine = false;
    if (g->version != 2 && g->version != 3) return "unsupported grant version";
    bool autoKind = strcmp(g->action_kind, "auto_isolate") == 0;
    int key = autoKind ? TRUST_KEY_AUTO : TRUST_KEY_RESPONSE;
    if (!t->have_key[key]) return autoKind ? "no auto-isolation key is pinned" : "no response key is pinned";
    if (strcmp(g->tenant_id, t->tenant) != 0) return "grant for another tenant";
    uint8_t hash[32];
    char hex[65];
    Response_SHA256_Sum(payload, len, hash);
    Response_BytesToHex(hash, 32, hex);
    if (strcasecmp(hex, g->action_digest) != 0) return "payload does not match the grant digest";
    uint8_t canon[1024], sig[64];
    size_t clen = EncodeGrantCanonical(g->version, g->grant_id, g->tenant_id, g->endpoint_id, g->action_kind, g->action_digest,
                                       g->operator_id, g->response_session_id, g->issued_at, g->expires_at, g->nonce, g->job_id,
                                       g->signer_key_id, canon, sizeof(canon));
    if (!clen || strlen(g->signature) != 128 || !Response_HexToBytes(g->signature, sig, 64)) return "grant signature unreadable";
    if (!Ed25519_Verify(sig, canon, clen, t->keys[key])) return "grant signature does not verify";
    if (genuine) *genuine = true;
    if (g->issued_at <= 0 || g->expires_at < g->issued_at) return "grant has no valid time window";
    if (now < g->issued_at - 60) return "grant is not valid yet (clock skew)";
    if (now > g->expires_at + 60) return "grant has expired";
    return NULL;
}

/* Trust_ReadGrantObject parses {"grant":{...},"payload_b64":"..."}. */
static inline bool Trust_ReadGrantObject(const char* v, const char* ve, ResponseGrant* g, uint8_t* payload, size_t* plen) {
    const char *gv, *gve;
    char b64[(TRUST_MAX_PAYLOAD / 3 + 2) * 4 + 4];
    if (TJ_Member(v, ve, "grant", &gv, &gve) != 1) return false;
    if (!TJ_MemberPlain(v, ve, "payload_b64", b64, sizeof(b64))) return false;
    char gbuf[2048];
    size_t gl = (size_t)(gve - gv);
    if (gl >= sizeof(gbuf)) return false;
    memcpy(gbuf, gv, gl);
    gbuf[gl] = '\0';
    const char* p = gbuf;
    if (!ExtractGrantObject(&p, g)) return false;
    size_t n = Response_Base64Decode(b64, strlen(b64), payload, TRUST_MAX_PAYLOAD);
    if (n == 0 || n >= TRUST_MAX_PAYLOAD) return false;
    *plen = n;
    return true;
}

static inline TrustMeshSlot* Trust_MeshSlot(TrustState* s, const char* ip, bool create) {
    for (int i = 0; i < s->meshCount; i++) if (strcmp(s->mesh[i].ip, ip) == 0) return &s->mesh[i];
    if (!create || s->meshCount >= TRUST_MAX_MESH) return NULL;
    TrustMeshSlot* m = &s->mesh[s->meshCount++];
    memset(m, 0, sizeof(*m));
    snprintf(m->ip, sizeof(m->ip), "%s", ip);
    return m;
}

/* Trust_ApplyGrant verifies one enforcement grant and moves the authorized
 * state. Returns true when the state changed. Every outcome advances the
 * "seen" watermark except a missing key, which may still arrive. */
static inline bool Trust_ApplyGrant(TrustContext* t, const ResponseGrant* g, const uint8_t* payload, size_t len, int64_t now) {
    /* The next state is built in a copy and made durable before it is
     * published: a grant whose outcome could not be written is not taken (its
     * watermark does not move) and is processed again on the next beat. */
    static TrustState work;
    work = t->state;
    TrustState* s = &work;
    bool mesh = strcmp(g->action_kind, "mesh_quarantine") == 0;
    bool iso = strcmp(g->action_kind, "isolation_change") == 0 || strcmp(g->action_kind, "auto_isolate") == 0;
    if (!mesh && !iso) {
        Trust_Refuse(t, now, "enforcement grant of kind %s is not an enforcement change", g->action_kind);
        return false;
    }
    int64_t* seen = mesh ? &s->mesh_seen : &s->iso_seen;
    if (g->issued_at <= *seen) return false;          /* already processed; nothing to verify */
    /* Only a grant for this endpoint may move its isolation watermark: a
     * genuine grant for another host (the hub can send any) must not hide
     * this host's own older grants. */
    if (iso && strcmp(g->endpoint_id, t->endpoint_id) != 0) {
        Trust_Refuse(t, now, "isolation grant for another endpoint%s", "");
        return false;
    }

    bool genuine = false;
    const char* why = Trust_VerifyGrantCore(t, g, payload, len, now, &genuine);
    if (why) {
        Trust_Refuse(t, now, "%s", why);
        /* A genuine grant that is expired or early still moves the mark, but
         * never past this host's own clock: no grant may silence later ones. */
        if (genuine && g->issued_at <= now + TRUST_SKEW_SECONDS) {
            *seen = g->issued_at;
            if (Trust_SaveStateFrom(t, s)) t->state = work;
        }
        return false;
    }
    char text[TRUST_MAX_PAYLOAD + 1];
    memcpy(text, payload, len);
    text[len] = '\0';
    TrustAction a;
    why = Trust_ParseAction(text, len, g->action_kind, g->endpoint_id, t->endpoint_id, &a);
    if (why) {
        /* Not a readable action for this host (another target, another
         * address spelling): refused without moving the mark. */
        Trust_Refuse(t, now, "%s", why);
        return false;
    }
    *seen = g->issued_at;
    /* The manifest limits what new restriction this host accepts. A release
     * is always accepted: narrowing a manifest must never free a host the
     * owner contained. */
    bool restricts = a.op == TRUST_OP_ISOLATE || a.op == TRUST_OP_AUTO_ISOLATE || a.op == TRUST_OP_MESH_ON;
    if (!why && restricts && !Trust_Allows(t, g->action_kind)) why = mesh ? "this endpoint's manifest does not allow mesh quarantine"
                                                                            : "this endpoint's manifest does not allow isolation";
    if (why) {
        Trust_Refuse(t, now, "%s", why);
        if (Trust_SaveStateFrom(t, s)) t->state = work;
        return false;
    }

    bool changed = false;
    if (mesh) {
        TrustMeshSlot* m = Trust_MeshSlot(s, a.ip, a.op == TRUST_OP_MESH_ON);
        if (!m) {
            if (a.op == TRUST_OP_MESH_ON) Trust_Refuse(t, now, "mesh quarantine list is full%s", "");
        } else if (g->issued_at > m->at) {
            changed = m->on != (a.op == TRUST_OP_MESH_ON);
            m->on = a.op == TRUST_OP_MESH_ON;
            m->at = g->issued_at;
        }
    } else if (g->issued_at > s->iso_at) {
        if (a.op == TRUST_OP_AUTO_ISOLATE && s->isolated) {
            /* Already contained; the detector never widens or re-labels an
             * owner's isolation. */
        } else {
            bool want = a.op != TRUST_OP_RELEASE;
            changed = want != s->isolated || a.allowCount != s->allowCount;
            for (int i = 0; !changed && i < a.allowCount; i++) changed = strcmp(a.allow[i], s->allow[i]) != 0;
            s->isolated = want;
            snprintf(s->source, sizeof(s->source), "%s", a.op == TRUST_OP_AUTO_ISOLATE ? "auto" : (want ? "owner" : "none"));
            s->allowCount = want ? a.allowCount : 0;
            for (int i = 0; i < s->allowCount; i++) snprintf(s->allow[i], 64, "%s", a.allow[i]);
            if (!changed && want) {
                changed = a.ruleCount != s->ruleCount;
                for (int i = 0; !changed && i < a.ruleCount; i++) changed = memcmp(&a.rules[i], &s->rules[i], sizeof(TrustRule)) != 0;
            }
            s->ruleCount = want ? a.ruleCount : 0;
            if (want) memcpy(s->rules, a.rules, sizeof(TrustRule) * (size_t)a.ruleCount);
            s->iso_at = g->issued_at;
            snprintf(s->iso_grant, sizeof(s->iso_grant), "%s", g->grant_id);
        }
    }
    /* Forget released mesh slots once no grant that predates them can still be valid. */
    for (int i = 0; i < s->meshCount;) {
        if (!s->mesh[i].on && now - s->mesh[i].at > TRUST_MESH_FORGET_SECONDS) {
            s->mesh[i] = s->mesh[--s->meshCount];
            continue;
        }
        i++;
    }
    if (!Trust_SaveStateFrom(t, s)) {
        Trust_Refuse(t, now, "the enforcement state could not be written; the grant is retried on the next beat%s", "");
        return false;
    }
    t->state = work;
    if (changed) {
        printf("[+] Accepted %s grant %.8s... (%s).\n", g->action_kind, g->grant_id,
               mesh ? (a.op == TRUST_OP_MESH_ON ? "quarantine peer" : "lift peer quarantine")
                    : (a.op == TRUST_OP_RELEASE ? "release" : "isolate"));
        fflush(stdout);
    }
    return changed;
}

/* ---------------------------------------------------------------------------
 * The heartbeat hook and what the enforcer reads.
 * ------------------------------------------------------------------------- */

/* Trust_Bootstrap adopts the hub's view once, the first time this version runs
 * on a host that has no state file: an isolation or quarantine that was in
 * force before the upgrade stays in force. From then on only grants move it.
 * The marks come from this host's clock, never from the hub: grants issued
 * before this moment are taken as already reflected in the adopted view, and
 * any later owner grant (a release included) applies on top. */
static inline void Trust_Bootstrap(TrustContext* t, bool isolated, char allow[][64], int allowCount, char peers[][64], int peerCount,
                                   const TrustRule* rules, int ruleCount, int64_t now) {
    TrustState* s = &t->state;
    memset(s, 0, sizeof(*s));
    s->exists = true;   /* adopted once, even if the file cannot be written */
    int64_t mark = now - TRUST_SKEW_SECONDS;
    s->iso_seen = mark;
    s->iso_at = mark;
    s->mesh_seen = mark;
    s->isolated = isolated;
    snprintf(s->source, sizeof(s->source), "%s", isolated ? "bootstrap" : "none");
    for (int i = 0; isolated && i < allowCount && i < TRUST_MAX_ALLOW; i++) snprintf(s->allow[s->allowCount++], 64, "%.63s", allow[i]);
    for (int i = 0; isolated && i < ruleCount && i < TRUST_MAX_RULES; i++) s->rules[s->ruleCount++] = rules[i];
    for (int i = 0; i < peerCount && s->meshCount < TRUST_MAX_MESH; i++) {
        TrustMeshSlot* m = &s->mesh[s->meshCount++];
        snprintf(m->ip, sizeof(m->ip), "%.63s", peers[i]);
        m->on = true;
        m->at = mark;
    }
    if (Trust_SaveState(t)) {
        printf("[*] Enforcement state adopted from the hub once (isolated=%s, %d quarantined peer(s)); "
               "from now on only signed grants change it.\n", isolated ? "yes" : "no", peerCount);
        fflush(stdout);
    }
}

/* Trust_ProcessHeartbeat pins keys, takes a newer manifest and applies any
 * enforcement grants in the hub's answer. Returns true when the authorized
 * enforcement state changed. */
static inline bool Trust_ProcessHeartbeat(TrustContext* t, const char* resp, size_t len, int64_t now) {
    if (!resp || !len) return false;
    const char* end = resp + len;
    const char *v, *ve;
    if (TJ_Member(resp, end, "trust", &v, &ve) == 1) Trust_PinKeys(t, v, ve, now);
    if (t->mfloor_dirty && !t->untrusted && Trust_WriteFloors(t, t->mfloor, t->mfloorCount)) t->mfloor_dirty = false;
    if (TJ_Member(resp, end, "capability_manifest", &v, &ve) == 1) {
        if (t->mfloor_dirty) Trust_Refuse(t, now, "the manifest floor could not be made durable; no manifest is taken until it is%s", "");
        else Trust_AcceptManifest(t, v, ve, now);
    }
    bool changed = false;
    if (!t->state.exists) {
        /* First run of a grant-verifying agent on this host. Only a response
         * that states the hub's view (is_isolated present) is adopted. */
        const char *iv, *ive, *av, *ave, *pv, *pve, *mv, *mve;
        if (TJ_Member(resp, end, "is_isolated", &iv, &ive) != 1) return false;
        bool isolated = (ive - iv) >= 4 && strncmp(iv, "true", 4) == 0;
        static char allow[TRUST_MAX_ALLOW][64], peers[TRUST_MAX_MESH][64];
        int na = 0, np = 0;
        if (TJ_Member(resp, end, "isolation_allow_ips", &av, &ave) == 1) na = TJ_PlainArray(av, ave, allow, TRUST_MAX_ALLOW);
        if (TJ_Member(resp, end, "quarantined_peers", &pv, &pve) == 1) np = TJ_PlainArray(pv, pve, peers, TRUST_MAX_MESH);
        if (na < 0) na = 0;
        if (np < 0) np = 0;
        int ka = 0, kp = 0;
        for (int i = 0; i < na; i++) {
            if (!Trust_IsAllowEntry(allow[i])) continue;
            if (ka != i) memmove(allow[ka], allow[i], sizeof(allow[0]));
            ka++;
        }
        for (int i = 0; i < np; i++) {
            if (!Trust_IsIPLiteral(peers[i])) continue;
            if (kp != i) memmove(peers[kp], peers[i], sizeof(peers[0]));
            kp++;
        }
        static TrustRule rules[TRUST_MAX_RULES];
        int nr = 0;
        if (isolated && TJ_Member(resp, end, "isolation_baseline", &mv, &mve) == 1) nr = Trust_ParseRules(mv, mve, rules, TRUST_MAX_RULES);
        if (nr < 0) nr = 0;
        Trust_Bootstrap(t, isolated, allow, ka, peers, kp, rules, nr, now);
        changed = true;
    }
    if (TJ_Member(resp, end, "enforcement_grants", &v, &ve) == 1) {
        const char* p = TJ_Ws(v, ve);
        if (p < ve && *p == '[') {
            p = TJ_Ws(p + 1, ve);
            int n = 0;
            while (p < ve && *p != ']' && n++ < TRUST_MAX_GRANTS) {
                const char* e = TJ_SkipValue(p, ve, 1);
                if (!e) break;
                ResponseGrant g;
                static uint8_t payload[TRUST_MAX_PAYLOAD];
                size_t plen = 0;
                if (Trust_ReadGrantObject(p, e, &g, payload, &plen)) {
                    if (Trust_ApplyGrant(t, &g, payload, plen, now)) changed = true;
                } else {
                    Trust_Refuse(t, now, "unreadable enforcement grant%s", "");
                }
                p = TJ_Ws(e, ve);
                if (p < ve && *p == ',') p = TJ_Ws(p + 1, ve);
            }
        }
    }
    return changed;
}

/* Trust_UpdateAuthorized checks the owner's grant for installing version on
 * this endpoint. Returns NULL when authorized, else why not. */
static inline const char* Trust_UpdateAuthorized(const TrustContext* t, const char* resp, size_t len, const char* version, int64_t now) {
    const char *v, *ve;
    if (TJ_Member(resp, resp + len, "agent_update_grant", &v, &ve) != 1) return "the hub offered an update without an owner grant";
    ResponseGrant g;
    static uint8_t payload[TRUST_MAX_PAYLOAD];
    size_t plen = 0;
    if (!Trust_ReadGrantObject(v, ve, &g, payload, &plen)) return "the update grant is unreadable";
    if (strcmp(g.action_kind, "agent_update") != 0) return "the update grant is of another kind";
    const char* why = Trust_VerifyGrantCore(t, &g, payload, plen, now, NULL);
    if (why) return why;
    char text[TRUST_MAX_PAYLOAD + 1];
    memcpy(text, payload, plen);
    text[plen] = '\0';
    TrustAction a;
    why = Trust_ParseAction(text, plen, g.action_kind, g.endpoint_id, t->endpoint_id, &a);
    if (why) return why;
    if (strcmp(a.version, version) != 0) return "the owner approved a different version than the one offered";
    if (!Trust_Allows(t, "agent_update")) return "this endpoint's manifest does not allow agent updates";
    return NULL;
}

/* What the enforcer applies: the authorized state. The manifest was checked
 * when each restriction was accepted; it is not re-applied here, so a
 * narrowed manifest cannot release what the owner contained. */
static inline bool Trust_EffectiveIsolated(const TrustContext* t) {
    return t->state.isolated;
}

static inline int Trust_EffectivePeers(const TrustContext* t, char out[][64], int cap) {
    int n = 0;
    for (int i = 0; i < t->state.meshCount && n < cap; i++) {
        const TrustMeshSlot* m = &t->state.mesh[i];
        if (m->on) snprintf(out[n++], 64, "%s", m->ip);
    }
    return n;
}

/* The dead-man release frees a host whose hub stopped answering, because an
 * isolation nobody can lift is a lost endpoint. For isolations nobody
 * supervised (detector, bootstrap) that is five minutes of missed beats, as
 * before. An owner's isolation is held for twelve hours: a hub that is down
 * or made to go quiet cannot free a contained host quickly, and the owner
 * still gets a host back eventually if the containment itself cut the hub
 * off. A local administrator can always run --cleanup. */
#define TRUST_DEADMAN_OWNER_SECONDS (12 * 3600)

/* unsupervisedBeats is the platform's five-minute count; beatMillis its beat. */
static inline int Trust_DeadmanBeats(const TrustContext* t, int unsupervisedBeats, int beatMillis) {
    if (strcmp(t->state.source, "owner") != 0 || beatMillis <= 0) return unsupervisedBeats;
    return (int)((int64_t)TRUST_DEADMAN_OWNER_SECONDS * 1000 / beatMillis);
}

/* Trust_OfferRefusal checks a response job offer (collection, script,
 * terminal, screen) beyond its signature: the offer's kind must be the kind the grant
 * signs (so an isolation or update grant can never open a terminal), and the
 * manifest must allow it. Returns NULL when the offer may run. */
static inline const char* Trust_OfferRefusal(const TrustContext* t, const char* offerKind, const ResponseGrant* g) {
    if (!t->have_key[TRUST_KEY_RESPONSE]) return "no response key is pinned";
    if (strcmp(g->tenant_id, t->tenant) != 0) return "grant for another tenant";
    if (!offerKind || strcmp(offerKind, g->action_kind) != 0) return "the offer's kind differs from the kind its grant signs";
    if (strcmp(offerKind, "forensic_collection") != 0 && strcmp(offerKind, "script_exec") != 0 &&
        strcmp(offerKind, "terminal_session") != 0 && strcmp(offerKind, "screen_session") != 0)
        return "not a response job kind";
    if (!Trust_Allows(t, offerKind)) return "this endpoint's capability manifest does not allow it";
    return NULL;
}

/* Trust_TextCount counts occurrences of needle in hay. */
static inline int Trust_TextCount(const char* hay, const char* needle) {
    int n = 0;
    size_t l = strlen(needle);
    for (const char* p = hay; (p = strstr(p, needle)) != NULL; p += l) n++;
    return n;
}

/* Trust_HostAutoRefusal: an auto-role grant runs only a package on the host's
 * allow-list (script_digest equals its sha256) in one of its modes
 * (parameters.mode). The executor reads the payload with plain string
 * search, so the fields read here must each occur exactly once in the text:
 * then both readers see the same digest and parameters. */
static inline const char* Trust_HostAutoRefusal(const TrustContext* t, const char* payload_json) {
    if (!payload_json) return "no payload";
    const char* end = payload_json + strlen(payload_json);
    if (Trust_TextCount(payload_json, "\"script_digest\"") != 1 || Trust_TextCount(payload_json, "\"parameters\"") != 1 ||
        Trust_TextCount(payload_json, "\"source\"") != 1)
        return "auto grant payload is ambiguous";
    char digest[80], mode[32];
    const char *pv, *pve;
    if (!TJ_MemberPlain(payload_json, end, "script_digest", digest, sizeof(digest)) || !Trust_Hex64(digest))
        return "auto grant payload has no script digest";
    if (TJ_Member(payload_json, end, "parameters", &pv, &pve) != 1 || !TJ_MemberPlain(pv, pve, "mode", mode, sizeof(mode)))
        return "auto grant payload has no mode";
    for (int i = 0; i < t->hostAllowCount; i++) {
        const TrustHostAllow* a = &t->host_allow[i];
        if (strcasecmp(a->sha256, digest) != 0) continue;
        for (int j = 0; j < a->modeCount; j++) if (strcmp(a->modes[j], mode) == 0) return NULL;
        return "auto grant: this mode is not allowed for the package here";
    }
    return "auto grant: the package is not on this host's allow-list";
}

/* Trust_OfferGrantRefusal checks a response offer's grant signature, after
 * Trust_OfferRefusal. A V3 grant must name the offered job. Where a host
 * authority is pinned (host_authority.json), script_exec runs only on a V3
 * grant signed by one of its keys: operator nightshift:tap for a tap key,
 * nightshift:auto for an auto key (then also the allow-list); the hub's
 * response key no longer runs scripts there. Everything else verifies
 * against the pinned response key. Returns NULL when the grant is good. */
static inline const char* Trust_OfferGrantRefusal(const TrustContext* t, const char* job_id, const ResponseGrant* g, const char* payload_json,
                                                  const char* endpoint_id) {
    if (g->version == 3 && (!job_id || strcmp(g->job_id, job_id) != 0)) return "the grant is for another job";
    if (strcmp(g->action_kind, "script_exec") == 0 && t->host_present) {
        if (g->version != 3) return "scripts here need a host-authority grant (V3)";
        const TrustHostKey* k = NULL;
        for (int i = 0; i < t->hostKeyCount; i++)
            if (strcasecmp(t->host_keys[i].id, g->signer_key_id) == 0) k = &t->host_keys[i];
        if (!k) return "the grant's signer is not a pinned host-authority key";
        if (strcmp(g->operator_id, k->autoRole ? "nightshift:auto" : "nightshift:tap") != 0)
            return "the grant's operator does not match its host-authority key's role";
        if (!VerifyResponseGrantKey(g, payload_json, endpoint_id, k->key)) return "host-authority grant does not verify";
        return k->autoRole ? Trust_HostAutoRefusal(t, payload_json) : NULL;
    }
    if (!t->have_key[TRUST_KEY_RESPONSE]) return "no response key is pinned";
    if (!VerifyResponseGrantKey(g, payload_json, endpoint_id, t->keys[TRUST_KEY_RESPONSE])) return "grant does not verify";
    return NULL;
}

static inline void Trust_ResponseKeyPath(const TrustContext* t, char* out, size_t cap) {
    Trust_Path(t, false, TRUST_KEY_FILES[TRUST_KEY_RESPONSE], out, cap);
}

/* Trust_HostReportJSON appends the host authority to a report that is
 * still open (no closing brace) and closes it: key ids and roles, the
 * allow-list, and why a file was not used. Public facts only. When it does
 * not fit, only host_authority and a count are written, so the report stays
 * valid JSON. */
static inline void Trust_HostReportJSON(const TrustContext* t, char* out, size_t cap) {
    size_t len = strlen(out);
    if (len + 2 > cap) {   /* cannot happen with the agent's buffers; keep it valid */
        if (cap >= 5) snprintf(out, cap, "null");
        else if (cap) out[0] = '\0';
        return;
    }
    char host[2600];
    size_t h = 0;
#define TRUST_HOST_APPEND(...) do { int _n = snprintf(host + h, sizeof(host) - h, __VA_ARGS__); \
        if (_n < 0 || (size_t)_n >= sizeof(host) - h) { h = sizeof(host); } else h += (size_t)_n; } while (0)
    TRUST_HOST_APPEND(",\"host_authority\":%s", t->hostKeyCount > 0 ? "true" : "false");
    if (t->host_present) {
        TRUST_HOST_APPEND(",\"host_keys\":[");
        for (int i = 0; i < t->hostKeyCount && h < sizeof(host); i++)
            TRUST_HOST_APPEND("%s{\"id\":\"%s\",\"role\":\"%s\"}", i ? "," : "", t->host_keys[i].id, t->host_keys[i].autoRole ? "auto" : "tap");
        TRUST_HOST_APPEND("],\"host_allow\":[");
        for (int i = 0; i < t->hostAllowCount && h < sizeof(host); i++) {
            const TrustHostAllow* a = &t->host_allow[i];
            TRUST_HOST_APPEND("%s{\"name\":\"", i ? "," : "");
            for (const char* c = a->name; *c && h < sizeof(host); c++)
                TRUST_HOST_APPEND("%c", (*c == '"' || *c == '\\' || (unsigned char)*c < 0x20) ? ' ' : *c);
            TRUST_HOST_APPEND("\",\"sha256\":\"%s\",\"modes\":[", a->sha256);
            for (int j = 0; j < a->modeCount; j++) TRUST_HOST_APPEND("%s\"%s\"", j ? "," : "", a->modes[j]);
            TRUST_HOST_APPEND("]}");
        }
        TRUST_HOST_APPEND("]");
        if (t->host_error[0]) TRUST_HOST_APPEND(",\"host_error\":\"%s\"", t->host_error);
    }
#undef TRUST_HOST_APPEND
    if (h >= sizeof(host) || len + h + 2 > cap) {
        h = (size_t)snprintf(host, sizeof(host), ",\"host_authority\":%s,\"host_keys_count\":%d",
                             t->hostKeyCount > 0 ? "true" : "false", t->hostKeyCount);
        if (len + h + 2 > cap) h = 0;
    }
    memcpy(out + len, host, h);
    out[len + h] = '}';
    out[len + h + 1] = '\0';
}

/* Trust_UTCOffsetMinutes is the machine clock's offset east of UTC now
 * (daylight saving included), for maintenance windows in machine time. */
static inline int Trust_UTCOffsetMinutes(void) {
#ifdef _WIN32
    TIME_ZONE_INFORMATION tz;
    DWORD r = GetTimeZoneInformation(&tz);
    if (r == TIME_ZONE_ID_INVALID) return 0;
    long bias = tz.Bias;
    if (r == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
    else if (r == TIME_ZONE_ID_STANDARD) bias += tz.StandardBias;
    return (int)-bias;
#else
    time_t now = time(NULL);
    struct tm lt;
    if (!localtime_r(&now, &lt)) return 0;
    return (int)(lt.tm_gmtoff / 60);
#endif
}

/* Trust_ReportJSON is what this agent tells the hub about its trust state:
 * no keys, no grant ids, nothing secret. */
static inline void Trust_ReportJSON(const TrustContext* t, char* out, size_t cap) {
    const char* keys = "pinned";
    for (int i = 0; i < TRUST_KEY_COUNT; i++) if (!t->have_key[i]) keys = "missing";
    for (int i = 0; i < TRUST_KEY_COUNT; i++) if (t->mismatch[i]) keys = "mismatch";
    char peers[TRUST_MAX_MESH][64];
    int npeers = Trust_EffectivePeers(t, peers, TRUST_MAX_MESH);
    char refused[200];
    size_t j = 0;
    for (size_t i = 0; t->refused[i] && j + 1 < sizeof(refused); i++) {
        char c = t->refused[i];
        refused[j++] = (c == '"' || c == '\\' || (unsigned char)c < 0x20) ? ' ' : c;
    }
    refused[j] = '\0';
    snprintf(out, cap,
             "{\"v\":1,\"keys\":\"%s\",\"response_key\":%s,\"auto_isolate_key\":%s,\"policy_key\":%s,"
             "\"manifest_seq\":%lld,\"profile\":\"%s\",\"iso_seen\":%lld,\"mesh_seen\":%lld,"
             "\"isolated\":%s,\"isolation_source\":\"%s\",\"peers\":%d,\"refused\":\"%s\",\"refused_at\":%lld,\"ceiling\":\"%s\",\"utc_offset_minutes\":%d",
             keys, t->have_key[0] ? "true" : "false", t->have_key[1] ? "true" : "false", t->have_key[2] ? "true" : "false",
             (long long)(t->manifest.have ? t->manifest.seq : 0), t->manifest.have ? t->manifest.profile : "",
             (long long)t->state.iso_seen, (long long)t->state.mesh_seen, Trust_EffectiveIsolated(t) ? "true" : "false",
             t->state.source, npeers, refused, (long long)t->refused_at, t->ceiling, Trust_UTCOffsetMinutes());
    Trust_HostReportJSON(t, out, cap);
}

/* Trust_Repin removes the pinned bundle so the next contact pins the hub's
 * current offer, again only with a release-key-signed bundle and at an epoch
 * no lower than trust.epoch (kept). Only a local administrator runs it; it is
 * the explicit re-pin. */
/* Trust_SetCeiling records the local capability ceiling (an administrator
 * at the host; "none" removes it). */
static inline bool Trust_SetCeiling(const TrustContext* t, const char* profile) {
    char path[260], line[32];
    Trust_Path(t, false, "capability.ceiling", path, sizeof(path));
    if (profile && strcmp(profile, "none") == 0) return Trust_RemoveFile(path);
    if (!Trust_CeilingName(profile)) return false;
    snprintf(line, sizeof(line), "%s\n", profile);
    return Trust_WriteFile(t, path, line, false);
}

/* Returns how many pins were removed, or -1 when one could not be removed
 * (the re-pin then failed: the old keys stay trusted). */
static inline int Trust_Repin(const TrustContext* t) {
    int removed = 0;
    bool ok = true;
    char path[260];
    /* A floor recovered from manifest.state at start is only in memory; it
     * must be on disk before the key that verified it goes. */
    if (t->mfloor_dirty && !Trust_WriteFloors(t, t->mfloor, t->mfloorCount)) return -1;
    /* A re-pin revokes the keys in force: the next bundle must come from a
     * strictly later epoch, so the bundle being replaced (or any older one)
     * cannot be pinned again. The floor is written before the pin goes. */
    Trust_Path(t, false, "trust.pin", path, sizeof(path));
    if (Trust_PathExists(path)) {   /* once per pin: a repeated re-pin does not climb */
        /* One above the pin being revoked, never above the floor already
         * written: a re-pin interrupted after this write and retried does
         * not climb again. */
        int64_t next = t->epoch + 1 > t->epoch_floor ? t->epoch + 1 : t->epoch_floor;
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld\n", (long long)next);
        Trust_Path(t, false, "trust.epoch", path, sizeof(path));
        if (!Trust_WriteFile(t, path, buf, false)) return -1;
    }
    Trust_Path(t, false, "trust.pin", path, sizeof(path));
    if (Trust_PathExists(path)) {
        ok = Trust_RemoveFile(path) && !Trust_PathExists(path);
        if (ok) removed++;
    }
    for (int i = 0; i < TRUST_KEY_COUNT; i++) {   /* copies older builds kept */
        Trust_Path(t, false, TRUST_KEY_FILES[i], path, sizeof(path));
        if (Trust_PathExists(path) && !(Trust_RemoveFile(path) && !Trust_PathExists(path))) ok = false;
    }
    return ok ? removed : -1;
}

/* Trust_LocalRelease is the local recovery: an administrator at the console
 * lifts isolation and quarantines and records it as such. */
static inline bool Trust_LocalRelease(TrustContext* t) {
    t->state.isolated = false;
    t->state.allowCount = 0;
    for (int i = 0; i < t->state.meshCount; i++) t->state.mesh[i].on = false;
    snprintf(t->state.source, sizeof(t->state.source), "local");
    return Trust_SaveState(t);
}

/* Release statement: what the release key signs besides the package bytes,
 * so the version an agent installs is signed, not just the file. */
static inline int Trust_ReleaseStatement(const char* package, const char* version, const char* sha256, char* out, size_t cap) {
    return snprintf(out, cap, "OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n", package, version, sha256);
}

#endif /* OMINULL_AGENT_TRUST_H */
