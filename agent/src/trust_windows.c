/*
 * The Windows agent's one trust context (agent_trust.h): pinned response
 * authority keys, the capability manifest and the authorized enforcement
 * state. Everything that changes this host asks here first: the enforcer
 * (service.c), the response dispatcher (response_windows.c), the updater
 * (updater.c) and the heartbeat report (hub_client.c).
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <bcrypt.h>

#include "../include/agent.h"
#include "../include/agent_trust.h"
#include "../include/der_sig.h"
#define OMINULL_NEED_PUBKEY_XY
#include "../include/release_key.h"

static TrustContext g_Trust;
static bool g_TrustLoaded = false;

static bool WinVerifyRelease(const char* msg, size_t len, const uint8_t* der, size_t derlen);

void Agent_TrustInit(const char* endpoint_id) {
    bool dirOk = Agent_TrustSecureDirectory(TRUST_DEFAULT_KEY_DIR);
    Trust_Init(&g_Trust, endpoint_id, NULL, NULL, true);
    if (!dirOk) {
        /* Nothing read from or written to a directory someone else controls. */
        Trust_Distrust(&g_Trust);
    }
    g_Trust.verify_release = WinVerifyRelease;
    g_TrustLoaded = true;
    printf("[*] Trust: response key %s, auto-isolation key %s, policy key %s; manifest %s.\n",
           g_Trust.have_key[TRUST_KEY_RESPONSE] ? "pinned" : "missing", g_Trust.have_key[TRUST_KEY_AUTO] ? "pinned" : "missing",
           g_Trust.have_key[TRUST_KEY_POLICY] ? "pinned" : "missing", g_Trust.manifest.have ? g_Trust.manifest.profile : "none yet");
}

bool Agent_TrustLoaded(void) { return g_TrustLoaded; }

bool Agent_TrustHasResponseKey(void) { return g_TrustLoaded && g_Trust.have_key[TRUST_KEY_RESPONSE]; }

void Agent_TrustReport(char* out, size_t cap) {
    if (!g_TrustLoaded) {
        snprintf(out, cap, "null");
        return;
    }
    Trust_ReportJSON(&g_Trust, out, cap);
}

bool Agent_TrustProcessHeartbeat(const char* resp) {
    if (!g_TrustLoaded || !resp) return false;
    return Trust_ProcessHeartbeat(&g_Trust, resp, strlen(resp), (int64_t)time(NULL));
}

bool Agent_TrustIsolated(void) { return g_TrustLoaded && Trust_EffectiveIsolated(&g_Trust); }

int Agent_TrustAllow(char out[][64], int cap) {
    int n = 0;
    for (int i = 0; g_TrustLoaded && g_Trust.state.isolated && i < g_Trust.state.allowCount && n < cap; i++)
        snprintf(out[n++], 64, "%s", g_Trust.state.allow[i]);
    return n;
}

int Agent_TrustRules(OMINULL_BASELINE_RULE* out, int cap) {
    int n = 0;
    for (int i = 0; g_TrustLoaded && g_Trust.state.isolated && i < g_Trust.state.ruleCount && n < cap; i++) {
        const TrustRule* r = &g_Trust.state.rules[i];
        memset(&out[n], 0, sizeof(out[n]));
        snprintf(out[n].service, sizeof(out[n].service), "%s", r->service);
        snprintf(out[n].destination, sizeof(out[n].destination), "%s", r->destination);
        snprintf(out[n].protocol, sizeof(out[n].protocol), "%s", r->protocol);
        out[n++].port = r->port;
    }
    return n;
}

int Agent_TrustPeers(char out[][64], int cap) {
    return g_TrustLoaded ? Trust_EffectivePeers(&g_Trust, out, cap) : 0;
}

int Agent_TrustDeadmanBeats(int unsupervisedBeats, int beatMillis) {
    if (!g_TrustLoaded) return unsupervisedBeats;
    return Trust_DeadmanBeats(&g_Trust, unsupervisedBeats, beatMillis);
}

const char* Agent_TrustOfferRefusal(const char* kind, const void* grant) {
    if (!g_TrustLoaded) return "trust state not loaded";
    const char* why = Trust_OfferRefusal(&g_Trust, kind, (const ResponseGrant*)grant);
    if (why) Trust_Refuse(&g_Trust, (int64_t)time(NULL), "response offer refused: %s", why);
    return why;
}

const char* Agent_TrustOfferGrantRefusal(const char* job_id, const void* grant, const char* payload_json, const char* endpoint_id) {
    if (!g_TrustLoaded) return "trust state not loaded";
    const char* why = Trust_OfferGrantRefusal(&g_Trust, job_id, (const ResponseGrant*)grant, payload_json, endpoint_id);
    if (why) Trust_Refuse(&g_Trust, (int64_t)time(NULL), "response offer refused: %s", why);
    return why;
}

bool Agent_TrustResponseKey(uint8_t out[32]) {
    if (!g_TrustLoaded || !g_Trust.have_key[TRUST_KEY_RESPONSE]) return false;
    memcpy(out, g_Trust.keys[TRUST_KEY_RESPONSE], 32);
    return true;
}

void Agent_TrustResponseKeyPath(char* out, size_t cap) {
    if (!g_TrustLoaded) {
        snprintf(out, cap, "%s", OMINULL_DEFAULT_RESPONSE_PUBKEY_PATH);
        return;
    }
    Trust_ResponseKeyPath(&g_Trust, out, cap);
}

const char* Agent_TrustUpdateRefusal(const char* respJson, const char* version, const char* running) {
    if (!Trust_UpdateVersionAdmissible(version, running)) return "not newer than the running version";
    if (!g_TrustLoaded) return "trust state not loaded";
    const char* why = Trust_UpdateAuthorized(&g_Trust, respJson, strlen(respJson), version, (int64_t)time(NULL));
    if (why) Trust_Refuse(&g_Trust, (int64_t)time(NULL), "agent update refused: %s", why);
    return why;
}

int Agent_TrustReleaseStatement(const char* package, const char* version, const char* sha256, char* out, size_t cap) {
    return Trust_ReleaseStatement(package, version, sha256, out, cap);
}

size_t Agent_TrustBase64Decode(const char* in, unsigned char* out, size_t cap) {
    return Response_Base64Decode(in, strlen(in), out, cap);
}

bool Agent_TrustSetCeiling(const char* profile) {
    return g_TrustLoaded && !g_Trust.untrusted && Trust_SetCeiling(&g_Trust, profile);
}

int Agent_TrustRepin(void) {
    return g_TrustLoaded ? Trust_Repin(&g_Trust) : 0;
}

bool Agent_TrustLocalRelease(void) {
    return g_TrustLoaded && g_Trust.state.exists && Trust_LocalRelease(&g_Trust);
}

bool Agent_TrustArtifactName(const char* version, char* out, size_t cap) {
    return Trust_AgentArtifactName(version, out, cap);
}

/* ProgramData lets ordinary users create directories. If one pre-created
 * C:\ProgramData\Ominull (or put a junction there), they would keep write or
 * delete rights over the pins and the enforcement state. The directory is
 * taken over: owner Administrators, a protected ACL (SYSTEM and
 * Administrators full, Users read), inherited by what is written inside. */
bool Agent_TrustSecureDirectory(const char* dir) {
    DWORD attrs = GetFileAttributesA(dir);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY) || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
        printf("[!] %s is missing, not a directory, or a reparse point; trust material is not kept there.\n", dir);
        return false;
    }
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
                                                              SDDL_REVISION_1, &sd, NULL))
        return false;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    PSID owner = NULL;
    bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && GetSecurityDescriptorOwner(sd, &owner, &defaulted) &&
              SetNamedSecurityInfoA((LPSTR)dir, SE_FILE_OBJECT,
                                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner,
                                    NULL, dacl, NULL) == ERROR_SUCCESS;
    LocalFree(sd);
    if (!ok) printf("[!] Could not take ownership of %s and protect its ACL (Error: %lu).\n", dir, GetLastError());
    return ok;
}

/* Agent_VerifyReleaseMessage checks a DER ECDSA P-256 signature over msg
 * against the release key compiled into this agent (CNG). */
bool Agent_VerifyReleaseMessage(const char* msg, size_t len, const unsigned char* der, size_t derlen) {
    unsigned char raw[64], hash[32];
    if (!msg || !der || !DerToRawSignature(der, derlen, raw)) return false;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    bool hashed = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0 && BCryptHashData(hHash, (PUCHAR)msg, (ULONG)len, 0) == 0 &&
                  BCryptFinishHash(hHash, hash, 32, 0) == 0;
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!hashed) return false;
    unsigned char blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), OMINULL_RELEASE_PUBKEY_XY, OMINULL_RELEASE_PUBKEY_XY_LEN);
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0) return false;
    if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob, sizeof(blob), 0) == 0)
        ok = BCryptVerifySignature(hKey, NULL, hash, 32, raw, 64, 0) == 0;
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool WinVerifyRelease(const char* msg, size_t len, const uint8_t* der, size_t derlen) {
    return Agent_VerifyReleaseMessage(msg, len, der, derlen);
}
