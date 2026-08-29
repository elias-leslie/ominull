/*
 * Windows agent self-update.
 *
 * Nothing here installs anything it has not first proved genuine. The package
 * is checked against the digest the hub advertised and then - the check that
 * actually matters - against a detached ECDSA P-256 signature verified with the
 * release public key compiled into this binary. That key does not come from the
 * hub, so a compromised hub, or anyone on the plain-HTTP LAN path to it, can
 * serve any bytes they like and none of them will be installed.
 *
 * Verification uses BCrypt (CNG), which Windows already ships, so signature
 * checking adds no dependency to the agent.
 */

#define OMINULL_NEED_PUBKEY_XY
#include "../include/agent.h"
#include "../include/release_key.h"
#include <winhttp.h>
#include <bcrypt.h>
#include <ctype.h>
#include "../include/der_sig.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define UPDATE_MAX_ATTEMPTS 3

/* ------------------------------------------------------------------ paths */

/* The install directory is the only place a release is ever staged. It is
 * writable by administrators alone, and it is the same volume as the binary
 * being replaced, which is what makes the final rename atomic. Staging in a
 * world-writable directory such as %TEMP% would leave a window between
 * verifying the file and using it in which anyone could swap it. */
static bool InstallDir(char* out, size_t cap) {
    char self[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self, MAX_PATH)) return false;
    char* slash = strrchr(self, '\\');
    if (!slash) return false;
    *slash = '\0';
    if (strlen(self) + 1 > cap) return false;
    snprintf(out, cap, "%s", self);
    return true;
}

static void PathIn(const char* dir, const char* leaf, char* out, size_t cap) {
    snprintf(out, cap, "%s\\%s", dir, leaf);
}

/* ------------------------------------------------------------------- JSON */

/* ExtractJsonString pulls one string value out of a JSON object body. The
 * responses this parses are small and flat; anything it cannot understand ends
 * up rejected by the checks downstream rather than guessed at. */
static bool ExtractJsonString(const char* json, const char* key, char* out, size_t outLen) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* p = strstr(json, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outLen - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

/* IsSafeUrlPath keeps anything exotic out of a value that becomes a request
 * path. Nothing here reaches a shell, but a descriptor is attacker-influenced
 * input and narrow input is easier to reason about than clever escaping. */
static bool IsSafeUrlPath(const char* s) {
    for (const char* p = s; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) continue;
        if (strchr("./-_~%+", *p)) continue;
        return false;
    }
    return true;
}

/* HubPathOf takes only the path from a descriptor URL, and only if it points at
 * the hub's package route. The advertised host is ignored deliberately: behind
 * a reverse proxy the hub advertises a host the agent does not dial, and
 * ignoring it means no hub response can redirect the download elsewhere. */
static const char* HubPathOf(const char* url) {
    const char* path = strstr(url, "://");
    path = path ? strchr(path + 3, '/') : (url[0] == '/' ? url : NULL);
    if (!path || strncmp(path, "/download/", 10) != 0) return NULL;
    if (!IsSafeUrlPath(path)) return NULL;
    return path;
}

static bool IsHexDigest(const char* s) {
    size_t n = 0;
    for (; s[n]; n++) {
        if (!isxdigit((unsigned char)s[n])) return false;
    }
    return n == 64;
}

/* ------------------------------------------------------------------- HTTP */

/* DownloadToFile fetches one hub path into a file, replacing whatever is there.
 * A short or failed download leaves no file behind, so a later step can never
 * pick up a partial one. */
static bool DownloadToFile(const AGENT_CONFIG* config, const char* path, const char* destPath) {
    /* The download carries the API key too, and it is fetched from wherever the
     * agent is pointed. Prove that is the enrolled hub before asking it for
     * anything. */
    if (!Hub_TransportReady(config)) return false;

    char host[128] = {0};
    WORD port = 80;
    BOOL isHttps = FALSE;
    Hub_SplitURL(config->hub_url, host, sizeof(host), &port, &isHttps);

    WCHAR wHost[128] = {0}, wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 128);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 512);

    HINTERNET hSession = WinHttpOpen(L"OminullAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    bool ok = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HINTERNET hConnect = WinHttpConnect(hSession, wHost, port, 0);
    HINTERNET hRequest = NULL;
    if (!hConnect) goto done;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath, NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) goto done;

    /* No SECURITY_FLAG_IGNORE_* overrides here either. The release signature
     * already makes a forged package uninstallable; refusing an unverifiable
     * hub keeps a hostile path from serving one at all. */

    {
        WCHAR wHeaders[512] = {0}, wKey[128] = {0};
        MultiByteToWideChar(CP_UTF8, 0, config->api_key, -1, wKey, 128);
        swprintf(wHeaders, 512, L"X-API-Key: %s\r\n", wKey);
        WinHttpAddRequestHeaders(hRequest, wHeaders, (DWORD)-1L,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hRequest, NULL)) goto done;
    if (!Hub_VerifyRequestPin(hRequest, config)) goto done;

    {
        DWORD status = 0, statusLen = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen, WINHTTP_NO_HEADER_INDEX);
        if (status != 200) {
            printf("[!] Update download of %s returned HTTP %lu\n", path, status);
            goto done;
        }
    }

    hFile = CreateFileA(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) goto done;
        if (avail == 0) break;
        char buf[16384];
        while (avail > 0) {
            DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            DWORD got = 0, wrote = 0;
            if (!WinHttpReadData(hRequest, buf, want, &got) || got == 0) goto done;
            if (!WriteFile(hFile, buf, got, &wrote, NULL) || wrote != got) goto done;
            avail -= got;
        }
    }
    ok = true;

done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (!ok) DeleteFileA(destPath);
    return ok;
}

/* ----------------------------------------------------------------- crypto */

static bool Sha256File(const char* path, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != STATUS_SUCCESS) return false;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != STATUS_SUCCESS) goto done;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    for (;;) {
        unsigned char buf[32768];
        DWORD got = 0;
        if (!ReadFile(hFile, buf, sizeof(buf), &got, NULL)) goto done;
        if (got == 0) break;
        if (BCryptHashData(hHash, buf, got, 0) != STATUS_SUCCESS) goto done;
    }
    ok = (BCryptFinishHash(hHash, out, 32, 0) == STATUS_SUCCESS);

done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* VerifyReleaseSignature checks a detached signature against the pinned release
 * key. This is the control that makes the whole update path safe: the key is
 * compiled in, so trust never routes through the hub. */
static bool VerifyReleaseSignature(const unsigned char hash[32], const unsigned char* sig, size_t sigLen) {
    unsigned char raw[64];
    if (!DerToRawSignature(sig, sigLen, raw)) {
        printf("[!] Release signature is not a well-formed ECDSA DER structure.\n");
        return false;
    }

    unsigned char blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)blob;
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), OMINULL_RELEASE_PUBKEY_XY, OMINULL_RELEASE_PUBKEY_XY_LEN);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != STATUS_SUCCESS) return false;
    if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob, sizeof(blob), 0) != STATUS_SUCCESS) goto done;
    ok = (BCryptVerifySignature(hKey, NULL, (PUCHAR)hash, 32, raw, 64, 0) == STATUS_SUCCESS);

done:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool ReadWholeFile(const char* path, unsigned char** out, size_t* outLen) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > (1u << 20)) { CloseHandle(h); return false; }
    unsigned char* buf = (unsigned char*)malloc(size ? size : 1);
    if (!buf) { CloseHandle(h); return false; }
    DWORD got = 0;
    BOOL read = ReadFile(h, buf, size, &got, NULL);
    CloseHandle(h);
    if (!read || got != size) { free(buf); return false; }
    *out = buf;
    *outLen = size;
    return true;
}

/* ------------------------------------------------------------- rollback */

/* An update that does not come back is a failed update. Before swapping the
 * binary the agent records the attempt; the new build clears the record once it
 * is running. If it starts but keeps failing, the count climbs and the previous
 * binary is put back. This covers a build that runs badly. A build so broken
 * the SCM cannot launch it at all is caught by the recovery action registered
 * in Service_Install, which restores the same file from outside the process. */
static void UpdateMarkerPath(char* out, size_t cap) {
    char dir[MAX_PATH];
    if (!InstallDir(dir, sizeof(dir))) { out[0] = '\0'; return; }
    PathIn(dir, "update.pending", out, cap);
}

static void ClearUpdateMarker(void) {
    char dir[MAX_PATH], marker[MAX_PATH], old[MAX_PATH];
    if (!InstallDir(dir, sizeof(dir))) return;
    UpdateMarkerPath(marker, sizeof(marker));
    PathIn(dir, "ominulld.old", old, sizeof(old));
    if (marker[0]) DeleteFileA(marker);
    /* The previous binary is unlocked once its process has exited. If it is
     * somehow still held, queue the delete for the next boot rather than
     * leaving it to accumulate. */
    if (GetFileAttributesA(old) != INVALID_FILE_ATTRIBUTES && !DeleteFileA(old)) {
        MoveFileExA(old, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

void Update_CheckStartup(const AGENT_CONFIG* config) {
    char dir[MAX_PATH], marker[MAX_PATH], cur[MAX_PATH], old[MAX_PATH];
    if (!InstallDir(dir, sizeof(dir))) return;
    UpdateMarkerPath(marker, sizeof(marker));
    if (!marker[0]) return;

    FILE* f = fopen(marker, "r");
    if (!f) return;
    char version[64] = {0};
    int attempts = 0;
    if (fscanf(f, "%63s %d", version, &attempts) != 2) attempts = UPDATE_MAX_ATTEMPTS;
    fclose(f);

    if (strcmp(version, OMINULL_AGENT_VERSION) == 0) {
        printf("[+] Agent v%s started after update; retiring the previous build.\n", OMINULL_AGENT_VERSION);
        ClearUpdateMarker();
        return;
    }

    PathIn(dir, "ominulld.exe", cur, sizeof(cur));
    PathIn(dir, "ominulld.old", old, sizeof(old));
    attempts++;
    if (attempts >= UPDATE_MAX_ATTEMPTS) {
        if (GetFileAttributesA(old) != INVALID_FILE_ATTRIBUTES &&
            MoveFileExA(old, cur, MOVEFILE_REPLACE_EXISTING)) {
            printf("[!] Update to v%s failed %d times; restored the previous agent binary.\n", version, attempts);
        }
        DeleteFileA(marker);
        ExitProcess(1);   /* let the SCM restart into the binary just restored */
    }

    f = fopen(marker, "w");
    if (f) {
        fprintf(f, "%s %d\n", version, attempts);
        fclose(f);
    }
    (void)config;
}

/* --------------------------------------------------------------- install */

/* ExtractPackage unpacks the verified tarball with the bsdtar that ships in
 * Windows System32. It only ever runs against bytes whose signature has already
 * been checked. */
static bool ExtractPackage(const char* archive, const char* destDir) {
    char sys[MAX_PATH], tarExe[MAX_PATH];
    if (!GetSystemDirectoryA(sys, MAX_PATH)) return false;
    snprintf(tarExe, sizeof(tarExe), "%s\\tar.exe", sys);
    if (GetFileAttributesA(tarExe) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] %s is missing; cannot unpack the agent package.\n", tarExe);
        return false;
    }

    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd), "\"%s\" -xzf \"%s\" -C \"%s\"", tarExe, archive, destDir);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, destDir, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static void RemoveDirTree(const char* dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char child[MAX_PATH];
            PathIn(dir, fd.cFileName, child, sizeof(child));
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                RemoveDirTree(child);
            } else {
                DeleteFileA(child);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
}

/* Update_Apply installs a newer agent when the hub offers one on a telemetry
 * heartbeat, and only once the package has been proved genuine.
 *
 * The running image cannot be overwritten - Windows locks it against write and
 * delete - but it can be renamed, so the swap is: move the running binary aside,
 * move the new one into its place, and exit non-zero. The SCM's recovery action
 * restarts the service from the registered binPath, which now points at the new
 * build. Nothing else registers or reconfigures the service, because the binPath
 * carries this endpoint's key and identity. */
void Update_Apply(const AGENT_CONFIG* config, const char* respJson) {
    // Bounded retry, not a single shot: a dropped download would otherwise wedge
    // this endpoint on the offered version until the service restarted, while
    // retrying forever would refetch an unverifiable package every heartbeat.
    static char attemptedVersion[64] = {0};
    static int attempts = 0;
    if (!config || !respJson) return;

    const char* block = strstr(respJson, "\"agent_update\"");
    if (!block) return;

    char version[64] = {0}, pkg[32] = {0}, url[512] = {0}, sigUrl[512] = {0}, sha[80] = {0};
    if (!ExtractJsonString(block, "version", version, sizeof(version))) return;
    if (!ExtractJsonString(block, "url", url, sizeof(url))) return;
    ExtractJsonString(block, "package", pkg, sizeof(pkg));

    if (strcmp(attemptedVersion, version) != 0) {
        snprintf(attemptedVersion, sizeof(attemptedVersion), "%s", version);
        attempts = 0;
    }
    if (attempts >= 3) return;
    attempts++;

    if (pkg[0] && strcmp(pkg, "windows") != 0) {
        printf("[!] Hub offers agent v%s as a '%s' package; this agent only self-installs the Windows bundle.\n", version, pkg);
        return;
    }
    /* No signature, no install. There is no degraded mode worth having here:
     * an unverified install running as LocalSystem is the thing being
     * prevented, not an inconvenience to route around. */
    if (!ExtractJsonString(block, "signature", sigUrl, sizeof(sigUrl)) ||
        !ExtractJsonString(block, "sha256", sha, sizeof(sha))) {
        printf("[!] Rejected agent update v%s: the hub offered it without a signature and digest.\n", version);
        return;
    }
    if (!IsHexDigest(sha)) {
        printf("[!] Rejected agent update v%s: advertised digest is not a SHA-256 hex string.\n", version);
        return;
    }

    const char* pkgPath = HubPathOf(url);
    const char* sigPath = HubPathOf(sigUrl);
    if (!pkgPath || !sigPath) {
        printf("[!] Rejected agent update v%s: package or signature is not on a hub download path.\n", version);
        return;
    }

    char dir[MAX_PATH];
    if (!InstallDir(dir, sizeof(dir))) return;

    char stage[MAX_PATH], archive[MAX_PATH], sigFile[MAX_PATH], newExe[MAX_PATH];
    char curExe[MAX_PATH], oldExe[MAX_PATH], marker[MAX_PATH];
    PathIn(dir, "update-stage", stage, sizeof(stage));
    PathIn(dir, "ominulld.exe", curExe, sizeof(curExe));
    PathIn(dir, "ominulld.old", oldExe, sizeof(oldExe));
    UpdateMarkerPath(marker, sizeof(marker));

    RemoveDirTree(stage);
    if (!CreateDirectoryA(stage, NULL)) {
        printf("[!] Cannot create the update staging directory %s\n", stage);
        return;
    }
    PathIn(stage, "agent.tar.gz", archive, sizeof(archive));
    PathIn(stage, "agent.tar.gz.sig", sigFile, sizeof(sigFile));
    PathIn(stage, "ominulld.exe", newExe, sizeof(newExe));

    printf("[*] Hub published agent v%s (running v%s); fetching and verifying before install.\n",
           version, OMINULL_AGENT_VERSION);

    if (!DownloadToFile(config, pkgPath, archive) || !DownloadToFile(config, sigPath, sigFile)) {
        printf("[!] Agent update v%s: download failed; staying on the running version.\n", version);
        RemoveDirTree(stage);
        return;
    }

    unsigned char hash[32];
    if (!Sha256File(archive, hash)) {
        RemoveDirTree(stage);
        return;
    }

    char hexHash[65];
    for (int i = 0; i < 32; i++) snprintf(hexHash + (i * 2), 3, "%02x", hash[i]);
    if (_stricmp(hexHash, sha) != 0) {
        printf("[!] Rejected agent update v%s: package digest does not match the one advertised.\n", version);
        RemoveDirTree(stage);
        return;
    }

    unsigned char* sigBytes = NULL;
    size_t sigLen = 0;
    if (!ReadWholeFile(sigFile, &sigBytes, &sigLen) || !VerifyReleaseSignature(hash, sigBytes, sigLen)) {
        free(sigBytes);
        printf("[!] Rejected agent update v%s: signature does not verify against the pinned release key.\n", version);
        RemoveDirTree(stage);
        return;
    }
    free(sigBytes);
    printf("[+] v%s verified against the pinned release key; installing.\n", version);

    if (!ExtractPackage(archive, stage) || GetFileAttributesA(newExe) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] Agent update v%s: package did not contain ominulld.exe.\n", version);
        RemoveDirTree(stage);
        return;
    }

    FILE* f = fopen(marker, "w");
    if (f) {
        fprintf(f, "%s 0\n", version);
        fclose(f);
    }

    DeleteFileA(oldExe);
    if (!MoveFileExA(curExe, oldExe, MOVEFILE_REPLACE_EXISTING)) {
        printf("[!] Agent update v%s: could not move the running binary aside (Error %lu).\n", version, GetLastError());
        DeleteFileA(marker);
        RemoveDirTree(stage);
        return;
    }
    if (!MoveFileExA(newExe, curExe, MOVEFILE_REPLACE_EXISTING)) {
        printf("[!] Agent update v%s: could not install the new binary (Error %lu); restoring the previous one.\n",
               version, GetLastError());
        MoveFileExA(oldExe, curExe, MOVEFILE_REPLACE_EXISTING);
        DeleteFileA(marker);
        RemoveDirTree(stage);
        return;
    }

    RemoveDirTree(stage);
    printf("[+] Agent v%s installed; exiting so the service restarts from the new binary.\n", version);
    fflush(stdout);
    ExitProcess(1);   /* a non-zero exit is what triggers the SCM recovery restart */
}
