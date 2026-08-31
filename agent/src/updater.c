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
        /* %ls for the same reason as hub_client.c: %s in a wide format is
         * a narrow string to mingw, and this header carried one character. */
        swprintf(wHeaders, 512, L"X-API-Key: %ls\r\n", wKey);
        WinHttpAddRequestHeaders(hRequest, wHeaders, (DWORD)-1L,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    /* The same CertificateRequest that the heartbeat has to answer applies here.
     * A download that stays silent about its certificate - even to say it has
     * none - loses the handshake with 12044, and the endpoint sits on the
     * release it already has while every heartbeat keeps succeeding. That is
     * exactly how a fleet stops taking updates without ever looking offline. */
    Hub_AttachClientCert(hRequest, config);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        DWORD sendErr = GetLastError();
        if (!Hub_RetryWithoutClientCert(hRequest, sendErr) ||
            !WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
            printf("[!] Update download of %s could not be sent (WinHTTP error %lu)\n", path, sendErr);
            goto done;
        }
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("[!] Update download of %s got no response (WinHTTP error %lu)\n", path, GetLastError());
        goto done;
    }
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

/* --------------------------------------------------------------- install */

static bool WaitForInstalledServiceStopped(void) {
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service = OpenServiceA(manager, SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) {
        CloseServiceHandle(manager);
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
    }
    SERVICE_STATUS status;
    bool stopped = false;
    for (DWORD waited = 0; waited <= 300000; waited += 250) {
        if (!QueryServiceStatus(service, &status)) break;
        if (status.dwCurrentState == SERVICE_STOPPED) {
            stopped = true;
            break;
        }
        Sleep(250);
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return stopped;
}

static bool StartInstalledService(void) {
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service = OpenServiceA(manager, SERVICE_NAME, SERVICE_START);
    if (!service) {
        CloseServiceHandle(manager);
        return false;
    }
    bool started = StartServiceA(service, 0, NULL) != FALSE;
    if (!started && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) started = true;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return started;
}

static void ScheduleUpdateCleanup(const char* packagePath);

/* The helper is a copy of the installed executable, so it can wait for SCM to
 * stop the service while MSI replaces the installed image. MSI owns the
 * transaction and its rollback; this process only keeps the old service from
 * racing the package install. */
int Update_RunNativeInstaller(const char* packagePath) {
    if (!packagePath || !packagePath[0]) return 1;
    if (!WaitForInstalledServiceStopped()) {
        fprintf(stderr, "[-] Native package helper timed out waiting for %s to stop.\n", SERVICE_NAME);
        return 1;
    }

    char systemDir[MAX_PATH] = {0};
    if (!GetSystemDirectoryA(systemDir, sizeof(systemDir))) return 1;
    char command[MAX_PATH * 3];
    int n = snprintf(command, sizeof(command),
                     "\"%s\\msiexec.exe\" /i \"%s\" /qn /norestart REBOOT=ReallySuppress",
                     systemDir, packagePath);
    if (n < 0 || (size_t)n >= sizeof(command)) return 1;

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                        &startup, &process)) {
        fprintf(stderr, "[-] Could not launch MSI installer (Error: %lu).\n", GetLastError());
        return 1;
    }
    DWORD waitResult = WaitForSingleObject(process.hProcess, 300000);
    if (waitResult != WAIT_OBJECT_0) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        fprintf(stderr, "[-] Native MSI helper timed out waiting for Windows Installer.\n");
        return 1;
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
	if (exitCode == ERROR_SUCCESS || exitCode == ERROR_SUCCESS_REBOOT_REQUIRED) {
		if (!StartInstalledService()) {
			ScheduleUpdateCleanup(packagePath);
			fprintf(stderr, "[-] Native MSI installed, but %s could not be started.\n", SERVICE_NAME);
			return 1;
		}
		ScheduleUpdateCleanup(packagePath);
		printf("[+] Native MSI installation completed.\n");
		return 0;
	}
	(void)StartInstalledService();
	ScheduleUpdateCleanup(packagePath);
    fprintf(stderr, "[-] Native MSI installation failed with code %lu; MSI rollback retained the prior release.\n", exitCode);
    return (int)exitCode;
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

/* ScheduleUpdateCleanup removes the package staged for the MSI helper after
 * this process exits. It accepts only the exact update-stage directory created
 * by Update_Apply; a manually supplied MSI elsewhere is never treated as a
 * cleanup target. */
static void ScheduleUpdateCleanup(const char* packagePath) {
    if (!packagePath || !packagePath[0]) return;

    char stage[MAX_PATH];
    snprintf(stage, sizeof(stage), "%s", packagePath);
    char* slash = strrchr(stage, '\\');
    if (!slash) return;
    *slash = '\0';
    char* parent = strrchr(stage, '\\');
    if (!parent || _stricmp(parent + 1, "update-stage") != 0) return;

    char systemDir[MAX_PATH] = {0};
    if (!GetSystemDirectoryA(systemDir, sizeof(systemDir))) return;
    char command[MAX_PATH * 5];
    int n = snprintf(command, sizeof(command),
                     "\"%s\\cmd.exe\" /d /c \"ping -n 3 127.0.0.1 >nul & del /f /q \"\"%s\\*\"\" >nul 2>&1 & rmdir \"\"%s\"\" >nul 2>&1\"",
                     systemDir, stage, stage);
    if (n < 0 || (size_t)n >= sizeof(command)) return;

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    if (CreateProcessA(NULL, command, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL,
                       &startup, &process)) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
}

/* Update_Apply installs a newer agent when the hub offers one on a telemetry
 * heartbeat, and only once the package has been proved genuine. The running
 * service exits after launching a detached helper; Windows Installer owns file
 * replacement, service registration, rollback, and the subsequent restart. */
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

	if (strcmp(pkg, "windows-native") != 0) {
		printf("[!] Hub offers agent v%s as a '%s' package; this agent only self-installs Windows Installer packages.\n", version, pkg);
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

	char stage[MAX_PATH], archive[MAX_PATH], sigFile[MAX_PATH];
	PathIn(dir, "update-stage", stage, sizeof(stage));

    RemoveDirTree(stage);
    if (!CreateDirectoryA(stage, NULL)) {
        printf("[!] Cannot create the update staging directory %s\n", stage);
        return;
    }
	PathIn(stage, "agent.msi", archive, sizeof(archive));
	PathIn(stage, "agent.msi.sig", sigFile, sizeof(sigFile));

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

	char helper[MAX_PATH];
	PathIn(stage, "ominull-msi-helper.exe", helper, sizeof(helper));
	char current[MAX_PATH];
	PathIn(dir, "ominulld.exe", current, sizeof(current));
	if (!CopyFileA(current, helper, FALSE)) {
		printf("[!] Agent update v%s: could not stage the MSI helper (Error %lu).\n", version, GetLastError());
		RemoveDirTree(stage);
		return;
	}
	char command[MAX_PATH * 3];
	int commandLen = snprintf(command, sizeof(command), "\"%s\" --apply-msi \"%s\"", helper, archive);
	if (commandLen < 0 || (size_t)commandLen >= sizeof(command)) {
		RemoveDirTree(stage);
		return;
	}
	STARTUPINFOA startup;
	PROCESS_INFORMATION process;
	ZeroMemory(&startup, sizeof(startup));
	ZeroMemory(&process, sizeof(process));
	startup.cb = sizeof(startup);
	if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS,
	                    NULL, NULL, &startup, &process)) {
		printf("[!] Agent update v%s: could not launch the MSI helper (Error %lu).\n", version, GetLastError());
		RemoveDirTree(stage);
		return;
	}
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	printf("[+] Agent v%s verified; MSI helper will install it after this service exits.\n", version);
	fflush(stdout);
	ExitProcess(0);
}
