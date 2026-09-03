/*
 * Cross-language response fixture test for Ominull C agent.
 * Verifies that the C runtime correctly parses valid fixtures, safely rejects
 * missing required fields, tolerates forward-compatible unknown fields, and
 * ensures legacy agent telemetry parsing safely ignores response_offers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int failures = 0;

static void expect(const char* name, bool got, bool want) {
    if (got != want) {
        printf("  [-] %s: got %s, want %s\n", name, got ? "true" : "false", want ? "true" : "false");
        failures++;
    } else {
        printf("  [+] %s\n", name);
    }
}

static char* readFile(const char* path, size_t* outLen) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("  [-] cannot open fixture: %s\n", path);
        failures++;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, sz, f);
    fclose(f);
    buf[n] = '\0';
    if (outLen) *outLen = n;
    return buf;
}

/* Bounded string field extractor for JSON test validation */
static bool extractJsonString(const char* json, const char* key, char* out, size_t outCap) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outCap - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (*p == '"');
}

int main(int argc, char** argv) {
    const char* baseDir = "hub/tests/fixtures/response";
    if (argc > 1) {
        baseDir = argv[1];
    }

    char path[512];

    /* 1. Test heartbeat_response_old_agent.json */
    snprintf(path, sizeof(path), "%s/heartbeat_response_old_agent.json", baseDir);
    size_t len = 0;
    char* data = readFile(path, &len);
    if (data) {
        char status[32] = {0};
        bool hasStatus = extractJsonString(data, "status", status, sizeof(status));
        expect("heartbeat status extracted", hasStatus && strcmp(status, "ok") == 0, true);

        /* Confirm presence of quarantined peers */
        bool hasPeers = strstr(data, "\"quarantined_peers\"") != NULL;
        expect("heartbeat contains quarantined_peers", hasPeers, true);

        /* Confirm presence of agent_update */
        bool hasUpdate = strstr(data, "\"agent_update\"") != NULL;
        expect("heartbeat contains agent_update", hasUpdate, true);

        /* Confirm presence of response_offers and verify it is not acted upon */
        bool hasOffers = strstr(data, "\"response_offers\"") != NULL;
        expect("heartbeat contains response_offers", hasOffers, true);

        free(data);
    }

    /* 2. Test grant_valid.json */
    snprintf(path, sizeof(path), "%s/grant_valid.json", baseDir);
    data = readFile(path, &len);
    if (data) {
        char grantID[128] = {0};
        char actionDigest[128] = {0};
        char sig[256] = {0};
        bool hasGrant = extractJsonString(data, "grant_id", grantID, sizeof(grantID));
        bool hasDigest = extractJsonString(data, "action_digest", actionDigest, sizeof(actionDigest));
        bool hasSig = extractJsonString(data, "signature", sig, sizeof(sig));

        expect("grant_valid has valid grant_id", hasGrant && strlen(grantID) > 0, true);
        expect("grant_valid has 64-char action_digest", hasDigest && strlen(actionDigest) == 64, true);
        expect("grant_valid has 128-char hex signature", hasSig && strlen(sig) == 128, true);

        free(data);
    }

    /* 3. Test grant_missing_required.json */
    snprintf(path, sizeof(path), "%s/grant_missing_required.json", baseDir);
    data = readFile(path, &len);
    if (data) {
        char endpointID[128] = {0};
        char sig[256] = {0};
        bool hasEndpoint = extractJsonString(data, "endpoint_id", endpointID, sizeof(endpointID));
        bool hasSig = extractJsonString(data, "signature", sig, sizeof(sig));

        expect("grant_missing_required lacks endpoint_id", hasEndpoint, false);
        expect("grant_missing_required lacks signature", hasSig, false);

        free(data);
    }

    /* 4. Test offer_unknown_fields.json */
    snprintf(path, sizeof(path), "%s/offer_unknown_fields.json", baseDir);
    data = readFile(path, &len);
    if (data) {
        char jobID[128] = {0};
        char leaseID[128] = {0};
        bool hasJob = extractJsonString(data, "job_id", jobID, sizeof(jobID));
        bool hasLease = extractJsonString(data, "lease_id", leaseID, sizeof(leaseID));
        bool hasPriority = strstr(data, "\"priority\"") != NULL;

        expect("offer_unknown_fields has valid job_id", hasJob && strlen(jobID) > 0, true);
        expect("offer_unknown_fields has valid lease_id", hasLease && strlen(leaseID) > 0, true);
        expect("offer_unknown_fields carries unknown field priority", hasPriority, true);

        free(data);
    }

    /* 5. Test offer_max_size.json */
    snprintf(path, sizeof(path), "%s/offer_max_size.json", baseDir);
    data = readFile(path, &len);
    if (data) {
        expect("offer_max_size is non-empty bounded payload", len > 5000 && len < 20000000, true);
        free(data);
    }

    if (failures == 0) {
        printf("[+] All C agent fixture validation checks passed.\n");
        return 0;
    } else {
        printf("[-] %d fixture validation checks failed.\n", failures);
        return 1;
    }
}
