/* Writes starting inputs for the fuzz harnesses into DIR/<harness>/, built
 * from the signed trust fixtures and hub-shaped offers so the fuzzer starts
 * deep in each parser. Usage: gen_seeds DIR */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../trust_fixtures.h"

static const char* g_dir;

static void seed(const char* harness, const char* name, const char* text) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, harness);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/%s/seed-%s", g_dir, harness, name);
    FILE* f = fopen(path, "wb");
    if (!f) { perror(path); return; }
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

#define GRANT(kind, digest) "\"grant\":{\"version\":3,\"grant_id\":\"g1\",\"tenant_id\":\"default\",\"endpoint_id\":\"ep-1\"," \
    "\"action_kind\":\"" kind "\",\"action_digest\":\"" digest "\",\"operator_id\":\"admin\",\"response_session_id\":\"s\"," \
    "\"issued_at\":1800000000,\"expires_at\":1800000300,\"nonce\":\"n1\",\"job_id\":\"job-1\",\"signer_key_id\":\"k\"," \
    "\"signature\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"
#define D64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: gen_seeds DIR\n"); return 2; }
    g_dir = argv[1];
    mkdir(g_dir, 0700);

    seed("fuzz_offers", "terminal", "{\"response_offers\":[{\"job_id\":\"job-1\",\"lease_id\":\"l1\",\"kind\":\"terminal_session\"," GRANT("terminal_session", D64)
         ",\"payload_json\":\"{\\\"session_id\\\":\\\"s1\\\",\\\"program\\\":\\\"/bin/bash\\\",\\\"connect_token\\\":\\\"tok\\\",\\\"max_duration_seconds\\\":3600}\"}]}");
    seed("fuzz_offers", "screen", "{\"response_offers\":[{\"job_id\":\"job-1\",\"lease_id\":\"l1\",\"kind\":\"screen_session\"," GRANT("screen_session", D64)
         ",\"payload_json\":\"{\\\"session_id\\\":\\\"s1\\\",\\\"mode\\\":\\\"control\\\",\\\"connect_token\\\":\\\"t\\\",\\\"operator\\\":\\\"admin\\\",\\\"unattended\\\":true}\"}]}");
    seed("fuzz_offers", "script", "{\"response_offers\":[{\"job_id\":\"job-1\",\"lease_id\":\"l1\",\"kind\":\"script_exec\"," GRANT("script_exec", D64)
         ",\"payload_json\":\"{\\\"script_id\\\":\\\"pkg\\\",\\\"script_version\\\":2,\\\"script_digest\\\":\\\"" D64 "\\\",\\\"interpreter\\\":\\\"/bin/bash\\\","
         "\\\"source\\\":\\\"#!/bin/bash\\\\necho \\\\\\\"hi\\\\\\\"\\\\n\\\",\\\"parameters\\\":{\\\"mode\\\":\\\"audit\\\",\\\"x\\\":\\\"a\\\\\\\\b\\\"},"
         "\\\"timeout_seconds\\\":60,\\\"max_output_bytes\\\":65536}\"}]}");
    seed("fuzz_offers", "forensics", "{\"response_offers\":[{\"job_id\":\"job-1\",\"lease_id\":\"l1\",\"kind\":\"forensic_collection\"," GRANT("forensic_collection", D64)
         ",\"payload_json\":{\"bundle_id\":\"b1\",\"profile\":\"diagnostic\",\"max_bytes\":1048576,\"timeout_seconds\":60}}]}");

    seed("fuzz_term_frame", "stdin", "{\"type\":\"stdin\",\"timestamp\":\"2026-11-08T00:00:00Z\",\"data\":\"bHMgLWxhCg==\"}");
    seed("fuzz_term_frame", "resize", "{\"type\":\"resize\",\"rows\":40,\"cols\":120,\"data\":null}");
    seed("fuzz_term_frame", "close", "{\"type\":\"close\",\"extra\":{\"a\":[1,2,{\"b\":\"c\\u0041\"}]}}");

    seed("fuzz_cert_renewal", "pair", "{\"status\":\"ok\",\"client_certificate\":{\"cert_pem_b64\":"
         "\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\",\"key_pem_b64\":"
         "\"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUIKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=\"}}");

    char buf[16384];
    snprintf(buf, sizeof(buf), "{\"status\":\"ok\",\"is_isolated\":true,\"isolation_allow_ips\":[\"10.0.0.251\",\"10.0.0.0/24\"],"
             "\"quarantined_peers\":[\"10.0.0.250\"],\"isolation_baseline\":[],\"enforcement_grants\":[%s,%s,%s,%s]}",
             FX_G_ISO, FX_G_REL, FX_G_MESH_ON, FX_G_ISO_RULES);
    seed("fuzz_trust_reply", "grants", buf);
    snprintf(buf, sizeof(buf), "{\"status\":\"ok\",\"capability_manifest\":%s,\"enforcement_grants\":[%s,%s]}", FX_M_RESPOND_3, FX_G_ISO_CIDR, FX_G_AUTO);
    seed("fuzz_trust_reply", "manifest", buf);
    snprintf(buf, sizeof(buf), "{\"status\":\"ok\",\"agent_update\":{\"version\":\"9.9.9\"},\"agent_update_grant\":%s}", FX_G_UPDATE);
    seed("fuzz_trust_reply", "update", buf);
    size_t n = strlen(FX_KEYS_NEXT_JSON);
    snprintf(buf, sizeof(buf), "{\"status\":\"ok\",\"trust\":%.*s,\"bundle_sig\":\"%s\"}}", (int)(n - 1), FX_KEYS_NEXT_JSON, FX_TB_SIG_NEXT);
    seed("fuzz_trust_reply", "trust", buf);
    return 0;
}
