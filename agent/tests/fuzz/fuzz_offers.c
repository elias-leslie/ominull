/* Heartbeat reply -> response job offers -> grant check -> worker payload
 * readers (terminal, screen, script, forensics). The grant check runs against
 * a fixed key: signatures never verify, but every digest path up to the
 * signature check is exercised, and the canonical builders must agree with
 * the worker readers on what they accept. */
#include "fuzz_common.h"
#include "../../include/response_dispatcher.h"
#include "../../include/terminal_linux.h"
#include "../../include/script_exec_linux.h"
#include "../../include/forensics_linux.h"

static const uint8_t kKey[32] = {0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
                                 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c};

static ResponseJobOffer offers[MAX_RESPONSE_OFFERS];
static ScriptExecParams script;

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc; (void)argv;
    Fuzz_QuietStdout();
    return 0;
}

static void check_payload(const char* payload) {
    char canon[TERMINAL_CANON_MAX];
    char sid[64], prog[64], tok[128];
    bool c = TerminalCanonicalFromOffer(payload, canon, sizeof(canon));
    bool w = TermPayload_Parse(payload, sid, sizeof(sid), prog, sizeof(prog), tok, sizeof(tok));
    /* The canonical form is only built from an offer the worker reader takes. */
    if (c && !w) abort();
    if (c) {
        /* ... and it names the program the worker reads. */
        char sid2[64], prog2[64], tok2[128];
        if (!TermPayload_Parse(canon, sid2, sizeof(sid2), prog2, sizeof(prog2), tok2, sizeof(tok2))) abort();
        if (strcmp(prog, prog2) != 0) abort();
    }
    char scanon[64];
    (void)ScreenCanonicalFromOffer(payload, scanon, sizeof(scanon));
    TerminalSessionParams tp;
    (void)Terminal_ParsePayload(payload, &tp);
    (void)ScriptExec_ParsePayload(payload, &script);
    ForensicCollectionParams fp;
    (void)Forensics_ParsePayload(payload, &fp);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* text = Fuzz_Text(data, size);
    int n = ParseResponseOffers(text, offers, MAX_RESPONSE_OFFERS);
    for (int i = 0; i < n; i++) {
        (void)VerifyResponseGrantKey(&offers[i].grant, offers[i].payload_json, offers[i].grant.endpoint_id, kKey);
        check_payload(offers[i].payload_json);
    }
    /* The payload readers also see raw input directly. */
    check_payload(text);
    free(text);
    return 0;
}
