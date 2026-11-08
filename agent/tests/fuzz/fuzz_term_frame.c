/* Terminal relay frames from the hub (stdin, resize, close) and their base64. */
#include "fuzz_common.h"
#include "../../include/terminal_frame.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* TermFrame_Parse is length-bounded: pass the exact bytes, no terminator. */
    char* buf = (char*)malloc(size ? size : 1);
    if (!buf) abort();
    memcpy(buf, data, size);
    TermInFrame f;
    if (TermFrame_Parse(buf, size, &f) && f.data) {
        unsigned char out[4096];
        (void)TermB64_Decode(f.data, f.data_len, out, sizeof(out));
    }
    unsigned char raw[256];
    (void)TermB64_Decode(buf, size, raw, sizeof(raw));
    free(buf);
    return 0;
}
