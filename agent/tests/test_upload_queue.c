/* Kept telemetry batches: bounded by count and bytes, oldest given up first,
 * and every observation either delivered or counted lost exactly once. */
#include <assert.h>
#include <stdio.h>
#include "upload_queue.h"

static uint8_t *body(size_t n) {
    uint8_t *b = malloc(n);
    assert(b);
    memset(b, 'x', n);
    return b;
}

int main(void) {
    static UPLOAD_QUEUE q;
    UPLOAD_LOSS loss = {0};

    /* Byte budget: a fifth body of a quarter budget evicts the oldest. */
    size_t quarter = UPLOAD_QUEUE_MAX_BYTES / 4;
    for (int i = 0; i < 4; i++)
        UploadQueue_Push(&q, body(quarter), quarter, true, 10, 1, &loss);
    assert(q.count == 4 && loss.tcp_observations == 0);
    UploadQueue_Push(&q, body(quarter), quarter, false, 20, 2, &loss);
    assert(q.count == 4 && q.bytes <= UPLOAD_QUEUE_MAX_BYTES);
    assert(loss.tcp_observations == 10 && loss.udp_observations == 1 && q.evicted_batches == 1);

    /* Delivered batches are not losses; a refused one is. */
    UploadQueue_Pop(&q, NULL);
    assert(q.replayed_batches == 1 && loss.tcp_observations == 10);
    UploadQueue_Pop(&q, &loss);
    assert(loss.tcp_observations == 20);
    while (UploadQueue_Peek(&q))
        UploadQueue_Pop(&q, NULL);
    assert(q.count == 0 && q.bytes == 0);

    /* A body larger than the whole budget is refused, not allowed to empty
     * the queue. */
    UploadQueue_Push(&q, body(16), 16, true, 1, 0, &loss);
    UPLOAD_LOSS big = {0};
    UploadQueue_Push(&q, body(UPLOAD_QUEUE_MAX_BYTES + 1), UPLOAD_QUEUE_MAX_BYTES + 1, false, 5, 5, &big);
    assert(q.count == 1 && big.tcp_observations == 5 && big.udp_observations == 5);

    /* Count budget, with the ring wrapping. */
    UPLOAD_LOSS many = {0};
    for (int i = 0; i < UPLOAD_QUEUE_MAX_ITEMS + 10; i++)
        UploadQueue_Push(&q, body(8), 8, true, 1, 0, &many);
    assert(q.count == UPLOAD_QUEUE_MAX_ITEMS && many.tcp_observations == 11);
    while (UploadQueue_Peek(&q))
        UploadQueue_Pop(&q, NULL);

    assert(Upload_Retryable(0) && Upload_Retryable(503) && Upload_Retryable(429) && Upload_Retryable(408));
    assert(!Upload_Retryable(400) && !Upload_Retryable(401) && !Upload_Retryable(410) && !Upload_Retryable(200));
    assert(Upload_HubAcceptsGzip("{\"status\":\"ok\",\"accept_encoding\":\"gzip\"}"));
    assert(!Upload_HubAcceptsGzip("{\"status\":\"ok\"}") && !Upload_HubAcceptsGzip(NULL));
    printf("[+] upload queue bounds and loss accounting hold.\n");
    return 0;
}
