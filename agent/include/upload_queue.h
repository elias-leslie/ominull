#ifndef OMINULL_UPLOAD_QUEUE_H
#define OMINULL_UPLOAD_QUEUE_H

/* Telemetry batches the hub could not take, kept for a later send.
 *
 * A batch used to be sent once: a hub restart, a schema migration holding the
 * write lock or a short network outage meant the observations in it were gone
 * and counted as dropped. Now a batch that failed for a reason that can pass
 * (no connection, a timeout, HTTP 408, 429 or 5xx) is kept here as the exact
 * body that was built, already compressed, and is sent again after the next
 * accepted heartbeat, marked as a replay so the hub takes only its events.
 *
 * Bounded twice, by bytes and by count. When full, the oldest batch goes and
 * its observations are counted as dropped then, which is when they are
 * actually lost. Shared by the Linux and Windows agents; not thread-safe, the
 * telemetry loop is the only user. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UPLOAD_QUEUE_MAX_ITEMS 1024
#define UPLOAD_QUEUE_MAX_BYTES (4u << 20)
/* Replays per accepted heartbeat: drains a long outage in minutes without
 * turning one beat into a burst the hub has to absorb at once. */
#define UPLOAD_QUEUE_REPLAY_PER_BEAT 16

typedef struct {
    uint8_t *data;
    size_t length;
    bool gzip;
    /* Observations inside, by collector, for loss accounting on eviction. */
    uint64_t tcp_observations, udp_observations;
} UPLOAD_ITEM;

typedef struct {
    UPLOAD_ITEM items[UPLOAD_QUEUE_MAX_ITEMS];
    size_t head, count, bytes;
    uint64_t evicted_batches, replayed_batches;
} UPLOAD_QUEUE;

/* What was given up to make room; the caller adds it to its drop counters. */
typedef struct {
    uint64_t tcp_observations, udp_observations;
} UPLOAD_LOSS;

static void UploadQueue_DropOldest(UPLOAD_QUEUE *q, UPLOAD_LOSS *loss) {
    UPLOAD_ITEM *it = &q->items[q->head];
    if (loss) {
        loss->tcp_observations += it->tcp_observations;
        loss->udp_observations += it->udp_observations;
    }
    q->bytes -= it->length;
    free(it->data);
    it->data = NULL;
    q->head = (q->head + 1) % UPLOAD_QUEUE_MAX_ITEMS;
    q->count--;
    q->evicted_batches++;
}

/* UploadQueue_Push takes ownership of data. A body larger than the whole byte
 * budget is refused (freed and counted as lost) rather than emptying the
 * queue for it. */
static void UploadQueue_Push(UPLOAD_QUEUE *q, uint8_t *data, size_t length, bool gzip, uint64_t tcpObs,
                             uint64_t udpObs, UPLOAD_LOSS *loss) {
    if (!data || length > UPLOAD_QUEUE_MAX_BYTES) {
        free(data);
        if (loss) {
            loss->tcp_observations += tcpObs;
            loss->udp_observations += udpObs;
        }
        return;
    }
    while (q->count && (q->count >= UPLOAD_QUEUE_MAX_ITEMS || q->bytes + length > UPLOAD_QUEUE_MAX_BYTES))
        UploadQueue_DropOldest(q, loss);
    UPLOAD_ITEM *it = &q->items[(q->head + q->count) % UPLOAD_QUEUE_MAX_ITEMS];
    it->data = data;
    it->length = length;
    it->gzip = gzip;
    it->tcp_observations = tcpObs;
    it->udp_observations = udpObs;
    q->count++;
    q->bytes += length;
}

static UPLOAD_ITEM *UploadQueue_Peek(UPLOAD_QUEUE *q) { return q->count ? &q->items[q->head] : NULL; }

/* Removes the oldest batch after it was delivered (or refused for good, in
 * which case the caller passes loss to count it). */
static void UploadQueue_Pop(UPLOAD_QUEUE *q, UPLOAD_LOSS *loss) {
    if (!q->count)
        return;
    UPLOAD_ITEM *it = &q->items[q->head];
    if (loss) {
        loss->tcp_observations += it->tcp_observations;
        loss->udp_observations += it->udp_observations;
    } else {
        q->replayed_batches++;
    }
    q->bytes -= it->length;
    free(it->data);
    it->data = NULL;
    q->head = (q->head + 1) % UPLOAD_QUEUE_MAX_ITEMS;
    q->count--;
}

/* Names one batch as built: random per process, then a counter. A replay
 * carries the same id, so a hub that stored the first send (and lost only its
 * reply) answers "duplicate" instead of storing it twice. */
static void Upload_BatchID(uint64_t processNonce, char *out, size_t cap) {
    static uint64_t counter;
    snprintf(out, cap, "%016llx-%llx", (unsigned long long)processNonce, (unsigned long long)++counter);
}

/* A send that can succeed if repeated later. 0 is "no HTTP answer at all". */
static bool Upload_Retryable(long status) {
    return status == 0 || status == 408 || status == 429 || status >= 500;
}

/* The hub's heartbeat reply names the encodings it decodes. The same hub
 * generation also takes replayed batches, so one flag gates both. */
static bool Upload_HubAcceptsGzip(const char *reply) {
    return reply && strstr(reply, "\"accept_encoding\":\"gzip\"") != NULL;
}

#endif
