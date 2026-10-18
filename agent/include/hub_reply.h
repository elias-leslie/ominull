#ifndef OMINULL_HUB_REPLY_H
#define OMINULL_HUB_REPLY_H

/* The heartbeat reply carries trust keys, the manifest, enforcement state and
 * up to four job offers whose payloads include whole maintenance scripts,
 * escaped twice. 32 KiB cut a single 24 KB package off, and a reply cut short
 * silently drops every offer (and any state) past the cut, so the job was
 * offered again forever. The hub packs offers under 256 KiB of request bytes;
 * 1 MiB holds that with room for escaping and the rest of the reply. Kept on
 * the heap, allocated once. */
#define HUB_REPLY_BYTES ((size_t)1 << 20)

#endif
