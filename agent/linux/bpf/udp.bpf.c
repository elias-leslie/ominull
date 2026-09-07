/* SPDX-License-Identifier: (GPL-2.0-only OR MIT)
 * Passive socket observations. No packet or policy modification.
 * Capture send metadata before UDP consumes the skb; publish only on success.
 * Receive observations run in the consuming process, excluding MSG_PEEK.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "udp_observation.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
const volatile __u32 target_netns;
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} observations SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ominull_udp_observation);
} sends SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, int);
} receives SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} health SEC(".maps");

static __always_inline void lost(__u32 reason) {
    __u64 *count = bpf_map_lookup_elem(&health, &reason);
    if (count)
        __sync_fetch_and_add(count, 1);
}
static __always_inline bool ours(struct sock *sk) {
    return sk && BPF_CORE_READ(sk, sk_protocol) == 17 &&
           BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) == target_netns;
}
static __always_inline void identity(struct ominull_udp_observation *event) {
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->process_start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    event->observed_ns = bpf_ktime_get_boot_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}
static __always_inline void publish(struct ominull_udp_observation *event) {
    if (bpf_ringbuf_output(&observations, event, sizeof(*event), 0))
        lost(0);
}
static __always_inline int send_start(struct sk_buff *skb, void *flow, bool v6) {
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (!ours(sk))
        return 0;
    struct ominull_udp_observation event = {};
    long offset =
        BPF_CORE_READ(skb, transport_header) - (BPF_CORE_READ(skb, data) - BPF_CORE_READ(skb, head));
    long payload = (long)BPF_CORE_READ(skb, len) - offset - 8;
    if (payload < 0 || payload > 16 * 1024 * 1024) {
        lost(2);
        return 0;
    }
    event.payload_bytes = payload;
    event.ip_version = v6 ? 6 : 4;
    event.outbound = 1;
    event.local_port = BPF_CORE_READ((struct inet_sock *)sk, inet_sport);
    if (v6) {
        struct flowi6 *f = flow;
        BPF_CORE_READ_INTO(&event.local_ip, f, saddr);
        BPF_CORE_READ_INTO(&event.remote_ip, f, daddr);
        event.remote_port = BPF_CORE_READ(f, uli.ports.dport);
        event.ifindex = BPF_CORE_READ(f, __fl_common.flowic_oif);
    } else {
        struct flowi4 *f = flow;
        BPF_CORE_READ_INTO(&event.local_ip, f, saddr);
        BPF_CORE_READ_INTO(&event.remote_ip, f, daddr);
        event.remote_port = BPF_CORE_READ(f, uli.ports.dport);
    }
    identity(&event);
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&sends, &tid, &event, BPF_ANY))
        lost(1);
    return 0;
}
static __always_inline int send_finish(int result) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ominull_udp_observation *event = bpf_map_lookup_elem(&sends, &tid);
    if (event && result == 0)
        publish(event);
    bpf_map_delete_elem(&sends, &tid);
    return 0;
}
SEC("fentry/udp_send_skb")
int BPF_PROG(send4, struct sk_buff *skb, struct flowi4 *flow, struct inet_cork *cork) {
    return send_start(skb, flow, false);
}
SEC("fentry/udp_v6_send_skb")
int BPF_PROG(send6, struct sk_buff *skb, struct flowi6 *flow, struct inet_cork *cork) {
    return send_start(skb, flow, true);
}
SEC("fexit/udp_send_skb")
int BPF_PROG(sent4, struct sk_buff *skb, struct flowi4 *flow, struct inet_cork *cork, int result) {
    return send_finish(result);
}
SEC("fexit/udp_v6_send_skb")
int BPF_PROG(sent6, struct sk_buff *skb, struct flowi6 *flow, struct inet_cork *cork, int result) {
    return send_finish(result);
}

static __always_inline int receive_start(struct sock *sk, int flags) {
    if (!ours(sk))
        return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&receives, &tid, &flags, BPF_ANY))
        lost(1);
    return 0;
}
static __always_inline int receive_finish(void) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&receives, &tid);
    return 0;
}
SEC("fentry/udp_recvmsg")
int BPF_PROG(receive4, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
    return receive_start(sk, flags);
}
SEC("fentry/udpv6_recvmsg")
int BPF_PROG(receive6, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
    return receive_start(sk, flags);
}
SEC("fexit/udp_recvmsg") int BPF_PROG(received4) {
    return receive_finish();
}
SEC("fexit/udpv6_recvmsg") int BPF_PROG(received6) {
    return receive_finish();
}
SEC("fentry/skb_consume_udp") int BPF_PROG(consume, struct sock *sk, struct sk_buff *skb, int len) {
    if (!ours(sk))
        return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    int *flags = bpf_map_lookup_elem(&receives, &tid);
    if (!flags || (*flags & 2) || len < 0)
        return 0; /* MSG_PEEK */
    struct ominull_udp_observation event = {};
    unsigned char *head = BPF_CORE_READ(skb, head);
    unsigned short network = BPF_CORE_READ(skb, network_header);
    unsigned short transport = BPF_CORE_READ(skb, transport_header);
    __u8 version = 0;
    if (bpf_probe_read_kernel(&version, 1, head + network)) {
        lost(2);
        return 0;
    }
    event.ip_version = version >> 4;
    if (event.ip_version == 4) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network)) {
            lost(2);
            return 0;
        }
        __builtin_memcpy(event.local_ip, &ip.daddr, 4);
        __builtin_memcpy(event.remote_ip, &ip.saddr, 4);
    } else if (event.ip_version == 6) {
        struct ipv6hdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network)) {
            lost(2);
            return 0;
        }
        __builtin_memcpy(event.local_ip, &ip.daddr, 16);
        __builtin_memcpy(event.remote_ip, &ip.saddr, 16);
        event.ifindex = BPF_CORE_READ(skb, skb_iif);
    } else {
        lost(2);
        return 0;
    }
    struct udphdr udp;
    if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport)) {
        lost(2);
        return 0;
    }
    event.local_port = udp.dest;
    event.remote_port = udp.source;
    event.payload_bytes = BPF_CORE_READ(skb, len);
    identity(&event);
    publish(&event);
    return 0;
}
