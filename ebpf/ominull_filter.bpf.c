#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long long uint64_t;

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

struct bpf_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
};

// 1. Block Rules Map (IPv4)
struct bpf_map_def SEC("maps") ominull_rules_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t), // Remote IPv4
    .value_size = sizeof(uint32_t), // Action: 1 = BLOCK, 2 = ALLOW
    .max_entries = 1024,
    .map_flags = 0,
};

// 2. Isolation Config Map
struct isolation_config {
    uint32_t active;
    uint32_t hub_ip;
    uint16_t hub_port;
    uint8_t  allow_dhcp;
    uint8_t  allow_dns;
};

struct bpf_map_def SEC("maps") ominull_isolation = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct isolation_config),
    .max_entries = 1,
    .map_flags = 0,
};

// BPF Helper function definitions
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

SEC("tc_egress")
int ominull_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    uint32_t dst_ip = ip->daddr;
    uint8_t protocol = ip->protocol;
    uint16_t src_port = 0, dst_port = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = __builtin_bswap16(tcp->source);
            dst_port = __builtin_bswap16(tcp->dest);
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            src_port = __builtin_bswap16(udp->source);
            dst_port = __builtin_bswap16(udp->dest);
        }
    }

    // 1. Check Kernel Host Isolation
    uint32_t zero_key = 0;
    struct isolation_config *iso = bpf_map_lookup_elem(&ominull_isolation, &zero_key);
    if (iso && iso->active) {
        // Allow Loopback
        if ((dst_ip & 0xFF) == 127) {
            return TC_ACT_OK;
        }

        // Allow Hub Server
        if (iso->hub_ip != 0 && dst_ip == iso->hub_ip) {
            if (iso->hub_port == 0 || dst_port == iso->hub_port || src_port == iso->hub_port) {
                return TC_ACT_OK;
            }
        }

        // Allow DHCP
        if (iso->allow_dhcp && protocol == IPPROTO_UDP && (dst_port == 67 || dst_port == 68)) {
            return TC_ACT_OK;
        }

        // Allow DNS
        if (iso->allow_dns && (dst_port == 53 || src_port == 53)) {
            return TC_ACT_OK;
        }

        return TC_ACT_SHOT; // Default-Deny quarantine
    }

    // 2. Check Block Rule Hash Map
    uint32_t *action = bpf_map_lookup_elem(&ominull_rules_v4, &dst_ip);
    if (action && *action == 1) { // 1 = BLOCK
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
