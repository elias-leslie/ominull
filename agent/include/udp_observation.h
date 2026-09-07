#ifndef OMINULL_UDP_OBSERVATION_H
#define OMINULL_UDP_OBSERVATION_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
/* Network-order addresses/ports. Byte count is UDP payload, not wire bytes.
 * Sends are accepted socket submissions; receives are consumed datagrams.
 * observed_ns and process_start_ns use CLOCK_BOOTTIME. */
struct ominull_udp_observation {
    __u64 observed_ns;
    __u64 process_start_ns;
    __u32 pid;
    __u32 payload_bytes;
    __u32 ifindex;
    __u16 local_port;
    __u16 remote_port;
    __u8 local_ip[16];
    __u8 remote_ip[16];
    __u8 ip_version;
    __u8 outbound;
    char comm[16];
};
#endif
