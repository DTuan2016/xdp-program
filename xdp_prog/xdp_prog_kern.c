// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC 1000000000ULL

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, accounting);
    __uint(max_entries, 1);
} accounting_map SEC(".maps");


/* ================= PACKET PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc))
        return -2; // drop LLDP

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(icmp + 1) > data_end)
            return -1;

        __u32 src = bpf_ntohl(iph->saddr);
        __u32 dst = bpf_ntohl(iph->daddr);

        // 192.168.50.3 -> 192.168.50.4 (type 8 = Echo Request)
        // 192.168.50.4 -> 192.168.50.3 (type 0 = Echo Reply)
        if ((src == 0xC0A83203 && dst == 0xC0A83204 && icmp->type == 8) ||
            (src == 0xC0A83204 && dst == 0xC0A83203 && icmp->type == 0)) {
            return 1;
        }
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end) return -1;
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end) return -1;
        key->src_port = udph->source;
        key->dst_port = udph->dest;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    key->src_port = bpf_ntohs(key->src_port);
    key->dst_port = bpf_ntohs(key->dst_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;
    __u32 key_ac;
    
    accounting *ac;

    ac = bpf_map_lookup_elem(&accounting_map, &key_ac);
    if (!ac)
        return XDP_PASS; 

    ac->time_in = bpf_ktime_get_ns();
    parse_packet_get_data(ctx, &key, &pkt_len);
    __u64 time_out = bpf_ktime_get_ns();
    // ac->proc_time += time_out - ac->time_in;
    // ac->total_bytes += pkt_len;
    // ac->total_pkts += 1;
    __sync_fetch_and_add(&ac->proc_time, time_out - ac->time_in);
    __sync_fetch_and_add(&ac->total_pkts, 1);
    __sync_fetch_and_add(&ac->total_bytes, pkt_len);
    bpf_map_update_elem(&accounting_map, &key_ac, ac, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
