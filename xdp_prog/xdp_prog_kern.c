// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC     1000000000ULL
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ==================== MAP DEFINITIONS ==================== */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

/* ==================== PARSING ==================== */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    /* Nếu là LLDP (EtherType = 0x88CC) thì drop */
    if (eth->h_proto == bpf_htons(0x88CC)) {
        return -2;  /* giá trị đặc biệt để main biết drop */
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;

    // __u16 src_port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        key->src_port = tcph->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        key->src_port = udph->source;
    } else {
        key->src_port = 0;
    }

    // key->src_port = bpf_ntohs(src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);

    return 0;
}

/* ==================== UPDATE STATS (lookup 1 lần) ==================== */
static __always_inline data_point *update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (!dp) {
        data_point zero = {};
        zero.start_ts           = ts;
        zero.last_seen          = ts;
        zero.total_pkts         = 1;
        zero.total_bytes        = pkt_len;
        zero.sum_IAT            = 0;
        zero.flow_IAT_mean      = 0;
        zero.flow_bytes_per_s   = 0;
        zero.flow_pkts_per_s    = 0;
        zero.pkts_len_mean      = 0;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        return bpf_map_lookup_elem(&xdp_flow_tracking, key);
    }

    /* FLOW ĐÃ TỒN TẠI */
    __u64 current_ns = ts;
    __u64 iat_ns = 0;
    if (dp->last_seen > 0 && current_ns >= dp->last_seen)
        iat_ns = current_ns - dp->last_seen;

    dp->total_pkts++;
    dp->total_bytes += pkt_len;
    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;
        
    dp->last_seen = current_ns;

    if (dp->total_pkts > 1)
    {
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
        dp->pkts_len_mean = dp->total_bytes / dp->total_pkts;
    }
    else
        dp->flow_IAT_mean = 0;

    dp->flow_duration = dp->last_seen - dp->start_ts;
    if(dp->flow_duration > 0){
        dp->flow_bytes_per_s = (dp->total_bytes * 1000000000) / dp->flow_duration;
        dp->flow_pkts_per_s  = (dp->total_pkts  * 1000000000) / dp->flow_duration;
    }
    return dp;
}

/* ==================== MAIN PROCESS ==================== */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) {
        return XDP_DROP;  /* drop luôn */
    }

    if (ret < 0)
        return XDP_PASS;

    data_point *dp = update_stats(&key, ctx);
    if (!dp)
        return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";