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
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, svm_weight);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} svm_map SEC(".maps");

// Flow tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, accounting);
    __uint(max_entries, 1);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
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

        if ((src == 0xC0A83203 && dst == 0xC0A83204 && icmp->type == 8) ||
            (src == 0xC0A83204 && dst == 0xC0A83203 && icmp->type == 0)) {
            return 1;
        }
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end){
            return -1;
        }
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end){
            return -1;
        }
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

static __always_inline __s128 calculate_svm (data_point *dp, const svm_weight *params)
{
    if (!params)
        return 0;
    __s128 dot = 0;
    for (int i = 0; i < MAX_FEATURES; i++) {
        bpf_printk("feature[%d]=%llu, min_vals[%d]=%llu, max_vals[%d]=%llu", i, dp->features[i], i, params->min_vals[i], i, params->max_vals[i]);
        fixed test = dp->features[i] - params->min_vals[i];
        fixed scale = params->max_vals[i] - params->min_vals[i];

        dp->features[i] = fixed_div(test, scale);
        bpf_printk("Feature %d co gia tri la: %llu", i, dp->features[i]);
        bpf_printk("Weight of feature %d co gia tri la: %llu", i, params->value[i]);
        __s128 term = fixed_mul(dp->features[i], params->value[i]);
        if (params->is_neg[i]== 1){
            dot -= term;
        }
        else dot += term;
        bpf_printk("Value of dot of feature %d is: %lld", i, dot);
    }

    if(params->is_neg[MAX_FEATURES] == 1){
        dot -= params->value[MAX_FEATURES];
    }
    else dot += params->value[MAX_FEATURES];

    return dot;
}

/* ================= FLOW STATS ================= */
static __always_inline int update_stats(struct flow_key *key,
                                               struct xdp_md *ctx)
{
    __u64 ts_ns = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - 
                            (__u8 *)((void *)(long)ctx->data));
    int ret = XDP_PASS;
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts_ns;
        zero.last_seen = ts_ns;
        zero.min_IAT = 0xFFFFFFFFFFFFFFFFULL;
        zero.total_pkts = 1;
        zero.max_pkt_len = pkt_len;
        zero.min_pkt_len = pkt_len;
        zero.total_bytes = pkt_len;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0){
            return ret;
        }
        return ret;
    }
    __u64 iat_ns = (dp->last_seen > 0 && ts_ns >= dp->last_seen) ? ts_ns - dp->last_seen : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0 && iat_ns < dp->min_IAT)
        dp->min_IAT = iat_ns;
    if (pkt_len > dp->max_pkt_len)
        dp->max_pkt_len = pkt_len;
    if (pkt_len < dp->min_pkt_len)
        dp->min_pkt_len = pkt_len;

    dp->last_seen = ts_ns;

    dp->features[FEATURE_FLOW_DURATION]                 = fixed_log2(dp->last_seen - dp->start_ts);
    dp->features[FEATURE_TOTAL_FWD_PACKET]              = fixed_log2(dp->total_pkts);
    dp->features[FEATURE_TOTAL_LENGTH_OF_FWD_PACKET]    = fixed_log2(dp->total_bytes);
    dp->features[FEATURE_FWD_PACKET_LENGTH_MAX]         = fixed_log2(dp->max_pkt_len);
    dp->features[FEATURE_FWD_PACKET_LENGTH_MIN]         = fixed_log2(dp->min_pkt_len);
    dp->features[FEATURE_FWD_IAT_MIN]                   = fixed_log2(dp->min_IAT);

    bpf_printk("dp->last_seen=%llu; dp->total_pkts=%u; dp->total_bytes=%llu; ", dp->last_seen, dp->total_pkts, dp->total_bytes);
    __u32 key_pr = 0;
    svm_weight *svm_pr = bpf_map_lookup_elem(&svm_map, &key_pr); 

    __s128 svm_ret = calculate_svm(dp, svm_pr);
    if(svm_ret < 0){
        dp->label = 1;
        bpf_printk("Toi drop roi khong track nua!");
        ret = XDP_PASS;
    }
    else{
        dp->label = 0;
        ret = XDP_PASS;
    }
    if(bpf_map_update_elem(&xdp_flow_tracking, key, dp, BPF_ANY) != 0){
        return ret;
    }
    return ret;
}

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    // bpf_printk("===START===");
    struct flow_key key = {};
    __u64 pkt_len = 0;
    __u32 key_ac = 0;
    
    accounting *ac;

    ac = bpf_map_lookup_elem(&accounting_map, &key_ac);
    if (!ac)
        return XDP_PASS; 

    ac->time_in = bpf_ktime_get_ns();
    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2)
        return XDP_DROP;  // drop LLDP
    if (ret == 1)
        return XDP_PASS;

    if (ret < 0)
        return XDP_PASS;

    ret = update_stats(&key, ctx);
    __u64 time_out = bpf_ktime_get_ns();
    ac->proc_time += time_out - ac->time_in;
    ac->total_bytes += pkt_len;
    ac->total_pkts += 1;
    bpf_map_update_elem(&accounting_map, &key_ac, ac, BPF_ANY);
    return ret;
}

char _license[] SEC("license") = "GPL";