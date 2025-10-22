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

#define NANOSEC_PER_SEC 1000000000ULL
#define MAX_FEATURES 5

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= MAPS ================= */

// SVM weights + bias: 5 features + 1 bias
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, svm_weight);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} svm_map SEC(".maps");

// Flow tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

/* ================= PACKET PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u16 eth_proto = 0;
    __u32 ip_header_len;
    __u8 *transport_data;
    const int eth_header_len = sizeof(struct ethhdr);

    // 1. Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    eth_proto = eth->h_proto;

    if (eth_proto == bpf_htons(0x88cc))
        return -2; // drop LLDP

    if (eth_proto != bpf_htons(ETH_P_IP))
        return -1;

    // 2. IP Header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    // Kích thước tối thiểu của header IP
    if ((void *)(iph + 1) > data_end)
        return -1;

    ip_header_len = iph->ihl * 4;
    
    // KIỂM TRA GIỚI HẠN CHO IP HEADER: Đảm bảo IP header không bị cắt
    if (data + eth_header_len + ip_header_len > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;
    
    transport_data = (__u8 *)iph + ip_header_len;

    // 3. Transport Header (TCP/UDP)
    if (iph->protocol == IPPROTO_TCP) {
        // KIỂM TRA GIỚI HẠN VÀ TRUY CẬP AN TOÀN
        struct tcphdr *tcph = (struct tcphdr *)transport_data;
        if ((void *)(tcph + 1) > data_end) 
            return -1;
            
        key->src_port = bpf_ntohs(tcph->source);
        key->dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        // KIỂM TRA GIỚI HẠN VÀ TRUY CẬP AN TOÀN
        struct udphdr *udph = (struct udphdr *)transport_data;
        if ((void *)(udph + 1) > data_end)
            return -1;
            
        key->src_port = bpf_ntohs(udph->source);
        key->dst_port = bpf_ntohs(udph->dest);
    } else {
        key->src_port = bpf_ntohs(0);
        key->dst_port = bpf_ntohs(0);
    }

    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

static __always_inline void apply_min_max_scale(data_point *dp, const svm_weight *params)
{
    if (!params)
        return;

// #pragma unroll
    for (int i = 0; i < MAX_FEATURES; i++) {
        fixed x = dp->features[i];
        fixed minv = params->min_vals[i];
        fixed maxv = params->max_vals[i];
        // if (x < minv) x = minv;
        // if (x > maxv) x = maxv;
        fixed range = maxv - minv;

        if (range <= 0)
        {
            bpf_printk("Range of feature[%d] < 0", i);
            dp->features[i] = 0;
        
        }else{
            dp->features[i] = fixed_div((x - minv), range);
        }   
    }
}

/* ================= FEATURE UPDATE ================= */
static __always_inline void update_feature(data_point *dp, const svm_weight *params)
{
    if(dp->total_pkts <= 1){
        return;
    }

    dp->features[0] = fixed_log2(dp->flow_duration + 1);
    dp->features[1] = fixed_log2(dp->total_pkts) + fixed_log2(1000000) - dp->features[0];
    dp->features[2] = fixed_log2(dp->total_bytes) + fixed_log2(1000000) - dp->features[0];
    dp->features[3] = fixed_log2(dp->sum_IAT + 1) - fixed_log2(dp->total_pkts - 1);
    dp->features[4] = fixed_log2(dp->total_bytes) - fixed_log2(dp->total_pkts);
    bpf_printk("After log scale: 1. %d, 2. %d, 3. %d, 4. %d, 5. %d\n", dp->features[0], dp->features[1], dp->features[2], 
                            dp->features[3], dp->features[4]);

    apply_min_max_scale(dp, params);
    bpf_printk("After min max scale: 1. %d, 2. %d, 3. %d, 4. %d, 5. %d\n", dp->features[0], dp->features[1], dp->features[2], 
                        dp->features[3], dp->features[4]);
    
}

/* ================= FLOW STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                               struct xdp_md *ctx)
{
    __u64 ts_us = bpf_ktime_get_ns() / 1000;
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - 
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts_us;
        zero.last_seen = ts_us;
        zero.total_pkts = 1;
        zero.total_bytes = pkt_len;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        return bpf_map_lookup_elem(&xdp_flow_tracking, key); 
    }

    __u64 iat_us = (dp->last_seen > 0 && ts_us >= dp->last_seen) ? ts_us - dp->last_seen : 0;

    lock_xadd(&dp->total_pkts, 1);
    lock_xadd(&dp->total_bytes, pkt_len);

    if (iat_us > 0)
        lock_xadd(&dp->sum_IAT, iat_us);

    dp->last_seen = ts_us;
    dp->flow_duration = dp->last_seen - dp->start_ts;
    __u32 pkey = 0;
    svm_weight *params = bpf_map_lookup_elem(&svm_map, &pkey);
    bpf_printk("flow_duration=%llu start=%llu last=%llu pkts=%u bytes=%u\n",
           dp->flow_duration, dp->start_ts, dp->last_seen,
           dp->total_pkts, dp->total_bytes);
    if (params) {
        update_feature(dp, params);
        bpf_printk("MIN VALS: 1. %d, 2. %d, 3. %d, 4. %d, 5. %d\n", params->min_vals[0], params->min_vals[1], params->min_vals[2], 
                        params->min_vals[3], params->min_vals[4]);
    
        bpf_printk("MAX VALS: 1. %d, 2. %d, 3. %d, 4. %d, 5. %d\n", params->max_vals[0], params->max_vals[1], params->max_vals[2], 
                        params->max_vals[3], params->max_vals[4]);
    } else {
        update_feature(dp, NULL);
    }
    return dp;
}

static __always_inline fixed calculate_svm(data_point *dp)
{
    __u32 idx = 0;
    svm_weight *w = bpf_map_lookup_elem(&svm_map, &idx);
    if (!w) return 0;

    fixed dot = 0;
#pragma unroll
    for (int i = 0; i < MAX_FEATURES; i++) {
        fixed term = fixed_mul(w->value[i], dp->features[i]);
        dot += term;
    }

    // Bias
    dot += w->value[MAX_FEATURES];

    return dot;
}

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2)
        return XDP_DROP;  // drop LLDP
    if (ret < 0)
        return XDP_PASS;

    data_point *dp = update_stats(&key, ctx);
    if (!dp)
        return XDP_PASS;

    fixed eval = calculate_svm(dp);
    bpf_printk("Gia tri eval la: %d\n", eval);
    dp->label = (eval < 0) ? 0 : 1;
    bpf_map_update_elem(&xdp_flow_tracking, &key, dp, BPF_ANY); 
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";