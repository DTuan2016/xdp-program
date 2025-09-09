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

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TREES * MAX_NODE_PER_TREE);
    __type(key, __u32);
    __type(value, iTreeNode);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_isoforest_nodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct forest_params);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_isoforest_params SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");


/* ================= PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc)) {
        return -2;  // báo hiệu để drop
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

/* ================= UPDATE FEATURE ================= */
static __always_inline void update_feature_in_datapoint(data_point *dp)
{
    dp->features[0] = (__u32)(dp->flow_duration);
    dp->features[1] = dp->total_pkts;
    dp->features[2] = dp->total_bytes;
    dp->features[3] = dp->flow_IAT_mean;
}

/* ================= UPDATE STATS ================= */
static __always_inline data_point *update_stats(struct flow_key *key,
                                                struct xdp_md *ctx,
                                                int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts    = ts;
        zero.last_seen   = ts;
        zero.total_pkts  = 1;
        zero.total_bytes = pkt_len;

        for(int i = 0; i < MAX_FEATURES; i++){
            zero.features[i] = 0;
        }

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        /* tăng counter flow */
        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return bpf_map_lookup_elem(&xdp_flow_tracking, key);
    }

    __u64 current_ns = ts;
    __u64 iat_ns = (dp->last_seen > 0 && current_ns >= dp->last_seen) ?
                   current_ns - dp->last_seen : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);
    
    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;

    dp->last_seen = current_ns;

    if (dp->total_pkts > 1)
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);

    dp->flow_duration = dp->last_seen - dp->start_ts;
    update_feature_in_datapoint(dp);
    return dp;
}

static __always_inline int compute_path_length(data_point *dp, __u32 tree_idx, struct forest_params *params) {
    int node_idx = tree_idx * MAX_NODE_PER_TREE;
    int depth = 0;

#pragma unroll
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) {
        iTreeNode *node = bpf_map_lookup_elem(&xdp_isoforest_nodes, &node_idx);
        if (!node || node->is_leaf) break;

        __u32 f_val = 0;
        switch (node->feature) {
            case 0: f_val = dp->features[0]; break;
            case 1: f_val = dp->features[1]; break;
            case 2: f_val = dp->features[2]; break;
            case 3: f_val = dp->features[3]; break;
            default: break;
        }

        if (f_val < node->split_value) {
            if (node->left_idx == NULL_IDX) break;
            node_idx = node->left_idx;
        } else {
            if (node->right_idx == NULL_IDX) break;
            node_idx = node->right_idx;
        }
        depth++;
    }
    return depth;
}

static __always_inline int is_anomaly(data_point *dp)
{
    __u32 key_params = 0;
    struct forest_params *params = bpf_map_lookup_elem(&xdp_isoforest_params, &key_params);
    if (!params) return 0;

    int total_depth = 0;
#pragma unroll
    for (__u32 t = 0; t < MAX_TREES; t++) {
        total_depth += compute_path_length(dp, t, params);
    }

    int avg_depth = (total_depth * SCALE) / params->n_trees;
    return avg_depth < (params->threshold * SCALE);
}

/* ================= XDP MAIN ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) {
        return XDP_DROP;  // Drop LLDP
    }
    if (ret < 0)
        return XDP_PASS;

    data_point *target = update_stats(&key, ctx, 1);
    if(!target){
        return XDP_PASS;
    }

    __u32 idx = 0;
    __u32 *counter = bpf_map_lookup_elem(&flow_counter, &idx);
    int local_counter = 0;
    if (counter){
        local_counter = *counter;
    }
    if(local_counter < TRAINING_SET){
        target->label = 0;
        return XDP_PASS;
    }
    else{/* Run isolation forest inference */
        if (is_anomaly(target)) {
            /* Nếu muốn, copy sang flow_dropped map */
            target->label = 1;
            bpf_map_update_elem(&flow_dropped, &key, target, BPF_ANY);
            bpf_map_update_elem(&xdp_flow_tracking, &key, target, BPF_ANY);
            // bpf_map_delete_elem(&xdp_flow_tracking, &key);
            return XDP_PASS;
        }
        target->label = 0;
        bpf_map_update_elem(&xdp_flow_tracking, &key, target, BPF_ANY);
        return XDP_PASS;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
