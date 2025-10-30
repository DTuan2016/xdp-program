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
    __uint(max_entries, MAX_TREES * MAX_NODE_PER_TREE);
    __type(key, __u32);
    __type(value, Node);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_randforest_nodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");

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

/* ================= TREE INFERENCE ================= */
static __always_inline int predict_one_tree(__u32 root_idx, struct feat_vec fv)
{
    __u32 node_idx = root_idx;

    #pragma unroll MAX_DEPTH
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (node_idx >= (MAX_TREES * MAX_NODE_PER_TREE)) {
            // bpf_printk("Node OOB: node_idx=%u, root_idx=%u", node_idx, root_idx);
            return 0; // out-of-bounds
        }

        Node *node = bpf_map_lookup_elem(&xdp_randforest_nodes, &node_idx);
        if (!node){
            return 0;
        }
        if (node->is_leaf) {
            // bpf_printk("NODE LA: idx=%u, label=%d", node_idx, node->label);
            return node->label;
        }
        // bpf_printk("Tree %d, Depth %d, NodeIdx=%u, Left=%d, Right=%d, Split=%llu, Feature=%d, IsLeaf=%u, Label=%d",
        //                 node->tree_idx, depth, node_idx, node->left_idx, node->right_idx,
        //                 node->split_value, node->feature_idx, node->is_leaf, node->label);
        __u32 f_idx = node->feature_idx;
        if (f_idx >= MAX_FEATURES){
            return 0;   
        }
        fixed f_val = fv.features[f_idx];
        fixed split = node->split_value;

        __u32 next_idx;
        if (f_val <= split) {
            next_idx = node->left_idx;
        } else {
            next_idx = node->right_idx;
        }

        if (next_idx == (__u32)-1 || next_idx >= (MAX_TREES * MAX_NODE_PER_TREE)) {
            return 0;
        }

        node_idx = next_idx;
    }
    // bpf_printk("Reached MAX_DEPTH: root_idx=%u", root_idx);
    return 0;
}

/* ================= RANDOM FOREST ================= */
static __always_inline int predict_forest(struct feat_vec fv)
{
    int votes0 = 0, votes1 = 0;

    #pragma unroll MAX_TREES
    for (__u32 t = 0; t < MAX_TREES; t++) {
        __u32 root_key = t * MAX_NODE_PER_TREE;
        int pred = predict_one_tree(root_key, fv);
        if (pred == 0) votes0++;
        else votes1++;
    }
    // bpf_printk("Forest votes0=%d, votes1=%d", votes0, votes1);
    return (votes1 > votes0) ? 1 : 0;
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

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return ret;

        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

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
    struct feat_vec fv = {
        .features = {0},
    };

    fv.features[QS_FEATURE_FLOW_DURATION] = fixed_from_uint(dp->last_seen - dp->start_ts);
    fv.features[QS_FEATURE_TOTAL_FWD_PACKET] = fixed_from_uint(dp->total_pkts);
    fv.features[QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET] = fixed_from_uint(dp->total_bytes);
    fv.features[QS_FEATURE_FWD_PACKET_LENGTH_MAX] = fixed_from_uint(dp->max_pkt_len);
    fv.features[QS_FEATURE_FWD_PACKET_LENGTH_MIN] = fixed_from_uint(dp->min_pkt_len);
    fv.features[QS_FEATURE_FWD_IAT_MIN] = fixed_from_uint(dp->min_IAT);
    int pred = predict_forest(fv);
    /*BENIGN = 0, ATTACK = 1*/
    dp->label = pred ? 1 : 0;    
    if(dp->label == 1){
        ret = XDP_DROP;
        bpf_map_update_elem(&xdp_flow_dropped, key, dp, BPF_ANY);
    }
    else ret = XDP_PASS;

    return ret;
}

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2)
        return XDP_DROP;  // Drop LLDP
    if (ret == 1)
        return XDP_PASS;
    if (ret < 0)
        return XDP_PASS;

    ret = update_stats(&key, ctx);
    return ret;
}

char _license[] SEC("license") = "GPL";
