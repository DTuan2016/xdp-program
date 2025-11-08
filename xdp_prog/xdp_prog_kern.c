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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qsDataStruct);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} qs_forest SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, accounting);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} accounting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOW_SAVED);
    __type(key, struct flow_key);
    __type(value, data_point);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_dropped SEC(".maps");

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
        if ((void *)(tcph + 1) > data_end)
            return -1;
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
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

static __always_inline __u64 qs_vote_all(struct qsDataStruct *tree)
{
    __u64 votes = 0;
    __u64 leaf_base = 0;
    // bpf_printk("START VOTING");
    // #pragma unroll
    for (int h = 0; h < QS_NUM_TREES; h++) {
        // bpf_printk("Voting with tree %d", h);
        // BITVECTOR_TYPE exit_leaf_idx = (BITVECTOR_TYPE)(__u8)msb_index(tree->v[h]);
        BITVECTOR_TYPE exit_leaf_idx = (__u8)msb_index(tree->v[h]);
        __u8 num_leaves = tree->num_leaves_per_tree[h];
        if (exit_leaf_idx >= num_leaves)
            goto next_tree;

        __u64 leaf_index = leaf_base + exit_leaf_idx;
        if (leaf_index >= QS_NUM_LEAVES)
            goto next_tree;

        votes += tree->leaves[leaf_index];

    next_tree:
        leaf_base += num_leaves; 
    }
    
    return votes;
}
/* ================= RF INFERENCE ================= */
static __always_inline int predict_forest(struct feat_vec fv)
{
    __u32 key = 0;
    struct qsDataStruct *tree = bpf_map_lookup_elem(&qs_forest, &key);
    // bpf_printk("JMP TO PREDICT_FOREST");
    if (!tree)
        return 0;

    // __u16 h = 0;

    QS_FEATURE(0, QS_OFFSETS_0, QS_OFFSETS_1);
    QS_FEATURE(1, QS_OFFSETS_1, QS_OFFSETS_2);
    QS_FEATURE(2, QS_OFFSETS_2, QS_OFFSETS_3);
    QS_FEATURE(3, QS_OFFSETS_3, QS_OFFSETS_4);
    QS_FEATURE(4, QS_OFFSETS_4, QS_OFFSETS_5);
    QS_FEATURE(5, QS_OFFSETS_5, QS_OFFSETS_6);
    // bpf_printk("DONE QS FEATURE");
    __u64 votes = qs_vote_all(tree);
    // bpf_printk("DONE QS FEATURE");
    if (votes > (QS_NUM_TREES / 2)){
        // bpf_printk("Vote = 1");
        return 1;
    }
    else{
        // bpf_printk("Vote = 0");
        return 0;
    }
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

    // New flow: only initialize stats, don't predict yet
    if (!dp) {
        data_point zero = {0};
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
    if (iat_ns > 0 && iat_ns < dp->min_IAT)
        dp->min_IAT = iat_ns;
    if (pkt_len > dp->max_pkt_len)
        dp->max_pkt_len = pkt_len;
    if (pkt_len < dp->min_pkt_len)
        dp->min_pkt_len = pkt_len;
    dp->last_seen = ts_ns;
    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    struct feat_vec fv = {
        .features = {0},
    };

    // bpf_printk("START DETECTION");
    fv.features[QS_FEATURE_FLOW_DURATION] = fixed_from_uint(dp->last_seen - dp->start_ts);
    fv.features[QS_FEATURE_TOTAL_FWD_PACKET] = fixed_from_uint(dp->total_pkts);
    fv.features[QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET] = fixed_from_uint(dp->total_bytes);
    fv.features[QS_FEATURE_FWD_PACKET_LENGTH_MAX] = fixed_from_uint(dp->max_pkt_len);
    fv.features[QS_FEATURE_FWD_PACKET_LENGTH_MIN] = fixed_from_uint(dp->min_pkt_len);
    fv.features[QS_FEATURE_FWD_IAT_MIN] = fixed_from_uint(dp->min_IAT);

    int pred = predict_forest(fv);
    // bpf_printk("DONE PREDICT");
    dp->label = pred ? 1 : 0;
    
    if(dp->label == 0){
        // bpf_printk("[DETECTION] BENIGN -> PASS");
        ret = XDP_PASS;
    } 
    else {
        // bpf_printk("[DETECTION] ATTACK -> DROP");
        ret = XDP_DROP;
        if (bpf_map_update_elem(&xdp_flow_dropped, key, dp, BPF_ANY) != 0)
            return ret;
    }
    if (bpf_map_update_elem(&xdp_flow_tracking, key, dp, BPF_ANY) != 0)
        return ret;

    return ret;
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
    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2)
        return XDP_DROP;  // Drop LLDP
    if(ret == 1)
        return XDP_PASS;
    if (ret < 0)
        return XDP_PASS;

    ret = update_stats(&key, ctx);

    ac->time_out = bpf_ktime_get_ns();
    ac->proc_time += ac->time_out - ac->time_in;
    ac->total_bytes += pkt_len;
    ac->total_pkts += 1;
    bpf_map_update_elem(&accounting_map, &key_ac, ac, BPF_ANY);
    return ret;
}

char _license[] SEC("license") = "GPL";
