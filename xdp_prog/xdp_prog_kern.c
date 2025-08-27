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

/* map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

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

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;

    __u16 src_port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        src_port = tcph->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        src_port = udph->source;
    } else {
        src_port = 0;
    }

    key->src_port = bpf_ntohs(src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/* ================= CALL LOG2(x) ================= */
static __always_inline __u8 ilog2_u64(__u64 x)
{
    static const __u8 tbl[16] = {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
    __u8 r = 0;

    if (x >> 32) {
        __u32 hi = x >> 32;
        if (hi >= (1<<16)) { hi >>= 16; r += 16; }
        if (hi >= (1<<8))  { hi >>= 8;  r += 8; }
        if (hi >= (1<<4))  { hi >>= 4;  r += 4; }
        // lookup luôn 4-bit cuối
        return r + tbl[hi & 0xF];
    } else {
        __u32 lo = x & 0xFFFFFFFF;
        if (lo >= (1<<16)) { lo >>= 16; r += 16; }
        if (lo >= (1<<8))  { lo >>= 8;  r += 8; }
        if (lo >= (1<<4))  { lo >>= 4;  r += 4; }
        return r + tbl[lo & 0xF];
    }
}
static __always_inline __u16 bpf_sqrt(__u32 x)
{
    if (x == 0)
        return 0;

    __u32 res = x;
    __u32 prev = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        prev = res;
        res = (res + x / res) >> 1;
        if (res == prev)
            break;
    }
    return res;
}

/* ================= UPDATE STATS ================= */
static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts;
        zero.last_seen = ts;
        zero.total_pkts = 1;
        zero.total_bytes = pkt_len;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return -1;

        // tăng counter flow
        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
        return 1;
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

    return 0;
}

/* =================  EUCLIDEAN DISTANCE ================= */
static __always_inline __u16 euclidean_distance(const data_point *a, const data_point *b)
{
    __u64 fx, fy, fz, fw;
    if (a->total_bytes > b->total_bytes){ 
        fx = a->total_bytes - b->total_bytes;
    }
    else {
        fx = b->total_bytes - a->total_bytes;
    }

    if (a->total_pkts > b->total_pkts){ 
        fy = a->total_pkts - b->total_pkts;
    }
    else {
        fy = b->total_pkts - a->total_pkts;
    }
    if (a->flow_IAT_mean > b->flow_IAT_mean){ 
        fz = a->flow_IAT_mean - b->flow_IAT_mean;
    }
    else {
        fz = b->flow_IAT_mean - a->flow_IAT_mean;
    }
    
    __u64 flow_dur_a = a->last_seen - a->start_ts;
    __u64 flow_dur_b = b->last_seen - b->start_ts;

    if (flow_dur_a > flow_dur_b){ 
        fw = flow_dur_a - flow_dur_b;
    }
    else {
        fw = flow_dur_b - flow_dur_a;
    }

    __u8 dx = ( __u8 ) ilog2_u64(fx);
    __u8 dy = ( __u8 ) ilog2_u64(fy);
    __u8 dz = ( __u8 ) ilog2_u64(fz);
    __u8 dw = ( __u8 ) ilog2_u64(fw);

    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw;

    __u16 root = bpf_sqrt(sum);

    if (root > UINT16_MAX)
        return UINT16_MAX;
    return (__u16)root;
}

/* ================= INIT KNN ================= */
static __always_inline void init_knn(__u32 *knn_dist,
                                     struct flow_key *knn_keys)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        knn_dist[i] = UINT32_MAX;
        knn_keys[i].src_ip   = 0;
        knn_keys[i].src_port = 0;
    }
}

/* ================= UPDATE KNN ================= */
static __always_inline void update_knn(__u32 *knn_dist,
                                       struct flow_key *knn_keys,
                                       __u32 dist,
                                       const struct flow_key *new_key)
{
#pragma unroll
    for (int m = 0; m < KNN; m++) {
        if (dist < knn_dist[m]) {
#pragma unroll
            for (int n = KNN - 1; n > m; n--) {
                knn_dist[n] = knn_dist[n - 1];
                knn_keys[n] = knn_keys[n - 1];
            }
            knn_dist[m] = dist;
            knn_keys[m] = *new_key;
            break;
        }
    }
}

/* ================= CONTEXT ================= */
struct knn_ctx_local {
    data_point      *target;
    __u32           *knn_dist;
    struct flow_key *knn_keys;
    int              neighbor_count;
};

/* ================= CALLBACK ================= */
static int knn_scan_cb(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx_local *c = ctx;
    const struct flow_key *k = key;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target)
        return 0;

    c->neighbor_count++;
    __u32 dist = euclidean_distance(c->target, neighbor);
    update_knn(c->knn_dist, c->knn_keys, dist, k);
    return 0;
}

/* ================= COMPUTE K-DIST AND LRD ================= */
static __always_inline void compute_k_distance_and_lrd(data_point *target, __u32 *knn_dist, struct flow_key *knn_keys)
{
    init_knn(knn_dist, knn_keys);

    struct knn_ctx_local c = {
        .target         = target,
        .knn_dist       = knn_dist,
        .knn_keys       = knn_keys,
        .neighbor_count = 0,
    };

    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_scan_cb, &c, 0);
    if (it < 0)
        return;

    target->k_distance = knn_dist[KNN - 1];

    __u64 reach_sum = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        data_point *o = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!o) continue;

        __u32 dist  = knn_dist[i];
        __u32 reach = dist;
        if (o->k_distance > dist)   
            reach = o->k_distance;

        reach_sum += reach;
    }

    if (reach_sum > 0)
        target->lrd_value = (KNN * SCALEEEEEE) / reach_sum;
    else
        target->lrd_value = 0;
}

/* ================= LOF CONTEXT ================= */
struct lof_ctx {
    data_point      *target;
    struct flow_key *knn_keys;
    int              neighbor_count;
    __u64            sum_ratio;
};

/* ================= LOF SCAN ================= */
static __always_inline void compute_lof_for_target(data_point *target,
                                                   struct flow_key *knn_keys)
{
    struct lof_ctx ctx = {
        .target         = target,
        .knn_keys       = knn_keys,
        .neighbor_count = 0,
        .sum_ratio      = 0,
    };

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        data_point *neighbor = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!neighbor || neighbor == target)
            continue;

        ctx.neighbor_count++;

        if (neighbor->lrd_value > 0 && target->lrd_value > 0) {
            __u64 ratio = ((__u64)SCALEEEEEE * neighbor->lrd_value) / target->lrd_value;
            ctx.sum_ratio += ratio;
        }
    }

    if (ctx.neighbor_count > 0 && ctx.sum_ratio > 0)
        target->lof_value = (ctx.sum_ratio * SCALEEEEEE) / ctx.neighbor_count;
    else
        target->lof_value = 0;
}

static __always_inline void compute_anomaly_for_target(struct flow_key *key,
                                                       data_point *target)
{
    if (!target)
        return;

    __u32 knn_dist[KNN];
    struct flow_key knn_keys[KNN];
    compute_k_distance_and_lrd(target, knn_dist, knn_keys);

    /* Tính LOF */
    compute_lof_for_target(target, knn_keys);

    if (target->lof_value > LOF_THRESHOLD * SCALEEEEEE) {
        bpf_printk("ANOMALY DETECTED: LOF=%d > THRESH=%d -> removing flow",
                   target->lof_value, LOF_THRESHOLD);

        /* Xoá luôn flow khỏi map */
        bpf_map_delete_elem(&xdp_flow_tracking, key);
    }
}

/* ================= XDP program ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    update_stats(&key, ctx, 1);

    data_point *target = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
    if (!target)
        return XDP_PASS;

    __u32 idx = 0;
    __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
    if (cnt && *cnt >= MAX_FLOW_SAVED) {
        compute_anomaly_for_target(&key, target);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";