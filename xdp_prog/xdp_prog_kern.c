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
#define MAX_FLOW_SAVED      100
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

/* ---------------- PARSING ---------------- */
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

/* ---------------- utilities (verifier-safe) ---------------- */
/* ilog2: if-chain, returns 0 for x==0 */
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

/* ---------------- stats update ---------------- */
/* return 1 when new entry created, 0 on update, -1 on error */
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
        zero.sum_IAT = 0;
        zero.flow_IAT_mean = 0;
        zero.k_distance = 0;
#pragma unroll
        for (int i = 0; i < KNN; i++)
            zero.reach_dist[i] = 0;
        zero.lrd_value = 0;
        zero.lof_value = 0;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return -1;
        return 1;
    }

    __u64 current_ns = ts;
    __u64 iat_ns = 0;
    if (dp->last_seen > 0 && current_ns >= dp->last_seen)
        iat_ns = current_ns - dp->last_seen;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;

    dp->last_seen = current_ns;

    if (dp->total_pkts > 1)
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
    else
        dp->flow_IAT_mean = 0;

    return 0;
}

/* ---------------- DISTANCE AND KNN HELPERS ---------------- */
static __always_inline __u16 euclidean_distance(const data_point *a, const data_point *b)
{
    /* compute absolute differences using signed 64 for subtraction safety */
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

    /* ilog2 result in [0..63] */
    __u8 dx = ( __u8 ) ilog2_u64(fx);
    __u8 dy = ( __u8 ) ilog2_u64(fy);
    __u8 dz = ( __u8 ) ilog2_u64(fz);
    __u8 dw = ( __u8 ) ilog2_u64(fw);

    /* sum of squares -> fits in 32-bit (max ~4*63^2 = 15876) */
    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw;

    __u16 root = bpf_sqrt(sum);

    if (root > UINT16_MAX)
        return UINT16_MAX;
    return (__u16)root;
}

/* INTIT REACH-DIST */
static __always_inline void init_reach_dist(int32_t *reach_dist)
{
#pragma unroll
    for (int i = 0; i < KNN; i++)
        reach_dist[i] = INT32_MAX;
}

/* SAVE REACH-DIST TO data_point.reach-dist[i] */
static __always_inline void persist_reach_dist(data_point *dst, const int32_t *src)
{
#pragma unroll
    for (int i = 0; i < KNN; i++)
        dst->reach_dist[i] = src[i];
}

/* Update top-K distacne*/
static __always_inline void update_knn_distances(int32_t *reach_dist, int32_t dist)
{
#pragma unroll
    for (int m = 0; m < KNN; m++) {
        int32_t cur = reach_dist[m];
        if (dist < cur) {
#pragma unroll
            for (int n = KNN - 1; n > m; n--)
                reach_dist[n] = reach_dist[n - 1];
            reach_dist[m] = dist;
            break;
        }
    }
}

/* knn scan callback - keep minimal, no printk inside */
struct knn_ctx_local {
    data_point *target;
    int32_t *reach_dist;
    int neighbor_count;
};

static int knn_scan_cb(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx_local *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target)
        return 0;

    c->neighbor_count++;
    int32_t dist = euclidean_distance(c->target, neighbor);
    update_knn_distances(c->reach_dist, dist);
    return 0;
}

static __always_inline void compute_k_distance_and_lrd(data_point *target)
{
    int32_t reach_dist[KNN];
    init_reach_dist(reach_dist);

    struct knn_ctx_local c = {
        .target = target,
        .reach_dist = reach_dist,
        .neighbor_count = 0,
    };

    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_scan_cb, &c, 0);
    if (it < 0)
        return;

    persist_reach_dist(target, reach_dist);
    target->k_distance = reach_dist[KNN - 1];

    int32_t reach_sum = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++)
        reach_sum += reach_dist[i];

    if (reach_sum > 0)
        target->lrd_value = (KNN * SCALEEEEEE) / reach_sum;
    else
        target->lrd_value = 0;
}

/* LOF callback & compute (minimal, no prints) */
struct lof_ctx {
    data_point *target;
    long ti_le_lrd;
    int neighbor_count;
};

static int compute_lof_callback(void *map, const void *key, void* value, void *ctx)
{
    struct lof_ctx *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target)
        return 0;

    c->neighbor_count++;

    if (neighbor->lrd_value > 0 && c->target->lrd_value > 0) {
        long ratio = (SCALEEEEEE * neighbor->lrd_value) / c->target->lrd_value;
        c->ti_le_lrd += ratio;
    }
    return 0;
}

static __always_inline void compute_lof_for_target(data_point *target)
{
    struct lof_ctx ctx = {
        .target = target,
        .ti_le_lrd = 0,
        .neighbor_count = 0,
    };

    long ret = bpf_for_each_map_elem(&xdp_flow_tracking, compute_lof_callback, &ctx, 0);
    if (ret < 0)
        return;

    if (ctx.ti_le_lrd > 0)
        target->lof_value = (ctx.ti_le_lrd) / KNN;
    else
        target->lof_value = 0;
}

/* update affected callback - minimal */
struct affected_ctx {
    data_point *target;
    int32_t target_kdist;
    void *map;
    int affected_count;
};

static int update_affected_callback(void *map, const void *key, void *value, void *ctx)
{
    struct affected_ctx *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target)
        return 0;

    int32_t dist = euclidean_distance(c->target, neighbor);

    if (dist <= c->target_kdist) {
        c->affected_count++;
        compute_k_distance_and_lrd(neighbor);
        compute_lof_for_target(neighbor);
    }
    return 0;
}

/* ---------------- XDP program ---------------- */
SEC("xdp")
int xdp_print_all_flows(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    update_stats(&key, ctx, 1);

    data_point *target = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
    if (!target)
        return XDP_PASS;

    compute_k_distance_and_lrd(target);
    struct affected_ctx actx = {
        .target = target,
        .target_kdist = target->k_distance,
        .map = &xdp_flow_tracking,
        .affected_count = 0,
    };
    long ret = bpf_for_each_map_elem(&xdp_flow_tracking, update_affected_callback, &actx, 0);
    (void)ret;
    compute_lof_for_target(target);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
