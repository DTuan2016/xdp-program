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
} flow_counter SEC(".maps");

/*==================== PARSING ====================*/
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

/*==================== CALCULATE LOF2(x) ====================*/
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
/*==================== CALCULATE SQRT(x) ====================*/
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

/*==================== DISTANCE <EUCLIDEAN> ====================*/
static __always_inline __u64 abs_diff_u64(__u64 a, __u64 b)
{
    __s64 d = (__s64)a - (__s64)b;
    return d < 0 ? -d : d;
}

static __always_inline __u16 euclidean_distance(const data_point *a, const data_point *b)
{
    __u64 fx = abs_diff_u64(a->total_bytes, b->total_bytes);
    __u64 fy = abs_diff_u64(a->total_pkts,  b->total_pkts);
    __u64 fz = abs_diff_u64(a->flow_IAT_mean, b->flow_IAT_mean);

    __u64 flow_dur_a = a->last_seen - a->start_ts;
    __u64 flow_dur_b = b->last_seen - b->start_ts;
    __u64 fw = abs_diff_u64(flow_dur_a, flow_dur_b);

    /* ilog2 result in [0..63] */
    __u8 dx = (__u8)ilog2_u64(fx);
    __u8 dy = (__u8)ilog2_u64(fy);
    __u8 dz = (__u8)ilog2_u64(fz);
    __u8 dw = (__u8)ilog2_u64(fw);

    /* sum of squares -> fits in 32-bit */
    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw;

    __u32 root = bpf_sqrt(sum);

    if (root > UINT16_MAX)
        return UINT16_MAX;
    return (__u16)root;
}

/* =================== KNN FOR ONE POINT =================== */
static __always_inline void init_knn(__u32 *knn_dist,
                                     struct flow_key *knn_keys)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        knn_dist[i] = INT32_MAX;
        knn_keys[i].src_ip = 0;
        knn_keys[i].src_port = 0;
    }
}

/* =================== UPDATE KNN =================== */
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

/* =================== KNN CALLBACK =================== */
struct knn_ctx {
    data_point      *target;
    __u32           *knn_dist;
    struct flow_key *knn_keys;
};

static int knn_callback(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx *c = ctx;
    const struct flow_key *k = key;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target)
        return 0;

    __u32 dist = euclidean_distance(c->target, neighbor);
    update_knn(c->knn_dist, c->knn_keys, dist, k);
    return 0;
}

/* =================== COMPUTE K-DISTANCE =================== */
static __always_inline __u32 compute_k_distance(const __u32 *knn_dist)
{
    return knn_dist[KNN - 1]; // farthest neighbor in KNN
}

/* =================== COMPUTE LRD =================== */
static __always_inline __u32 compute_lrd_single(const data_point *target,
                                                  const struct flow_key *knn_keys,
                                                  const __u32 *knn_dist,
                                                  int neighbor_count)
{
    long sum_reach = 0;
    int used = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (i >= neighbor_count) break;
        if (knn_keys[i].src_ip == 0 && knn_keys[i].src_port == 0) continue;

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!neighbor_dp) continue;

        // reach-dist(x,p) = max{k-distance(p), d(x,p)}
        __u32 reach = knn_dist[i];
        if (neighbor_dp->k_distance > reach)
            reach = neighbor_dp->k_distance;

        sum_reach += reach;
        used++;
    }

    if (sum_reach > 0 && used > 0)
        return (__u32)((used * SCALEEEEEE) / sum_reach);
    return 0;
}

/* =================== COMPUTE LOF =================== */
static __always_inline __u32 compute_lof_single(const struct flow_key *knn_keys,
                                                  int neighbor_count,
                                                  __u32 lrd_target)
{
    long ratio_sum = 0;
    int used = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (i >= neighbor_count) break;
        if (knn_keys[i].src_ip == 0 && knn_keys[i].src_port == 0) continue;

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!neighbor_dp) continue;

        __u32 lrd_n = neighbor_dp->lrd_value;
        if (lrd_n > 0 && lrd_target > 0) {
            ratio_sum += ((long)SCALEEEEEE * (long)lrd_n) / (long)lrd_target;
            used++;
        }
    }

    if (used > 0)
        return (__u32)(ratio_sum / used);
    return 0;
}

/* =================== FULL PIPELINE FOR NEW FLOW =================== */
static __always_inline void calculate_lof_for_new_flow(data_point *target)
{
    __u32 knn_dist[KNN];
    struct flow_key knn_keys[KNN];

    init_knn(knn_dist, knn_keys);

    struct knn_ctx c = {
        .target   = target,
        .knn_dist = knn_dist,
        .knn_keys = knn_keys,
    };

    // scan all baseline flows
    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_callback, &c, 0);
    if (it < 0)
        return;

    target->k_distance = compute_k_distance(knn_dist);
    target->lrd_value  = compute_lrd_single(target, knn_keys, knn_dist, KNN);
    target->lof_value  = compute_lof_single(knn_keys, KNN, target->lrd_value);
}

/*==================== UPDATE STATS (INFERENCE MODE) ====================*/
static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));
    __u32 idx0 = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&flow_counter, &idx0);
    if (!count_ptr) {
        bpf_printk("flow_counter not initialized");
        return -1;
    }
    __u32 count = *count_ptr;

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (count < MAX_FLOW_SAVED) {
        /* === BUILDING BASELINE DATASET === */
        if (dp) {
            // Flow đã tồn tại, update thống kê
            __u64 iat_ns = (ts > dp->last_seen) ? ts - dp->last_seen : 0;
            dp->last_seen = ts;
            __sync_fetch_and_add(&dp->total_pkts, 1);
            __sync_fetch_and_add(&dp->total_bytes, pkt_len);
            if (iat_ns > 0)
                dp->sum_IAT += iat_ns;
            if (dp->total_pkts > 1)
                dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
            else
                dp->flow_IAT_mean = 0;

            bpf_printk("Baseline flow updated: pkts=%llu bytes=%llu",
                       dp->total_pkts, dp->total_bytes);
        } else {
            // Flow mới, thêm vào baseline
            data_point zero = {};
            zero.start_ts    = ts;
            zero.last_seen   = ts;
            zero.total_pkts  = 1;
            zero.total_bytes = pkt_len;
            zero.sum_IAT     = 0;
            zero.flow_IAT_mean = 0;
            zero.k_distance  = 0;
#pragma unroll
            for (int i = 0; i < KNN; i++)
                zero.reach_dist[i] = 0;
            zero.lrd_value   = 0;
            zero.lof_value   = 0;

            if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) == 0) {
                __sync_fetch_and_add(count_ptr, 1);
                bpf_printk("Baseline flow inserted (count=%u)", *count_ptr);
            } else {
                bpf_printk("!! Failed to insert baseline flow");
            }
        }
        return 0;
    }

    /* === INFERENCE MODE === */
    if (dp) {
        // Flow đã có trong baseline -> update tiếp, không inference
        __u64 iat_ns = (ts > dp->last_seen) ? ts - dp->last_seen : 0;
        dp->last_seen = ts;
        __sync_fetch_and_add(&dp->total_pkts, 1);
        __sync_fetch_and_add(&dp->total_bytes, pkt_len);
        if (iat_ns > 0)
            dp->sum_IAT += iat_ns;
        if (dp->total_pkts > 1)
            dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
        else
            dp->flow_IAT_mean = 0;

        bpf_printk("Baseline flow (existing) updated in inference mode");
        return 0;
    } else {
        // Flow mới hoàn toàn -> chỉ inference
        data_point tmp = {};
        tmp.start_ts    = ts;
        tmp.last_seen   = ts;
        tmp.total_pkts  = 1;
        tmp.total_bytes = pkt_len;
        tmp.sum_IAT     = 0;
        tmp.flow_IAT_mean = 0;
        tmp.k_distance  = 0;
#pragma unroll
        for (int i = 0; i < KNN; i++)
            tmp.reach_dist[i] = 0;
        tmp.lrd_value   = 0;
        tmp.lof_value   = 0;

        calculate_lof_for_new_flow(&tmp);

        bpf_printk("Inference flow: k_dist=%d, lrd=%d, lof=%d",
                   tmp.k_distance, tmp.lrd_value, tmp.lof_value);

        if (tmp.lof_value > LOF_THRESHOLD) {
            bpf_printk("ANOMALY DETECTED: LOF=%d > THRESH=%d",
                       tmp.lof_value, LOF_THRESHOLD);
            return -1;
        }
        return 0;
    }
}

/* =================== XDP PROGRAM =================== */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;
    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    int ret = update_stats(&key, ctx, 1);
    if(ret == -1){
        bpf_printk("ANOMALY");
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
