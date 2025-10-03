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

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, WARM_UP_FOR_KNN);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} benign_flows SEC(".maps");

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
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;
    // __u16 src_port = 0;
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
    }

    key->src_port = bpf_ntohs(key->src_port);
    key->dst_port = bpf_ntohs(key->dst_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);

    return 0;
}

/* ==================== CALCULATE LOG2(x) ==================== */
static __always_inline __u8 ilog2_u64(__u64 x)
{
    static const __u8 tbl[16] = {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
    __u8 r = 0;

    if (x >> 32) {
        __u32 hi = x >> 32;
        if (hi >= (1<<16)) { hi >>= 16; r += 16; }
        if (hi >= (1<<8))  { hi >>= 8;  r += 8; }
        if (hi >= (1<<4))  { hi >>= 4;  r += 4; }
        return r + tbl[hi & 0xF];
    } else {
        __u32 lo = x & 0xFFFFFFFF;
        if (lo >= (1<<16)) { lo >>= 16; r += 16; }
        if (lo >= (1<<8))  { lo >>= 8;  r += 8; }
        if (lo >= (1<<4))  { lo >>= 4;  r += 4; }
        return r + tbl[lo & 0xF];
    }
}

/* ==================== CALCULATE SQRT(x) ==================== */
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

/* ==================== DISTANCE ==================== */
static __always_inline __u16 euclidean_distance(const data_point *a, const data_point *b)
{
    __u64 fx, fy, fz, fw, fh;

    fx = (a->flow_bytes_per_s > b->flow_bytes_per_s) ? a->flow_bytes_per_s - b->flow_bytes_per_s
                                           : b->flow_bytes_per_s - a->flow_bytes_per_s;
    fy = (a->flow_pkts_per_s > b->flow_pkts_per_s) ? a->flow_pkts_per_s - b->flow_pkts_per_s
                                         : b->flow_pkts_per_s - a->flow_pkts_per_s;
    fz = (a->pkts_len_mean > b->pkts_len_mean) ? a->pkts_len_mean - b->pkts_len_mean
                                               : b->pkts_len_mean - a->pkts_len_mean;

    fw = (a->flow_duration > b->flow_duration) ? a->flow_duration - b->flow_duration
                                   : b->flow_duration - a->flow_duration;
    fh = (a->flow_IAT_mean > b->flow_IAT_mean) ? a->flow_IAT_mean - b->flow_IAT_mean
                                               : b->flow_IAT_mean - a->flow_IAT_mean;

    __u8 dx = (__u8)ilog2_u64(fx);
    __u8 dy = (__u8)ilog2_u64(fy);
    __u8 dz = (__u8)ilog2_u64(fz);
    __u8 dw = (__u8)ilog2_u64(fw);
    __u8 dh = (__u8)ilog2_u64(fh);
    // bpf_printk("DIST: fx=%llu fy=%llu fz=%llu fw=%llu fh=%llu | dx=%u dy=%u dz=%u dw=%u dh=%u\n",
    //            fx, fy, fz, fw, fh, dx, dy, dz, dw, dh);
    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw + dh*dh;
    __u16 res = bpf_sqrt(sum);
    // bpf_printk("DIST sqrt=%u\n", res);
    return res;
}

/* ==================== INSERT KNN ==================== */
static __always_inline void insert_knn(struct knn_entries *entries,
                                       __u16 dist,
                                       const struct flow_key *neighbor_key)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (dist < entries->knn[i].distance) {
#pragma unroll
            for (int j = KNN - 1; j > i; j--) {
                entries->knn[j] = entries->knn[j - 1];
            }
            entries->knn[i].distance = dist;
            __builtin_memcpy(&entries->knn[i].key, neighbor_key, sizeof(*neighbor_key));
            break;
        }
    }
}

/* ==================== CALLBACK KNN ==================== */
struct knn_callback_ctx {
    const struct flow_key *target_key;
    data_point *target_dp;
    struct knn_entries *entries;
};

static __always_inline int callback_knn(void *map, const void *key, void *value, void *ctx)
{
    struct knn_callback_ctx *c = ctx;
    const struct flow_key *k = key;
    data_point *neighbor = value;

    /* Bỏ qua chính nó (so sánh theo key) */
    if (k->src_ip == c->target_key->src_ip && k->src_port == c->target_key->src_port)
        return 0;
    
    /* Bỏ qua anomaly đã bị flag */
    // if (neighbor->is_normal == 0)
    //     return 0;

    __u16 dist = euclidean_distance(c->target_dp, neighbor);
    struct flow_key neighbor_key = *k;  // copy giá trị key
    insert_knn(c->entries, dist, &neighbor_key);
    // insert_knn(c->entries, dist, k);
    return 0;
}

/* ==================== FIND KNN & SAVE INTO DP ==================== */
static __always_inline void find_knn_and_store(const struct flow_key *target_key, data_point *target_dp)
{
    struct knn_entries entries = {};

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        entries.knn[i].distance = 0xffff; /* init max */
        entries.knn[i].key.src_ip = 0;
        entries.knn[i].key.src_port = 0;
    }

    struct knn_callback_ctx ctx = {
        .target_key = target_key,
        .target_dp  = target_dp,
        .entries    = &entries,
    };

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn, &ctx, 0);

    /* Lưu KNN trực tiếp vào data_point */
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        target_dp->neighbors.knn[i] = entries.knn[i];
    }
}

/* ==================== ANOMALY DETECTION (dùng dp trực tiếp) ==================== */
static __always_inline int detect_anomaly(const struct flow_key *key, data_point *dp)
{
    if (!dp)
        return 0;

    /* Cập nhật KNN vào dp */
    find_knn_and_store(key, dp);

    __u16 max_dist = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        __u16 d = dp->neighbors.knn[i].distance;
        if (d != 0xffff && d > max_dist)
            max_dist = d;
    }

    return (max_dist > DIST_THRESHOLD);
}

/* ==================== UPDATE STATS (lookup 1 lần) ==================== */
static __always_inline data_point *update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts      = bpf_ktime_get_ns();
    ts = ts / 1000;
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (!dp) {
        /* FLOW MỚI */
        data_point zero = {};
        zero.start_ts           = ts;
        zero.last_seen          = ts;
        zero.total_pkts         = 1;
        zero.total_bytes        = pkt_len;
        zero.sum_IAT            = 0;
        zero.flow_IAT_mean      = 0;
        zero.is_normal          = 1;
        zero.flow_bytes_per_s   = 0;
        zero.flow_pkts_per_s    = 0;
        zero.pkts_len_mean      = 0;
        // zero.is_normal          = 1;

        /* init neighbors (distance=0xffff) để tránh rác */
#pragma unroll
        for (int i = 0; i < KNN; i++) {
            zero.neighbors.knn[i].distance = 0xffff;
            zero.neighbors.knn[i].key.src_ip = 0;
            zero.neighbors.knn[i].key.src_port = 0;
        }

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        /* tăng counter số flow */
        __u32 idx = 0;
        __u32 *count = bpf_map_lookup_elem(&flow_counter, &idx);
        if (count)
            (*count)++;

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
        dp->flow_bytes_per_s = (dp->total_bytes * 1000000) / dp->flow_duration;
        dp->flow_pkts_per_s  = (dp->total_pkts  * 1000000) / dp->flow_duration;
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
        // bpf_printk("DROP LLDP frame\n");
        return XDP_DROP;  /* drop luôn */
    }

    if (ret < 0)
        return XDP_PASS;

    data_point *dp = update_stats(&key, ctx);
    if (!dp)
        return XDP_PASS;
    
    __u32 idx = 0;
    __u32 *count = bpf_map_lookup_elem(&flow_counter, &idx);
    if (count && *count > WARM_UP_FOR_KNN) {
        int anomaly = detect_anomaly(&key, dp);
        if (anomaly) {
            dp->is_normal = 0;
            data_point local_dp = {};
            __builtin_memcpy(&local_dp, dp, sizeof(data_point));
            bpf_map_update_elem(&flow_dropped, &key, &local_dp, BPF_ANY);
            bpf_map_update_elem(&xdp_flow_tracking, &key, &local_dp, BPF_ANY);
            return XDP_PASS;
        } else {
            dp->is_normal = 1;
            data_point local_dp = {};
            __builtin_memcpy(&local_dp, dp, sizeof(data_point));
            bpf_map_update_elem(&xdp_flow_tracking, &key, &local_dp, BPF_ANY);
        }
    } else {
        dp->is_normal = 1;
    }
    // bpf_map_update_elem(&xdp_flow_tracking, &key, &dp, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";