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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct knn_entries);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} maps_knn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");


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

/* ==================== LOF2(x) ==================== */
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

/* ---------------- DISTANCE AND KNN HELPERS ---------------- */
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
/*==================== INSERT KNN ====================*/
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

/* ==================== CALL BACK FOR KNN ==================== */
static __always_inline int callback_knn(void *map, const void *key, void *value, void *ctx)
{
    struct knn_callback_ctx *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target_dp)
        return 0;

    __u16 dist = euclidean_distance(c->target_dp, neighbor);
    if ((__s16)dist < 0)   // phòng lỗi trả giá trị âm
        return 0;

    insert_knn(c->entries, dist, (const struct flow_key *)key);
    return 0;
}

/* ==================== FIND KNN AND STORES ==================== */
static __always_inline void find_knn_and_store(const struct flow_key *target_key, data_point *target_dp)
{
    struct knn_entries entries = {};

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        entries.knn[i].distance = 0xffff;
    }

    struct knn_callback_ctx ctx = {
        .target_key = target_key,
        .target_dp  = target_dp,
        .entries    = &entries,
    };

    // quét toàn bộ flow trong xdp_flow_tracking
    bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn, &ctx, 0);

    // lưu lại kết quả KNN vào maps_knn
    bpf_map_update_elem(&maps_knn, target_key, &entries, BPF_ANY);

    bpf_printk("find_knn_and_store(): saved KNN for flow %u:%u\n",
               target_key->src_ip, target_key->src_port);
}

/* ========================== ANOMALY DETECTION ========================== */
static __always_inline int detect_anomaly(const struct flow_key *key, __u64 pkt_len)
{
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        return 0;
    }

    find_knn_and_store(key, dp);

    struct knn_entries *entries = bpf_map_lookup_elem(&maps_knn, key);
    if (!entries) {
        return 0;
    }

    __u16 max_dist = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (entries->knn[i].distance != 0xffff && entries->knn[i].distance > max_dist) {
            max_dist = entries->knn[i].distance;
        }
    }

    bpf_printk("flow %u:%u max_dist=%u\n", key->src_ip, key->src_port, max_dist);

    if (max_dist > DIST_THRESHOLD) {
        bpf_printk("flow %u:%u anomaly detected! dist=%u\n", key->src_ip, key->src_port, max_dist);
        return 1;
    }
    return 0;
}
/* ==================== UPDATE STATS ==================== */
static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (!dp) {
        // ===== FLOW MỚI =====
        data_point zero = {};
        zero.start_ts      = ts;
        zero.last_seen     = ts;
        zero.total_pkts    = 1;
        zero.total_bytes   = pkt_len;
        zero.sum_IAT       = 0;
        zero.flow_IAT_mean = 0;
        zero.is_normal     = 1;  
        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return -1;

        __u32 idx = 0;
        __u32 *count = bpf_map_lookup_elem(&flow_counter, &idx);
        if (count) {
            (*count)++;
            if (*count >= WARM_UP_FOR_KNN) {
                data_point *new_dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
                if (new_dp) {
                    find_knn_and_store(key, new_dp);

                    if (detect_anomaly(key, pkt_len)) {
                        new_dp->is_normal = 0;  // anomaly
                        return 2;
                    } else {
                        new_dp->is_normal = 1;  // bình thường
                    }
                }
            }
        }
        return 1;
    }

    // ===== FLOW ĐÃ TỒN TẠI =====
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
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
    else
        dp->flow_IAT_mean = 0;

    // detect sau khi update
    if (detect_anomaly(key, pkt_len)) {
        dp->is_normal = 0; // anomaly
        return -2;
    }

    dp->is_normal = 1; // bình thường
    return 0;
}

/* ==================== MAIN PROCESS ==================== */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) {
        return XDP_PASS;  // không xử lý nếu parse fail
    }

    update_stats(&key, ctx, 1);

    // if (ret == 2 || ret == -2) {
    //     return XDP_DROP;  
    // }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
