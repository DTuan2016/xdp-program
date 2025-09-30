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

/* ================= MATH HELPERS ================= */
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
        zero.start_ts           = ts;
        zero.last_seen          = ts;
        zero.total_pkts         = 1;
        zero.total_bytes        = pkt_len;
        zero.is_normal          = 1;   // default normal
        zero.flow_bytes_per_s   = 0;
        zero.flow_duration      = 0;
        zero.pkts_len_mean      = 0;
        zero.flow_pkts_per_s    = 0;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return NULL;

        dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
        if (!dp)
            return NULL;

        /* tăng counter flow */
        __u32 idx = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return dp;
    }

    __u64 current_ns = ts;
    __u64 iat_ns = (dp->last_seen > 0 && current_ns >= dp->last_seen) ?
                   current_ns - dp->last_seen : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;

    dp->last_seen = current_ns;

    if (dp->total_pkts > 1){
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1);
        dp->pkts_len_mean = dp->total_bytes / dp->total_pkts;
    }
    dp->flow_duration = dp->last_seen - dp->start_ts;
    if(dp->flow_duration > 0){
        dp->flow_bytes_per_s = (dp->total_bytes * 1000000000) / dp->flow_duration;
        dp->flow_pkts_per_s  = (dp->total_pkts  * 1000000000) / dp->flow_duration;
    }
    return dp;
}


/* ================= DISTANCE ================= */
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


/* ================= KNN (CỤC BỘ, KHÔNG LƯU TRONG MAP) ================= */
static __always_inline void init_knn(__u32 *knn_dist,
                                     struct flow_key *knn_keys)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        knn_dist[i] = 0xFFFFFFFFu;
        knn_keys[i].src_ip = 0;
        knn_keys[i].src_port = 0;
    }
}

static __always_inline void insert_knn(__u32 *knn_dist,
                                       struct flow_key *knn_keys,
                                       __u16 dist,
                                       const struct flow_key *neighbor_key)
{
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if ((__u32)dist < knn_dist[i]) {
#pragma unroll
            for (int j = KNN - 1; j > i; j--) {
                knn_dist[j] = knn_dist[j - 1];
                knn_keys[j] = knn_keys[j - 1];
            }
            knn_dist[i] = dist;
            knn_keys[i] = *neighbor_key;
            break;
        }
    }
}

/* ====== for_each context (để tính KNN tạm thời) ====== */
struct knn_ctx_local {
    const struct flow_key *target_key; /* bỏ qua chính nó theo key */
    data_point            *target;
    __u32                 *knn_dist;
    struct flow_key       *knn_keys;
    int                    neighbor_count;
};

static int knn_scan_cb(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx_local *c = ctx;
    const struct flow_key *k = key;
    data_point *neighbor = value;

    if (!neighbor || !c->target)
        return 0;

    /* bỏ qua chính nó */
    if (k->src_ip == c->target_key->src_ip &&
        k->src_port == c->target_key->src_port)
        return 0;

    c->neighbor_count++;
    __u16 dist = euclidean_distance(c->target, neighbor);
    insert_knn(c->knn_dist, c->knn_keys, dist, k);
    return 0;
}


/* ================= K-DIST & LRD (dùng KNN cục bộ) ================= */
static __always_inline void compute_k_distance_and_lrd(const struct flow_key *tkey,
                                                       data_point *target,
                                                       __u32 *knn_dist,
                                                       struct flow_key *knn_keys)
{
    if (!target) return;

    init_knn(knn_dist, knn_keys);

    struct knn_ctx_local c = {
        .target_key      = tkey,
        .target          = target,
        .knn_dist        = knn_dist,
        .knn_keys        = knn_keys,
        .neighbor_count  = 0,
    };

    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_scan_cb, &c, 0);
    if (it < 0)
        return;

    /* k-distance là phần tử K cuối (đã sắp xếp tăng dần) */
    target->k_distance = (__u16)knn_dist[KNN - 1];

    /* LRD = K / sum(reach-dist(target, ni)) */
    __u64 reach_sum = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_dist[i] == 0xFFFFFFFFu || knn_keys[i].src_ip == 0)
            continue;

        data_point *o = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!o) continue;

        __u16 dist  = (__u16)knn_dist[i];
        __u16 reach = dist;
        if (o->k_distance > dist)
            reach = o->k_distance;

        reach_sum += reach;
    }

    if (reach_sum > 0)
        target->lrd_value = (KNN * SCALEEEEEE) / reach_sum;
    else
        target->lrd_value = 0;
}


/* ================= LOF (dùng KNN cục bộ) ================= */
static __always_inline void compute_lof_for_target(data_point *target,
                                                   __u32 *knn_dist,
                                                   struct flow_key *knn_keys)
{
    if (!target) return;

    int neighbor_count = 0;
    __u64 sum_ratio = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_dist[i] == 0xFFFFFFFFu || knn_keys[i].src_ip == 0)
            continue;

        data_point *nbr = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_keys[i]);
        if (!nbr) continue;

        if (nbr->lrd_value > 0 && target->lrd_value > 0) {
            __u64 ratio = ((__u64)SCALEEEEEE * nbr->lrd_value) / target->lrd_value;
            sum_ratio += ratio;
            neighbor_count++;
        }
    }

    if (neighbor_count > 0 && sum_ratio > 0)
        target->lof_value = (sum_ratio * SCALEEEEEE) / neighbor_count;
    else
        target->lof_value = 0;
}


/* ================= ANOMALY ================= */
static __always_inline void compute_anomaly_for_target(const struct flow_key *key,
                                                       data_point *target)
{
    if (!target)
        return;

    /* Tính toán KNN, k-distance, LRD và LOF cho flow này */
    __u32 knn_dist[KNN] = {};
    struct flow_key knn_keys[KNN] = {};

    compute_k_distance_and_lrd(key, target, knn_dist, knn_keys);
    compute_lof_for_target(target, knn_dist, knn_keys);

    /* So sánh với ngưỡng LOF để phân loại */
    __u32 threshold = LOF_THRESHOLD * SCALEEEEEE;

    if (target->lof_value > threshold) {
        target->is_normal = 0;   // Bất thường
        // bpf_printk("ANOMALY DETECTED: LOF=%u > THRESH=%u",
        //            target->lof_value, threshold);
        bpf_map_update_elem(&flow_dropped, key, target, BPF_ANY);
        // bpf_map_delete_elem(&xdp_flow_tracking, key);
    } else {
        target->is_normal = 1;   // Bình thường
    }

    /* Ghi ngược lại vào map */
    bpf_map_update_elem(&xdp_flow_tracking, key, target, BPF_ANY);
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

    // if (key.src_ip == bpf_htonl(0xC0A83203)) {  /* 192.168.50.3 -> 0xC0A83203 */
    //     // bpf_printk("Bypass anomaly detection for 192.168.50.3\n");
    //     return XDP_PASS;
    // }

    data_point *target = update_stats(&key, ctx, 1);
    if (!target)
        return XDP_PASS;

    __u32 idx = 0;
    __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
    if (cnt) {
        if (*cnt > DATA_CAL_LOF) {
            /* đủ số lượng -> chạy LOF */
            compute_anomaly_for_target(&key, target);
        } else {
            /* giai đoạn warmup -> luôn gán normal */
            target->is_normal = 1;
            bpf_map_update_elem(&xdp_flow_tracking, &key, target, BPF_ANY);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
