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

// #define INT32_MAX 2147483647
#define NANOSEC_PER_SEC     1000000000ULL
#define MAX_FLOW_SAVED      100
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/*================= MAPS =================*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        bpf_printk("[PARSE] Failed: Ethernet header bounds check");
        return -1;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        bpf_printk("[PARSE] Skipped: Not IP packet");
        return -1;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end){
        bpf_printk("[PARSE] Failed: IP header bounds check");
        return -1;
    }

    key->src_ip = iph->saddr;

    __u16 src_port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end){
            bpf_printk("[PARSE] Failed: TCP header bounds check");
            return -1;
        }
        src_port = tcph->source;
        bpf_printk("[PARSE] TCP packet parsed");
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end){
            bpf_printk("[PARSE] Failed: UDP header bounds check");
            return -1;
        }
        src_port = udph->source;
        bpf_printk("[PARSE] UDP packet parsed");
    } else {
        src_port = 0;
        bpf_printk("[PARSE] Other protocol: %d", iph->protocol);
    }

    key->src_port = bpf_ntohs(src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    bpf_printk("[PARSE] Success: src_port=%u, pkt_len=%llu", key->src_port, *pkt_len);
    return 0;
}

/*================= STATS UPDATE =================*/
/* Trả về: 1 nếu mới tạo entry, 0 nếu cập nhật entry thành công, -1 nếu lỗi */
static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                            (__u8 *)((void *)(long)ctx->data));
    
    bpf_printk("[STATS] Updating stats for port %u, pkt_len=%llu", key->src_port, pkt_len);

    /* Lookup or insert data_point */
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        bpf_printk("[STATS] Creating new flow entry for port %u", key->src_port);
        data_point zero = {};
        /* init new entry */
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

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0) {
            bpf_printk("[STATS] ERROR: Failed to insert new data_point for port %u", key->src_port);
            return -1;
        }
        bpf_printk("[STATS] Successfully created new flow for port %u", key->src_port);
        /* created new entry */
        return 1;
    }

    /* Update existing entry */
    __u64 current_ns = ts; // Convert to ms
    __u64 iat_ns = 0;
    
    if (dp->last_seen > 0 && current_ns >= dp->last_seen)
        iat_ns = current_ns - dp->last_seen;

    bpf_printk("[STATS] Updating existing flow port %u: pkts %u->%u, iat_ms=%llu", 
               key->src_port, dp->total_pkts, dp->total_pkts + 1, iat_ns);

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;          

    dp->last_seen = current_ns;           

    /* Mean IAT in milliseconds */
    if (dp->total_pkts > 1)
        dp->flow_IAT_mean = dp->sum_IAT / (dp->total_pkts - 1); 
    else
        dp->flow_IAT_mean = 0;

    bpf_printk("[STATS] Updated: total_pkts=%u, mean_iat=%u", dp->total_pkts, dp->flow_IAT_mean);
    return 0;
}

/*================= HELPERS =================*/
static __always_inline __u32 int_sqrt64(__u64 x)
{
    if (x == 0)
        return 0;

    __u64 res = x;
    __u64 prev = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        prev = res;
        res = (res + x / res) >> 1;
        if (res == prev)
            break;
    }
    return res;
}


/*================= MATH (fixed) =================*/
static __always_inline int32_t euclidean_distance_fixed(const data_point *a, const data_point *b)
{
    bpf_printk("[DISTANCE] Computing distance between flows");
    int64_t fx = (int64_t)a->total_bytes - (int64_t)b->total_bytes;
    int64_t fy = (int64_t)a->total_pkts - (int64_t)b->total_pkts;  
    int64_t fz = (int64_t)a->flow_IAT_mean - (int64_t)b->flow_IAT_mean;
    int64_t fw = ((int64_t)a->last_seen - (int64_t)a->start_ts) - 
                 ((int64_t)b->last_seen - (int64_t)b->start_ts);

    int64_t sum_squares = fx*fx + fy*fy + fz*fz + fw*fw;
    if (sum_squares > INT64_MAX) sum_squares = INT64_MAX;
    int32_t ans = int_sqrt64((__u32)sum_squares);
    
    return ans;
}

static __always_inline void init_reach_dist(int32_t *reach_dist) {
    bpf_printk("[KNN] Initializing reach_dist array");
#pragma unroll
    for (int i = 0; i < KNN; i++)
        reach_dist[i] = INT32_MAX; // init large
}

static __always_inline void persist_reach_dist(data_point *dst, const int32_t *src) {
#pragma unroll
    for (int i = 0; i < KNN; i++)
        dst->reach_dist[i] = src[i];
}

static __always_inline void update_knn_distances(int32_t *reach_dist, int32_t dist) {
    bpf_printk("[KNN] Updating KNN with distance: %lld", dist);
#pragma unroll
    for (int m = 0; m < KNN; m++) {
        if (dist < reach_dist[m]) {
            bpf_printk("[KNN] Inserting at position %d", m);
#pragma unroll
            for (int n = KNN - 1; n > m; n--)
                reach_dist[n] = reach_dist[n - 1];
            reach_dist[m] = dist;
            break;
        }
    }
    bpf_printk("[KNN] Current top-K: [0]=%lld, [1]=%lld", reach_dist[0], reach_dist[1]);
}

struct knn_ctx_local {
    data_point *target;
    int32_t *reach_dist;
    int neighbor_count;
};

static int knn_scan_cb(void *map, const void *key, void *value, void *ctx)
{
    struct knn_ctx_local *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || neighbor == c->target) {
        bpf_printk("[KNN_SCAN] Skipping: self or null neighbor");
        return 0;
    }

    c->neighbor_count++;
    bpf_printk("[KNN_SCAN] Processing neighbor #%d", c->neighbor_count);

    int32_t dist = euclidean_distance_fixed(c->target, neighbor);
    bpf_printk("[KNN_SCAN] Neighbor distance: %lld", dist);
    
    update_knn_distances(c->reach_dist, dist);
    return 0;
}

static __always_inline void compute_k_distance_and_lrd(data_point *target)
{
    bpf_printk("[LRD] Computing K-distance and LRD");
    
    int32_t reach_dist[KNN];
    init_reach_dist(reach_dist);

    struct knn_ctx_local c = {
        .target = target,
        .reach_dist = reach_dist,
        .neighbor_count = 0,
    };

    long it = bpf_for_each_map_elem(&xdp_flow_tracking, knn_scan_cb, &c, 0);
    if (it < 0) {
        bpf_printk("[LRD] ERROR: knn_scan iterate failed: %ld", it);
        return;
    }

    bpf_printk("[LRD] Found %d neighbors", c.neighbor_count);
    bpf_printk("[LRD] Final reach_dist: [0]=%lld, [1]=%lld", reach_dist[0], reach_dist[1]);
    
    persist_reach_dist(target, reach_dist);
    target->k_distance = reach_dist[KNN - 1];
    bpf_printk("[LRD] K-distance (reach_dist[%d]): %lld", KNN-1, target->k_distance);

    int32_t reach_sum = 0;
#pragma unroll
    for (int i = 0; i < KNN; i++)
        reach_sum += reach_dist[i];

    bpf_printk("[LRD] Reach sum: %lld", reach_sum);

    if (reach_sum > 0) {
        target->lrd_value = (KNN * SCALEEEEEE) / reach_sum;  
        // target->lrd_value = fixed_div(fixed_from_int(KNN), reach_sum);
        bpf_printk("[LRD] LRD = %d *%d / %lld = %lld", KNN, SCALEEEEEE, reach_sum, target->lrd_value);
    } else {
        target->lrd_value = 0;
        bpf_printk("[LRD] LRD = 0 (reach_sum was 0)");
    }
}
/* compute_lof_for_target uses original compute_lof_callback but adapted locally */
struct lof_ctx {
    data_point *target;
    long ti_le_lrd;
    int neighbor_count;
};

static int compute_lof_callback(void *map, const void *key, void* value, void *ctx){
    struct lof_ctx *c = ctx;
    data_point *neighbor = value;
    
    if(!neighbor || neighbor == c->target) {
        bpf_printk("[LOF_CB] Skipping: self or null neighbor");
        return 0;
    }

    c->neighbor_count++;
    bpf_printk("[LOF_CB] Processing neighbor #%d, neighbor_lrd=%lld, target_lrd=%lld", 
               c->neighbor_count, neighbor->lrd_value, c->target->lrd_value);

    if(neighbor->lrd_value > 0 && c->target->lrd_value > 0) {
        long ratio = (SCALEEEEEE * neighbor->lrd_value) / c->target->lrd_value;
        // fixed ratio = fixed_div(neighbor->lrd_value, c->target->lrd_value);
        // c->ti_le_lrd = fixed_add(c->ti_le_lrd, ratio);
        c->ti_le_lrd = c->ti_le_lrd + ratio;
        bpf_printk("[LOF_CB] Added ratio %lld, running sum=%lld", ratio, c->ti_le_lrd);
    } else {
        bpf_printk("[LOF_CB] Skipped: zero LRD value");
    }
    return 0;
}

static __always_inline void compute_lof_for_target(data_point *target) {
    bpf_printk("[LOF] Computing LOF for target, target_lrd=%lld", target->lrd_value);
    
    struct lof_ctx ctx = {
        .target = target,
        .ti_le_lrd = 0,
        .neighbor_count = 0,
    };

    long ret = bpf_for_each_map_elem(&xdp_flow_tracking, compute_lof_callback, &ctx, 0);
    if (ret < 0) {
        bpf_printk("[LOF] ERROR: iterate failed: %ld", ret);
        return;
    }

    bpf_printk("[LOF] Processed %d neighbors, sum_ratio=%lld", ctx.neighbor_count, ctx.ti_le_lrd);

    if (ctx.ti_le_lrd > 0) {
        // target->lof_value = fixed_div(ctx.ti_le_lrd, fixed_from_int(KNN));
        target->lof_value = (ctx.ti_le_lrd) / KNN;
        bpf_printk("[LOF] Final LOF = %lld / %d = %lld", ctx.ti_le_lrd, KNN, target->lof_value);
    } else {
        target->lof_value = 0;
        bpf_printk("[LOF] LOF = 0 (sum_ratio was 0)");
    }
}

/*================= AFFECTED NEIGHBORS UPDATE =================*/
struct affected_ctx {
    data_point *target;
    int32_t target_kdist;
    void *map;
    int affected_count;
};

static int update_affected_callback(void *map, const void *key, void *value, void *ctx) {
    struct affected_ctx *c = ctx;
    data_point *neighbor = value;
    
    if(!neighbor || neighbor == c->target) {
        return 0;
    }   

    int32_t dist = euclidean_distance_fixed(c->target, neighbor);
    bpf_printk("[AFFECTED] Checking neighbor: dist=%lld, target_kdist=%lld", dist, c->target_kdist);

    if (dist <= c->target_kdist) {
        c->affected_count++;
        bpf_printk("[AFFECTED] Updating affected neighbor #%d", c->affected_count);
        
        compute_k_distance_and_lrd(neighbor);
        compute_lof_for_target(neighbor);
    }
    return 0;
}

/*================= XDP PROGRAM =================*/
SEC("xdp")
int xdp_print_all_flows(struct xdp_md *ctx)
{
    bpf_printk("=== [MAIN] XDP packet processing started ===");
    
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) {
        bpf_printk("[MAIN] Parse failed, passing packet");
        return XDP_PASS;
    }

    int created = update_stats(&key, ctx, 1);
    bpf_printk("[MAIN] Stats update result: %d (1=created, 0=updated, -1=error)", created);

    data_point *target = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
    if (!target) {
        bpf_printk("[MAIN] ERROR: Cannot lookup target after update");
        return XDP_PASS;
    }

    bpf_printk("[MAIN] Computing LOF for target flow port %u", key.src_port);
    
    compute_k_distance_and_lrd(target);
    compute_lof_for_target(target);

    bpf_printk("[MAIN] Target results: k_dist=%lld, lrd=%lld, lof=%lld", 
               target->k_distance, target->lrd_value, target->lof_value);

    struct affected_ctx actx = {
        .target = target,
        .target_kdist = target->k_distance,
        .map = &xdp_flow_tracking,
        .affected_count = 0,
    };

    bpf_printk("[MAIN] Updating affected neighbors...");
    long ret = bpf_for_each_map_elem(&xdp_flow_tracking, update_affected_callback, &actx, 0);
    if (ret < 0) {
        bpf_printk("[MAIN] ERROR: affected neighbors update failed: %ld", ret);
    } else {
        bpf_printk("[MAIN] Updated %d affected neighbors", actx.affected_count);
    }

    __u32 ip_le = bpf_ntohl(key.src_ip);
    __u32 a = (ip_le >> 24) & 0xff;
    __u32 b = (ip_le >> 16) & 0xff;
    __u32 c = (ip_le >>  8) & 0xff;
    __u32 d = (ip_le >>  0) & 0xff;

    bpf_printk("=== [FINAL] Flow %u.%u.%u.%u:%u pkts=%u bytes=%u meanIAT=%u kdist=%lld lrd=%lld lof=%lld (created=%d) ===",
               a, b, c, d, key.src_port,
               target->total_pkts, target->total_bytes, target->flow_IAT_mean,
               target->k_distance, target->lrd_value, target->lof_value, created);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
