#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC     1000000000ULL
#define MAX_FLOW_SAVED      100

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

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct krnn_entries);
    __uint(max_entries, UPDATE_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
}xdp_update SEC(".maps");

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
    for (int i = 0; i < 4; i++) {
        prev = res;
        res = (res + x / res) >> 1;
        if (res == prev)
            break;
    }
    return res;
}

static __always_inline int update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts = bpf_ktime_get_ns();
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
        zero.lrd_value = 0;
        zero.lof_value = 0;
        for (int i = 0; i < KNN; i++)
            zero.reach_dist[i] = 0;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return -1;
        return 1;
    }

    __u64 iat_ns = (ts >= dp->last_seen) ? ts - dp->last_seen : 0;
    lock_xadd(&dp->total_pkts, 1);
    lock_xadd(&dp->total_bytes, pkt_len);

    if (iat_ns > 0)
        dp->sum_IAT += iat_ns;

    dp->last_seen = ts;
    dp->flow_IAT_mean = (dp->total_pkts > 1) ? dp->sum_IAT / (dp->total_pkts - 1) : 0;

    return 0;
}

static __always_inline __u16 euclidean_distance(const data_point *a, const data_point *b)
{
    __u64 fx = (a->total_bytes > b->total_bytes) ? a->total_bytes - b->total_bytes : b->total_bytes - a->total_bytes;
    __u64 fy = (a->total_pkts > b->total_pkts) ? a->total_pkts - b->total_pkts : b->total_pkts - a->total_pkts;
    __u64 fz = (a->flow_IAT_mean > b->flow_IAT_mean) ? a->flow_IAT_mean - b->flow_IAT_mean : b->flow_IAT_mean - a->flow_IAT_mean;
    __u64 flow_dur_a = a->last_seen - a->start_ts;
    __u64 flow_dur_b = b->last_seen - b->start_ts;
    __u64 fw = (flow_dur_a > flow_dur_b) ? flow_dur_a - flow_dur_b : flow_dur_b - flow_dur_a;

    __u8 dx = ilog2_u64(fx);
    __u8 dy = ilog2_u64(fy);
    __u8 dz = ilog2_u64(fz);
    __u8 dw = ilog2_u64(fw);

    __u32 sum = dx*dx + dy*dy + dz*dz + dw*dw;
    __u16 root = bpf_sqrt(sum);

    return (root > UINT16_MAX) ? UINT16_MAX : root;
}

static int callback_knn(void *map, const void *key, void *value, void *ctx)
{
    struct knn_context *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || __builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    __u16 dist = euclidean_distance(c->target, neighbor);
    int index_max = 0;
    __u16 dist_max = c->results[0].distance;
#pragma unroll
    for (int i = 1; i < KNN; i++) {
        if (c->results[i].distance > dist_max) {
            dist_max = c->results[i].distance;
            index_max = i;
        }
    }

    if (dist < dist_max) {
        c->results[index_max].distance = dist;
        __builtin_memcpy(&c->results[index_max].key, key, sizeof(struct flow_key));
    }
    return 0;
}

static __always_inline void compute_reach_dist(data_point *target_dp, struct knn_entry *results)
{
    for (int i = 0; i < KNN; i++) {
        if (results[i].distance == 0xffff)
            break;

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &results[i].key);
        if (!neighbor_dp)
            continue;

        __u16 dist = euclidean_distance(target_dp, neighbor_dp);
        target_dp->reach_dist[i] = (dist > neighbor_dp->k_distance) ? dist : neighbor_dp->k_distance;
    }
}

static __always_inline int find_knn(const struct flow_key *target_key,
                                   data_point *target,
                                   struct knn_entry *results)
{
    #pragma unroll
    for (int i = 0; i < KNN; i++) {
        __builtin_memset(&results[i].key, 0, sizeof(struct flow_key));
        results[i].distance = 0xffff;
    }

    struct knn_context ctx = {
        .target_key = target_key,
        .target = target,
        .results = results,
    };

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn, &ctx, 0);
    compute_reach_dist(target, ctx.results);
    return 0;
}

struct krnn_callback_ctx {
    const struct flow_key *target_key;   /* flow đang xét */
    const data_point *target_dp;         /* dữ liệu của flow target */
    __u16 k_distance;                    /* khoảng cách k-NN hiện tại */
    int K;                               /* số k lân cận */
};

/* Callback: kiểm tra xem target có nằm trong KNN của neighbor không */
static int callback_krnn(void *map, const void *key, void *value, void *ctx)
{
    struct krnn_callback_ctx *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || __builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    struct knn_entry knn_results[KNN];
    find_knn((const struct flow_key *)key, neighbor, knn_results);

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_results[i].distance == 0xffff)
            break;

        if (__builtin_memcmp(&knn_results[i].key, c->target_key, sizeof(struct flow_key)) == 0) {
            /* Update k-distance cho neighbor */
            neighbor->k_distance = knn_results[KNN - 1].distance;

            /* Ghi vào map kết quả RNN */
            struct krnn_entry *stored = bpf_map_lookup_elem(&xdp_update, c->target_key);
            if (!stored)
                return 0;

#pragma unroll
            for (int j = 0; j < UPDATE_MAX; j++) {
                if (stored[j].distance == 0xffff) {
                    stored[j].distance = knn_results[i].distance;
                    __builtin_memcpy(&stored[j].key, key, sizeof(struct flow_key));
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

static __always_inline int find_krnn(const struct flow_key *target_key,
                                    const data_point *target)
{
    /* Khởi tạo mảng rỗng trong map */
    struct krnn_entry empty[UPDATE_MAX];
#pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&empty[i].key, 0, sizeof(struct flow_key));
        empty[i].distance = 0xffff;
    }
    bpf_map_update_elem(&xdp_update, target_key, empty, BPF_ANY);

    /* Truyền target_key xuống callback */
    struct krnn_callback_ctx {
        const struct flow_key *target_key;
        const data_point *target;
    } ctx = {
        .target_key = target_key,
        .target = target,
    };

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_krnn, &ctx, 0);

    return 0;
}

static __always_inline bool is_key_in_update_set(const struct flow_key *key, 
                                                struct update_lrd_entry *update_set, 
                                                int count)
{
    #pragma unroll
    for (int i = 0; i < count && i < UPDATE_MAX; i++) {
        if (update_set[i].is_valid && 
            __builtin_memcmp(key, &update_set[i].key, sizeof(struct flow_key)) == 0) {
            return true;
        }
    }
    return false;
}

static __always_inline int add_to_update_set(const struct flow_key *key,
                                            struct update_lrd_entry *update_set,
                                            int *count,
                                            int max_size)
{
    if (*count >= max_size)
        return -1;

    if (is_key_in_update_set(key, update_set, *count))
        return 0;

    __builtin_memcpy(&update_set[*count].key, key, sizeof(struct flow_key));
    update_set[*count].is_valid = true;
    (*count)++;
    return 1;
}

static int callback_knn_for_update(void *map, const void *key, void *value, void *ctx)
{
    struct knn_for_update_context *c = ctx;
    data_point *neighbor = value;

    if (!neighbor || __builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0)
        return 0;

    __u16 dist = euclidean_distance(c->target_dp, neighbor);
    if (dist <= c->target_dp->k_distance) {
        add_to_update_set((const struct flow_key *)key, c->update_set, 
                         c->update_count, c->max_size);
    }
    return 0;
}


/* Từ target và các krnn trong map, xác định tập update LRD */
static __always_inline int determine_update_lrd_set(const struct flow_key *target_key,
                                                   const data_point *target_dp,
                                                   struct update_lrd_entry *update_set)
{
    int update_count = 0;
    add_to_update_set(target_key, update_set, &update_count, UPDATE_MAX);

    /* Lấy tất cả krnn_entry trong map */
    struct krnn_entry *kr;
    // struct flow_key lookup_key = {};
    __u32 i = 0;

#pragma unroll
    for (i = 0; i < UPDATE_MAX; i++) {
        /* ở đây giả sử target_key là key để lookup nhiều krnn_entry khác nhau */
        kr = bpf_map_lookup_elem(&xdp_update, (void *)target_key);
        if (!kr)
            break;
        if (kr->distance == 0xffff)
            break;

        add_to_update_set(&kr->key, update_set, &update_count, UPDATE_MAX);

        /* lấy data_point của krnn để mở rộng tập update */
        data_point *krnn_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &kr->key);
        if (!krnn_dp)
            continue;

        struct knn_for_update_context ctx = {
            .target_key = &kr->key,
            .target_dp = krnn_dp,
            .update_set = update_set,
            .update_count = &update_count,
            .max_size = UPDATE_MAX,
            .K = KNN
        };
        bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn_for_update, &ctx, 0);
    }

    return update_count;
}

/* Tính LRD cho 1 data_point */
static __always_inline void compute_lrd(data_point *dp, const struct flow_key *key)
{
    __u64 sum_reach_dist = 0;
    int valid_neighbors = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (dp->reach_dist[i] > 0) {
            sum_reach_dist += dp->reach_dist[i];
            valid_neighbors++;
        }
    }

    dp->lrd_value = (valid_neighbors > 0 && sum_reach_dist > 0) ?
                    (__u16)(((__u64)valid_neighbors * 1000) / sum_reach_dist) : 0;
}

/* Update LRD cho các điểm trong update_set */
static __always_inline void update_lrd_for_set(struct update_lrd_entry *update_set, 
                                              int update_count)
{
#pragma unroll
    for (int i = 0; i < update_count && i < UPDATE_MAX; i++) {
        if (!update_set[i].is_valid)
            continue;

        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &update_set[i].key);
        if (!dp)
            continue;

        struct knn_entry knn_results[KNN];
        find_knn(&update_set[i].key, dp, knn_results);
        compute_lrd(dp, &update_set[i].key);
    }
}


/* Tính LOF */
static __always_inline void compute_lof(data_point *dp, 
                                       const struct flow_key *key,
                                       struct knn_entry *knn_results)
{
    __u64 sum_lrd_ratio = 0;
    int valid_neighbors = 0;

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_results[i].distance == 0xffff)
            break;

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_results[i].key);
        if (!neighbor_dp)
            continue;

        if (dp->lrd_value > 0 && neighbor_dp->lrd_value > 0) {
            __u64 ratio = ((__u64)neighbor_dp->lrd_value * 1000) / dp->lrd_value;
            sum_lrd_ratio += ratio;
            valid_neighbors++;
        }
    }

    dp->lof_value = (valid_neighbors > 0) ? (__u16)(sum_lrd_ratio / valid_neighbors) : 1000;
}

/* Update LOF cho update_set */
static __always_inline void update_lof_for_set(struct update_lrd_entry *update_set, 
                                              int update_count)
{
#pragma unroll
    for (int i = 0; i < update_count && i < UPDATE_MAX; i++) {
        if (!update_set[i].is_valid)
            continue;

        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &update_set[i].key);
        if (!dp)
            continue;

        struct knn_entry knn_results[KNN];
        find_knn(&update_set[i].key, dp, knn_results);
        compute_lof(dp, &update_set[i].key, knn_results);
    }
}

/* bước 1: update LRD */
static __always_inline int lof_update_lrd_step(const struct flow_key *target_key,
                                              const data_point *target_dp)
{
    struct update_lrd_entry update_set[UPDATE_MAX];
#pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&update_set[i].key, 0, sizeof(struct flow_key));
        update_set[i].is_valid = false;
    }

    int update_count = determine_update_lrd_set(target_key, target_dp, update_set);
    if (update_count <= 0)
        return -1;

    update_lrd_for_set(update_set, update_count);
    return update_count;
}

/* bước 2: update LOF */
static __always_inline int lof_final_step(const struct flow_key *target_key,
                                         data_point *target_dp)
{
    struct update_lrd_entry update_lof_set[UPDATE_MAX];
    int update_lof_count = 0;

#pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&update_lof_set[i].key, 0, sizeof(struct flow_key));
        update_lof_set[i].is_valid = false;
    }

    update_lof_count = determine_update_lrd_set(target_key, target_dp, update_lof_set);

    update_lof_for_set(update_lof_set, update_lof_count);

    struct knn_entry target_knn[KNN];
    find_knn(target_key, target_dp, target_knn);
    compute_lof(target_dp, target_key, target_knn);

    return 0;
}

/* entry point cho incremental LOF */
static __always_inline int incremental_lof_insertion(const struct flow_key *target_key,
                                                    data_point *target_dp)
{
    // dùng map xdp_update để lưu kết quả krnn
    int krnn_count = find_krnn(target_key, target_dp);

    if (krnn_count <= 0)
        return -1;

    // update LRD trước
    int lrd_updated = lof_update_lrd_step(target_key, target_dp);
    if (lrd_updated < 0)
        return -1;

    // update LOF
    return lof_final_step(target_key, target_dp);
}

/* Kiểm tra flow có phải bất thường hay không dựa trên LOF */
static __always_inline bool is_anomaly(const data_point *dp, __u16 threshold)
{
    return dp->lof_value > threshold;
}

/* Thực hiện chèn điểm mới vào mô hình LOF + kiểm tra bất thường */
static __always_inline int detect_anomaly_lof(struct flow_key *key,
                                             struct xdp_md *ctx,
                                             __u16 anomaly_threshold)
{
    /* Tìm data_point tương ứng trong flow_tracking */
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp || dp->total_pkts < 3)
        return 0;  /* không đủ dữ liệu để tính LOF */

    /* Cập nhật incremental LOF cho flow */
    int result = incremental_lof_insertion(key, dp);
    if (result < 0)
        return 0;

    /* So sánh LOF với ngưỡng để quyết định anomaly */
    return is_anomaly(dp, anomaly_threshold) ? 1 : 0;
}

/* Chương trình XDP chính */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    /* Parse packet ra flow_key */
    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    /* Cập nhật thống kê cho flow */
    if (update_stats(&key, ctx) < 0)
        return XDP_PASS;

    /* Chạy phát hiện anomaly bằng LOF */
    int anomaly_detected = detect_anomaly_lof(&key, ctx, 1500);
    if (anomaly_detected) {
        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
        if (dp) {
            bpf_printk("Anomaly detected: src_ip=%u, src_port=%u, LOF=%u\n",
                       key.src_ip, key.src_port, (unsigned int)dp->lof_value);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";