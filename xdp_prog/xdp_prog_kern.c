// SPDX-License-Identifier: GPL-2.0
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

#define UPDATE_MAX (7)

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

/* knn scan callback - keep minimal, no printk inside */
struct knn_entry{
    struct flow_key key;
    __u16 distance;
};

struct knn_context{
    const struct flow_key *target_key;
    data_point *target;
    struct knn_entry *results;
    int k;
};

static int callback_knn(void *map, const void *key, void *value, void *ctx){
    struct knn_context *c = ctx;
    data_point *neighbor = value;

    if(!neighbor)
        return 0;
    
    if(__builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0){
        return 0;
    }

    __u16 dist = euclidean_distance(c->target, neighbor);

    int index_max = 0;
    __u16 dist_max =  c->results[0].distance;
    #pragma unroll
    for(int i = 1; i < KNN; i++){
        if(c->results[i].distance > dist_max){
            dist_max = c->results[i].distance;
            index_max = i;
        }
    }

    if (dist < dist_max){
        c->results[index_max].distance = dist;
        /* BUGFIX: ghi đúng key vào vị trí kết quả (memcpy thay vì memcmp) */
        __builtin_memcpy(&c->results[index_max].key, key, sizeof(struct flow_key));
    }
    return 0;
}

static __always_inline void compute_reach_dist(data_point *target_dp, struct knn_entry *results, int K){
    #pragma unroll
    for(int i = 0; i < KNN; i++){
        if(results[i].distance == 0xffff)
        {
            return;
        }

        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &results[i].key);
        if(!neighbor_dp){
            continue;
        }

        __u16 dist = euclidean_distance(target_dp, neighbor_dp);
        __u16 neighbor_kdist = neighbor_dp->k_distance;

        __u16 reach = dist > neighbor_kdist ? dist : neighbor_kdist;

        target_dp->reach_dist[i] = reach;
    }
}

static __always_inline int find_knn(const struct flow_key *target_key,
                                    data_point *target,
                                    struct knn_entry *results,
                                    int K)
{
    #pragma unroll
    for (int i = 0; i < K; i++) {
        __builtin_memset(&results[i].key, 0, sizeof(struct flow_key));
        results[i].distance = 0xffff;
    }

    struct knn_context ctx = {
        .target_key = target_key,
        .target     = target,
        .results    = results,
        .k          = K,
    };

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_knn, &ctx, 0);
    
    /* BUGFIX: dùng K thực tế thay vì KNN hằng số */
    compute_reach_dist(target, ctx.results, K);

    return 0;
}

struct krnn_entry{
    struct flow_key key;
    __u16 distance;
};

struct krnn_context{
    const struct flow_key *target_key;
    const data_point *target;
    struct krnn_entry *results;
    int K;
    int count;
};

static int callback_krnn(void *map, const void *key, void *value, void *ctx){
    struct krnn_context *c = ctx;
    data_point *neighbor = value;
    struct knn_entry knn_results[KNN];
    if(!neighbor){
        return 0;
    }

    if(__builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0){
        return 0;
    }

    find_knn((const struct flow_key *)key, neighbor, knn_results, c->K);

    #pragma unroll
    for(int i = 0; i < KNN; i++){
        if(knn_results[i].distance == 0xffff){
            break;
        }
        if (__builtin_memcmp(&knn_results[i].key, c->target_key, sizeof(struct flow_key)) == 0) {
            // Update k-distance
            neighbor->k_distance = knn_results[c->K - 1].distance;
            // thêm vào kết quả KRNN
            c->results[c->count].distance = knn_results[i].distance;
            __builtin_memcpy(&c->results[c->count].key, key, sizeof(struct flow_key));
            c->count++;
            break;
        }
    }

    return 0;
}

static __always_inline int find_krnn(const struct flow_key *target_key,
                                     const data_point *target,
                                     struct krnn_entry *results,
                                     int K)
{
    struct krnn_context ctx = {
        .target_key = target_key,
        .target     = target,
        .results    = results,
        .K          = K,
        .count      = 0,
    };

    #pragma unroll
    for (int i = 0; i < K; i++) {
        __builtin_memset(&results[i].key, 0, sizeof(struct flow_key));
        results[i].distance = 0xffff;
    }

    bpf_for_each_map_elem(&xdp_flow_tracking, callback_krnn, &ctx, 0);

    return ctx.count;
}

// Thêm vào phần sau find_krnn() trong code của bạn

struct update_lrd_entry {
    struct flow_key key;
    bool is_valid;
};

struct update_lrd_context {
    struct update_lrd_entry *update_set;
    int count;
    int max_size;
};

// Hàm kiểm tra xem một key đã có trong update_set chưa
static __always_inline bool is_key_in_update_set(const struct flow_key *key, 
                                                 struct update_lrd_entry *update_set, 
                                                 int count) {
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (i >= count) break;
        if (!update_set[i].is_valid) continue;
        
        if (__builtin_memcmp(key, &update_set[i].key, sizeof(struct flow_key)) == 0) {
            return true;
        }
    }
    return false;
}

// Hàm thêm key vào update_set (nếu chưa có)
static __always_inline int add_to_update_set(const struct flow_key *key,
                                             struct update_lrd_entry *update_set,
                                             int *count,
                                             int max_size) {
    if (*count >= max_size) {
        return -1; // Đầy rồi
    }
    
    // Kiểm tra xem đã có chưa
    if (is_key_in_update_set(key, update_set, *count)) {
        return 0; // Đã có rồi
    }
    
    // Thêm mới
    __builtin_memcpy(&update_set[*count].key, key, sizeof(struct flow_key));
    update_set[*count].is_valid = true;
    (*count)++;
    return 1; // Thêm thành công
}

// Callback để tìm kNN của một điểm cụ thể và thêm vào update_set
struct knn_for_update_context {
    const struct flow_key *target_key;
    const data_point *target_dp;
    struct update_lrd_entry *update_set;
    int *update_count;
    int max_size;
    int K;
};

static int callback_knn_for_update(void *map, const void *key, void *value, void *ctx) {
    struct knn_for_update_context *c = ctx;
    data_point *neighbor = value;
    
    if (!neighbor) return 0;
    
    if (__builtin_memcmp(key, c->target_key, sizeof(struct flow_key)) == 0) {
        return 0;
    }
    
    __u16 dist = euclidean_distance(c->target_dp, neighbor);
    
    if (dist <= c->target_dp->k_distance) {
        add_to_update_set((const struct flow_key *)key, c->update_set, 
                         c->update_count, c->max_size);
    }
    return 0;
}

// Hàm chính để xác định tập update_lrd
static __always_inline int determine_update_lrd_set(const struct flow_key *target_key,
                                                    const data_point *target_dp,
                                                    struct krnn_entry *krnn_results,
                                                    int krnn_count,
                                                    struct update_lrd_entry *update_set) {
    int update_count = 0;
    
    // Bước 1: Thêm chính target point vào update_set
    add_to_update_set(target_key, update_set, &update_count, UPDATE_MAX);
    
    // Bước 2: Thêm tất cả các điểm trong kRNN (S_update_k_distance)
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (i >= krnn_count) break;
        if (krnn_results[i].distance == 0xffff) break;
        
        add_to_update_set(&krnn_results[i].key, update_set, &update_count, UPDATE_MAX);
    }
    
    // Bước 3: Với mỗi điểm trong kRNN, tìm kNN của nó và thêm vào update_set
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (i >= krnn_count) break;
        if (krnn_results[i].distance == 0xffff) break;
        if (update_count >= UPDATE_MAX) break;
        
        // Lấy data_point của điểm trong kRNN
        data_point *krnn_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &krnn_results[i].key);
        if (!krnn_dp) continue;
        
        // Tìm kNN của điểm này và thêm vào update_set
        struct knn_for_update_context ctx = {
            .target_key = &krnn_results[i].key,
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

// Hàm tính LRD cho một điểm
static __always_inline void compute_lrd(data_point *dp, const struct flow_key *key) {
    if (!dp) return;
    
    __u64 sum_reach_dist = 0;
    int valid_neighbors = 0;
    
    #pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (dp->reach_dist[i] > 0) {
            sum_reach_dist += dp->reach_dist[i];
            valid_neighbors++;
        }
    }
    
    if (valid_neighbors > 0 && sum_reach_dist > 0) {
        // LRD = k / sum(reach-dist(p,o))
        // Để tránh chia floating point, ta lưu nghịch đảo tỷ lệ
        dp->lrd_value = (__u16)(((__u64)valid_neighbors * 1000) / sum_reach_dist);
    } else {
        dp->lrd_value = 0;
    }
}

// Hàm cập nhật LRD cho tất cả điểm trong update_set
static __always_inline void update_lrd_for_set(struct update_lrd_entry *update_set, 
                                               int update_count) {
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (i >= update_count) break;
        if (!update_set[i].is_valid) continue;
        
        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &update_set[i].key);
        if (!dp) continue;
        
        // Tính lại kNN và reach-dist cho điểm này
        struct knn_entry knn_results[KNN];
        find_knn(&update_set[i].key, dp, knn_results, KNN);
        
        // Tính LRD mới
        compute_lrd(dp, &update_set[i].key);
    }
}

// Hàm chính để thực hiện bước update LRD trong thuật toán LOF
static __always_inline int lof_update_lrd_step(const struct flow_key *target_key,
                                               const data_point *target_dp,
                                               struct krnn_entry *krnn_results,
                                               int krnn_count) {
    struct update_lrd_entry update_set[UPDATE_MAX];
    
    // Khởi tạo update_set
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&update_set[i].key, 0, sizeof(struct flow_key));
        update_set[i].is_valid = false;
    }
    
    // Xác định tập update_lrd
    int update_count = determine_update_lrd_set(target_key, target_dp, 
                                               krnn_results, krnn_count, update_set);
    
    if (update_count <= 0) {
        return -1;
    }
    
    // Cập nhật LRD cho tất cả điểm trong tập
    update_lrd_for_set(update_set, update_count);
    
    return update_count;
}

// Hàm tính LOF cho một điểm dựa trên kNN của nó
static __always_inline void compute_lof(data_point *dp, 
                                       const struct flow_key *key,
                                       struct knn_entry *knn_results) {
    if (!dp) return;
    
    __u64 sum_lrd_ratio = 0;
    int valid_neighbors = 0;
    
    #pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (knn_results[i].distance == 0xffff) break;
        
        data_point *neighbor_dp = bpf_map_lookup_elem(&xdp_flow_tracking, &knn_results[i].key);
        if (!neighbor_dp) continue;
        
        // Tính tỷ lệ LRD(neighbor) / LRD(dp)
        // Để tránh chia floating point, ta sử dụng phép nhân chéo
        if (dp->lrd_value > 0 && neighbor_dp->lrd_value > 0) {
            // Tỷ lệ = neighbor_lrd / dp_lrd
            // Nhân với 1000 để tăng độ chính xác
            __u64 ratio = ((__u64)neighbor_dp->lrd_value * 1000) / dp->lrd_value;
            sum_lrd_ratio += ratio;
            valid_neighbors++;
        }
    }
    
    if (valid_neighbors > 0) {
        // LOF = (1/k) * sum(LRD(neighbor)/LRD(dp))
        dp->lof_value = (__u16)(sum_lrd_ratio / valid_neighbors);
    } else {
        dp->lof_value = 1000; // LOF = 1.0 (nhân 1000)
    }
}

// Hàm cập nhật LOF cho tất cả điểm trong tập update_lof
static __always_inline void update_lof_for_set(struct update_lrd_entry *update_set, 
                                               int update_count) {
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (i >= update_count) break;
        if (!update_set[i].is_valid) continue;
        
        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &update_set[i].key);
        if (!dp) continue;
        
        // Tìm kNN của điểm này để tính LOF
        struct knn_entry knn_results[KNN];
        find_knn(&update_set[i].key, dp, knn_results, KNN);
        
        // Tính LOF mới
        compute_lof(dp, &update_set[i].key, knn_results);
    }
}

// Hàm thêm kRNN(pc) vào tập update_lof
static __always_inline int add_krnn_to_update_lof(struct krnn_entry *krnn_results,
                                                  int krnn_count,
                                                  struct update_lrd_entry *update_set,
                                                  int *update_count) {
    #pragma unroll
    for (int i = 0; i < KNN; i++) {
        if (i >= krnn_count) break;
        if (krnn_results[i].distance == 0xffff) break;
        
        add_to_update_set(&krnn_results[i].key, update_set, update_count, UPDATE_MAX);
    }
    
    return 0;
}

// Hàm chính thực hiện bước cuối: update LOF và tính LOF cho điểm mới
static __always_inline int lof_final_step(const struct flow_key *target_key,
                                         data_point *target_dp,
                                         struct krnn_entry *krnn_results,
                                         int krnn_count) {
    struct update_lrd_entry update_lof_set[UPDATE_MAX];
    int update_lof_count = 0;
    
    // Khởi tạo update_lof_set
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        __builtin_memset(&update_lof_set[i].key, 0, sizeof(struct flow_key));
        update_lof_set[i].is_valid = false;
    }
    
    // S_update_lof = S_update_lrd (đã có từ bước trước)
    // Tái tạo S_update_lrd từ kRNN
    determine_update_lrd_set(target_key, target_dp, krnn_results, 
                           krnn_count, update_lof_set);
    update_lof_count = 0;
    
    // Đếm lại số phần tử hợp lệ
    #pragma unroll
    for (int i = 0; i < UPDATE_MAX; i++) {
        if (update_lof_set[i].is_valid) {
            update_lof_count++;
        }
    }
    
    // Thêm kRNN(pc) vào S_update_lof
    add_krnn_to_update_lof(krnn_results, krnn_count, update_lof_set, &update_lof_count);
    
    // Cập nhật LOF cho tất cả điểm trong S_update_lof
    update_lof_for_set(update_lof_set, update_lof_count);
    
    // Tính LOF cho điểm mới (pc)
    struct knn_entry target_knn[KNN];
    find_knn(target_key, target_dp, target_knn, KNN);
    compute_lof(target_dp, target_key, target_knn);
    
    return 0;
}

// Hàm tổng hợp thực hiện toàn bộ thuật toán LOF incremental
static __always_inline int incremental_lof_insertion(const struct flow_key *target_key,
                                                    data_point *target_dp) {
    struct krnn_entry krnn_results[KNN];
    
    // Bước 1: Tìm kRNN của điểm mới và cập nhật k-distance
    int krnn_count = find_krnn(target_key, target_dp, krnn_results, KNN);
    
    // Bước 2: Update LRD cho tập S_update_lrd
    int lrd_updated = lof_update_lrd_step(target_key, target_dp, krnn_results, krnn_count);
    if (lrd_updated < 0) {
        return -1;
    }
    
    // Bước 3: Update LOF và tính LOF cho điểm mới
    int final_result = lof_final_step(target_key, target_dp, krnn_results, krnn_count);
    
    return final_result;
}

// Hàm kiểm tra anomaly dựa trên LOF threshold
static __always_inline bool is_anomaly(const data_point *dp, __u16 threshold) {
    // threshold đã được nhân 1000 (ví dụ: 1500 = 1.5)
    return (dp->lof_value > threshold);
}

// Hàm chính để gọi trong XDP program
static __always_inline int detect_anomaly_lof(struct flow_key *key, 
                                              struct xdp_md *ctx,
                                              __u16 anomaly_threshold) {
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        return 0; // Điểm mới, chưa đủ dữ liệu
    }
    
    // Chỉ thực hiện LOF nếu có đủ dữ liệu (ít nhất một vài packets)
    if (dp->total_pkts < 3) {
        return 0;
    }
    
    // Thực hiện thuật toán LOF incremental
    int result = incremental_lof_insertion(key, dp);
    if (result < 0) {
        return 0; // Lỗi trong quá trình tính toán
    }
    
    // Kiểm tra anomaly
    if (is_anomaly(dp, anomaly_threshold)) {
        return 1; // Phát hiện anomaly
    }
    
    return 0; // Bình thường
}

// Ví dụ cách tích hợp vào XDP program chính
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx) {
    struct flow_key key = {};
    __u64 pkt_len = 0;
    
    // Parse packet để lấy flow key
    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) {
        return XDP_PASS;
    }
    
    // Cập nhật thống kê flow
    int update_result = update_stats(&key, ctx, 1);
    if (update_result < 0) {
        return XDP_PASS; // Lỗi trong việc update stats
    }
    
    // Phát hiện anomaly sử dụng LOF
    // Threshold 1500 = 1.5 (LOF > 1.5 được coi là anomaly)
    int anomaly_detected = detect_anomaly_lof(&key, ctx, 1500);
    
    if (anomaly_detected) {
        // Hành động khi phát hiện anomaly
        // Có thể DROP packet hoặc ghi log
        data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, &key);
        __u16 lof = 0;
        if (dp) {
            lof = dp->lof_value;
        }
        bpf_printk("Anomaly detected: src_ip=%u, src_port=%u, LOF=%u\n", 
                   key.src_ip, key.src_port, (unsigned int)lof);
        
        // Uncomment dòng dưới nếu muốn drop anomalous traffic
        // return XDP_DROP;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
