/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" /* defines: struct datarec, flow_key, flow_stats, data_point */

#define NANOSEC_PER_SEC 1000000000ULL
#define MAX_FLOW_SAVED 100

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

/*================= MAPS =================*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);            // index
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dp_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u32);   // index trong dp_array
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_index_map SEC(".maps");

static __always_inline int is_forward(const struct flow_key *key,
                                      __u32 pkt_src_ip, __u16 pkt_src_port,
                                      __u32 pkt_dst_ip, __u16 pkt_dst_port)
{
    return pkt_src_ip == key->src_ip
        && pkt_src_port == key->src_port
        && pkt_dst_ip == key->dst_ip
        && pkt_dst_port == key->dst_port;
}

/* ================= PACKET PARSER =================*/
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->protocol = iph->protocol;
    key->src_ip   = iph->saddr;
    key->dst_ip   = iph->daddr;

    __u16 src_port = 0, dst_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        src_port = udph->source;
        dst_port = udph->dest;
    } else {
        src_port = 0;
        dst_port = 0;
    }

    key->src_port = bpf_ntohs(src_port);
    key->dst_port = bpf_ntohs(dst_port);

    *pkt_len = (__u64)(data_end - data);
    return 0;
}

/* Global counter để gán index cho flow mới */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);       // luôn dùng key = 0
    __type(value, __u32);     // flow_count
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_counter SEC(".maps");


static __always_inline void update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)(ctx->data_end - ctx->data);

    /* ================= Lookup or insert flow_stats ================= */
    struct flow_stats new_stats = {};
    struct flow_stats *stats = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    __u32 idx = 0;

    if (!stats) {
        // New flow
        new_stats.time_start_ns = ts;
        new_stats.time_end_ns   = ts;

        if (is_fwd) {
            new_stats.fwd_pkt_count = 1;
            new_stats.total_fwd_len = pkt_len;
        } else {
            new_stats.bwd_pkt_count = 1;
            new_stats.total_bwd_len = pkt_len;
        }

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &new_stats, BPF_ANY) != 0) {
            bpf_printk("Failed to insert new flow_stats\n");
            return;
        }

        // ================= Gán index cho flow mới =================
        __u32 zero = 0;
        __u32 *flow_count = bpf_map_lookup_elem(&flow_counter, &zero);
        if (!flow_count) {
            bpf_printk("Failed to read flow_counter\n");
            return;
        }

        idx = *flow_count;  // gán index = flow_count hiện tại

        // lưu key -> index
        if (bpf_map_update_elem(&flow_index_map, key, &idx, BPF_ANY) != 0) {
            bpf_printk("Failed to insert new flow_index_map\n");
            return;
        }

        // tăng counter
        __sync_fetch_and_add(flow_count, 1);

        // lấy pointer trong map
        stats = bpf_map_lookup_elem(&xdp_flow_tracking, key);
        if (!stats) {
            bpf_printk("Failed to lookup after insert\n");
            return;
        }

    } else {
        // ================= Update existing flow =================
        __u64 iat = ts - stats->time_end_ns;
        __sync_fetch_and_add(&stats->sum_iat_ns, iat);
        stats->time_end_ns = ts;

        if (is_fwd) {
            __sync_fetch_and_add(&stats->fwd_pkt_count, 1);
            __sync_fetch_and_add(&stats->total_fwd_len, pkt_len);
        } else {
            __sync_fetch_and_add(&stats->bwd_pkt_count, 1);
            __sync_fetch_and_add(&stats->total_bwd_len, pkt_len);
        }

        // lấy index từ flow_index_map
        __u32 *idx_ptr = bpf_map_lookup_elem(&flow_index_map, key);
        if (!idx_ptr) {
            bpf_printk("Flow exists but no index found!\n");
            return;
        }
        idx = *idx_ptr;
    }

    /* ================= Update dp_array ================= */
    data_point dp = {};
    dp.flow_bytes_per_sec   = stats->total_fwd_len + stats->total_bwd_len;
    dp.flow_packets_per_sec = stats->fwd_pkt_count + stats->bwd_pkt_count;
    dp.flow_duration        = stats->time_end_ns - stats->time_start_ns;
    if (dp.flow_packets_per_sec > 0)
        dp.flow_IAT_mean = stats->sum_iat_ns / dp.flow_packets_per_sec;

    if (bpf_map_update_elem(&dp_array, &idx, &dp, BPF_ANY) != 0) {
        bpf_printk("Failed to update dp_array at index %u\n", idx);
    }
}

// static __always_inline void update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
// {
//     __u64 ts = bpf_ktime_get_ns();
//     __u64 pkt_len = (__u64)(ctx->data_end - ctx->data);

//     // Lookup flow_stats
//     struct flow_stats new_stats = {};
//     struct flow_stats *stats = bpf_map_lookup_elem(&xdp_flow_tracking, key);

//     __u32 idx = 0;

//     if (!stats) {
//         // New flow
//         new_stats.time_start_ns = ts;
//         new_stats.time_end_ns   = ts;

//         if (is_fwd) {
//             new_stats.fwd_pkt_count = 1;
//             new_stats.total_fwd_len = pkt_len;
//         } else {
//             new_stats.bwd_pkt_count = 1;
//             new_stats.total_bwd_len = pkt_len;
//         }

//         // Update flow_stats map
//         if (bpf_map_update_elem(&xdp_flow_tracking, key, &new_stats, BPF_ANY) != 0) {
//             bpf_printk("Failed to insert new flow_stats\n");
//             return;
//         }

//         // Lấy index = flow_count (bắt đầu từ 0)
//         // __u32 *flow_count_ptr = bpf_map_lookup_elem(&flow_index_map, &idx);
//         // Ở lần đầu flow_count chưa có → dùng idx = 0
//         // Bạn có thể thay bằng counter global nếu muốn chính xác
//         idx = 0;

//         // Lưu index vào flow_index_map
//         if (bpf_map_update_elem(&flow_index_map, key, &idx, BPF_ANY) != 0) {
//             bpf_printk("Failed to insert new flow_index_map\n");
//             return;
//         }

//         // Lấy pointer trong map sau khi update
//         stats = bpf_map_lookup_elem(&xdp_flow_tracking, key);
//         if (!stats) {
//             bpf_printk("Failed to lookup after insert\n");
//             return;
//         }
//     } else {
//         // Update existing flow
//         __u64 iat = ts - stats->time_end_ns;
//         __sync_fetch_and_add(&stats->sum_iat_ns, iat);
//         stats->time_end_ns = ts;

//         if (is_fwd) {
//             __sync_fetch_and_add(&stats->fwd_pkt_count, 1);
//             __sync_fetch_and_add(&stats->total_fwd_len, pkt_len);
//         } else {
//             __sync_fetch_and_add(&stats->bwd_pkt_count, 1);
//             __sync_fetch_and_add(&stats->total_bwd_len, pkt_len);
//         }

//         // Lấy index từ flow_index_map
//         __u32 *idx_ptr = bpf_map_lookup_elem(&flow_index_map, key);
//         if (!idx_ptr) {
//             bpf_printk("Flow exists but no index found!\n");
//             return;
//         }
//         idx = *idx_ptr;
//     }

//     // ================= Update dp_array =================
//     data_point dp = {};
//     dp.flow_bytes_per_sec   = stats->total_fwd_len + stats->total_bwd_len;
//     dp.flow_packets_per_sec = stats->fwd_pkt_count + stats->bwd_pkt_count;
//     dp.flow_duration        = stats->time_end_ns - stats->time_start_ns;
//     if (dp.flow_packets_per_sec > 0)
//         dp.flow_IAT_mean = stats->sum_iat_ns / dp.flow_packets_per_sec;

//     if (bpf_map_update_elem(&dp_array, &idx, &dp, BPF_ANY) != 0) {
//         bpf_printk("Failed to update dp_array at index %u\n", idx);
//     }
// }

/*================= TEST MATH =================*/
static __always_inline fixed euclidean_distance_fixed(const data_point *a, const data_point *b)
{
    fixed dx = a->flow_bytes_per_sec    - b->flow_bytes_per_sec;
    fixed dy = a->flow_packets_per_sec  - b->flow_packets_per_sec;
    fixed dz = a->flow_IAT_mean         - b->flow_IAT_mean;
    fixed dw = a->flow_duration         - b->flow_duration;

    return fixed_sqrt(
        fixed_add(
            fixed_add(fixed_mul(dx, dx), fixed_mul(dy, dy)),
            fixed_add(fixed_mul(dz, dz), fixed_mul(dw, dw))
        )
    );
}

/*================= XDP PROGRAM =================*/
SEC("xdp") 
int xdp_flow_tracking_run(struct xdp_md *ctx) { 
    struct flow_key key = {}; 
    __u64 pkt_len = 0; 
    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) 
        return XDP_PASS;
    is_forward(&key, key.src_ip, key.src_port, key.dst_ip, key.dst_port) ? 
        update_stats(&key, ctx, 1) /* forward */ : 
        update_stats(&key, ctx, 0); /* backward */ 
    return XDP_PASS; 
}
/* Optional math test program */
SEC("xdp")
int test(struct xdp_md *ctx)
{
    data_point a = { fixed_from_int(10),  fixed_from_int(101),
                     fixed_from_int(100), fixed_from_int(1) };
    data_point b = { fixed_from_int(20),  fixed_from_int(202),
                     fixed_from_int(200), fixed_from_int(2) };

    bpf_printk("Euclidean distance: %lld\n", euclidean_distance_fixed(&a, &b));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
