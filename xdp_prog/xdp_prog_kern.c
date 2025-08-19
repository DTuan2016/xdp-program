// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" /* defines: fixed, flow_key, data_point, KNN, fixed_* */

#define NANOSEC_PER_SEC 1000000000ULL
#define MAX_FLOW_SAVED  10240

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

/*================= HELPERS =================*/
static __always_inline int is_forward(const struct flow_key *key,
                                      __u32 pkt_src_ip, __u16 pkt_src_port)
{
    return pkt_src_ip == key->src_ip && pkt_src_port == key->src_port;
}

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
        /* non TCP/UDP: set src_port=0 so all such packets of same src_ip merge */
        src_port = 0;
    }

    key->src_port = bpf_ntohs(src_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/*================= MATH (fixed) =================*/
static __always_inline fixed euclidean_distance_fixed(const data_point *a, const data_point *b)
{
    fixed dx = a->total_bytes   - b->total_bytes;
    fixed dy = a->total_pkts    - b->total_pkts;
    fixed dz = a->flow_IAT_mean - b->flow_IAT_mean;
    fixed dw = a->flow_duration - b->flow_duration;

    return fixed_sqrt(
        fixed_add(
            fixed_add(fixed_mul(dx, dx), fixed_mul(dy, dy)),
            fixed_add(fixed_mul(dz, dz), fixed_mul(dw, dw))
        )
    );
}

/*================= STATS UPDATE =================*/
static __always_inline void update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - (__u8 *)((void *)(long)ctx->data));

    /* Lookup or insert data_point */
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        /* init new entry */
        zero.flow_duration = ts;     /* dùng tạm như last_seen */
        zero.total_pkts    = 1;
        zero.total_bytes   = pkt_len;
        zero.flow_IAT_mean = 0;      /* gói đầu tiên chưa có IAT */

        zero.k_distance = fixed_from_int(0);
#pragma unroll
        for (int i = 0; i < KNN; i++)
            zero.reach_dist[i] = fixed_from_int(0);
        zero.lrd_value = fixed_from_int(0);
        zero.lof_value = fixed_from_int(0);

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0) {
            bpf_printk("Failed to insert new data_point\n");
        }
        return;
    }

    /* Update existing entry */
    __u64 iat = 0;
    if (dp->flow_duration > 0 && ts >= dp->flow_duration)
        iat = ts - dp->flow_duration;

    /* total packets / bytes */
    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    /* last_seen */
    dp->flow_duration = ts;

    /* incremental mean IAT */
    if (dp->total_pkts > 1) {
        dp->flow_IAT_mean = dp->flow_IAT_mean +
                            (iat - dp->flow_IAT_mean) / dp->total_pkts;
    }

    /* is_fwd hiện chưa dùng trong data_point rút gọn, để dành nếu cần hướng */
    (void)is_fwd;
}

/*================= XDP PROGRAMS =================*/
SEC("xdp")
int xdp_flow_tracking_run(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    /* Dùng is_forward() nếu sau này bạn tách hướng; hiện tại chỉ cập nhật chung */
    if (is_forward(&key, key.src_ip, key.src_port))
        update_stats(&key, ctx, 1);
    else
        update_stats(&key, ctx, 0);

    return XDP_PASS;
}

/* Callback for bpf_for_each_map_elem:
 * Prototype must be: long (*cb)(struct bpf_map *map, const void *key, void *value, void *ctx)
 */
static long print_flow_callback(struct bpf_map *map,
                                const void *k,
                                void *v,
                                void *ctx)
{
    const struct flow_key *fk = k;
    data_point *dp = v;
    (void)map;
    (void)ctx;

    /* In IP theo dạng a.b.c.d:port (không có helper format string, tách thủ công) */
    __u32 ip_be = fk->src_ip;                  /* network order */
    __u32 ip_le = bpf_ntohl(ip_be);            /* host order */
    __u32 a = (ip_le >> 24) & 0xff;
    __u32 b = (ip_le >> 16) & 0xff;
    __u32 c = (ip_le >> 8)  & 0xff;
    __u32 d = (ip_le >> 0)  & 0xff;

    bpf_printk("Flow %u.%u.%u.%u:%u pkts=%llu bytes=%llu last_seen(ns)=%llu mean_iat(ns)=%llu",
               a, b, c, d, fk->src_port,
               dp->total_pkts, dp->total_bytes,
               dp->flow_duration, dp->flow_IAT_mean);
    return 0;
}

/* NOTE: bpf_for_each_map_elem() có thể không được phép ở một số phiên bản kernel/loại chương trình XDP.
 * Nếu verifier từ chối, hãy bỏ chương trình này hoặc chuyển sang user-space để dump map.
 */
SEC("xdp")
int xdp_print_all_flows(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0)
        return XDP_PASS;

    /* Dùng is_forward() nếu sau này bạn tách hướng; hiện tại chỉ cập nhật chung */
    if (is_forward(&key, key.src_ip, key.src_port))
        update_stats(&key, ctx, 1);
    else
        update_stats(&key, ctx, 0);

    // return XDP_PASS;
    /* In tiêu đề 1 lần mỗi packet khi program này chạy: chỉ dùng để thử nghiệm */
    bpf_printk("=== Printing all flows ===");
    long ret = bpf_for_each_map_elem(&xdp_flow_tracking, print_flow_callback, NULL, 0);
    if (ret < 0)
        bpf_printk("Error iterating flows: %ld", ret);
    else
        bpf_printk("Processed %ld flows", ret);
    return XDP_PASS;
}

/* Optional math test program */
SEC("xdp")
int test(struct xdp_md *ctx)
{
    data_point a = {
        .flow_duration  = fixed_from_int(10),
        .total_pkts     = fixed_from_int(101),
        .total_bytes    = fixed_from_int(100),
        .flow_IAT_mean  = fixed_from_int(1),
        .k_distance     = 0,
        .lrd_value      = 0,
        .lof_value      = 0,
    };
    data_point b = {
        .flow_duration  = fixed_from_int(20),
        .total_pkts     = fixed_from_int(202),
        .total_bytes    = fixed_from_int(200),
        .flow_IAT_mean  = fixed_from_int(2),
        .k_distance     = 0,
        .lrd_value      = 0,
        .lof_value      = 0,
    };

#pragma unroll
    for (int i = 0; i < KNN; i++) {
        a.reach_dist[i] = 0;
        b.reach_dist[i] = 0;
    }

    bpf_printk("Euclid dist (fixed) = %lld", euclidean_distance_fixed(&a, &b));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
