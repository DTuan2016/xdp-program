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
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_flow_tracking SEC(".maps");

static __always_inline int is_forward(const struct flow_key *key,
                                      __u32 pkt_src_ip, __u16 pkt_src_port)
{
    return pkt_src_ip == key->src_ip
        && pkt_src_port == key->src_port;
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

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;
    key->src_ip   = iph->saddr;

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
    *pkt_len = (__u64)(data_end - data);
    return 0;
}

/*================= TEST MATH =================*/
static __always_inline fixed euclidean_distance_fixed(const data_point *a, const data_point *b)
{
    fixed dx = a->total_bytes    - b->total_bytes;
    fixed dy = a->total_pkts     - b->total_pkts;
    fixed dz = a->flow_IAT_mean  - b->flow_IAT_mean;
    fixed dw = a->flow_duration  - b->flow_duration;

    return fixed_sqrt(
        fixed_add(
            fixed_add(fixed_mul(dx, dx), fixed_mul(dy, dy)),
            fixed_add(fixed_mul(dz, dz), fixed_mul(dw, dw))
        )
    );
}

static __always_inline void update_stats(struct flow_key *key, struct xdp_md *ctx, int is_fwd)
{
    __u64 ts = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)(ctx->data_end - ctx->data);

    /* ================= Lookup or insert data_point ================= */
    data_point new_dp = {};
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (!dp) {
        // ===== Flow mới =====
        new_dp.flow_duration = 0;
        new_dp.total_pkts    = 1;
        new_dp.total_bytes   = pkt_len;
        new_dp.flow_IAT_mean = 0;   // gói đầu tiên chưa có IAT

        // Các trường LOF/LOF-related khởi tạo
        new_dp.k_distance = fixed_from_int(0);
        #pragma unroll
        for (int i = 0; i < KNN; i++) {
            new_dp.reach_dist[i] = fixed_from_int(0);
        }
        new_dp.lrd_value = fixed_from_int(0);
        new_dp.lof_value = fixed_from_int(0);

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &new_dp, BPF_ANY) != 0) {
            bpf_printk("Failed to insert new data_point\n");
            return;
        }

    } else {
        // ===== Flow đã tồn tại, update =====
        __u64 iat = ts - dp->flow_duration; // tạm coi flow_duration như last_seen

        // Cập nhật số packet + byte
        __sync_fetch_and_add(&dp->total_pkts, 1);
        __sync_fetch_and_add(&dp->total_bytes, pkt_len);

        // Update flow_duration (tính như "last_seen")
        dp->flow_duration = ts;

        // Cập nhật IAT trung bình
        if (dp->total_pkts > 1) {
            dp->flow_IAT_mean = dp->flow_IAT_mean +
                                (iat - dp->flow_IAT_mean) / dp->total_pkts;
        }
    }
}

/*================= XDP PROGRAM =================*/
SEC("xdp") 
int xdp_flow_tracking_run(struct xdp_md *ctx) { 
    struct flow_key key = {}; 
    __u64 pkt_len = 0; 
    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) 
        return XDP_PASS;
    is_forward(&key, key.src_ip, key.src_port) ? 
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
