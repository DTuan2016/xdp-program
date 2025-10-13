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

#define NANOSEC_PER_SEC 1000000000ULL
#define MAX_FLOW_SAVED 100

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
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("[PARSE] Failed: Ethernet header bounds check");
        return -1;
    }

    // Chỉ xử lý IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("[PARSE] Skipped: Not IP packet");
        return -1;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("[PARSE] Failed: IP header bounds check");
        return -1;
    }

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // Vị trí header transport
    void *trans_hdr = (__u8 *)iph + (iph->ihl * 4);
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)trans_hdr;
        if ((void *)(tcph + 1) > data_end) {
            bpf_printk("[PARSE] Failed: TCP header bounds check");
            return -1;
        }
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)trans_hdr;
        if ((void *)(udph + 1) > data_end) {
            bpf_printk("[PARSE] Failed: UDP header bounds check");
            return -1;
        }
        src_port = udph->source;
        dst_port = udph->dest;
    }

    key->src_port = bpf_ntohs(src_port);
    key->dst_port = bpf_ntohs(dst_port);
    
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

// Giả định fixed_log2 đã được đơn giản hóa trong common_kern_user.h
static __always_inline void update_feature(data_point *dp)
{
    // Cần total_pkts > 1 để tránh chia cho 0
    if (dp->total_pkts > 1) {
        fixed flow_duration = fixed_log2(dp->flow_duration);
        __u64 mean_iat_us = dp->sum_IAT / (dp->total_pkts - 1);

        dp->features[0] = flow_duration;
        dp->features[1] = fixed_log2(dp->total_pkts * 1000000) - flow_duration;
        dp->features[2] = fixed_log2(dp->total_bytes * 1000000) - flow_duration;
        dp->features[3] = fixed_log2(mean_iat_us); // Log2(Mean IAT)
        dp->features[4] = fixed_log2(dp->total_bytes) - fixed_log2(dp->total_pkts);

        // Cập nhật flow_IAT_mean cho thông tin debug
        dp->flow_IAT_mean = (mean_iat_us > 0) ? fixed_to_uint(fixed_log2(mean_iat_us)) : 0;
    }
}

/*================= STATS UPDATE =================*/
static __always_inline data_point* update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts      = bpf_ktime_get_ns();
    __u64 us      = ts / 1000;
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) - (__u8 *)((void *)(long)ctx->data));
    
    /* Lookup or insert data_point */
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        /* init new entry */
        zero.start_ts      = us;
        zero.last_seen     = us;
        zero.total_pkts    = 1;
        zero.total_bytes   = pkt_len;
        // Các trường khác đã được khởi tạo là 0

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0) {
            bpf_printk("[STATS] ERROR: Failed to insert new data_point");
            return NULL;
        }
        return NULL; // Return NULL cho lần tạo đầu tiên (không có pointer hợp lệ)
    }

    /* Update existing entry */
    __u64 current_us = us;
    __u64 iat_us = 0;
    
    if (dp->last_seen > 0 && current_us >= dp->last_seen)
        iat_us = current_us - dp->last_seen;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_us > 0)
        dp->sum_IAT += iat_us;
    
    dp->last_seen = current_us;
    dp->flow_duration = dp->last_seen - dp->start_ts;
    
    // Tính lại features chỉ khi đã có nhiều hơn 1 gói
    if (dp->total_pkts > 1) {
        update_feature(dp);
    }
    
    return dp;
}

/*================= XDP PROGRAM =================*/
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    if (parse_packet_get_data(ctx, &key, &pkt_len) < 0) {
        return XDP_PASS;
    }

    data_point *dp = update_stats(&key, ctx);
    if (!dp) {
        // Lần đầu tiên tạo entry
        return XDP_PASS;
    }

    // --- LOGIC LOF/KNN ĐÃ ĐƯỢC LOẠI BỎ Ở ĐÂY ---

    __u32 ip_le = bpf_ntohl(key.src_ip);
    __u32 a = (ip_le >> 24) & 0xff;
    __u32 b = (ip_le >> 16) & 0xff;
    __u32 c = (ip_le >>  8) & 0xff;
    __u32 d = (ip_le >>  0) & 0xff;

    bpf_printk("=== [FINAL] Flow %u.%u.%u.%u:%u pkts=%u bytes=%u dur=%llu features[0]=%lld ===",
               a, b, c, d, key.src_port,
               dp->total_pkts, dp->total_bytes, dp->flow_duration, dp->features[0]);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";