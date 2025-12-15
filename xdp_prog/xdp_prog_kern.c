// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC 1000000000ULL

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);   // number of RX queues
    __type(key, __u32);        // queue_id
    __type(value, __u32);      // AF_XDP socket FD
} xsks_map SEC(".maps");

/* ================= XDP ENTRY ================= */
SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    __u32 queue_idx = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &queue_idx)){
        return bpf_redirect_map(&xsks_map, queue_idx, XDP_PASS);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
