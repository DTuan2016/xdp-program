/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>

#define MAX_FLOW_SAVED       2000
#define MAX_FEATURES         5
/*Config random forest*/
#define SCALE                1000
/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
} __attribute__((packed));

typedef struct {
    __u32 start_ts;             /* Timestamp of first packet */
    __u32 last_seen;            /* Timestamp of last packet */
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    /* Feature use for algorithm */
    __u32 flow_duration;        /* Duration of a flow */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time */
    __u32 flow_pkts_per_s;
    __u32 flow_bytes_per_s;
    __u32 pkt_len_mean;

    __u32 features[MAX_FEATURES];
    int   label;
} data_point;
/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */