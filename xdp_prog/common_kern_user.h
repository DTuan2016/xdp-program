/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#define KNN             2
#define FIXED_SHIFT     16
#define SCALEEEEEE      100
#define FIXED_SCALE     (1 << FIXED_SHIFT)
#define DIST_THRESHOLD  30

typedef int32_t fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;  
} __attribute__((packed));

/* Flow statistics and anomaly detection data */
typedef struct {
    /* Timing information */
    __u64 start_ts;             /* Timestamp of first packet */
    __u64 last_seen;            /* Timestamp of last packet */
    
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time */
    
    __u16 k_distance;            /* k-distance value */
    __u16 reach_dist[KNN];       /* Reachability distances to k neighbors */
    __u16 lrd_value;             /* Local Reachability Density */
    __u16 lof_value;             /* Local Outlier Factor score */
} data_point;

struct knn_entry {
    struct flow_key key;
    __u16 distance;
};

struct knn_entries{
    struct knn_entry knn[KNN];
};
/* Context để truyền cho callback */
struct knn_callback_ctx {
    const struct flow_key *target_key;
    data_point *target_dp;
    struct knn_entries *entries;
};

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */