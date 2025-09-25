/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
#define KNN                 2
#define SCALEEEEEE          1000
#define DATA_CAL_LOF        100
#define MAX_FLOW_SAVED      1000
#define LOF_THRESHOLD       1.3 // Threshold accuracy cao nhất
typedef int32_t fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;  
} __attribute__((packed));

struct knn_entry {
    struct flow_key key;   /* flow láng giềng */
    __u16 distance;        /* khoảng cách tới neighbor */
};

/* Flow statistics and anomaly detection data */
typedef struct {
    /* Timing information */
    __u64 start_ts;             /* Timestamp of first packet */
    __u64 last_seen;            /* Timestamp of last packet */
    
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time */
    __u64 flow_duration;
    __u32 flow_pkts_per_s;
    __u32 flow_bytes_per_s;
    __u32 pkts_len_mean;
    int   is_normal;

    __u16 k_distance;            /* k-distance value */
    __u16 reach_dist[KNN];       /* Reachability distances to k neighbors */
    __u16 lrd_value;             /* Local Reachability Density */
    __u16 lof_value;             /* Local Outlier Factor score */

    struct knn_entry knn[KNN];
} data_point;

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */