/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>

/* Configuration constants */
#define KNN  2
#define FIXED_SHIFT 16
#define FIXED_SCALE (1 << FIXED_SHIFT)

/* Fixed-point arithmetic type */
typedef int32_t fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;  /* Explicit padding for alignment */
} __attribute__((packed));

/* Flow statistics and anomaly detection data */
typedef struct {
    /* Timing information */
    __u64 start_ts;         /* Timestamp of first packet */
    __u64 last_seen;        /* Timestamp of last packet */
    
    /* Traffic statistics */
    __u32 total_pkts;       /* Total packet count (Paccket/s)*/
    __u32 total_bytes;      /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;          /* Sum of Inter-Arrival Times */
    __u32 flow_IAT_mean;    /* Mean Inter-Arrival Time */
    
    /* LOF (Local Outlier Factor) algorithm data */
    // fixed k_distance;       /* k-distance value */
    // fixed reach_dist[KNN];  /* Reachability distances to k neighbors */
    // fixed lrd_value;        /* Local Reachability Density */
    // fixed lof_value;        /* Local Outlier Factor score */

    int32_t k_distance;       /* k-distance value */
    int32_t reach_dist[KNN];  /* Reachability distances to k neighbors */
    long lrd_value;        /* Local Reachability Density */
    long lof_value;        /* Local Outlier Factor score */
} data_point;

/* Fixed-point arithmetic functions */

/* Convert float to fixed-point */
static inline fixed fixed_from_float(float value)
{
    return (fixed)(value * FIXED_SCALE);
}

/* Convert fixed-point to float */
static inline float fixed_to_float(fixed value)
{
    return (float)value / FIXED_SCALE;
}

/* Convert integer to fixed-point */
static inline fixed fixed_from_int(int value)
{
    return (fixed)(value << FIXED_SHIFT);
}

/* Convert fixed-point to integer */
static inline int fixed_to_int(fixed value)
{
    return (int)(value >> FIXED_SHIFT);
}

/* Fixed-point addition */
static inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

/* Fixed-point subtraction */
static inline fixed fixed_sub(fixed a, fixed b)
{
    return a - b;
}

/* Fixed-point multiplication */
static inline fixed fixed_mul(fixed a, fixed b)
{
    int64_t temp = (int64_t)a * (int64_t)b;
    return (fixed)(temp >> FIXED_SHIFT);
}

/* Fixed-point division */
static inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0) 
        return 0;
    
    uint64_t ua = (a < 0) ? (uint64_t)(-(int64_t)a) : (uint64_t)a;
    uint32_t ub = (b < 0) ? (uint32_t)(-(int)b) : (uint32_t)b;
    uint64_t tmp = (ua << FIXED_SHIFT);
    fixed res = (fixed)(tmp / ub);
    
    if ((a ^ b) < 0) 
        res = -res;
    
    return res;
}

/* Fixed-point square root using Newton's method */
static inline fixed fixed_sqrt(fixed value)
{
    if (value < 0) 
        return 0;

    fixed x = value;
    for (int i = 0; i < 16; i++) {
        x = fixed_div(fixed_add(x, fixed_div(value, x)), fixed_from_int(2));
    }
    return x;
}

/* Fixed-point absolute value */
static inline fixed fixed_abs(fixed value)
{
    return (value < 0) ? -value : value;
}

/* Compare two fixed-point values */
static inline int fixed_compare(fixed a, fixed b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

/* Fixed-point minimum */
static inline fixed fixed_min(fixed a, fixed b)
{
    return (a < b) ? a : b;
}

/* Fixed-point maximum */
static inline fixed fixed_max(fixed a, fixed b)
{
    return (a > b) ? a : b;
}

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */