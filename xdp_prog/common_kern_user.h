/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
/*All of this defines have max accuracy ~93%*/ 
#define SCALE               10000
#define TRAINING_SET        10000
#define MAX_FLOW_SAVED      1000
#define MAX_FEATURES        5
// Còn 20, 10
#define MAX_TREES           20
#define MAX_NODE_PER_TREE   256
#define MAX_SAMPLE_PER_NODE 512
#define NULL_IDX            -1
#define MAX_TEST            300
#define MAX_DEPTH           9
#define CONTAMINATION       100
/*Define for fixed point*/
#define FIXED_SHIFT          24
#define FIXED_SCALE          (1 << FIXED_SHIFT)
typedef __u32                fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
} __attribute__((packed));

typedef struct {
    __u32   start_ts;             /* Timestamp of first packet */
    __u32   last_seen;            /* Timestamp of last packet */
    __u32   total_pkts;           /* Total packet count (Paccket/s)*/
    __u32   total_bytes;          /* Total byte count (Bytes/s)*/
    __u64   sum_IAT;              /* Sum of Inter-Arrival Times */
    /* Feature use for algorithm */
    __u32   flow_duration;        /* Duration of a flow */
    // __u32   flow_IAT_mean;        /* Mean Inter-Arrival Time */
    // __u32   flow_pkts_per_s;
    // __u32   flow_bytes_per_s;
    __u32   pkt_len_mean;

    /*
        features[0]: flow_duration      (Log2) 
        features[1]: flow_pkts_per_s    (Log2)
        features[2]: flow_bytes_per_s   (Log2)
        features[3]: flow_IAT_mean      (Log2)
        features[4]: pkts_len_mean      (Log2)
    */
    fixed features[MAX_FEATURES];
    int   label;
} data_point;

typedef struct iTreeNode{
    int     left_idx;
    int     right_idx;
    int     feature_idx;
    fixed   split_value;             /* Have to SCALE */
    __u32   num_points;
    int     is_leaf;
} iTreeNode;

typedef struct iTree{
    iTreeNode nodes[MAX_NODE_PER_TREE];
    __u32     num_nodes;
    __u32     max_depth;
}iTree;

typedef struct{
    iTree trees[MAX_TREES];
    __u32 n_trees;
    __u32 max_depth;
    __u32 sample_size;
}IsolationForest;

struct forest_params {
    __u32 n_trees;
    __u32 sample_size;
    fixed threshold; /* integer threshold on avg path length */
    __u32 max_depth;
    __u32 contamination;
};

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{
    return (__u32)(value * (double)FIXED_SCALE);
}

/* Convert fixed-point to float */
static __always_inline float fixed_to_float(fixed value)
{
    return (float)value / (float)FIXED_SCALE;
}

/* Convert unsigned integer to fixed-point */
static __always_inline fixed fixed_from_uint(__u32 value)
{
    return value << FIXED_SHIFT;
}

/* Convert fixed-point to integer (truncate fractional) */
static __always_inline __u32 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
}

/* Add (safe for unsigned overflow wraparound) */
static __always_inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

/* Subtract (saturating underflow protection) */
static __always_inline fixed fixed_sub(fixed a, fixed b)
{
    return (a > b) ? (a - b) : 0;
}

/* Multiply (with scale correction) */
static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    /* Cast to 64-bit temporarily to avoid overflow before shift */
    unsigned long long temp = (unsigned long long)a * (unsigned long long)b;
    return (fixed)(temp >> FIXED_SHIFT);
}

/* Fixed-point division */
static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;
    unsigned long long temp = ((unsigned long long)a << FIXED_SHIFT);
    return (fixed)(temp / b);
}

/* Square root using integer Newton's method */
static __always_inline fixed fixed_sqrt(fixed value)
{
    if (value == 0)
        return 0;

    fixed x = value;
    for (int i = 0; i < 8; i++) {
        x = fixed_div(fixed_add(x, fixed_div(value, x)), fixed_from_uint(2));
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

static __always_inline fixed fixed_log2(__u32 x)
{
    if (x == 0)
        return 0;

    __u32 int_part = 0;
    __u32 tmp = x;
    while (tmp >>= 1)
        int_part++;

    __u32 base = 1 << int_part;
    __u32 remainder = x - base;

    __u32 frac = (remainder << FIXED_SHIFT) / base;
    return (int_part << FIXED_SHIFT) | frac;
}

static __always_inline fixed fixed_exp2(fixed x)
{
    if (x > (31 << FIXED_SHIFT))
        return 0xFFFFFFFF; 
    if ((int)x < -(31 << FIXED_SHIFT))
        return 0;

    __u32 int_part = x >> FIXED_SHIFT;
    fixed frac = x & (FIXED_SCALE - 1);
    const fixed LN2 = (fixed)(0.693147 * FIXED_SCALE);
    fixed t = fixed_mul(frac, LN2);
    fixed t2 = fixed_mul(t, t);
    fixed frac_pow = fixed_add(fixed_from_uint(1),
                     fixed_add(t, fixed_div(t2, fixed_from_uint(2))));

    // 2^int_part
    fixed int_pow;
    if (int_part >= 31)
        int_pow = 0xFFFFFFFF;
    else
        int_pow = fixed_from_uint(1 << int_part);

    return fixed_mul(int_pow, frac_pow);
}

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */