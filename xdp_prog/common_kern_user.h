/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>

#define MAX_FLOW_SAVED                       10000
#define MAX_FEATURES                         6
#define FEATURE_FLOW_DURATION                0
#define FEATURE_TOTAL_FWD_PACKET             1
#define FEATURE_TOTAL_LENGTH_OF_FWD_PACKET   2
#define FEATURE_FWD_PACKET_LENGTH_MAX        3
#define FEATURE_FWD_PACKET_LENGTH_MIN        4
#define FEATURE_FWD_IAT_MIN                  5

/* Define for fixed point Q48.16 */
#define FIXED_SHIFT                          16
#define FIXED_SCALE                          (1ULL << FIXED_SHIFT)
typedef __u64                                fixed;

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
} __attribute__((packed));

typedef struct {
    __u64   start_ts;             /* Timestamp of first packet */
    __u64   last_seen;            /* Timestamp of last packet */
    __u64   min_IAT;              /* Minimum Inter-Arrival Time */
    __u32   total_pkts;           /* Total packet count */
    __u32   max_pkt_len;          /* Maximum packet length */
    __u32   min_pkt_len;          /* Minimum packet length */
    __u32   total_bytes;          /* Total byte count */
    fixed   features[MAX_FEATURES];
    int     label;
} data_point;

/* Latency statistics structure */
typedef struct {
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u64 total_pkts;
    __u64 total_bytes;
} accounting;

typedef struct svm_weight {
    /*Cong 1 de tham bias*/
    fixed   value[MAX_FEATURES + 1]; 
    int     is_neg[MAX_FEATURES + 1];       
    fixed   scale[MAX_FEATURES];
    fixed   min_vals[MAX_FEATURES];
    fixed   max_vals[MAX_FEATURES];
} svm_weight;

static __always_inline fixed fixed_from_float(double value)
{
    return (__u64)(value * (double)FIXED_SCALE);
}

static __always_inline double fixed_to_float(fixed value)
{
    return (double)value / (double)FIXED_SCALE;
}

static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

static __always_inline __u64 fixed_to_int(fixed value)
{
    return value >> FIXED_SHIFT;
}

static __always_inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

static __always_inline fixed fixed_sub(fixed a, fixed b)
{
    return a - b;
}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    __u64 a_int = a >> FIXED_SHIFT;
    __u64 a_frac = a & ((1ULL << FIXED_SHIFT) - 1);
    __u64 b_int = b >> FIXED_SHIFT;
    __u64 b_frac = b & ((1ULL << FIXED_SHIFT) - 1);
    
    __u64 int_part = a_int * b_int;
    __u64 mix_part = ((a_int * b_frac) >> (FIXED_SHIFT - 1)) +
                     ((a_frac * b_int) >> (FIXED_SHIFT - 1));

    __u64 frac_part = (a_frac * b_frac) >> FIXED_SHIFT;

    return (int_part << FIXED_SHIFT) + mix_part + frac_part;
}

static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;
    return (a << FIXED_SHIFT) / b;
}


static __always_inline fixed fixed_log2(__u64 x){
    if (x == 0)
        return 0;

    __u64 int_part = 0;
    __u64 tmp = x;
    
    while (tmp >>= 1)
        int_part++;

    __u64 base = 1ULL << int_part;
    __u64 remainder = x - base;

    __u64 frac = (remainder << FIXED_SHIFT) / base;
    
    return (int_part << FIXED_SHIFT) | frac;
}
const svm_weight svm_weights = {
    .value = {
        63478ULL, 1158482ULL, 981943ULL, 270448ULL, 390579ULL, 205535ULL, 35477ULL
    },
    .is_neg = {
        1, 0, 1, 0, 0, 0, 1
    },
    .min_vals = {
        0ULL, 65536ULL, 0ULL, 0ULL, 0ULL, 0ULL
    },
    .max_vals = {
        7864237555712000ULL, 2679635968ULL, 59768832000ULL, 233963520ULL, 191365120ULL, 338065883136000ULL
    },
    .scale = {
        0ULL, 2ULL, 0ULL, 18ULL, 22ULL, 0ULL
    },
};
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
