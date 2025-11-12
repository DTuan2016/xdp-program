#ifndef COMMON_KERNEL_USER_H
#define COMMON_KERNEL_USER_H

#include <linux/types.h>

/* Fixed-point configuration */
#define FIXED_SHIFT         16
#define FIXED_SCALE         65536
#define MAX_TREES           10
#define MAX_NODE_PER_TREE   15
#define MAX_FEATURES        6
#define MAX_DEPTH           4
#define TOTAL_NODES         150
#define MAX_FLOW_SAVED      1000

#define QS_FEATURE_FLOW_DURATION                0
#define QS_FEATURE_TOTAL_FWD_PACKET             1
#define QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET   2
#define QS_FEATURE_FWD_PACKET_LENGTH_MAX        3
#define QS_FEATURE_FWD_PACKET_LENGTH_MIN        4
#define QS_FEATURE_FWD_IAT_MIN                  5

typedef __u64               fixed;

/* Latency statistics structure */
typedef struct {
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u32 total_pkts;
    __u32 total_bytes;
} accounting;

/* Flow key structure */
struct flow_key {
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
} __attribute__((packed));

/* Definition of a datapoint or a flow (accounting) */
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

// /* Definition of feature vector to calculate RF */
// struct feat_vec {
//     fixed features[MAX_FEATURES];
// };

/* Definition of a Node of Decision Tree */
typedef struct {
    int     left_idx;
    int     right_idx;
    fixed   split_value;
    int     feature_idx;
    __u32   is_leaf;
    int     label;
    int     tree_idx;
} Node;

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{
    return (__u64)(value * (double)FIXED_SCALE);
}

/* Convert fixed-point to float */
static __always_inline double fixed_to_float(fixed value)
{
    return (double)value / (double)FIXED_SCALE;
}

/* Convert unsigned integer to fixed-point */
static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

/* Convert fixed-point to integer (truncate fractional) */
static __always_inline __u64 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
}

/* Add two fixed-point values */
static __always_inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

/* Subtract two fixed-point values (with underflow protection) */
static __always_inline fixed fixed_sub(fixed a, fixed b)
{
    return (a > b) ? (a - b) : 0;
}

/* Multiply two fixed-point values (with scale correction) */
static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    /* Use 128-bit intermediate to prevent overflow */
    __u64 a_int = a >> FIXED_SHIFT;
    __u64 a_frac = a & ((1ULL << FIXED_SHIFT) - 1);
    __u64 b_int = b >> FIXED_SHIFT;
    __u64 b_frac = b & ((1ULL << FIXED_SHIFT) - 1);
    
    __u64 result_int = a_int * b_int;
    __u64 result_frac = (a_int * b_frac + a_frac * b_int) >> FIXED_SHIFT;
    __u64 result_frac_frac = (a_frac * b_frac) >> (FIXED_SHIFT * 2);
    
    return (result_int << FIXED_SHIFT) + result_frac + result_frac_frac;
}

/* Divide two fixed-point values */
static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;
    
    /* Shift dividend left to maintain precision */
    __u64 shifted_a = a << FIXED_SHIFT;
    return shifted_a / b;
}

/* Square root using integer Newton's method */
static __always_inline fixed fixed_sqrt(fixed value)
{
    if (value == 0)
        return 0;

    fixed x = value;
    fixed two = fixed_from_uint(2);
    
    // #pragma unroll
    for (int i = 0; i < 10; i++) {
        fixed x_squared = fixed_div(value, x);
        x = fixed_div(fixed_add(x, x_squared), two);
    }
    
    return x;
}

/* Fixed-point absolute value */
static __always_inline fixed fixed_abs(fixed value)
{
    /* For unsigned __u64, this is just the value itself */
    return value;
}

/* Compare two fixed-point values */
static __always_inline int fixed_compare(fixed a, fixed b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

/* Fixed-point minimum */
static __always_inline fixed fixed_min(fixed a, fixed b)
{
    return (a < b) ? a : b;
}

/* Fixed-point maximum */
static __always_inline fixed fixed_max(fixed a, fixed b)
{
    return (a > b) ? a : b;
}

/* Fixed-point log2 approximation */
static __always_inline fixed fixed_log2(__u64 x)
{
    if (x == 0)
        return 0;

    __u64 int_part = 0;
    __u64 tmp = x;
    
    /* Find integer part of log2 */
    while (tmp >>= 1)
        int_part++;

    /* Calculate fractional part using linear approximation */
    __u64 base = 1ULL << int_part;
    __u64 remainder = x - base;

    /* Fractional part: remainder / base scaled to fixed-point */
    __u64 frac = (remainder << FIXED_SHIFT) / base;
    
    return (int_part << FIXED_SHIFT) | frac;
}

/* Natural logarithm approximation (ln) */
static __always_inline fixed fixed_ln(__u64 x)
{
    if (x == 0)
        return 0;
    
    /* ln(x) = log2(x) * ln(2) */
    /* ln(2) ≈ 0.693147... ≈ 177 / 256 for 8-bit fractional */
    fixed log2_val = fixed_log2(x);
    fixed ln2 = 177;  /* 0.693147 * 256 ≈ 177 */
    
    return fixed_mul(log2_val, ln2);
}

/* Exponential function approximation (e^x) using Taylor series */
static __always_inline fixed fixed_exp(fixed x)
{
    /* e^x ≈ 1 + x + x²/2! + x³/3! + x⁴/4! ... (first 5 terms) */
    fixed result = FIXED_SCALE;  /* 1.0 */
    fixed term = FIXED_SCALE;    /* Current term */
    
    // #pragma unroll
    for (int i = 1; i <= 6; i++) {
        term = fixed_mul(term, x);
        term = fixed_div(term, fixed_from_uint(i));
        result = fixed_add(result, term);
    }
    
    return result;
}

/* Power function (a^b) for small integer exponents */
static __always_inline fixed fixed_pow(fixed base, __u32 exp)
{
    fixed result = FIXED_SCALE;  /* 1.0 */
    
    // #pragma unroll
    for (__u32 i = 0; i < exp && i < 16; i++) {
        result = fixed_mul(result, base);
    }
    
    return result;
}

#endif /*COMMON_KERN_USER_H*/
