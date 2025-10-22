// /* This common_kern_user.h is used by kernel side BPF-progs and
//  * userspace programs, for sharing common struct's and DEFINEs.
//  */
// #ifndef __COMMON_KERN_USER_H
// #define __COMMON_KERN_USER_H

// #include <stdint.h>
// #include <math.h>

// #define MAX_FLOW_SAVED      2000
// #define MAX_FEATURES        5
// /*Define for fixed point*/
// #define FIXED_SHIFT         24
// #define FIXED_SCALE         (1 << FIXED_SHIFT)
// typedef __u32               fixed;
// // typedef __s32               fixed;
// /* Flow identification key */
// struct flow_key {
//     __u32 src_ip;
//     __u16 src_port;
//     __u32 dst_ip;
//     __u16 dst_port;
//     __u8  proto;
// } __attribute__((packed));

// typedef struct {
//     __u32 start_ts;             /* Timestamp of first packet */
//     __u32 last_seen;            /* Timestamp of last packet */
//     __u32 total_pkts;           /* Total packet count (Paccket/s)*/
//     __u32 total_bytes;          /* Total byte count (Bytes/s)*/
//     __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
//     __u32 flow_duration;        /* Duration of a flow */
//     __u32 pkts_len_mean;
//     /*
//         features[0]: flow_duration      (Log2) 
//         features[1]: flow_pkts_per_s    (Log2)
//         features[2]: flow_bytes_per_s   (Log2)
//         features[3]: flow_IAT_mean      (Log2)
//         features[4]: pkts_len_mean      (Log2)
//     */
//     fixed features[MAX_FEATURES];
//     int   label;
// } data_point;

// /* Convert float (as double in user space) to fixed-point */
// static __always_inline fixed fixed_from_float(double value)
// {
//     return (__u32)(value * (double)FIXED_SCALE);
// }

// /* Convert fixed-point to float */
// static __always_inline float fixed_to_float(fixed value)
// {
//     return (float)value / (float)FIXED_SCALE;
// }

// /* Convert unsigned integer to fixed-point */
// static __always_inline fixed fixed_from_uint(__u32 value)
// {
//     return value << FIXED_SHIFT;
// }

// /* Convert fixed-point to integer (truncate fractional) */
// static __always_inline __u32 fixed_to_uint(fixed value)
// {
//     return value >> FIXED_SHIFT;
// }

// /* Add (safe for unsigned overflow wraparound) */
// static __always_inline fixed fixed_add(fixed a, fixed b)
// {
//     return a + b;
// }

// /* Subtract (saturating underflow protection) */
// static __always_inline fixed fixed_sub(fixed a, fixed b)
// {
//     return (a > b) ? (a - b) : 0;
// }
// // static __always_inline fixed fixed_mul(fixed a, fixed b)
// // {
// //     return (fixed)(((int64_t)a * (int64_t)b) >> FIXED_SHIFT);
// // }

// // static __always_inline fixed fixed_div(fixed a, fixed b)
// // {
// //     if (b == 0) return 0;
// //     return (fixed)(((unsigned long long)a << FIXED_SHIFT) / (unsigned long long)b);
// // }
// /* Multiply (with scale correction) */
// static __always_inline fixed fixed_mul(fixed a, fixed b)
// {
//     /* Cast to 64-bit temporarily to avoid overflow before shift */
//     unsigned long long temp = (unsigned long long)a * (unsigned long long)b;
//     return (fixed)(temp >> FIXED_SHIFT);
// }

// /* Fixed-point division */
// static __always_inline fixed fixed_div(fixed a, fixed b)
// {
//     if (b == 0)
//         return 0;
//     unsigned long long temp = ((unsigned long long)a << FIXED_SHIFT);
//     return (fixed)(temp / b);
// }

// /* Square root using integer Newton's method */
// static __always_inline fixed fixed_sqrt(fixed value)
// {
//     if (value == 0)
//         return 0;

//     fixed x = value;
//     for (int i = 0; i < 8; i++) {
//         x = fixed_div(fixed_add(x, fixed_div(value, x)), fixed_from_uint(2));
//     }
//     return x;
// }
// /* Fixed-point absolute value */
// static inline fixed fixed_abs(fixed value)
// {
//     return (value < 0) ? -value : value;
// }

// /* Compare two fixed-point values */
// static inline int fixed_compare(fixed a, fixed b)
// {
//     if (a < b) return -1;
//     if (a > b) return 1;
//     return 0;
// }

// /* Fixed-point minimum */
// static inline fixed fixed_min(fixed a, fixed b)
// {
//     return (a < b) ? a : b;
// }

// /* Fixed-point maximum */
// static inline fixed fixed_max(fixed a, fixed b)
// {
//     return (a > b) ? a : b;
// }

// static __always_inline fixed fixed_log2(__u32 x)
// {
//     if (x == 0)
//         return 0;

//     __u32 int_part = 0;
//     __u32 tmp = x;
//     while (tmp >>= 1)
//         int_part++;

//     // Phần dư còn lại để tính phần thập phân
//     __u32 base = 1 << int_part;
//     __u64 remainder = (__u64)x - base;

//     // Tính phần thập phân (scale 24 bit)
//     __u64 frac = (remainder << FIXED_SHIFT) / base;

//     // Trả về fixed-point kiểu Q8.24
//     return ((fixed)int_part << FIXED_SHIFT) + (fixed)frac;
// }
// typedef struct svm_weight{
//     fixed   value[MAX_FEATURES + 1]; 
//     int     is_neg[MAX_FEATURES + 1];     /*is_neg = 1 --> value < 0 else value >= 0*/
//     fixed   min_vals[MAX_FEATURES];
//     fixed   max_vals[MAX_FEATURES];
// }svm_weight;

// /* XDP action definitions for compatibility */
// #ifndef XDP_ACTION_MAX
// #define XDP_ACTION_MAX (XDP_REDIRECT + 1)
// #endif

// #endif /* __COMMON_KERN_USER_H */


/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>

#define MAX_FLOW_SAVED      2000
#define MAX_FEATURES        5

/* Define for fixed point Q8.24 */
#define FIXED_SHIFT         24
#define FIXED_SCALE         (1 << FIXED_SHIFT)
typedef __s32 fixed;  // Signed fixed-point

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
    __u32 total_pkts;           /* Total packet count (Packet/s) */
    __u32 total_bytes;          /* Total byte count (Bytes/s) */
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    __u32 flow_duration;        /* Duration of a flow */
    __u32 pkts_len_mean;

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

/* Convert float to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{
    return (fixed)(value * (double)FIXED_SCALE);
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

/* Fixed-point arithmetic */
static __always_inline fixed fixed_add(fixed a, fixed b) { return a + b; }
static __always_inline fixed fixed_sub(fixed a, fixed b) { return a - b; }
static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    return (fixed)(((int64_t)a * (int64_t)b) >> FIXED_SHIFT);
}
static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;

    __u32 sign = 0;
    __u32 ua = a;
    __u32 ub = b;

    // Xác định dấu
    if ((int)a < 0) { ua = -a; sign ^= 1; }
    if ((int)b < 0) { ub = -b; sign ^= 1; }

    unsigned long long temp = ((unsigned long long)ua << FIXED_SHIFT) / ub;

    fixed res = (fixed)temp;
    return sign ? -res : res;
}
/* Square root using integer Newton's method */
static __always_inline fixed fixed_sqrt(fixed value)
{
    if (value <= 0) return 0;
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

/* Fixed-point minimum and maximum */
static inline fixed fixed_min(fixed a, fixed b) { return (a < b) ? a : b; }
static inline fixed fixed_max(fixed a, fixed b) { return (a > b) ? a : b; }

/* Fixed-point log2 approximation Q8.24 */
// static __always_inline fixed fixed_log2(__u32 x)
// {
//     if (x == 0) return 0;

//     __u32 int_part = 0;
//     __u32 tmp = x;
//     while (tmp >>= 1) int_part++;

//     __u32 base = 1 << int_part;
//     __u64 remainder = (__u64)x - base;
//     __u64 frac = (remainder << FIXED_SHIFT) / base;

//     return ((fixed)int_part << FIXED_SHIFT) + (fixed)frac;
// }

static __always_inline fixed fixed_log2(__u32 x)
{
    if (x == 0)
        return 0;

    // ==== Tính phần nguyên của log2(x) ====
    __u32 tmp = x;
    __u32 int_part = 0;
// #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (tmp >>= 1)
            int_part++;
        else
            break;
    }

    __u32 base = 1u << int_part;

    // ==== Tính phần lẻ f = (x / base) - 1  ====
    __u64 remainder = (__u64)x - base;
    fixed f = (fixed)((remainder << FIXED_SHIFT) / base);  // f ∈ [0, 1)

    // ==== log2(1 + f) ≈ f - f²/2 + f³/3  (Taylor 3 bậc) ====
    fixed f2 = fixed_mul(f, f);
    fixed f3 = fixed_mul(f2, f);

    fixed term1 = f;
    fixed term2 = f2 >> 1;  // f² / 2
    fixed term3 = fixed_div(f3, (3 << FIXED_SHIFT));  // f³ / 3

    fixed frac_log = term1 - term2 + term3;

    // ==== Tổng hợp phần nguyên + phần lẻ ====
    return ((fixed)int_part << FIXED_SHIFT) + frac_log;
}

typedef struct svm_weight {
    fixed value[MAX_FEATURES + 1]; 
    int   is_neg[MAX_FEATURES + 1]; /* is_neg = 1 --> value < 0, else >= 0 */
    fixed min_vals[MAX_FEATURES];
    fixed max_vals[MAX_FEATURES];
} svm_weight;

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
