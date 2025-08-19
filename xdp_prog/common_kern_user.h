/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#define KNN  2

typedef int64_t fixed;
struct flow_key{
	__u32 	src_ip;
	// __u32   dst_ip;
    __u16 	src_port;
    // __u16   dst_port; 
    // __u8    protocol;
};

typedef struct{
    __u64 flow_duration;
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 flow_IAT_mean;
    fixed k_distance;
    fixed reach_dist[KNN];
    fixed lrd_value;
    fixed lof_value;
} data_point;


// struct flow_stats {
//     __u64 time_start_ns;    // Timestamp của packet đầu tiên trong flow (ns)
//     __u64 time_end_ns;      // Timestamp của packet cuối cùng trong flow (ns)

//     __u64 sum_iat_ns;       // Tổng thời gian giữa các packet liên tiếp (Inter-Arrival Time)

//     __u64 total_fwd_len;    // Tổng độ dài (bytes) gói tin theo chiều forward (src → dst)
//     __u64 total_bwd_len;    // Tổng độ dài (bytes) gói tin theo chiều backward (dst → src)

//     __u64 fwd_pkt_count;    // Số lượng packet theo chiều forward
//     __u64 bwd_pkt_count;    // Số lượng packet theo chiều backward
// };

#define FIXED_SHIFT 16
#define FIXED_SCALE (1 << FIXED_SHIFT)

// static inline fixed fixed_to_int(fixed value)

static inline fixed fixed_from_float(float value){
    return (fixed)(value * FIXED_SCALE);
}

static inline float fixed_to_float(fixed value){
    return (float)value / FIXED_SCALE;
}

static inline fixed fixed_add(fixed a, fixed b){
    return a + b;
}

static inline fixed fixed_sub(fixed a, fixed b){
    return a - b;
}

static inline fixed fixed_mul(fixed a, fixed b){
    __int128_t temp = (__int128_t)a * (__int128_t)b;
    return (fixed)(temp >> FIXED_SHIFT);
}

static inline fixed fixed_div(fixed a, fixed b){
    if (b == 0) {
        return 0; // avoid div by zero
    }
    else {
        __uint128_t temp = (__uint128_t)a << FIXED_SHIFT;
        return (fixed)(temp / (unsigned)b);
    }
}

static inline fixed fixed_sqrt(fixed value){
    if(value < 0) return 0;
    
    fixed temp = value;
    for (int i = 0; i < 32; i++){
        temp = (temp + fixed_div(value, temp)) >> 1;
    }
    return temp;
}

static inline fixed fixed_from_int(int value){
    return (fixed)(value << FIXED_SHIFT);
}

// typedef struct {
//     fixed flow_duration;
//     fixed flow_packets_per_sec;
//     fixed flow_bytes_per_sec;
//     fixed flow_IAT_mean;
// } data_point;

// typedef struct {
//     data_point data;
//     fixed k_distance;
//     fixed *reach_dist;
//     fixed lrd_value;
//     fixed lof_value;
// }incremental_point;

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
