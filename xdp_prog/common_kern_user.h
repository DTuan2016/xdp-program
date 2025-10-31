#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <linux/types.h>

#define TRAINING_SET         10000
#define MAX_FLOW_SAVED       2000

#define QS_NUM_TREES 40
#define MAX_FEATURES 6 
#define QS_NUM_NODES 280
#define QS_NUM_LEAVES 320

#define QS_FEATURE_FLOW_DURATION 0
#define QS_FEATURE_TOTAL_FWD_PACKET 1
#define QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET 2
#define QS_FEATURE_FWD_PACKET_LENGTH_MAX 3
#define QS_FEATURE_FWD_PACKET_LENGTH_MIN 4
#define QS_FEATURE_FWD_IAT_MIN 5

#define FIXED_SHIFT 8
#define FIXED_SCALE (1ULL << FIXED_SHIFT)
typedef __u64 fixed;

typedef __u8 BITVECTOR_TYPE;

static __always_inline BITVECTOR_TYPE msb_index(BITVECTOR_TYPE x) {
    return __builtin_clzll((__u64)x) - 56;
}


/* Latency statistics structure */
typedef struct {
    __u64 time_in;
    __u64 time_out;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u32 total_pkts;
    __u32 total_bytes;
} accounting;

struct flow_key {
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
} __attribute__((packed));

typedef struct {
    __u64   start_ts;             /* Timestamp of first packet */
    __u64   last_seen;            /* Timestamp of last packet */
    __u64   min_IAT;              /* Minimum Inter-Arrival Time */
    __u32   total_pkts;           /* Total packet count*/
    __u32   max_pkt_len;          /* Maximum packet length */
    __u32   min_pkt_len;          /* Minimum packet length */
    __u32   total_bytes;          /* Total byte count*/

    int   label;
} data_point; 

/*
 Layout rules:
 - Internal nodes are grouped by feature id in ascending order.
 - For feature f, its nodes occupy range [QS_OFFSETS_f, QS_OFFSETS_f+1) in the thresholds array.
 - bitvectors mark (LSB=leaf0) the set of leaves in that tree reachable from the node.
 - leaves array is laid out as [tree0 | tree1 | ...], each block is num_leaves[h] entries with h the tree id.
   If a tree has fewer leaves, the remainder of its block is zero-padded.
 - Each leaves entry is a uint8 class id (argmax at the leaf).
*/
struct feat_vec {
    fixed features[MAX_FEATURES];
};

struct qsDataStruct{
    fixed threshold[QS_NUM_NODES];
    BITVECTOR_TYPE bitvectors[QS_NUM_NODES];
    BITVECTOR_TYPE v[QS_NUM_TREES];
    __u16 tree_ids[QS_NUM_NODES];
    __u8  num_leaves_per_tree[QS_NUM_TREES];
    __u8  leaves[QS_NUM_LEAVES];
};

static const fixed _qs_threshold[QS_NUM_NODES] = {
  384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 896000, 896000, 896000, 896000, 1152000, 4736000, 9728000, 14464000, 14464000, 14464000, 14720000, 14720000, 16000000, 141184000, 11533056000, 17074304000, 17198080000, 17240320000, 17664256000, 17664256000, 17664256000, 17729280000, 27920384000, 27921280000, 53192577024, 61367552000, 153690365952, 153709690880, 153709690880, 153709690880, 153755516928, 153755516928, 154083074048, 154534789120, 154546561024, 154546561024, 154592387072, 157700612096, 157962878976, 158417920000, 199545733120, 199545733120, 199545733120, 199808000000, 199808000000, 199808000000, 199928193024, 199985790976, 460620021760, 681872228352, 844722700288, 844738035712, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 640, 640, 1152, 1152, 1152, 1152, 1152, 1408, 1664, 1664, 1664, 2432, 2432, 3200, 3200, 3200, 3200, 3200, 3200, 3200, 3200, 3200, 3200, 3200, 5120, 5120, 6016, 6016, 7808, 7808, 7808, 7808, 7808, 7808, 11520, 11520, 11520, 12032, 12032, 12544, 12544, 36096, 36352, 36352, 42496, 42752, 42752, 42752, 42752, 42752, 98560, 98560, 98560, 98560, 98560, 98560, 98560, 205568, 344320, 594432, 604160, 608256, 4096, 4096, 4992, 5120, 5120, 5120, 5120, 5120, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 5504, 7040, 12160, 13184, 13184, 13184, 13184, 13184, 13184, 15744, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 21376, 21376, 21376, 21376, 21376, 21376, 21376, 21376, 21376, 21376, 24704, 26112, 132224, 132224, 132224, 377728, 2048, 2048, 2944, 5248, 5248, 5504, 5504, 5504, 5504, 5504, 5504, 10112, 10880, 11776, 11776, 11776, 12288, 13056, 13056, 13056, 13056, 13440, 17024, 17024, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 17280, 20096, 33152, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 384000, 384000, 384000, 384000, 384000, 384000, 640000, 1152000, 1152000, 1152000, 6528000, 6528000, 6656000, 6784000, 6912000, 7040000
};

static const BITVECTOR_TYPE _qs_bitvectors[QS_NUM_NODES] = {
  0x3f, 0x7f, 0x3f, 0xbf, 0x7f, 0x7f, 0x7f, 0x7f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x7f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x7f, 0x7f, 0xbf, 0x3f, 0xbf, 0x7f, 0x7f, 0x7f, 0x7f, 0xcf, 0xbf, 0xdf, 0x1f, 0x1f, 0x7f, 0xbf, 0xcf, 0xdf, 0xfd, 0xdf, 0xfb, 0xcf, 0xcf, 0xef, 0xdf, 0xdf, 0xe7, 0xef, 0xc7, 0x9f, 0xf9, 0xfb, 0xfd, 0x01, 0x01, 0xf7, 0x01, 0xef, 0xfd, 0xfd, 0x01, 0xef, 0xf7, 0xdf, 0xef, 0xdf, 0xdf, 0xdf, 0xbf, 0xef, 0xdf, 0xef, 0xdf, 0xef, 0xf9, 0xfd, 0xdf, 0x7f, 0x7f, 0xdf, 0x8f, 0x7f, 0x3f, 0xef, 0xdf, 0x3f, 0xdf, 0x7f, 0x7f, 0xf7, 0xdf, 0xf7, 0xbf, 0xdf, 0xdf, 0xfb, 0xfb, 0xfb, 0xfd, 0xfd, 0xfb, 0xef, 0xf7, 0xfb, 0xfb, 0xfb, 0xf7, 0xc7, 0xfb, 0xdf, 0xf3, 0x7f, 0x7f, 0x7f, 0x7f, 0x0f, 0x1f, 0x03, 0xdf, 0x07, 0x1f, 0xfb, 0xcf, 0x7f, 0x1f, 0x3f, 0xdf, 0xdf, 0xf7, 0x3f, 0x3f, 0xbf, 0xfb, 0xfd, 0xf9, 0xfb, 0xf3, 0x03, 0x03, 0x07, 0x03, 0x07, 0x07, 0x07, 0xfd, 0x8f, 0xe3, 0xdf, 0xc7, 0x7f, 0x7f, 0xdf, 0x7f, 0x7f, 0x7f, 0x7f, 0xcf, 0xcf, 0x87, 0x7f, 0x83, 0x3f, 0x07, 0x0f, 0x0f, 0xc7, 0x0f, 0x0f, 0xc7, 0x7f, 0x0f, 0x07, 0x7f, 0xbf, 0xef, 0xef, 0xfb, 0xf7, 0xef, 0xbf, 0xbf, 0xdf, 0x07, 0xf7, 0xf7, 0xbf, 0xef, 0x07, 0x07, 0xc7, 0x0f, 0x07, 0x07, 0x03, 0xfb, 0x03, 0x07, 0x03, 0xfd, 0x03, 0xfd, 0xfd, 0x0f, 0x07, 0xef, 0xcf, 0xfb, 0xfb, 0xf3, 0xfb, 0xfd, 0xf7, 0x9f, 0x7f, 0x7f, 0x0f, 0xcf, 0x1f, 0x03, 0xfb, 0x87, 0xf9, 0xf9, 0xf9, 0xf9, 0xf1, 0xfd, 0xfd, 0xfd, 0xf9, 0xfd, 0xdf, 0x01, 0x07, 0x07, 0x01, 0x07, 0x01, 0x01, 0x03, 0xef, 0x01, 0xc1, 0x03, 0x01, 0x01, 0x03, 0x03, 0x03, 0x0f, 0x01, 0x8f, 0xf1, 0xbf, 0xbf, 0x3f, 0xdf, 0x3f, 0x7f, 0x7f, 0x7f, 0xdf, 0x7f, 0x7f, 0x87, 0x7f, 0xbf, 0xbf, 0xbf, 0xf7, 0xf3, 0xcf, 0xbf, 0xdf, 0xc7, 0x1f, 0xc3, 0xcf, 0xdf, 0xdf
};

static const __u16 _qs_tree_ids[QS_NUM_NODES] = {
  0, 2, 3, 4, 6, 8, 9, 10, 12, 13, 14, 17, 19, 20, 22, 23, 24, 26, 29, 33, 34, 35, 36, 39, 8, 15, 16, 21, 32, 39, 22, 0, 18, 22, 1, 6, 20, 9, 14, 8, 31, 24, 19, 22, 26, 14, 4, 5, 33, 7, 31, 15, 17, 36, 4, 20, 33, 27, 13, 32, 7, 14, 24, 34, 6, 15, 21, 1, 5, 29, 31, 17, 10, 32, 37, 2, 3, 4, 5, 6, 8, 11, 16, 18, 23, 32, 33, 20, 23, 8, 16, 18, 27, 32, 27, 5, 23, 26, 12, 35, 0, 7, 9, 16, 19, 21, 25, 27, 28, 38, 39, 12, 39, 14, 33, 1, 4, 18, 20, 22, 36, 11, 23, 37, 5, 35, 12, 13, 38, 2, 25, 30, 7, 10, 11, 37, 38, 1, 3, 12, 13, 14, 19, 26, 24, 34, 9, 2, 30, 19, 29, 39, 3, 13, 17, 26, 33, 0, 6, 7, 8, 9, 10, 15, 16, 17, 21, 28, 29, 30, 31, 32, 38, 11, 9, 4, 6, 15, 36, 37, 38, 30, 0, 1, 3, 7, 12, 16, 21, 23, 25, 28, 31, 32, 2, 4, 5, 17, 22, 24, 30, 34, 35, 36, 30, 37, 12, 14, 35, 36, 5, 35, 11, 0, 24, 2, 3, 25, 27, 29, 34, 21, 28, 0, 16, 25, 23, 1, 3, 19, 26, 37, 15, 37, 2, 6, 7, 8, 9, 10, 13, 18, 20, 22, 27, 29, 30, 33, 34, 38, 39, 11, 38, 1, 10, 15, 17, 21, 25, 27, 28, 29, 31, 36, 11, 18, 28, 31, 34, 39, 25, 10, 18, 28, 13, 35, 20, 26, 19, 24
};

static const __u8 _qs_num_leaves_per_tree[QS_NUM_TREES] = {
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
};

static const __u8 _qs_leaves[QS_NUM_LEAVES] = {
  /* tree 0 */ 1, 0, 1, 0, 0, 1, 0, 1,
  /* tree 1 */ 1, 0, 1, 0, 0, 1, 0, 1,
  /* tree 2 */ 1, 0, 0, 0, 0, 0, 1, 0,
  /* tree 3 */ 1, 0, 0, 1, 0, 1, 0, 1,
  /* tree 4 */ 0, 1, 1, 0, 0, 1, 1, 0,
  /* tree 5 */ 0, 1, 0, 0, 1, 1, 0, 1,
  /* tree 6 */ 1, 1, 0, 1, 0, 0, 0, 1,
  /* tree 7 */ 1, 0, 0, 1, 0, 0, 1, 0,
  /* tree 8 */ 1, 1, 0, 1, 1, 0, 0, 1,
  /* tree 9 */ 1, 0, 0, 0, 1, 0, 0, 1,
  /* tree 10 */ 1, 0, 1, 0, 1, 0, 0, 1,
  /* tree 11 */ 0, 1, 0, 0, 1, 1, 0, 1,
  /* tree 12 */ 1, 0, 0, 0, 1, 1, 1, 0,
  /* tree 13 */ 1, 0, 0, 0, 1, 1, 1, 0,
  /* tree 14 */ 1, 0, 0, 1, 0, 1, 1, 0,
  /* tree 15 */ 1, 0, 1, 0, 0, 0, 0, 1,
  /* tree 16 */ 1, 0, 1, 0, 0, 1, 0, 1,
  /* tree 17 */ 1, 0, 0, 1, 0, 0, 1, 0,
  /* tree 18 */ 1, 0, 1, 0, 1, 0, 0, 1,
  /* tree 19 */ 1, 0, 0, 1, 1, 1, 0, 1,
  /* tree 20 */ 1, 0, 0, 0, 0, 0, 1, 1,
  /* tree 21 */ 1, 0, 1, 0, 0, 1, 0, 1,
  /* tree 22 */ 1, 0, 1, 0, 1, 0, 0, 1,
  /* tree 23 */ 1, 0, 0, 1, 0, 1, 0, 1,
  /* tree 24 */ 1, 0, 0, 1, 1, 0, 1, 1,
  /* tree 25 */ 0, 1, 0, 0, 1, 0, 1, 1,
  /* tree 26 */ 1, 0, 0, 1, 1, 1, 0, 1,
  /* tree 27 */ 0, 1, 0, 1, 0, 0, 0, 1,
  /* tree 28 */ 0, 1, 1, 1, 0, 1, 0, 1,
  /* tree 29 */ 1, 0, 0, 1, 0, 0, 0, 1,
  /* tree 30 */ 1, 0, 0, 1, 0, 0, 0, 1,
  /* tree 31 */ 0, 1, 1, 0, 0, 1, 1, 0,
  /* tree 32 */ 1, 0, 1, 1, 0, 0, 1, 0,
  /* tree 33 */ 1, 0, 0, 1, 0, 1, 1, 0,
  /* tree 34 */ 1, 0, 1, 0, 0, 0, 0, 1,
  /* tree 35 */ 1, 0, 0, 1, 0, 1, 1, 0,
  /* tree 36 */ 0, 1, 1, 0, 0, 1, 0, 0,
  /* tree 37 */ 1, 0, 1, 0, 0, 0, 1, 0,
  /* tree 38 */ 1, 0, 1, 0, 1, 0, 1, 1,
  /* tree 39 */ 1, 0, 0, 0, 0, 1, 0, 1,
};


#define QS_OFFSETS_0 0
#define QS_OFFSETS_1 76
#define QS_OFFSETS_2 111
#define QS_OFFSETS_3 149
#define QS_OFFSETS_4 210
#define QS_OFFSETS_5 253
#define QS_OFFSETS_6 280

#define QS_LEAF_BASE_0 0
#define QS_LEAF_BASE_1 8
#define QS_LEAF_BASE_2 16
#define QS_LEAF_BASE_3 24
#define QS_LEAF_BASE_4 32
#define QS_LEAF_BASE_5 40
#define QS_LEAF_BASE_6 48
#define QS_LEAF_BASE_7 56
#define QS_LEAF_BASE_8 64
#define QS_LEAF_BASE_9 72
#define QS_LEAF_BASE_10 80
#define QS_LEAF_BASE_11 88
#define QS_LEAF_BASE_12 96
#define QS_LEAF_BASE_13 104
#define QS_LEAF_BASE_14 112
#define QS_LEAF_BASE_15 120
#define QS_LEAF_BASE_16 128
#define QS_LEAF_BASE_17 136
#define QS_LEAF_BASE_18 144
#define QS_LEAF_BASE_19 152
#define QS_LEAF_BASE_20 160
#define QS_LEAF_BASE_21 168
#define QS_LEAF_BASE_22 176
#define QS_LEAF_BASE_23 184
#define QS_LEAF_BASE_24 192
#define QS_LEAF_BASE_25 200
#define QS_LEAF_BASE_26 208
#define QS_LEAF_BASE_27 216
#define QS_LEAF_BASE_28 224
#define QS_LEAF_BASE_29 232
#define QS_LEAF_BASE_30 240
#define QS_LEAF_BASE_31 248
#define QS_LEAF_BASE_32 256
#define QS_LEAF_BASE_33 264
#define QS_LEAF_BASE_34 272
#define QS_LEAF_BASE_35 280
#define QS_LEAF_BASE_36 288
#define QS_LEAF_BASE_37 296
#define QS_LEAF_BASE_38 304
#define QS_LEAF_BASE_39 312
#define QS_NUM_LEAVES_0 8
#define QS_NUM_LEAVES_1 8
#define QS_NUM_LEAVES_2 8
#define QS_NUM_LEAVES_3 8
#define QS_NUM_LEAVES_4 8
#define QS_NUM_LEAVES_5 8
#define QS_NUM_LEAVES_6 8
#define QS_NUM_LEAVES_7 8
#define QS_NUM_LEAVES_8 8
#define QS_NUM_LEAVES_9 8
#define QS_NUM_LEAVES_10 8
#define QS_NUM_LEAVES_11 8
#define QS_NUM_LEAVES_12 8
#define QS_NUM_LEAVES_13 8
#define QS_NUM_LEAVES_14 8
#define QS_NUM_LEAVES_15 8
#define QS_NUM_LEAVES_16 8
#define QS_NUM_LEAVES_17 8
#define QS_NUM_LEAVES_18 8
#define QS_NUM_LEAVES_19 8
#define QS_NUM_LEAVES_20 8
#define QS_NUM_LEAVES_21 8
#define QS_NUM_LEAVES_22 8
#define QS_NUM_LEAVES_23 8
#define QS_NUM_LEAVES_24 8
#define QS_NUM_LEAVES_25 8
#define QS_NUM_LEAVES_26 8
#define QS_NUM_LEAVES_27 8
#define QS_NUM_LEAVES_28 8
#define QS_NUM_LEAVES_29 8
#define QS_NUM_LEAVES_30 8
#define QS_NUM_LEAVES_31 8
#define QS_NUM_LEAVES_32 8
#define QS_NUM_LEAVES_33 8
#define QS_NUM_LEAVES_34 8
#define QS_NUM_LEAVES_35 8
#define QS_NUM_LEAVES_36 8
#define QS_NUM_LEAVES_37 8
#define QS_NUM_LEAVES_38 8
#define QS_NUM_LEAVES_39 8

#define QS_VOTE_BLOCK(H) do {                 \
    BITVECTOR_TYPE exit_leaf_idx = (BITVECTOR_TYPE)(__u8)msb_index(tree->v[H]);         \
    if (exit_leaf_idx >= QS_NUM_LEAVES_##H) return 0;                 \
    BITVECTOR_TYPE l = QS_LEAF_BASE_##H + exit_leaf_idx;              \
    if (l >= QS_NUM_LEAVES) return 0;                                 \
    votes += tree->leaves[l];                                         \
} while (0)


#define QS_FEATURE(IDX, START, END) do {                              \
    fixed feat_value = fv.features[IDX];                             \
    for (int i = (START); i < (END); i++) {                          \
        if (feat_value < tree->threshold[i]) {                       \
            __u16 h = tree->tree_ids[i];                             \
            if (h >= QS_NUM_TREES) return 0;                         \
            tree->v[h] &= tree->bitvectors[i];                       \
        } else break;                                                \
    }                                                                \
} while (0)


#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

static __always_inline __u64 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
} 

#endif /* __COMMON_KERN_USER_H */
