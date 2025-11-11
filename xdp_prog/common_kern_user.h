#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <linux/types.h>

#define TRAINING_SET         10000
#define MAX_FLOW_SAVED       2000

#define QS_NUM_TREES 10
#define MAX_FEATURES 6 
#define QS_NUM_NODES 70
#define QS_NUM_LEAVES 80

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
    static const __u8 index[8] = { 0, 1, 2, 6, 3, 7, 5, 4 };
    if (x == 0) return 0;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    return index[((x * 0x17) >> 3) & 0x7];
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
  384000, 384000, 384000, 384000, 384000, 384000, 384000, 896000, 14464000, 14720000, 14720000, 141184000, 17074304000, 27920384000, 27921280000, 61367552000, 153755516928, 154592387072, 199545733120, 199808000000, 199808000000, 844738035712, 384, 384, 384, 384, 384, 1152, 1664, 3200, 3200, 3200, 7808, 7808, 12032, 36352, 42752, 98560, 98560, 594432, 604160, 5120, 5504, 5504, 5504, 5504, 5504, 12160, 13184, 13184, 17280, 17280, 17280, 17280, 21376, 21376, 21376, 2048, 5248, 5504, 5504, 11776, 13056, 13056, 17280, 17280, 17280, 17280, 17280, 128000
};

static const BITVECTOR_TYPE _qs_bitvectors[QS_NUM_NODES] = {
  0x3f, 0x7f, 0x3f, 0xbf, 0x7f, 0x7f, 0x7f, 0xbf, 0xdf, 0x7f, 0xbf, 0xdf, 0xdf, 0xe7, 0xef, 0x9f, 0x01, 0x01, 0xef, 0xdf, 0xbf, 0xfd, 0xdf, 0x7f, 0x7f, 0xdf, 0x8f, 0xf7, 0xfb, 0xfb, 0xef, 0xf7, 0x0f, 0x1f, 0x1f, 0x3f, 0xfb, 0x03, 0x03, 0xe3, 0xdf, 0x7f, 0xcf, 0x87, 0x7f, 0x83, 0x3f, 0xef, 0xef, 0xfb, 0x07, 0xf7, 0xf7, 0xbf, 0xfb, 0x03, 0x07, 0xfd, 0x7f, 0x0f, 0xcf, 0xf9, 0xfd, 0xfd, 0x07, 0x01, 0x07, 0x01, 0x01, 0xbf
};

static const __u16 _qs_tree_ids[QS_NUM_NODES] = {
  0, 2, 3, 4, 6, 8, 9, 8, 0, 1, 6, 9, 8, 4, 5, 7, 4, 7, 6, 1, 5, 2, 3, 4, 5, 6, 8, 8, 5, 0, 7, 9, 1, 4, 5, 2, 7, 1, 3, 9, 2, 3, 0, 6, 7, 8, 9, 9, 4, 6, 0, 1, 3, 7, 2, 4, 5, 5, 0, 2, 3, 0, 1, 3, 2, 6, 7, 8, 9, 1
};

static const __u8 _qs_num_leaves_per_tree[QS_NUM_TREES] = {
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8
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
};


#define QS_OFFSETS_0 0
#define QS_OFFSETS_1 22
#define QS_OFFSETS_2 32
#define QS_OFFSETS_3 41
#define QS_OFFSETS_4 57
#define QS_OFFSETS_5 69
#define QS_OFFSETS_6 70

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
