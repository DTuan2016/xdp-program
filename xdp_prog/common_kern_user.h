#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <linux/types.h>

#define TRAINING_SET         10000
#define MAX_FLOW_SAVED       2000

#define QS_NUM_TREES 10
#define MAX_FEATURES 6 
#define QS_NUM_NODES 310
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

typedef __u32 BITVECTOR_TYPE;

static __always_inline BITVECTOR_TYPE msb_index(BITVECTOR_TYPE x) {
    return __builtin_clzll((__u64)x) - 32;
}


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
  128000, 128000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 640000, 640000, 896000, 896000, 896000, 896000, 896000, 896000, 3840000, 6144000, 9344000, 12544000, 13056000, 14464000, 14464000, 14592000, 14720000, 14720000, 23936000, 25088000, 31872000, 32128000, 32896000, 33152000, 33152000, 35456000, 35712000, 51072000, 57472000, 57472000, 141184000, 141184000, 145280000, 148608000, 7829248000, 7973248000, 11639808000, 14197248000, 17074304000, 17074304000, 17074304000, 17074304000, 17222912000, 17664256000, 17729280000, 18560640000, 22587904000, 27920384000, 27921280000, 36702720000, 51211520000, 53314942976, 60976254976, 61236736000, 61319553024, 61367552000, 69733376000, 80436097024, 80436097024, 80436097024, 80476291072, 116641918976, 153755516928, 154042753024, 154527236096, 154546561024, 154546561024, 154546561024, 154546561024, 154592387072, 158617853952, 165172985856, 199300096000, 199545733120, 199808000000, 199808000000, 199808000000, 199928193024, 201007996928, 209044733952, 682776289280, 721662197760, 727464706048, 844487057408, 844738035712, 844738035712, 846784782336, 3459369041920, 4536386355200, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 384, 640, 640, 640, 640, 640, 640, 640, 896, 896, 1152, 1152, 1152, 1152, 1152, 1152, 1408, 1664, 1664, 1664, 1664, 1920, 2304, 2432, 2688, 3200, 3200, 3200, 3200, 3200, 3200, 3456, 3712, 3712, 53248, 108544, 108544, 108544, 1280, 1536, 5120, 6016, 6912, 6912, 7808, 7808, 7808, 12032, 26880, 36096, 36096, 36096, 36352, 41728, 42752, 42752, 42752, 42752, 42752, 44544, 49408, 56064, 57344, 58240, 91392, 97024, 98176, 98560, 98560, 224768, 230656, 268032, 339456, 594432, 604160, 608256, 752128, 979712, 1027840, 70656000, 128, 384, 384, 1920, 1920, 4224, 5120, 5120, 5504, 5504, 5504, 5504, 5504, 5760, 6656, 6912, 7040, 7040, 12032, 12032, 12032, 12032, 12032, 12160, 13184, 13184, 13184, 13184, 13184, 13440, 13440, 16896, 17280, 17280, 17280, 17280, 18048, 18048, 18048, 21376, 21376, 21376, 21376, 21376, 21376, 22272, 22272, 22272, 79616, 108672, 110720, 110976, 112384, 112512, 112512, 131328, 132224, 132224, 146176, 149888, 154240, 221056, 297472, 407552, 2048, 2048, 3072, 4864, 4864, 5248, 5504, 5504, 8704, 10240, 11776, 13056, 13056, 17280, 17280, 17280, 17280, 17280, 18048, 21376, 22272, 22272, 24704, 33152, 33664, 407552, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 128000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 384000, 640000, 640000, 896000, 1152000, 5760000, 6272000, 22656000, 15817344000, 16578688000
};

static const BITVECTOR_TYPE _qs_bitvectors[QS_NUM_NODES] = {
  0x7fffffff, 0x7fffffff, 0x3fffffff, 0x3fffffff, 0x0fffffff, 0x0fffffff, 0xbfffffff, 0x9fffffff, 0x0fffffff, 0xfeffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff, 0xdfffffff, 0xfeffffff, 0xf7ffffff, 0xfe7fffff, 0xffffdfff, 0x3fffffff, 0xffefffff, 0xdfffffff, 0xff7fffff, 0xcfffffff, 0xf7ffffff, 0xffff7fff, 0xffefffff, 0xcfffffff, 0xe7ffffff, 0xf7ffffff, 0x07ffffff, 0xf3ffffff, 0xfbffffff, 0xfeffffff, 0xefffffff, 0xfdffffff, 0xdfffffff, 0xf7ffffff, 0xfbffffff, 0xf9ffffff, 0xfbffffff, 0xffffffbf, 0xffbfffff, 0xf7ffffff, 0xffffefff, 0xffff9fff, 0xfffffdff, 0xfffffbff, 0xffff7fff, 0xfffffdff, 0xffffcfff, 0xf3ffffff, 0xf9ffffff, 0xfcffffff, 0xcfffffff, 0xe7ffffff, 0xfffbffff, 0xf87fffff, 0xf9ffffff, 0xfffffbff, 0xfff7ffff, 0xffe0ffff, 0xffff7fff, 0xfffbffff, 0xffffc3ff, 0xfffffcff, 0xfbffffff, 0xff7fffff, 0xf7ffffff, 0xffc003ff, 0xfffffeff, 0xff3fffff, 0xf9ffffff, 0xffbfffff, 0xf3ffffff, 0xfeffffff, 0x00000001, 0xfffffc0f, 0xfff803ff, 0xffff3fff, 0xfffff807, 0xfffffe3f, 0xffffc1ff, 0x00000001, 0xffffe0ff, 0xfffffeff, 0xff03ffff, 0xffe1ffff, 0xfeffffff, 0xfeffffff, 0x8001ffff, 0xfffbffff, 0xffff8fff, 0xffdfffff, 0xffdfffff, 0xffdfffff, 0xfffbffff, 0xfffffff9, 0xffffffe1, 0xfffffffb, 0xffffff81, 0xfffffffd, 0xfffffffb, 0xf1ffffff, 0xffffff7f, 0xbfffffff, 0x7fffffff, 0xf0ffffff, 0x7fffffff, 0xffffefff, 0x7fffffff, 0xfc1fffff, 0xfffffffb, 0xffffffef, 0x01ffffff, 0xc0ffffff, 0xf8ffffff, 0x0fffffff, 0xffdfffff, 0xc1ffffff, 0xfe0fffff, 0xffffbfff, 0xfff7ffff, 0xfffffe1f, 0xffffdfff, 0xff8fffff, 0xffbfffff, 0xfff7ffff, 0xfffdffff, 0xefffffff, 0xfffff7ff, 0xff3fffff, 0xfffffbff, 0xfffff7ff, 0xffff87ff, 0xfffffbff, 0xffff7fff, 0xfffffbff, 0xffffc7ff, 0xfffff7ff, 0xffffbfff, 0xffffe07f, 0xfffffc1f, 0xfffff83f, 0xffff80ff, 0xfffffcff, 0xfffff03f, 0xfffff7ff, 0xfffe1fff, 0xfffffe1f, 0xfffffff3, 0xfffffff9, 0xfffffffd, 0xfffffff1, 0x007fffff, 0xc03fffff, 0xdfffffff, 0xbfffffff, 0xf001ffff, 0xfbffffff, 0x007fffff, 0xffdfffff, 0x001fffff, 0x0000ffff, 0xfff9ffff, 0xfffdffff, 0xffff7fff, 0xfffffeff, 0x0003ffff, 0xffff7fff, 0xfffcffff, 0xffff3fff, 0xffffff9f, 0xffffff9f, 0xfffffff7, 0xffffffef, 0xffffffe7, 0xffffefff, 0xfffeffff, 0xffff9fff, 0xfffff7ff, 0xfffffff3, 0xfffdffff, 0x000003ff, 0x000007ff, 0xfffff9ff, 0xffffffdf, 0xffffefff, 0xffffffcf, 0xffffe01f, 0xfffc03ff, 0xfffffc0f, 0xffff9fff, 0xfffffe7f, 0xfffffffb, 0xfffffff9, 0xf07fffff, 0xf03fffff, 0xe001ffff, 0xe7ffffff, 0xffefffff, 0x7fffffff, 0x1fffffff, 0x3fffffff, 0xc000ffff, 0xf000ffff, 0x003fffff, 0xc00fffff, 0x00007fff, 0xffefffff, 0xfe03ffff, 0xfbffffff, 0xffefffff, 0xff0fffff, 0xffff7fff, 0xffe7ffff, 0xfff7ffff, 0xffff9fff, 0xfffffdff, 0xffffefff, 0xffbfffff, 0xffe7ffff, 0xffff7fff, 0xffdfffff, 0xfff8ffff, 0xffc7ffff, 0xffe7ffff, 0xdfffffff, 0x00001fff, 0xff83ffff, 0xfffeffff, 0xffc3ffff, 0xffffffdf, 0xffffffef, 0xffffffbf, 0xffffffcf, 0xffffff1f, 0x00007fff, 0x000007ff, 0xffffffe7, 0xffffffef, 0xffff1fff, 0xffffefff, 0xffffbfff, 0xffffff7f, 0xfffffdff, 0xffffbfff, 0xffffff7f, 0xffffff3f, 0xfffffeff, 0xfffffcff, 0xffffff0f, 0xfffc3fff, 0xffff0fff, 0xfffffff7, 0xfffffe7f, 0xfffe0fff, 0xfffff87f, 0xfffff9ff, 0xfffffffb, 0xffffff1f, 0xfffffc07, 0xffffbfff, 0xffff3fff, 0xfffdffff, 0x7fffffff, 0x000001ff, 0xf001ffff, 0xffdfffff, 0xfffffdff, 0xffffe03f, 0xfffffc07, 0xfffff803, 0x000000ff, 0x0000007f, 0x0000007f, 0x000001ff, 0x0000000f, 0xffffffbf, 0xfffffe7f, 0xfffffff7, 0xffffffbf, 0xffffe7ff, 0xffffffc7, 0xfffffe03, 0xfffffffb, 0xf9ffffff, 0x7fffffff, 0xffff3fff, 0xffffdfff, 0x3fffffff, 0xfffffff7, 0x7fffffff, 0x3fffffff, 0xf07fffff, 0xfffeffff, 0xfffbffff, 0xff7fffff, 0x81ffffff, 0xffe7ffff, 0xfffeffff, 0xf807ffff, 0xff8fffff, 0xfffffe3f, 0xff7fffff, 0xdfffffff, 0xdfffffff, 0xefffffff, 0xffbfffff, 0xffdfffff, 0xfbffffff
};

static const __u16 _qs_tree_ids[QS_NUM_NODES] = {
  2, 9, 0, 1, 2, 3, 4, 5, 6, 7, 7, 8, 9, 4, 5, 3, 5, 6, 7, 7, 8, 3, 4, 6, 1, 1, 0, 9, 2, 1, 6, 9, 4, 8, 6, 7, 0, 3, 9, 2, 2, 3, 4, 0, 9, 1, 3, 7, 5, 6, 0, 3, 6, 7, 8, 6, 9, 2, 4, 5, 4, 5, 8, 6, 4, 8, 6, 7, 7, 5, 6, 8, 9, 7, 0, 4, 1, 8, 2, 3, 5, 6, 7, 0, 9, 3, 6, 1, 2, 5, 9, 5, 9, 8, 0, 0, 1, 2, 5, 6, 8, 0, 0, 2, 2, 3, 3, 4, 4, 5, 6, 6, 7, 7, 8, 9, 1, 3, 4, 5, 6, 8, 8, 7, 9, 0, 0, 2, 5, 6, 8, 9, 0, 4, 5, 8, 0, 7, 8, 5, 0, 1, 3, 6, 7, 9, 2, 2, 5, 9, 0, 3, 9, 7, 4, 6, 5, 0, 1, 1, 2, 4, 5, 4, 1, 3, 8, 2, 2, 1, 3, 6, 7, 9, 2, 2, 1, 9, 4, 9, 7, 7, 1, 3, 9, 3, 7, 3, 9, 2, 5, 8, 1, 4, 5, 2, 2, 9, 5, 6, 6, 2, 3, 0, 6, 7, 8, 9, 4, 5, 5, 2, 3, 0, 2, 3, 5, 7, 9, 1, 4, 6, 7, 8, 1, 7, 3, 0, 1, 3, 7, 0, 6, 7, 0, 2, 4, 5, 6, 8, 1, 3, 4, 4, 3, 8, 5, 4, 1, 3, 4, 7, 8, 4, 9, 2, 3, 0, 2, 4, 5, 9, 0, 8, 0, 2, 3, 1, 4, 0, 1, 3, 2, 6, 7, 8, 9, 6, 8, 8, 8, 1, 0, 8, 1, 1, 1, 1, 3, 6, 7, 8, 9, 0, 2, 4, 4, 5, 6, 7, 9, 0, 1, 8, 0, 1, 9, 5, 5, 4
};

static const __u8 _qs_num_leaves_per_tree[QS_NUM_TREES] = {
  32, 32, 32, 32, 32, 32, 32, 32, 32, 32
};

static const __u8 _qs_leaves[QS_NUM_LEAVES] = {
  /* tree 0 */ 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0,
  /* tree 1 */ 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0,
  /* tree 2 */ 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0,
  /* tree 3 */ 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0,
  /* tree 4 */ 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0,
  /* tree 5 */ 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0,
  /* tree 6 */ 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0,
  /* tree 7 */ 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0,
  /* tree 8 */ 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0,
  /* tree 9 */ 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0,
};


#define QS_OFFSETS_0 0
#define QS_OFFSETS_1 102
#define QS_OFFSETS_2 153
#define QS_OFFSETS_3 195
#define QS_OFFSETS_4 259
#define QS_OFFSETS_5 285
#define QS_OFFSETS_6 310

#define QS_LEAF_BASE_0 0
#define QS_LEAF_BASE_1 32
#define QS_LEAF_BASE_2 64
#define QS_LEAF_BASE_3 96
#define QS_LEAF_BASE_4 128
#define QS_LEAF_BASE_5 160
#define QS_LEAF_BASE_6 192
#define QS_LEAF_BASE_7 224
#define QS_LEAF_BASE_8 256
#define QS_LEAF_BASE_9 288
#define QS_NUM_LEAVES_0 32
#define QS_NUM_LEAVES_1 32
#define QS_NUM_LEAVES_2 32
#define QS_NUM_LEAVES_3 32
#define QS_NUM_LEAVES_4 32
#define QS_NUM_LEAVES_5 32
#define QS_NUM_LEAVES_6 32
#define QS_NUM_LEAVES_7 32
#define QS_NUM_LEAVES_8 32
#define QS_NUM_LEAVES_9 32

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
