/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
#define SCALE                1000
#define TRAINING_SET         100
#define MAX_FLOW_SAVED       200
#define MAX_FEATURES         4
#define MAX_TREES            16
#define MAX_NODE_PER_TREE    16
#define MAX_SAMPLES_PER_NODE 10
#define NULL_IDX             UINT32_MAX

/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
} __attribute__((packed));

typedef struct {
    __u64 start_ts;             /* Timestamp of first packet */
    __u64 last_seen;            /* Timestamp of last packet */
    __u64 flow_duration;        /* Duration of a flow */
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time */
    __u32 features[MAX_FEATURES];
    int   label;
} data_point;

typedef struct BestSplitReturn{
    __u32   resultanGini;
    int     feature;
    int     category;
}BestSplit;

typedef struct Node{
    int         left_idx;
    int         right_idx;
    int         size;
    int         is_leaf;
    data_point  points[MAX_SAMPLES_PER_NODE];
    int         num_points;
    BestSplit   split;
} Node;

typedef struct DecisionTree{
    Node        nodes[MAX_NODE_PER_TREE];
    int         max_depth;
    int         min_samples_split;
    int         node_count;
}DecisionTree;

typedef struct{
    DecisionTree trees[MAX_TREES];
    __u32        n_trees;
    __u32        sample_size;
    __u32        max_depth;
    __u32        min_samples_split;
}RandomForest;

struct forest_params {
    __u32 n_trees;
    __u32 sample_size;
    __u32 min_samples_split;
};

/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */