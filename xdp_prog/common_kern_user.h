/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>
/*Config numbers of total data_points to training*/
#define TRAINING_SET         3200
/*Config numbers of flow to save to map xdp_flow_tracking or flow_dropped*/
#define MAX_FLOW_SAVED       300
/*Config random forest*/
/*MAX 60 trees with max_node = 256*/
#define MAX_TREES            30
#define MAX_NODE_PER_TREE    256
#define MAX_SAMPLES_PER_NODE 256
#define MIN_SPLIT_SAMPLES    2
/*log2(TRAINING SET)*/     
#define MAX_TREE_DEPTH       8
/*Don't configure here*/
#define NULL_IDX             -1
#define MAX_FEATURES         5
#define SCALE                1000
/* Flow identification key */
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
} __attribute__((packed));
typedef struct {
    __u32 start_ts;             /* Timestamp of first packet */
    __u32 last_seen;            /* Timestamp of last packet */
    __u32 total_pkts;           /* Total packet count (Paccket/s)*/
    __u32 total_bytes;          /* Total byte count (Bytes/s)*/
    __u64 sum_IAT;              /* Sum of Inter-Arrival Times */
    /* Feature use for algorithm */
    __u32 flow_duration;        /* Duration of a flow */
    __u32 flow_IAT_mean;        /* Mean Inter-Arrival Time */
    __u32 flow_pkts_per_s;
    __u32 flow_bytes_per_s;
    __u32 pkt_len_mean;

    __u32 features[MAX_FEATURES];
    int   label;
} data_point;
typedef struct Node{
    int left_idx;
    int right_idx;
    __u32 split_value;
    int feature_idx;
    __u32 is_leaf;
    __u32 label;
} Node;
typedef struct DecisionTree{
    Node        nodes[MAX_NODE_PER_TREE];
    int         node_count;
    int         max_depth;
    int         min_samples_split;
}DecisionTree;
typedef struct{
    DecisionTree trees[MAX_TREES];
    __u32        n_trees;
    __u32        max_depth;
    __u32        sample_size;
}RandomForest;
struct forest_params {
    __u32 n_trees;
    __u32 sample_size;
    __u32 max_depth;
    __u32 min_samples_split;
};
/* XDP action definitions for compatibility */
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */