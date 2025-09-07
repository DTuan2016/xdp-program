/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <math.h>

#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'},
     "Show help", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>", "<ifname>", true},

    {{"quiet", no_argument, NULL, 'q'},
     "Quiet mode (no output)"},

    {{0, 0, NULL, 0}}
};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

/*==================== PRINT ====================*/
static void print_flow_key(struct flow_key *key) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    printf("%s:%u", src_ip, ntohs(key->src_port));
}

static void print_data_point(data_point *dp) {
    printf("%-12llu | %-12u | %-12u | %-12u |\n",
           dp->last_seen - dp->start_ts,
           dp->total_pkts,
           dp->total_bytes,
           dp->flow_IAT_mean);
}

/* Random interger in range from min to max */
static int rand_int(int min, int max){
    return min + rand() % (max - min + 1);
}

/* Create bootstrap sample */
static data_point *bootstrap_sample(data_point *dataset, int num_points, int sample_size){
    data_point *sample = (data_point*)malloc(sample_size * sizeof(data_point));
    for(int i = 0; i < sample_size; i++){
        int idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
    return sample;
}

/* Build iTree recursively into nodes array */
static int build_iTree(data_point *points, int num_points, int current_depth, int max_depth,
                                                            iTreeNode *nodes, int node_idx){
    if(num_points <= 1 || current_depth >= max_depth || node_idx >= MAX_NODE_PER_TREE){
        nodes[node_idx].is_leaf     = 1;
        nodes[node_idx].size        = num_points;
        nodes[node_idx].left_idx    = nodes[node_idx].right_idx = NULL_IDX;
        return node_idx;
    }
    int feature = rand() % MAX_FEATURES;
    int min_val = points[0].features[feature];
    int max_val = points[0].features[feature];
    for(int i = 0; i < num_points; i++){
        if(min_val > points[i].features[feature]) min_val = points[i].features[feature];
        if(max_val > points[i].features[feature]) max_val = points[i].features[feature];
    }
    if (min_val == max_val){
        nodes[node_idx].is_leaf     = 1;
        nodes[node_idx].size        = num_points;
        nodes[node_idx].left_idx    = nodes[node_idx].right_idx = NULL_IDX;
        return node_idx;
    }
    int split_value = rand_int(min_val, max_val);
    nodes[node_idx].feature      = feature;
    nodes[node_idx].split_value  = split_value;
    nodes[node_idx].size         = num_points;
    nodes[node_idx].is_leaf      = 0;
    
    int left_count, right_count = 0;
    for(int i = 0; i < num_points; i++){
        if(points[i].features[feature] < split_value) left_count++;
        else right_count++;
    }

    if (left_count == 0 || right_count == 0) {
        nodes[node_idx].is_leaf     = 1;
        nodes[node_idx].size        = num_points;
        nodes[node_idx].left_idx    = nodes[node_idx].right_idx = NULL_IDX;
        return node_idx;
    }

    data_point *left_points  = malloc(left_count  * sizeof(data_point));
    data_point *right_points = malloc(right_count * sizeof(data_point));
    if (!left_points || !right_points) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    int li = 0, ri = 0;
    for(int i  = 0; i < num_points; i++){
        if(points[i].features[feature] < split_value) left_points[li++] = points[i];
        else right_points[ri++] = points[i];
    }

    int left_idx  = node_idx * 2 + 1;
    int right_idx = node_idx * 2 + 2;
    nodes[node_idx].left_idx  = (left_idx  < MAX_NODE_PER_TREE) ? left_idx  : NULL_IDX;
    nodes[node_idx].right_idx = (right_idx < MAX_NODE_PER_TREE) ? right_idx : NULL_IDX;

    build_iTree(left_points,  left_count,  current_depth + 1, max_depth, nodes, left_idx);
    build_iTree(right_points, right_count, current_depth + 1, max_depth, nodes, right_idx);
    return node_idx;
}

IsolationForest *init_iForest(__u32 n_trees, __u32 sample_size, __u32 max_depth){
    IsolationForest *forest = malloc(sizeof(IsolationForest));
    forest->n_trees     = n_trees;
    forest->max_depth   = max_depth;
    forest->sample_size = sample_size;
    for(int i = 0; i < n_trees; i++){
        forest->trees[i].node_count = 0;
    }
    srand(time(NULL));
    return forest;
}

void fit_iForest(IsolationForest *forest, data_point *dataset, int num_points){
    for(int i = 0; i < forest->n_trees; i++){
        data_point *sample = bootstrap_sample(dataset, num_points, forest->sample_size);
        build_iTree(sample, forest->sample_size, 0, forest->max_depth, forest->trees[i].nodes, 0);
        forest->trees[i].node_count = MAX_NODE_PER_TREE;
        free(sample);
    }
}

static int serialize_forest_to_array(IsolationForest *forest, iTreeNode *out_array, int max_out) {
    if (!forest || !out_array) return 0;
    int total_needed = forest->n_trees * MAX_NODE_PER_TREE;
    if (max_out < total_needed) {
        fprintf(stderr, "serialize_forest_to_array: out array too small (%d < %d)\n", max_out, total_needed);
        return 0;
    }
    int idx = 0;
    for (int t = 0; t < forest->n_trees; t++) {
        /* Each tree uses MAX_NODE_PER_TREE slots (even if some unused). */
        for (int n = 0; n < MAX_NODE_PER_TREE; n++) {
            out_array[idx++] = forest->trees[t].nodes[n];
        }
    }
    return idx; /* equals total_needed */
}

/*==================== MAIN ====================*/
int main(int argc, char **argv)
{
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd;
    int len, err;

    struct config cfg = {
        .ifindex = -1,
        .do_unload = false,
    };

    const char *__doc__ = "Dump data_point from XDP BPF map\n";

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    map_fd = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd < 0)
        return EXIT_FAIL_BPF;

    struct flow_key key, next_key;
    data_point value;

    while (1) {
        data_point flows[MAX_FLOW_SAVED];
        struct flow_key keys[MAX_FLOW_SAVED];
        int flow_count = 0;

        memset(&key, 0, sizeof(key));

        while ((err = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                if (flow_count < MAX_FLOW_SAVED) {
                    flows[flow_count] = value;
                    keys[flow_count]  = next_key;
                    flow_count++;
                }
            }
            key = next_key;
        }

        if (flow_count == TRAINING_SET) {
           
            printf("\n=== Flow Table with LOF ===\n");
            printf("%-4s | %-21s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
                   "STT", "SrcIP:Port",
                   "FlowDur(ns)", "TotalPkts", "TotalBytes", "MeanIAT(ns)",
                   "k-dist", "reach[0]", "lrd", "lof");

            for (int i = 0; i < flow_count; i++) {
                printf("%-4d | ", i+1);
                print_flow_key(&keys[i]);
                printf(" | ");
                print_data_point(&flows[i]);
                printf("\n");
                // print_knn(&flows[i]);

                bpf_map_update_elem(map_fd, &keys[i], &flows[i], BPF_ANY);
            }
        } else {
            printf("\n[INFO] Current flows: %d (waiting for %d to compute LOF)\n",
                   flow_count, TRAINING_SET);
        }

        sleep(1);
    }
    return EXIT_OK;
}
