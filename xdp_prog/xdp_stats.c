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
// static void print_flow_key(struct flow_key *key) {
//     char src_ip[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
//     printf("%s:%u", src_ip, ntohs(key->src_port));
// }

// static void print_data_point(data_point *dp) {
//     printf("%-12llu | %-12u | %-12u | %-12u |\n",
//            dp->last_seen - dp->start_ts,
//            dp->total_pkts,
//            dp->total_bytes,
//            dp->flow_IAT_mean);
// }

/* Random value integer range from min to max */
static int rand_int_range(int min, int max) {
    if (max <= min) return min;
    double r = (double)rand() / (RAND_MAX + 1.0);
    long range = (long)max - (long)min + 1L;
    return (int)(min + (int)(r * range));
}

/* Bootstrap sample from dataset */
static data_point *bootstrap_sample(data_point *dataset, int num_points, int sample_size){
    data_point *sample = calloc(sample_size, sizeof(data_point));
    if(!sample) return NULL;
    for(int i = 0; i < sample_size; i++){
        int idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
    return sample;
}

/* compute harmonic number H(n) (simple O(n) implementation) */
static double harmonic_number(int n){
    if (n <= 0){
        return 0.0;
    }
    double h = 0.0;
    for (int i = 1; i <= n; ++i){
        h += 1.0 / (double)i;
    }
    return h;
}


/* expected average path length c(n) for sample size n in iForest literature */
static double expected_path_length(int n){
    if (n <= 1){
        return 0.0;
    }
    return 2.0 * harmonic_number(n - 1) - 2.0 * (double)(n - 1) / (double)n;
}

/* Build iTree recursively into nodes array, return used node count */
static int build_iTree(data_point *points, int num_points, int current_depth, int max_depth,
                        iTreeNode *nodes, int *next_free)
{
    if(num_points <= 0) return 0;
    if(*next_free >= MAX_NODE_PER_TREE){
        return 0;
    }
    int cur = (*next_free)++;
    nodes[cur].is_leaf      = 0;
    nodes[cur].size         = num_points;
    nodes[cur].left_idx     = NULL_IDX;
    nodes[cur].right_idx    = NULL_IDX;
    nodes[cur].feature      = 0;
    nodes[cur].split_value  = 0;

    if (num_points <= 1 || current_depth >= max_depth) {
        nodes[cur].is_leaf      = 1;
        nodes[cur].size         = num_points;
        nodes[cur].left_idx     = NULL_IDX;
        nodes[cur].right_idx    = NULL_IDX;
        return 1;
    }

    /* Pick random feature */
    int f = rand() % MAX_FEATURES;

    /* Find min and max */
    int min_val = points[0].features[f];
    int max_val = points[0].features[f];
    for (int i = 1; i < num_points; i++) {
        if (points[i].features[f] < min_val) min_val = points[i].features[f];
        if (points[i].features[f] > max_val) max_val = points[i].features[f];
    }

    /* If no split possible, make leaf */
    if (max_val - min_val <= 1) {
        nodes[cur].is_leaf      = 1;
        nodes[cur].size         = num_points;
        nodes[cur].left_idx     = NULL_IDX;
        nodes[cur].right_idx    = NULL_IDX;
        nodes[cur].feature      = f;
        nodes[cur].split_value  = min_val;
        return 1;
    }

    int split_low = min_val + 1;
    int split_high = max_val - 1;
    int split = rand_int_range(split_low, split_high);

    /* Count left/right */
    int left_count = 0, right_count = 0;
    for (int i = 0; i < num_points; i++){
        if(points[i].features[f] < split) left_count++;
        else right_count++;
    }

    if (left_count == 0 || right_count == 0){
        nodes[cur].is_leaf      = 1;
        nodes[cur].size         = num_points;
        nodes[cur].left_idx     = NULL_IDX;
        nodes[cur].right_idx    = NULL_IDX;
        nodes[cur].feature      = f;
        nodes[cur].split_value  = split;
        return 1;
    }

    /* Allocate child arrays */
    data_point *left = malloc(left_count * sizeof(data_point));
    data_point *right = malloc(right_count * sizeof(data_point));
    if (!left || !right){
        perror("malloc");
        free(left); free(right);
        /* mark node as leaf to keep program running */
        nodes[cur].is_leaf      = 1;
        nodes[cur].size         = num_points;
        nodes[cur].left_idx     = NULL_IDX;
        nodes[cur].right_idx    = NULL_IDX;
        nodes[cur].feature      = f;
        nodes[cur].split_value  = split;
        return 1;
    }

    int li = 0, ri = 0;
    for (int i = 0; i < num_points; ++i){
        if (points[i].features[f] < split) left[li++] = points[i];
        else right[ri++] = points[i];
    }

    /* fill node metadata */
    nodes[cur].is_leaf          = 0;
    nodes[cur].size             = num_points;
    nodes[cur].feature          = f;
    nodes[cur].split_value      = split;
    
    int used = 1;
    if (left_count > 0){
        int left_start = *next_free;
        int used_left = build_iTree(left, left_count, current_depth + 1, max_depth, nodes, next_free);
        if (used_left <= 0) {
            /* if child creation failed, make current a leaf to be safe */
            nodes[cur].is_leaf      = 1;
            nodes[cur].left_idx     = NULL_IDX;
            nodes[cur].right_idx    = NULL_IDX;
            free(left); 
            free(right);
            return 1;
        }
        nodes[cur].left_idx         = left_start;
        used += used_left;
    }
    if (right_count > 0){
        int right_start = *next_free;
        int used_right = build_iTree(right, right_count, current_depth + 1, max_depth, nodes, next_free);
        if (used_right <= 0){
            /* degrade to leaf */
            nodes[cur].is_leaf      = 1;
            nodes[cur].left_idx     = NULL_IDX;
            nodes[cur].right_idx    = NULL_IDX;
            free(left); 
            free(right);
            return 1;
        }
        nodes[cur].right_idx        = right_start;
        used += used_right;
    }
    free(left);
    free(right);
    return used;
}

/* Initialize forest */
IsolationForest *init_iForest(__u32 n_trees, __u32 sample_size, __u32 max_depth){
    IsolationForest *forest = calloc(1, sizeof(IsolationForest));
    if(!forest){
        perror("calloc");
        return NULL;
    }
    forest->n_trees         = n_trees;
    forest->sample_size     = sample_size;
    forest->max_depth       = max_depth;
    for(unsigned int i = 0; i < n_trees && i < MAX_TREES; ++i){
        forest->trees[i].node_count = 0;
    }
    return forest;
}

void free_iForest(IsolationForest *forest){
    if (!forest){
        return;
    }
    free(forest);
}

/* Fit forest, return array of actual node counts per tree */
void fit_iForest(IsolationForest *forest, data_point *dataset, int num_points){
    if(!forest) {
        return;
    }
    for (int t = 0; t < (int)forest->n_trees && t < MAX_TREES; ++t){
        data_point *sample = bootstrap_sample(dataset, num_points, forest->sample_size);
        if (!sample){
            fprintf(stderr, "[ERROR] bootstrap_sample failed for tree %d\n", t);
            continue;
        }

        memset(forest->trees[t].nodes, 0, sizeof(forest->trees[t].nodes));
        int next_free = 0;
        int used = build_iTree(sample, forest->sample_size, 0, forest->max_depth,
                                       forest->trees[t].nodes, &next_free);
        if (used < 0) used = 0;
        forest->trees[t].node_count = next_free;
        free(sample);
    }
}

/* Serialize forest to array */
int serialize_forest_blocked(IsolationForest *forest, int map_fd_nodes) {
    if (!forest) return -1;

    for (unsigned int t = 0; t < forest->n_trees && t < MAX_TREES; ++t) {
        int base = t * MAX_NODE_PER_TREE;
        int cnt  = forest->trees[t].node_count;

        for (int n = 0; n < MAX_NODE_PER_TREE; n++) {
            __u32 key_idx = base + n;
            iTreeNode node = {};
            if (n < cnt) {
                node = forest->trees[t].nodes[n];
            } else {
                // pad rỗng
                node.is_leaf = 1;
                node.left_idx = NULL_IDX;
                node.right_idx = NULL_IDX;
                node.size = 0;
            }

            if (bpf_map_update_elem(map_fd_nodes, &key_idx, &node, BPF_ANY) != 0) {
                fprintf(stderr, "[ERROR] update node %u failed: %s\n",
                        key_idx, strerror(errno));
                return -1;
            }
        }
    }
    return 0;
}

__u32 compute_avg_path_length(IsolationForest *forest, data_point *dataset, int num_points){
    if (!forest || forest->sample_size <= 1) return 0;
    double c = expected_path_length((int)forest->sample_size);
    if (c < 0.0) c = 0.0;
    return ( __u32 ) (c + 0.5);
}

/*==================== MAIN ====================*/
int main(int argc, char **argv)
{
    srand(time(NULL)); /* seed random once */
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd_nodes, map_fd_params;
    int len;

    struct config cfg = {
        .ifindex = -1,
        .do_unload = false,
    };

    const char *__doc__ = "Dump data_point from XDP BPF map and train IsolationForest\n";
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
    if (map_fd < 0) return EXIT_FAIL_BPF;

    map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_nodes'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    map_fd_params = open_bpf_map_file(pin_dir, "xdp_isoforest_params", &info);
    if (map_fd_params < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_params'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    while (1) {
        struct flow_key key = {}, next_key;
        data_point flows[TRAINING_SET];
        int flow_count = 0;

        /* Load flows from map */
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 && flow_count < TRAINING_SET) {
            data_point value;
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                flows[flow_count++] = value;
            }
            key = next_key;
        }

        if (flow_count < TRAINING_SET) {
            printf("[INFO] Current flows: %d (waiting for %d to train IsolationForest)\n",
                   flow_count, TRAINING_SET);
            sleep(1);
            continue;
        }

        printf("\n=== Training IsolationForest with %d flows ===\n", flow_count);

        /* Copy dataset */
        data_point dataset[TRAINING_SET];
        memcpy(dataset, flows, sizeof(dataset));

        /* Parameters */
        const __u32 n_trees     = MAX_TREES;
        const __u32 sample_size = (TRAINING_SET < 32) ? TRAINING_SET : 32;
        const __u32 max_depth   = 10;

        /* Init and fit */
        IsolationForest *forest = init_iForest(n_trees, sample_size, max_depth);
        if (!forest) {
            fprintf(stderr, "[ERROR] init_iForest failed\n");
            sleep(1);
            continue;
        }

        fit_iForest(forest, dataset, TRAINING_SET);

        /* Serialize nodes block layout */
        iTreeNode *all_nodes = calloc(MAX_TREES * MAX_NODE_PER_TREE, sizeof(iTreeNode));
        if (!all_nodes) {
            perror("calloc all_nodes");
            free_iForest(forest);
            sleep(1);
            continue;
        }

        for (unsigned int t = 0; t < forest->n_trees && t < MAX_TREES; ++t) {
            int cnt = forest->trees[t].node_count;
            int base = t * MAX_NODE_PER_TREE;
            for (int n = 0; n < MAX_NODE_PER_TREE; ++n) {
                if (n < cnt) {
                    all_nodes[base + n] = forest->trees[t].nodes[n];
                } else {
                    all_nodes[base + n].is_leaf   = 1;
                    all_nodes[base + n].left_idx  = NULL_IDX;
                    all_nodes[base + n].right_idx = NULL_IDX;
                    all_nodes[base + n].size      = 0;
                }
            }
        }

        /* Update BPF map */
        for (__u32 i = 0; i < MAX_TREES * MAX_NODE_PER_TREE; i++) {
            if (bpf_map_update_elem(map_fd_nodes, &i, &all_nodes[i], BPF_ANY) != 0) {
                fprintf(stderr, "[ERROR] update node %u failed: %s\n", i, strerror(errno));
            }
        }

        /* Compute threshold automatically */
        __u32 threshold = compute_avg_path_length(forest, dataset, TRAINING_SET);

        struct forest_params params = {
            .n_trees     = n_trees,
            .sample_size = sample_size,
            .threshold   = threshold,
        };
        __u32 param_key = 0;
        if (bpf_map_update_elem(map_fd_params, &param_key, &params, BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] update forest_params failed: %s\n", strerror(errno));
        } else {
            printf("[INFO] Updated forest_params (n_trees=%u, sample_size=%u, threshold=%u)\n",
                   n_trees, sample_size, threshold);
        }

        printf("[INFO] Successfully updated nodes into xdp_isoforest_nodes\n");

        free(all_nodes);
        free_iForest(forest);

        /* Đã train xong, break vòng lặp */
        break;
    }

    return EXIT_OK;
}