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

/*==================== Command line options ====================*/
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

/*==================== CSV Reading ====================*/
int read_csv_dataset(const char *filename, data_point *dataset, int max_rows) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char line[512];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && count < max_rows) {
        data_point dp = {};
        int index, src_port;
        char src_ip[32];
        double flow_duration, flow_bytes_per_s, flow_pkts_per_s, flow_IAT_mean;
        double fwd_len_mean, bwd_len_mean;
        int label;
        int n = sscanf(line,
                       "%d,%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%lf,%d",
                       &index, src_ip, &src_port,
                       &flow_duration, &flow_bytes_per_s, &flow_pkts_per_s,
                       &flow_IAT_mean, &fwd_len_mean, &bwd_len_mean,
                       &label);

        if (n != 10) continue;

        dp.flow_duration   = (__u64)flow_duration;
        dp.flow_bytes_per_s= (__u32)flow_bytes_per_s;
        dp.flow_pkts_per_s = (__u32)flow_pkts_per_s;
        dp.flow_IAT_mean   = (__u32)flow_IAT_mean;
        dp.pkt_len_mean    = (__u32)((fwd_len_mean + bwd_len_mean) / 2.0);

        /* Copy to dp.features[] */
        dp.features[0] = (uint32_t)dp.flow_duration;
        dp.features[1] = dp.flow_bytes_per_s;
        dp.features[2] = dp.flow_pkts_per_s;
        dp.features[3] = dp.flow_IAT_mean;
        dp.features[4] = dp.pkt_len_mean;
        dp.label = label;
        dataset[count++] = dp;
    }

    fclose(f);
    return count;
}

/*==================== Random helpers ====================*/
static int rand_int_range(int min, int max) {
    if (max <= min) return min;
    double r = (double)rand() / (RAND_MAX + 1.0);
    long range = (long)max - (long)min + 1L;
    return (int)(min + (int)(r * range));
}

static data_point *bootstrap_sample(data_point *dataset, int num_points, int sample_size) {
    data_point *sample = calloc(sample_size, sizeof(data_point));
    if (!sample) return NULL;
    for (int i = 0; i < sample_size; i++) {
        int idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
    return sample;
}

/* Harmonic number H(n) */
static double harmonic_number(int n){
    double h = 0.0;
    for (int i = 1; i <= n; i++) h += 1.0 / (double)i;
    return h;
}

/* Expected path length c(n) */
static double expected_path_length(int n){
    if (n <= 1) return 0.0;
    return 2.0 * harmonic_number(n - 1) - 2.0 * (double)(n - 1) / n;
}

/*==================== iTree / IsolationForest ====================*/
static int build_iTree(data_point *points, int num_points, int current_depth, int max_depth,
                        iTreeNode *nodes, int *next_free)
{
    if (num_points <= 0 || *next_free >= MAX_NODE_PER_TREE)
        return 0;

    int cur = (*next_free)++;
    nodes[cur].is_leaf = 0;
    nodes[cur].size = num_points;
    nodes[cur].left_idx = NULL_IDX;
    nodes[cur].right_idx = NULL_IDX;

    if (num_points <= 1 || current_depth >= max_depth) {
        nodes[cur].is_leaf = 1;
        return 1;
    }

    int f = rand() % MAX_FEATURES;

    int min_val = points[0].features[f];
    int max_val = points[0].features[f];
    for (int i = 1; i < num_points; i++) {
        if (points[i].features[f] < min_val) min_val = points[i].features[f];
        if (points[i].features[f] > max_val) max_val = points[i].features[f];
    }

    if (max_val - min_val <= 1) {
        nodes[cur].is_leaf = 1;
        nodes[cur].feature = f;
        nodes[cur].split_value = min_val;
        return 1;
    }

    int split = rand_int_range(min_val + 1, max_val - 1);

    /* Count left/right */
    int left_count = 0, right_count = 0;
    for (int i = 0; i < num_points; i++){
        if(points[i].features[f] < split) left_count++;
        else right_count++;
    }

    if (left_count == 0 || right_count == 0) {
        nodes[cur].is_leaf = 1;
        nodes[cur].feature = f;
        nodes[cur].split_value = split;
        return 1;
    }

    data_point *left = malloc(left_count * sizeof(data_point));
    data_point *right = malloc(right_count * sizeof(data_point));
    if (!left || !right) {
        free(left); free(right);
        nodes[cur].is_leaf = 1;
        return 1;
    }

    int li = 0, ri = 0;
    for (int i = 0; i < num_points; i++) {
        if(points[i].features[f] < split) left[li++] = points[i];
        else right[ri++] = points[i];
    }

    nodes[cur].feature = f;
    nodes[cur].split_value = split;

    int used = 1;
    if (left_count > 0) {
        int left_start = *next_free;
        int used_left = build_iTree(left, left_count, current_depth + 1, max_depth, nodes, next_free);
        nodes[cur].left_idx = left_start;
        used += used_left;
    }
    if (right_count > 0) {
        int right_start = *next_free;
        int used_right = build_iTree(right, right_count, current_depth + 1, max_depth, nodes, next_free);
        nodes[cur].right_idx = right_start;
        used += used_right;
    }

    free(left);
    free(right);
    return used;
}

IsolationForest *init_iForest(__u32 n_trees, __u32 sample_size, __u32 max_depth){
    IsolationForest *forest = calloc(1, sizeof(IsolationForest));
    if(!forest) return NULL;
    forest->n_trees = n_trees;
    forest->sample_size = sample_size;
    forest->max_depth = max_depth;
    return forest;
}

void free_iForest(IsolationForest *forest){
    if(forest) free(forest);
}

void fit_iForest(IsolationForest *forest, data_point *dataset, int num_points){
    if(!forest) return;
    for(int t=0; t<(int)forest->n_trees && t<MAX_TREES; t++){
        data_point *sample = bootstrap_sample(dataset, num_points, forest->sample_size);
        if (!sample) continue;
        memset(forest->trees[t].nodes, 0, sizeof(forest->trees[t].nodes));
        int next_free = 0;
        build_iTree(sample, forest->sample_size, 0, forest->max_depth,
                    forest->trees[t].nodes, &next_free);
        forest->trees[t].node_count = next_free;
        free(sample);
    }
}

/* Serialize forest to BPF map */
int serialize_forest_blocked(IsolationForest *forest, int map_fd_nodes){
    if(!forest) return -1;
    for(unsigned int t=0; t<forest->n_trees && t<MAX_TREES; t++){
        int base = t * MAX_NODE_PER_TREE;
        int cnt = forest->trees[t].node_count;
        for(int n=0; n<MAX_NODE_PER_TREE; n++){
            __u32 key_idx = base+n;
            iTreeNode node = {};
            if(n<cnt) node = forest->trees[t].nodes[n];
            else {
                node.is_leaf = 1;
                node.left_idx = NULL_IDX;
                node.right_idx = NULL_IDX;
                node.size = 0;
            }
            bpf_map_update_elem(map_fd_nodes, &key_idx, &node, BPF_ANY);
        }
    }
    return 0;
}

/* Compute threshold */
__u32 compute_avg_path_length(IsolationForest *forest, data_point *dataset, int num_points){
    if(!forest || forest->sample_size <= 1) return 0;
    double c = expected_path_length((int)forest->sample_size);
    return (__u32)(c + 0.5);
}

/*==================== MAIN ====================*/
int main(int argc, char **argv){
    srand(time(NULL));

    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd_flow, map_fd_nodes, map_fd_params;

    struct config cfg = { .ifindex=-1, .do_unload=false };
    const char *__doc__ = "Train IsolationForest and push to XDP BPF maps, then test dataset\n";
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
    if(cfg.ifindex==-1){
        fprintf(stderr,"[ERROR] Missing required --dev\n");
        usage(argv[0], __doc__, long_options, (argc==1));
        return EXIT_FAIL_OPTION;
    }

    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    map_fd_flow   = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    map_fd_nodes  = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    map_fd_params = open_bpf_map_file(pin_dir, "xdp_isoforest_params", &info);
    if(map_fd_flow<0 || map_fd_nodes<0 || map_fd_params<0){
        fprintf(stderr,"[ERROR] Failed to open one or more BPF maps\n");
        return EXIT_FAIL_BPF;
    }

    /*==================== Training ====================*/
    data_point train_dataset[TRAINING_SET];
    int train_count = read_csv_dataset("/home/dongtv/dtuan/training_isolation/benign_data.csv",
                                       train_dataset, TRAINING_SET);
    if(train_count<1){
        fprintf(stderr,"[ERROR] Training CSV empty or invalid\n");
        return EXIT_FAIL_OPTION;
    }
    printf("[INFO] Read %d training flows\n", train_count);

    const __u32 n_trees = MAX_TREES;
    const __u32 sample_size = (train_count < 64) ? train_count : 64;
    const __u32 max_depth = 10;

    IsolationForest *forest = init_iForest(n_trees, sample_size, max_depth);
    if(!forest){
        fprintf(stderr,"[ERROR] init_iForest failed\n");
        return EXIT_FAIL_BPF;
    }

    fit_iForest(forest, train_dataset, train_count);

    /* Push nodes to BPF map */
    serialize_forest_blocked(forest, map_fd_nodes);

    /* Compute threshold */
    __u32 threshold = compute_avg_path_length(forest, train_dataset, train_count);
    struct forest_params params = { .n_trees=n_trees, .sample_size=sample_size, .threshold=threshold };
    __u32 param_key = 0;
    bpf_map_update_elem(map_fd_params, &param_key, &params, BPF_ANY);

    printf("[INFO] IsolationForest trained and pushed to BPF maps\n");

    return EXIT_OK;
}
