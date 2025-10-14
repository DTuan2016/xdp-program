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

    {{"contamination", required_argument, NULL, 'c'},
     "Contamination (fraction of anomalies to set threshold)", "<float>", false},

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
    if (!f) {
        fprintf(stderr, "[ERROR] Cannot open file: %s\n", filename);
        return -1;
    }

    char line[1024];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && count < max_rows) {
        data_point dp = {0};
        int idx;
        int src_port, dst_port;
        char src_ip[64];
        char dst_ip[64];
        double feature0, feature1, feature2, feature3, feature4;
        int un_label, proto;
        char label_str[32];  // label as string
        
        int n = sscanf(line,
                       "%d,%63[^,],%d,%63[^,],%d,%d,%lf,%lf,%lf,%lf,%lf,%d,%31s",
                       &idx, src_ip, &src_port, dst_ip, &dst_port, &proto,
                       &feature0, &feature1, &feature2,
                       &feature3, &feature4, &un_label, label_str);

        if (n != 13) continue;

        /* Copy features */
        dp.features[0] = fixed_from_float(log2(feature0 + 1.0));
        dp.features[1] = fixed_from_float(log2(feature1 + 1.0));
        dp.features[2] = fixed_from_float(log2(feature2 + 1.0));
        dp.features[3] = fixed_from_float(log2(feature3 + 1.0));
        dp.features[4] = fixed_from_float(log2(feature4 + 1.0));
        /* Convert label string to int: BENIGN=1, else=0 */
        if (strcmp(label_str, "BENIGN") == 0)
            dp.label = 1;
        else
            dp.label = 0;

        dataset[count++] = dp;
    }
    fclose(f);
    return count;
}

fixed c_factor(int n) {
    if (n <= 1) return 0.0;
    return fixed_from_float(2.0 * (log((double)n - 1.0) + 0.5772156649) - 2.0*(n - 1.0) / n);
}

void init_forest(IsolationForest *forest, __u32 n_trees, __u32 max_depth){
    if (!forest) return;
    forest->n_trees         = n_trees;
    forest->max_depth       = max_depth;
    forest->sample_size     = 0;
    for(__u32 t = 0; t < n_trees && t < MAX_TREES; t++){
        forest->trees[t].num_nodes = 0;
        for(__u32 n = 0; n < MAX_NODE_PER_TREE; n++){
            iTreeNode *node = &forest->trees[t].nodes[n];
            node->is_leaf       = 1;
            node->left_idx      = NULL_IDX;
            node->right_idx     = NULL_IDX;
            node->feature_idx   = -1;
            node->split_value   = 0;
            node->num_points    = 0;
        }
    }
}

/*==================== Build Isolation Tree ====================*/
int build_tree(iTree *tree, data_point *points, __u32 num_points, int depth, int node_idx)
{
    if (!tree || !points || num_points == 0 || node_idx >= MAX_NODE_PER_TREE)
        return -1;

    iTreeNode *node = &tree->nodes[node_idx];
    node->is_leaf      = 1;
    node->num_points   = num_points;
    node->left_idx     = NULL_IDX;
    node->right_idx    = NULL_IDX;
    node->feature_idx  = -1;
    node->split_value  = 0;

    /* Update tree node count */
    tree->num_nodes = (tree->num_nodes > (unsigned)(node_idx + 1)) ? tree->num_nodes : (node_idx + 1);

    /* Stop condition */
    if (num_points <= 1 || depth >= (int)tree->max_depth) {
        return node_idx;
    }

    /* Randomly select a feature */
    int feat = rand() % MAX_FEATURES;

    /* Find min/max of the feature */
    fixed minv = points[0].features[feat];
    fixed maxv = minv;
    for (__u32 i = 1; i < num_points; i++) {
        if (points[i].features[feat] < minv) minv = points[i].features[feat];
        if (points[i].features[feat] > maxv) maxv = points[i].features[feat];
    }

    /* Cannot split if all values are equal */
    if (minv >= maxv) {
        return node_idx;
    }

    /* Choose split strictly inside (min, max) */
    uint32_t min_uint = fixed_to_uint(minv);
    uint32_t max_uint = fixed_to_uint(maxv);
    if (max_uint - min_uint <= 1) {
        return node_idx;
    }
    uint32_t split_uint = min_uint + 1 + rand() % (max_uint - min_uint - 1);
    fixed split = fixed_from_uint(split_uint);

    node->is_leaf      = 0;
    node->feature_idx  = feat;
    node->split_value  = split;

    /* Partition points into left/right */
    data_point left[MAX_FLOW_SAVED];
    data_point right[MAX_FLOW_SAVED];
    __u32 li = 0, ri = 0;

    for (__u32 i = 0; i < num_points; i++) {
        if (points[i].features[feat] <= split) {
            if (li < MAX_FLOW_SAVED) left[li++] = points[i];
        } else {
            if (ri < MAX_FLOW_SAVED) right[ri++] = points[i];
        }
    }

    /* If any side is empty, make this node a leaf */
    if (li == 0 || ri == 0) {
        node->is_leaf = 1;
        node->feature_idx = -1;
        node->split_value = 0;
        return node_idx;
    }

    /* Build left subtree */
    int left_idx = node_idx + 1;
    int last_left = build_tree(tree, left, li, depth + 1, left_idx);
    if (last_left < 0) {
        node->is_leaf = 1;
        node->feature_idx = -1;
        node->split_value = 0;
        return node_idx;
    }
    node->left_idx = left_idx;

    /* Build right subtree */
    int right_idx = last_left + 1;
    int last_right = build_tree(tree, right, ri, depth + 1, right_idx);
    if (last_right < 0) {
        node->is_leaf = 1;
        node->right_idx = NULL_IDX;
        return node_idx;
    }
    node->right_idx = right_idx;

    /* Update node count */
    node->num_points = num_points;
    tree->num_nodes = (tree->num_nodes > (unsigned)(last_right + 1)) ? tree->num_nodes : (last_right + 1);

    return last_right;
}


void train_isolation_tree(iTree *tree, data_point *dataset, __u32 num_points, __u32 max_depth) {
    if (!tree) return;
    tree->num_nodes = 0;
    tree->max_depth = max_depth;
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) {
        tree->nodes[i].is_leaf      = 1;
        tree->nodes[i].left_idx     = NULL_IDX;
        tree->nodes[i].right_idx    = NULL_IDX;
        tree->nodes[i].feature_idx  = -1;
        tree->nodes[i].split_value  = 0;
        tree->nodes[i].num_points   = 0;
    }

    int last = build_tree(tree, dataset, num_points, 0, 0);
    if (last < 0) {
        fprintf(stderr, "[WARN] build_tree returned error\n");
        tree->num_nodes = 0;
    }
}

void bootstrap_sample(data_point *dataset, __u32 num_points, __u32 sample_size, data_point *sample) {
    if (!dataset || !sample || num_points == 0) return;
    if (sample_size > MAX_FLOW_SAVED) sample_size = MAX_FLOW_SAVED; /* safety */
    for (__u32 i = 0; i < sample_size; i++) {
        __u32 idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
}

void train_isolation_forest(IsolationForest *forest, data_point *dataset, int num_points, struct forest_params *params) {
    if (!forest || !dataset || !params) return;

    forest->n_trees     = params->n_trees;
    forest->max_depth   = params->max_depth;
    forest->sample_size = params->sample_size;
    printf("[INFO] Training %u trees with max_depth=%u, sample_size=%u\n",
           params->n_trees, params->max_depth, params->sample_size);

    __u32 sample_size = params->sample_size;
    if (sample_size > MAX_FLOW_SAVED) sample_size = MAX_FLOW_SAVED;
    if (sample_size == 0) sample_size = (num_points > 0) ? ( (__u32) num_points ) : 1;
    if (sample_size > (unsigned)num_points) sample_size = (unsigned)num_points;

    for (__u32 t = 0; t < params->n_trees && t < MAX_TREES; t++) {
        printf("Training tree %u/%u...\n", t + 1, params->n_trees);
        data_point sample[MAX_FLOW_SAVED];
        memset(sample, 0, sizeof(sample));
        bootstrap_sample(dataset, (unsigned)num_points, sample_size, sample);
        train_isolation_tree(&forest->trees[t], sample, sample_size, params->max_depth);
        printf("Tree %u: %u nodes\n", t, forest->trees[t].num_nodes);
    }
}

int save_forest_to_map(int map_fd_nodes, int map_fd_c, int map_fd_params, IsolationForest *forest, struct forest_params *params) {
    if (!forest || map_fd_nodes < 0) return -1;

    int total_nodes = 0;
    for (__u32 t = 0; t < forest->n_trees && t < MAX_TREES; t++) {
        iTree *tree = &forest->trees[t];
        for (int n = 0; n < (int)tree->num_nodes && n < MAX_NODE_PER_TREE; n++) {
            __u32 key = t * MAX_NODE_PER_TREE + (unsigned)n;
            iTreeNode node = tree->nodes[n]; /* copy */
            if (bpf_map_update_elem(map_fd_nodes, &key, &node, BPF_ANY) != 0) {
                fprintf(stderr, "[ERROR] Failed to update node %u: %s\n", key, strerror(errno));
                return -1;
            }
            total_nodes++;
        }
    }
    printf("[INFO] Saved %d nodes to map\n", total_nodes);

    /* populate c(n) map if provided */
    if (map_fd_c >= 0) {
        for (__u32 n = 0; n <= (unsigned)TRAINING_SET; n++) {
            fixed c = c_factor((int)n);
            if (bpf_map_update_elem(map_fd_c, &n, &c, BPF_ANY) != 0) {
                fprintf(stderr, "[WARN] Failed to update c(%u): %s\n", n, strerror(errno));
                /* continue attempting others */
            }
        }
        printf("[INFO] Populated xdp_isoforest_c map (0..%d)\n", TRAINING_SET);
    }

    /* save params map if provided */
    if (map_fd_params >= 0 && params) {
        __u32 k0 = 0;
        if (bpf_map_update_elem(map_fd_params, &k0, params, BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] Failed to update params map: %s\n", strerror(errno));
            return -1;
        }
        printf("[INFO] Saved forest params to map\n");
    }

    return 0;
}

fixed path_length_point(iTreeNode *nodes, int node_idx, data_point *dp) {
    fixed length = fixed_from_float(0.0);
    int depth_check = 0;

    while (node_idx != NULL_IDX && node_idx < MAX_NODE_PER_TREE) {
        iTreeNode *node = &nodes[node_idx];

        // printf("[DEBUG] Visiting node idx=%d, is_leaf=%d, num_points=%d, feature_idx=%d, split=%u\n",
        //        node_idx, node->is_leaf, node->num_points, node->feature_idx,
        //        fixed_to_uint(node->split_value));

        if (node->is_leaf) {
            printf("[DEBUG] Reached leaf idx=%d, num_points=%d, length=%f\n",
                   node_idx, fixed_to_uint(node->num_points), fixed_to_float(length));
            return fixed_add(length, c_factor(node->num_points));
        }

        __u32 feat = (node->feature_idx >= 0 && node->feature_idx < MAX_FEATURES) ? node->feature_idx : 0;
        fixed f_val = dp->features[feat];

        node_idx = (f_val <= node->split_value) ? node->left_idx : node->right_idx;
        length = fixed_add(length, fixed_from_uint(1));

        if (++depth_check > MAX_NODE_PER_TREE) {
            printf("[WARN] path_length_point: max depth exceeded\n");
            break;
        }
    }
    return length;
}

fixed anomaly_score_point(IsolationForest *forest, data_point *dp, __u32 sample_size) {
    if (!forest || forest->n_trees == 0){
        return fixed_from_float(0.0);
    }
    fixed sum_path = fixed_from_float(0.0);
    for (__u32 t = 0; t < forest->n_trees; t++) {
        sum_path = fixed_add(sum_path, path_length_point(forest->trees[t].nodes, 0, dp));
    }
    fixed avg_path = fixed_div(sum_path, fixed_from_uint(forest->n_trees));
    fixed c_n = c_factor((int)sample_size);
    printf("avg_path=%u, c_n=%u", avg_path, c_n);
    if (c_n <= fixed_from_float(0.0)) 
    {
        return fixed_from_float(0.0);
    }
    /* avg_depth / c_n */
    fixed ratio = fixed_div(avg_path, c_n);

    /* score = 2^(-avg_depth / c_n) */
    fixed exp = fixed_exp2(ratio);          // 2^(avg/c)
    fixed score = fixed_div(fixed_from_uint(1), exp);  // 1 / 2^(avg/c)

    return score;
}

int is_anomaly(fixed score, struct forest_params *params) {
    if (!params) 
    {
        return 0;
    }
    return (score >= params->threshold) ? 1 : 0;
}

/*=============== Testing helper ===============*/
void test_forest_accuracy(IsolationForest *forest, data_point *test_data, int test_count, struct forest_params *params) {
    if (!forest || !test_data || test_count <= 0) return;
    int correct = 0;
    for (int i = 0; i < test_count; i++) {
        fixed score = anomaly_score_point(forest, &test_data[i], params->sample_size);
        int pred = is_anomaly(score, params);
        int actual = (test_data[i].label != 0) ? 1 : 0;
        if (pred == actual) correct++;
        if (i < 10) {
            printf("Test %d: score=%u pred=%d actual=%d\n", i, score, pred, actual);
        }
    }
    printf("[INFO] Accuracy: %d/%d = %.2f%%\n", correct, test_count, (double)correct/test_count*100.0);
}

int cmp_fixed_desc(const void *a, const void *b) {
    fixed fa = *(const fixed *)a;
    fixed fb = *(const fixed *)b;

    if (fa < fb) return 1;
    else if (fa > fb) return -1;
    else return 0;
}

/*==================== MAIN ====================*/
int main(int argc, char **argv) {
    srand(time(NULL));
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd_nodes = -1, map_fd_params = -1, map_fd_c = -1;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ = "Train IsolationForest and load into XDP BPF maps\n";
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

    /* Open pinned maps */
    map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_nodes'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    map_fd_c = open_bpf_map_file(pin_dir, "xdp_isoforest_c", &info);
    if (map_fd_c < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_c'\n", pin_dir);
        close(map_fd_nodes);
        return EXIT_FAIL_BPF;
    }

    map_fd_params = open_bpf_map_file(pin_dir, "xdp_isoforest_params", &info);
    if (map_fd_params < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_isoforest_params'\n", pin_dir);
        close(map_fd_nodes);
        close(map_fd_c);
        return EXIT_FAIL_BPF;
    }

    /* Load dataset */
    data_point train_dataset[TRAINING_SET];
    int train_count = read_csv_dataset("/home/dongtv/dtuan/xdp-program/data/data.csv",
                                       train_dataset, TRAINING_SET);
    if (train_count < 1) {
        fprintf(stderr, "[ERROR] Training dataset empty or invalid\n");
        close(map_fd_nodes);
        close(map_fd_params);
        close(map_fd_c);
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d training samples\n", train_count);

    /* Initialize forest */
    IsolationForest forest;
    init_forest(&forest, MAX_TREES, MAX_DEPTH);

    struct forest_params params;
    memset(&params, 0, sizeof(params));
    params.n_trees          = MAX_TREES;
    params.sample_size      = MAX_SAMPLE_PER_NODE;
    params.max_depth        = MAX_DEPTH;
    params.contamination    = CONTAMINATION;

    /* Train */
    printf("[INFO] Starting Isolation Forest training...\n");
    train_isolation_forest(&forest, train_dataset, train_count, &params);
    printf("[INFO] Isolation Forest trained with %u trees\n", forest.n_trees);
    /* Compute anomaly scores for training set */
    fixed scores_fp[TRAINING_SET];
    for (int i = 0; i < train_count; i++) {
        scores_fp[i] = anomaly_score_point(&forest, &train_dataset[i], params.sample_size);
        printf("[DEBUG] Train sample %d: score_fp=%u, score_float=%.6f\n",
            i, scores_fp[i], fixed_to_float(scores_fp[i]));
    }

    /* Sort fixed-point scores descending */
    qsort(scores_fp, train_count, sizeof(fixed), cmp_fixed_desc);

    // /* Compute threshold index */
    // int threshold_index = (int)((1.0 - (double)CONTAMINATION/SCALE) * train_count);
    // if (threshold_index >= train_count) threshold_index = train_count - 1;
    // if (threshold_index < 0) threshold_index = 0;

    // /* Log threshold info */
    // printf("[DEBUG] Threshold index=%d, contamination=%f\n", threshold_index, (double)CONTAMINATION/SCALE);
    // params.threshold = scores_fp[threshold_index];
    // printf("[DEBUG] Selected threshold_fp=%u, threshold_float=%.6f\n",
    //     params.threshold, fixed_to_float(params.threshold));

    double frac = (double)CONTAMINATION / SCALE; // CONTAMINATION là % (10)
    int threshold_index = (int)((1.0 - frac) * train_count);
    if (threshold_index >= train_count) threshold_index = train_count - 1;
    if (threshold_index < 0) threshold_index = 0;

    params.threshold = scores_fp[threshold_index];
    printf("[DEBUG] Threshold index=%d, threshold_fp=%u, threshold_float=%.6f\n",
        threshold_index, params.threshold, fixed_to_float(params.threshold));
    if (save_forest_to_map(map_fd_nodes, map_fd_c, map_fd_params, &forest, &params) != 0) {
        fprintf(stderr, "[ERROR] Failed to save forest to maps\n");
        close(map_fd_nodes);
        close(map_fd_c);
        close(map_fd_params);
        return EXIT_FAILURE;
    }
    data_point test_dataset[MAX_FLOW_SAVED];
    int test_count = read_csv_dataset("/home/dongtv/dtuan/training_isolation/data.csv",
                                       test_dataset, MAX_FLOW_SAVED);
    if (test_count < 1)
    {
        fprintf(stderr, "[ERROR] Testing dataset empty or invalid\n");
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d testing samples\n", test_count);

    test_forest_accuracy(&forest, test_dataset, MAX_FLOW_SAVED, &params);
    printf("[INFO] Successfully updated BPF maps\n");
    printf("[INFO] Forest params: n_trees=%u, max_depth=%u, sample_size=%u, threshold=%f\n",
           params.n_trees, params.max_depth, params.sample_size, fixed_to_float(params.threshold));

    close(map_fd_nodes);
    close(map_fd_c);
    close(map_fd_params);
    return EXIT_SUCCESS;
}