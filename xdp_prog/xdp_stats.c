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
    {{"help", no_argument, NULL, 'h'}, "Show help", false},
    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},
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

    char line[1024];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && count < max_rows) {
        data_point dp = {};
        int index, src_port;
        char src_ip[64];
        double flow_duration, fwd_packets, bwd_packets, len_fwd_pkts;
        double len_bwd_pkts, flow_IAT_mean;
        int label;
        int n = sscanf(line,
                       "%d,%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%lf,%d",
                       &index, src_ip, &src_port,
                       &flow_duration, &fwd_packets, &bwd_packets,
                       &len_fwd_pkts, &len_bwd_pkts, &flow_IAT_mean,
                       &label);

        if (n != 10) continue;

        dp.flow_duration   = (__u64)flow_duration;
        dp.flow_bytes_per_s= (__u32)(len_bwd_pkts + len_fwd_pkts) * 1000000 / flow_duration;
        dp.flow_pkts_per_s = (__u32)(fwd_packets + bwd_packets) * 1000000 / flow_duration;
        dp.flow_IAT_mean   = (__u32)flow_IAT_mean;
        dp.pkt_len_mean    = (__u32)((len_bwd_pkts + len_fwd_pkts) / (fwd_packets + bwd_packets));

        /* Copy to dp.features[] (order must match kernel) */
        dp.features[0] = (uint32_t)dp.flow_duration;
        dp.features[1] = dp.flow_bytes_per_s;
        dp.features[2] = dp.flow_pkts_per_s;
        dp.features[3] = dp.flow_IAT_mean;
        dp.features[4] = dp.pkt_len_mean;
        dp.label = label;
        dataset[count++] = dp;

        printf("Data: %u,%u,%u,%u,%u,%d \n", dp.features[0], dp.features[1], dp.features[2], 
            dp.features[3], dp.features[4], dp.label);
    }
    fclose(f);
    return count;
}

/*==================== TREE HELPERS ====================*/
static void count_classes(Node *node, int *count0, int *count1) {
    *count0 = 0;
    *count1 = 0;
    for (int i = 0; i < node->size; i++) {
        if (node->points[i].label == 0) (*count0)++;
        else (*count1)++;
    }
}

static Node *node_init_empty(Node *node) {
    if (!node) return NULL;
    node->left_idx              = NULL_IDX;
    node->right_idx             = NULL_IDX;
    node->size                  = 0;
    node->is_leaf               = 0;
    node->num_points            = 0;
    node->split.feature         = -1;
    node->split.category        = -1;
    node->split.resultanGini    = SCALE; /* worst */
    return node;
}

__u32 getGiniImpurity(Node *node) {
    if (!node || node->size == 0) return 0;

    int count0 = 0, count1 = 0;
    count_classes(node, &count0, &count1);

    float p0 = (float)count0 / node->size;
    float p1 = (float)count1 / node->size;
    return (__u32)(SCALE * (1.0f - (p0 * p0 + p1 * p1)));
}

BestSplit find_best_split(Node *node) {
    BestSplit best = {.resultanGini = SCALE, .feature = -1, .category = -1};
    if (!node || node->size <= 1) return best;

    for (int f = 0; f < MAX_FEATURES; f++) {
        for (int i = 0; i < node->num_points; i++) {
            int threshold = node->points[i].features[f];
            int left0 = 0, left1 = 0, right0 = 0, right1 = 0;

            for (int j = 0; j < node->num_points; j++) {
                if (node->points[j].features[f] < threshold) {
                    (node->points[j].label == 0) ? left0++ : left1++;
                } else {
                    (node->points[j].label == 0) ? right0++ : right1++;
                }
            }

            int left_count  = left0 + left1;
            int right_count = right0 + right1;
            if (left_count == 0 || right_count == 0) continue;

            float p_left0 = (float)left0 / left_count;
            float p_left1 = (float)left1 / left_count;
            float gini_left = 1.0f - (p_left0 * p_left0 + p_left1 * p_left1);

            float p_right0 = (float)right0 / right_count;
            float p_right1 = (float)right1 / right_count;
            float gini_right = 1.0f - (p_right0 * p_right0 + p_right1 * p_right1);

            float weighted_gini =
                ((float)left_count / node->num_points) * gini_left +
                ((float)right_count / node->num_points) * gini_right;

            __u32 scaled = (__u32)(weighted_gini * SCALE);
            if (scaled < best.resultanGini) {
                best.resultanGini = scaled;
                best.category     = threshold;
                best.feature      = f;
                
                printf("[DEBUG] Node best split updated: feature=%d threshold=%d weighted_gini=%u\n",
                f, threshold, scaled);
            }
        }
    }
    return best;
}

static void build_tree(DecisionTree *tree, int node_idx, int depth) {
    Node *node = &tree->nodes[node_idx];

    if (depth >= tree->max_depth ||
        node->num_points < tree->min_samples_split ||
        getGiniImpurity(node) == 0) {
        node->is_leaf = 1;
        return;
    }

    BestSplit best = find_best_split(node);
    if (best.feature < 0) {
        node->is_leaf = 1;
        return;
    }
    node->split = best;

    int left_idx  = tree->node_count++;
    int right_idx = tree->node_count++;
    if (left_idx >= MAX_NODE_PER_TREE || right_idx >= MAX_NODE_PER_TREE) {
        node->is_leaf = 1;
        return;
    }

    node->left_idx  = left_idx;
    node->right_idx = right_idx;

    Node *left_node  = &tree->nodes[left_idx];
    Node *right_node = &tree->nodes[right_idx];
    node_init_empty(left_node);
    node_init_empty(right_node);

    for (int i = 0; i < node->num_points; i++) {
        if (node->points[i].features[best.feature] <= best.category) {
            if (left_node->num_points < MAX_SAMPLES_PER_NODE) {
                left_node->points[left_node->num_points++] = node->points[i];
            }
        } else {
            if (right_node->num_points < MAX_SAMPLES_PER_NODE) {
                right_node->points[right_node->num_points++] = node->points[i];
            }
        }
    }

    if (left_node->num_points == 0 || right_node->num_points == 0) {
        node->is_leaf   = 1;
        node->left_idx  = NULL_IDX;
        node->right_idx = NULL_IDX;
        return;
    }
    build_tree(tree, left_idx, depth + 1);
    build_tree(tree, right_idx, depth + 1);
}

void init_tree_struct(DecisionTree *tree, int max_depth, int min_samples_split) {
    if (!tree) return;
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) node_init_empty(&tree->nodes[i]);
    tree->max_depth         = max_depth;
    tree->min_samples_split = min_samples_split;
    tree->node_count        = 0;
}

/*==================== FOREST ====================*/
static data_point *bootstrap_sample(data_point *points, int num_points, int sample_size) {
    if (num_points <= 0 || sample_size <= 0) return NULL;

    data_point *sample = calloc(sample_size, sizeof(data_point));
    if (!sample) return NULL;

    // Đếm số điểm theo label
    int count0 = 0, count1 = 0;
    for (int i = 0; i < num_points; i++) {
        if (points[i].label == 0) count0++;
        else if (points[i].label == 1) count1++;
    }
    if (count0 == 0 || count1 == 0) {
        // fallback random nếu không có đủ 2 label
        for (int i = 0; i < sample_size; i++) {
            int idx = rand() % num_points;
            sample[i] = points[idx];
        }
        return sample;
    }

    // stratified sampling theo tỉ lệ dataset
    int sample0 = (sample_size * count0) / (count0 + count1);
    int sample1 = sample_size - sample0;

    // lấy label 0
    for (int i = 0; i < sample0; i++) {
        int idx;
        do { idx = rand() % num_points; } while (points[idx].label != 0);
        sample[i] = points[idx];
    }
    // lấy label 1
    for (int i = 0; i < sample1; i++) {
        int idx;
        do { idx = rand() % num_points; } while (points[idx].label != 1);
        sample[sample0 + i] = points[idx];
    }

    return sample;
}

void fit_tree(DecisionTree *tree, data_point *points, int num_points) {
    if (!tree || !points || num_points <= 0) return;

    // reset toàn bộ nodes
    for (int i = 0; i < MAX_NODE_PER_TREE; i++)
        node_init_empty(&tree->nodes[i]);

    tree->node_count = 1;
    Node *root = &tree->nodes[0];
    node_init_empty(root);

    int tocopy = (num_points > MAX_SAMPLES_PER_NODE) ? MAX_SAMPLES_PER_NODE : num_points;

    data_point *sample = bootstrap_sample(points, num_points, tocopy);
    if (!sample) return;

    // copy vào root
    for (int i = 0; i < tocopy; i++)
        root->points[root->num_points++] = sample[i];

    // in debug label count
    int c0=0, c1=0;
    count_classes(root, &c0, &c1);
    printf("[DEBUG] Tree root num_points=%d label0=%d label1=%d Gini=%u\n",
           root->num_points, c0, c1, getGiniImpurity(root));

    free(sample);

    build_tree(tree, 0, 0);
}

RandomForest *init_forest(__u32 n_trees, __u32 sample_size, __u32 max_depth, __u32 min_samples_split) {
    if (n_trees == 0) return NULL;
    if (n_trees > MAX_TREES) n_trees = MAX_TREES;

    RandomForest *forest = calloc(1, sizeof(RandomForest));
    if (!forest) {
        perror("init_forest: calloc");
        return NULL;
    }
    forest->n_trees             = n_trees;
    forest->sample_size         = sample_size;
    forest->max_depth           = max_depth;
    forest->min_samples_split   = min_samples_split;

    for (unsigned int t = 0; t < forest->n_trees; t++) {
        init_tree_struct(&forest->trees[t], max_depth, min_samples_split);
    }
    return forest;
}

void free_forest(RandomForest *forest) {
    if (forest) free(forest);
}

void fit_forest(RandomForest *forest, data_point *dataset, int num_points) {
    if (!forest || !dataset || num_points <= 0) return;

    for (unsigned int t = 0; t < forest->n_trees; t++) {
        data_point *sample = bootstrap_sample(dataset, num_points, forest->sample_size);
        if (!sample) {
            fprintf(stderr, "[ERROR] bootstrap_sample failed for tree %u\n", t);
            continue;
        }
        fit_tree(&forest->trees[t], sample, forest->sample_size);
        free(sample);
    }
}

/*==================== PREDICT ====================*/
int predict_tree(DecisionTree *tree, data_point *pt) {
    if (!tree || !pt) return 0;
    int idx = 0;
    while (1) {
        Node *node = &tree->nodes[idx];
        if (node->is_leaf || node->num_points == 0) {
            int c0 = 0, c1 = 0; count_classes(node, &c0, &c1);
            return (c1 > c0) ? 1 : 0;
        }
        int f = node->split.feature;
        int cat = node->split.category;
        if (f < 0 || f >= MAX_FEATURES) {
            int c0 = 0, c1 = 0; count_classes(node, &c0, &c1);
            return (c1 > c0) ? 1 : 0;
        }
        idx = (pt->features[f] <= cat) ? node->left_idx : node->right_idx;
        if (idx == NULL_IDX) {
            int c0 = 0, c1 = 0; count_classes(node, &c0, &c1);
            return (c1 > c0) ? 1 : 0;
        }
    }
}

int predict_forest(RandomForest *forest, data_point *pt) {
    if (!forest || !pt) return 0;
    int votes0 = 0, votes1 = 0;
    for (unsigned int t = 0; t < forest->n_trees; t++) {
        int p = predict_tree(&forest->trees[t], pt);
        if (p == 0) votes0++; else votes1++;
    }
    return (votes1 > votes0) ? 1 : 0;
}

/*==================== MAIN ====================*/
int main(int argc, char **argv) {
    srand(time(NULL)); /* seed random once */
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd_nodes, map_fd_params;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ = "Dump data_point from XDP BPF map and train RandomForest\n";
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

    map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_randforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_randforest_nodes'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    map_fd_params = open_bpf_map_file(pin_dir, "xdp_randforest_params", &info);
    if (map_fd_params < 0) {
        fprintf(stderr, "[ERROR] Could not open pinned map '%s/xdp_randforest_params'\n", pin_dir);
        return EXIT_FAIL_BPF;
    }

    data_point train_dataset[TRAINING_SET];
    int train_count = read_csv_dataset("/home/dongtv/dtuan/training_isolation/training_data.csv",
                                    train_dataset, TRAINING_SET);
    if(train_count < 1){
        fprintf(stderr, "[ERROR] Training CSV empty or invalid\n");
        // close(map_fd_flow); close(map_fd_nodes); close(map_fd_params); close(map_fd_c);
        return EXIT_FAIL_OPTION;
    }
    printf("[INFO] Read %d training flows\n", train_count);

    const __u32 n_trees     = MAX_TREES;
    const __u32 sample_size = (train_count < MAX_SAMPLES_PER_NODE) ? train_count : MAX_SAMPLES_PER_NODE;
    const __u32 max_depth   = 6;
    const __u32 min_samples_split = 2;

    RandomForest *forest = init_forest(n_trees, sample_size, max_depth, min_samples_split);
    if (!forest) {
        fprintf(stderr, "[ERROR] init_forest failed\n");
        return EXIT_FAILURE;
    }

    fit_forest(forest, train_dataset, TRAINING_SET);

    Node *all_nodes = calloc(MAX_TREES * MAX_NODE_PER_TREE, sizeof(Node));
    if (!all_nodes) {
        perror("calloc all_nodes");
        free_forest(forest);
        return EXIT_FAILURE;
    }

    for(unsigned int t = 0; t < forest->n_trees && t < MAX_TREES; t++){
        int cnt = forest->trees[t].node_count;
        int base = t * MAX_NODE_PER_TREE;
        for(int n = 0; n < MAX_NODE_PER_TREE; n++){
            if(n < cnt){
                all_nodes[base + n] = forest->trees[t].nodes[n];
                printf("[DEBUG] Tree %u Node %d num_points=%d is_leaf=%d\n", t, n,
                       all_nodes[base + n].num_points, all_nodes[base + n].is_leaf);
            } else {
                all_nodes[base + n].is_leaf     = 1;
                all_nodes[base + n].left_idx    = -1;
                all_nodes[base + n].right_idx   = -1;
                all_nodes[base + n].num_points  = 0;
            }
        }
    }

    for (__u32 i = 0; i < MAX_TREES * MAX_NODE_PER_TREE; i++) {
        if (bpf_map_update_elem(map_fd_nodes, &i, &all_nodes[i], BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] update node %u failed: %s\n", i, strerror(errno));
        }
    }

    struct forest_params params = {
        .n_trees           = n_trees,
        .sample_size       = sample_size,
        .min_samples_split = min_samples_split,
    };
    __u32 param_key = 0;
    if (bpf_map_update_elem(map_fd_params, &param_key, &params, BPF_ANY) != 0) {
        fprintf(stderr, "[ERROR] update forest_params failed: %s\n", strerror(errno));
    } else {
        printf("[INFO] Updated forest_params (n_trees=%u, sample_size=%u, min_samples_split=%u)\n",
               n_trees, sample_size, min_samples_split);
    }

    printf("[INFO] Successfully updated nodes into xdp_randforest_nodes\n");

    free(all_nodes);
    free_forest(forest);

    return EXIT_OK;
}
