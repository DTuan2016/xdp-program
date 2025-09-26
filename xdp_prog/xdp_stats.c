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
// int read_csv_dataset(const char *filename, data_point *dataset, int max_rows) {
//     FILE *f = fopen(filename, "r");
//     if (!f) {
//         fprintf(stderr, "[ERROR] Cannot open file: %s\n", filename);
//         return -1;
//     }

//     char line[1024];
//     int count = 0;

//     /* Skip header */
//     if (!fgets(line, sizeof(line), f)) {
//         fclose(f);
//         return 0;
//     }

//     while (fgets(line, sizeof(line), f) && count < max_rows) {
//         data_point dp = {0};
//         int index, src_port;
//         char src_ip[64];
//         double flow_duration, flow_bytes_per_s, flow_pkts_per_s, len_fwd_pkts;
//         double len_bwd_pkts, flow_IAT_mean;
//         int label;
        
//         int n = sscanf(line,
//                        "%d,%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%lf,%d",
//                        &index, src_ip, &src_port,
//                        &flow_duration, &flow_bytes_per_s, &flow_pkts_per_s,
//                        &len_fwd_pkts, &len_bwd_pkts, &flow_IAT_mean,
//                        &label);

//         if (n != 10) continue;

//         // Calculate features correctly
//         double total_length = len_fwd_pkts + len_bwd_pkts;
        
//         dp.flow_duration    = (__u64)(flow_duration); // Convert to microseconds (assumption)
//         dp.total_bytes      = (__u64)total_length;
//         dp.flow_IAT_mean    = (__u32)(flow_IAT_mean); // Convert to microseconds (assumption)
//         dp.pkt_len_mean     = len_bwd_pkts + len_fwd_pkts;
        
//         // Calculate per-second rates
//         dp.flow_pkts_per_s  = flow_pkts_per_s;
//         dp.flow_bytes_per_s = flow_bytes_per_s;

//         /* Copy to dp.features[] - order must match kernel */
//         dp.features[0] = (__u32)dp.flow_duration;
//         dp.features[1] = dp.flow_pkts_per_s;
//         dp.features[2] = dp.pkt_len_mean;
//         dp.features[3] = dp.flow_IAT_mean;
//         dp.features[4] = dp.flow_bytes_per_s;
        
//         dp.label = label;
//         dataset[count++] = dp;

//         if (count <= 5) { // Print first few for debugging
//             printf("Sample %d: duration=%u, pkts/s=%u, mean_len=%u, IAT=%u, bytes/s=%u, label=%d\n",
//                    count, dp.features[0], dp.features[1], dp.features[2], 
//                    dp.features[3], dp.features[4], dp.label);
//         }
//     }
//     fclose(f);
//     return count;
// }

int read_csv_dataset1(const char *filename, data_point *dataset, int max_rows) {
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
        int src_port;
        char src_ip[64];
        double feature0, feature1, feature2, feature3, feature4;
        int label;
        
        int n = sscanf(line,
                       "%63[^,],%d,%lf,%lf,%lf,%lf,%lf,%d",
                        src_ip, &src_port,
                       &feature0, &feature1, &feature2,
                       &feature3, &feature4, &label);

        if (n != 8) continue;

        // Calculate features correctly
        // double total_length = len_fwd_pkts + len_bwd_pkts;
        
        // dp.flow_duration    = (__u64)(flow_duration); // Convert to microseconds (assumption)
        // dp.total_bytes      = (__u64)total_length;
        // dp.flow_IAT_mean    = (__u32)(flow_IAT_mean); // Convert to microseconds (assumption)
        // dp.pkt_len_mean     = len_bwd_pkts + len_fwd_pkts;
        
        // // Calculate per-second rates
        // dp.flow_pkts_per_s  = flow_pkts_per_s;
        // dp.flow_bytes_per_s = flow_bytes_per_s;

        /* Copy to dp.features[] - order must match kernel */
        dp.features[0] = feature0;
        dp.features[1] = feature1;
        dp.features[2] = feature2;
        dp.features[3] = feature3;
        dp.features[4] = feature4;
        
        dp.label = label;
        dataset[count++] = dp;

        if (count <= 5) { // Print first few for debugging
            printf("Sample %d: duration=%u, pkts/s=%u, mean_len=%u, IAT=%u, bytes/s=%u, label=%d\n",
                   count, dp.features[0], dp.features[1], dp.features[2], 
                   dp.features[3], dp.features[4], dp.label);
        }
    }
    fclose(f);
    return count;
}

/*==================== Decision Tree Training ====================*/
double getGiniImpurity(data_point *points, int num_points) {
    if (num_points == 0) return 0.0;

    int count0 = 0, count1 = 0;
    for (int i = 0; i < num_points; i++) {
        if (points[i].label == 0) count0++;
        else count1++;
    }

    if (count0 == 0 || count1 == 0) return 0.0; // Pure node

    double p0 = (double)count0 / num_points;
    double p1 = (double)count1 / num_points;

    return 1.0 - (p0*p0 + p1*p1);
}

int majority_label(data_point *points, int n) {
    int count0 = 0, count1 = 0;

    for (int i = 0; i < n; i++) {
        if (points[i].label == 0)
            count0++;
        else
            count1++;
    }

    return (count1 > count0) ? 1 : 0;
}

void find_best_split(data_point *points, int num_points,
                     int *best_feature, __u32 *best_threshold) {
    double best_gain = -1.0;
    *best_feature = -1;
    *best_threshold = 0;
    
    double parent_impurity = getGiniImpurity(points, num_points);
    if (parent_impurity == 0.0) return;

    for (int f = 0; f < MAX_FEATURES; f++) {
        __u32 *feature_values = malloc(sizeof(__u32) * num_points);
        if (!feature_values) continue;
        for (int i = 0; i < num_points; i++) {
            feature_values[i] = points[i].features[f];
        }

        for (int i = 0; i < num_points - 1; i++) {
            for (int j = 0; j < num_points - i - 1; j++) {
                if (feature_values[j] > feature_values[j + 1]) {
                    __u32 temp = feature_values[j];
                    feature_values[j] = feature_values[j + 1];
                    feature_values[j + 1] = temp;
                }
            }
        }

        for (int i = 0; i < num_points - 1; i++) {
            if (feature_values[i] == feature_values[i + 1]) {
                continue;
            }
            __u32 threshold = (feature_values[i] + feature_values[i + 1]) / 2;
            
            // Count samples on each side
            int count_left = 0, count_right = 0;
            int left_label0 = 0, left_label1 = 0;
            int right_label0 = 0, right_label1 = 0;

            for (int j = 0; j < num_points; j++) {
                if (points[j].features[f] <= threshold) {
                    count_left++;
                    if (points[j].label == 0) left_label0++;
                    else left_label1++;
                } else {
                    count_right++;
                    if (points[j].label == 0) right_label0++;
                    else right_label1++;
                }
            }

            if (count_left == 0 || count_right == 0) continue;

            // Calculate Gini impurity for left and right
            double p_left_0 = (double)left_label0 / count_left;
            double p_left_1 = (double)left_label1 / count_left;
            double gini_left = 1.0 - (p_left_0*p_left_0 + p_left_1*p_left_1);

            double p_right_0 = (double)right_label0 / count_right;
            double p_right_1 = (double)right_label1 / count_right;
            double gini_right = 1.0 - (p_right_0*p_right_0 + p_right_1*p_right_1);

            double weighted_impurity = ((double)count_left / num_points) * gini_left + 
                                     ((double)count_right / num_points) * gini_right;
            double gain = parent_impurity - weighted_impurity;

            if (gain > best_gain) {
                best_gain = gain;
                *best_feature = f;
                *best_threshold = threshold;
            }
        }
        free(feature_values);
    }
}

/*==================== Build Tree ====================*/
int build_tree(DecisionTree *tree, data_point *points, int n, int depth, int node_idx) {
    if (node_idx >= MAX_NODE_PER_TREE || tree->node_count >= MAX_NODE_PER_TREE) 
        return -1;
    
    Node *node = &tree->nodes[node_idx];
    tree->node_count = (node_idx + 1 > tree->node_count) ? node_idx + 1 : tree->node_count;

    int label0_count = 0, label1_count = 0;
    for (int i = 0; i < n; i++) {
        if (points[i].label == 0) label0_count++;
        else label1_count++;
    }

    // Create leaf node
    if (label0_count == 0 || label1_count == 0 || 
        depth >= tree->max_depth || n < tree->min_samples_split) {
        node->is_leaf       = 1;
        node->label         = majority_label(points, n);
        node->left_idx      = -1;
        node->right_idx     = -1;
        node->feature_idx   = -1;
        node->split_value   = -1;
        return node_idx;
    }

    // Find best split
    int best_feature;
    __u32 best_threshold;
    find_best_split(points, n, &best_feature, &best_threshold);

    if (best_feature == -1) {
        // No good split found, create leaf
        node->is_leaf       = 1;
        node->label         = majority_label(points, n);
        node->left_idx      = -1;
        node->right_idx     = -1;
        node->feature_idx   = -1;
        node->split_value   = -1;
        return node_idx;
    }

    node->is_leaf     = 0;
    node->feature_idx = best_feature;
    node->split_value = best_threshold;

    // Split data
    int left_count = 0, right_count = 0;
    for (int i = 0; i < n; i++) {
        if (points[i].features[best_feature] <= best_threshold) left_count++;
        else right_count++;
    }

    if (left_count == 0 || right_count == 0) {
        // Failed split, create leaf
        node->is_leaf       = 1;
        node->label         = majority_label(points, n);
        node->left_idx      = -1;
        node->right_idx     = -1;
        node->split_value   = -1;
        return node_idx;
    }

    data_point *left = malloc(left_count * sizeof(data_point));
    data_point *right = malloc(right_count * sizeof(data_point));
    
    if (!left || !right) {
        free(left); 
        free(right);
        return -1;
    }

    int li = 0, ri = 0;
    for (int i = 0; i < n; i++) {
        if (points[i].features[best_feature] <= best_threshold) {
            left[li++] = points[i];
        } else {
            right[ri++] = points[i];
        }
    }

    int left_node_idx = tree->node_count; 
    if (left_node_idx >= MAX_NODE_PER_TREE) { free(left); free(right); return -1; }

    int left_ret = build_tree(tree, left, left_count, depth + 1, left_node_idx);
    if (left_ret < 0) {
        free(left); free(right);
        return -1;
    }

    /* get next free index AFTER left subtree was created */
    int right_node_idx = tree->node_count;
    if (right_node_idx >= MAX_NODE_PER_TREE) {
        free(left); free(right);
        return -1;
    }

    int right_ret = build_tree(tree, right, right_count, depth + 1, right_node_idx);
    if (right_ret < 0) {
        free(left); free(right);
        return -1;
    }

    node->left_idx = left_ret;
    node->right_idx = right_ret;

    free(left);
    free(right);
    return node_idx;
}

/*==================== Train Decision Tree ====================*/
void train_decision_tree(DecisionTree *tree, data_point *dataset, int num_points, 
                        int max_depth, int min_samples_split) {
    tree->node_count = 0;
    tree->max_depth = max_depth;
    tree->min_samples_split = min_samples_split;
    
    // Initialize only used nodes area (safe)
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) {
        tree->nodes[i].is_leaf      = 1;
        tree->nodes[i].left_idx     = -1;
        tree->nodes[i].right_idx    = -1;
        tree->nodes[i].feature_idx  = -1;
        tree->nodes[i].split_value  = 0;
        tree->nodes[i].label        = 0;
    }
    
    build_tree(tree, dataset, num_points, 0, 0);
}

/*==================== Random Forest Training ====================*/
void bootstrap_sample(data_point *dataset, int num_points, data_point *sample, int sample_size) {
    for (int i = 0; i < sample_size; i++) {
        int idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
}

void train_random_forest(RandomForest *rf, data_point *dataset, int num_points, 
                        struct forest_params *params) {
    rf->n_trees = params->n_trees;
    rf->max_depth = params->max_depth;
    rf->sample_size = params->sample_size;

    printf("[INFO] Training %u trees with max_depth=%u, sample_size=%u\n", 
           params->n_trees, params->max_depth, params->sample_size);

    for (__u32 t = 0; t < params->n_trees && t < MAX_TREES; t++) {
        printf("Training tree %u/%u...\n", t + 1, params->n_trees);
        
        data_point *sample = malloc(params->sample_size * sizeof(data_point));
        if (!sample) {
            fprintf(stderr, "[ERROR] Memory allocation failed for tree %u\n", t);
            continue;
        }
        
        bootstrap_sample(dataset, num_points, sample, params->sample_size);
        train_decision_tree(&rf->trees[t], sample, params->sample_size, 
                          params->max_depth, params->min_samples_split);
        
        printf("Tree %u: %d nodes\n", t, rf->trees[t].node_count);
        free(sample);
    }
}

void reindex_tree(DecisionTree *tree) {
    if (!tree) return;
    if (tree->node_count <= 1) return; // nothing to do

    int old_to_new[MAX_NODE_PER_TREE];
    for (int i = 0; i < MAX_NODE_PER_TREE; i++)
        old_to_new[i] = -1;

    Node *new_nodes = calloc(MAX_NODE_PER_TREE, sizeof(Node));
    if (!new_nodes) return;

    int queue[MAX_NODE_PER_TREE];
    int qh = 0, qt = 0;
    // assume root is at local index 0
    queue[qt++] = 0;
    old_to_new[0] = 0;
    int new_count = 0; // index of last assigned node in new_nodes

    while (qh < qt) {
        int old_idx = queue[qh++];
        int new_idx = old_to_new[old_idx];
        Node *old_node = &tree->nodes[old_idx];
        Node *nnode = &new_nodes[new_idx];

        // copy node content
        *nnode = *old_node;

        // process left child (if valid local index)
        if (old_node->left_idx >= 0) {
            int child_old = old_node->left_idx;
            if (child_old < 0 || child_old >= MAX_NODE_PER_TREE) {
                nnode->left_idx = -1;
            } else {
                if (old_to_new[child_old] == -1) {
                    new_count++;
                    old_to_new[child_old] = new_count;
                    queue[qt++] = child_old;
                }
                nnode->left_idx = old_to_new[child_old];
            }
        } else {
            nnode->left_idx = -1;
        }

        // process right child
        if (old_node->right_idx >= 0) {
            int child_old = old_node->right_idx;
            if (child_old < 0 || child_old >= MAX_NODE_PER_TREE) {
                nnode->right_idx = -1;
            } else {
                if (old_to_new[child_old] == -1) {
                    new_count++;
                    old_to_new[child_old] = new_count;
                    queue[qt++] = child_old;
                }
                nnode->right_idx = old_to_new[child_old];
            }
        } else {
            nnode->right_idx = -1;
        }
    }

    // copy back new_nodes into tree->nodes (only up to new_count+1)
    int final_count = new_count + 1;
    for (int i = 0; i < final_count; i++) {
        tree->nodes[i] = new_nodes[i];
    }
    // clear remaining nodes (optional)
    for (int i = final_count; i < MAX_NODE_PER_TREE; i++) {
        tree->nodes[i].is_leaf = 1;
        tree->nodes[i].left_idx = -1;
        tree->nodes[i].right_idx = -1;
        tree->nodes[i].feature_idx = -1;
        tree->nodes[i].split_value = 0;
    }
    tree->node_count = final_count;
    free(new_nodes);
}

int save_forest_to_map(int map_fd, RandomForest *rf) {
    if (!rf) return -1;

    printf("[INFO] Saving forest to BPF map...\n");
    int total_nodes = 0;

    for (__u32 t = 0; t < rf->n_trees && t < MAX_TREES; t++) {
        DecisionTree *tree = &rf->trees[t];

        reindex_tree(tree);

        for (int n = 0; n < tree->node_count && n < MAX_NODE_PER_TREE; n++) {
            __u32 key = t * MAX_NODE_PER_TREE + n;
            Node tmp = tree->nodes[n];  /* local copy */

            /* Convert child indices from local -> global */
            if (tmp.left_idx >= 0) {
                /* sanity check */
                if (tmp.left_idx >= tree->node_count) {
                    fprintf(stderr, "[WARN] Tree %u local left_idx %d out of range (node_count=%d). Setting -1\n",
                            t, tmp.left_idx, tree->node_count);
                    tmp.left_idx = -1;
                } else {
                    tmp.left_idx = (__s32)(t * MAX_NODE_PER_TREE + tmp.left_idx);
                }
            }
            if (tmp.right_idx >= 0) {
                if (tmp.right_idx >= tree->node_count) {
                    fprintf(stderr, "[WARN] Tree %u local right_idx %d out of range (node_count=%d). Setting -1\n",
                            t, tmp.right_idx, tree->node_count);
                    tmp.right_idx = -1;
                } else {
                    tmp.right_idx = (__s32)(t * MAX_NODE_PER_TREE + tmp.right_idx);
                }
            }

            if (bpf_map_update_elem(map_fd, &key, &tmp, BPF_ANY) < 0) {
                fprintf(stderr, "[ERROR] Failed to update node %u (tree=%u local=%d): %s\n",
                        key, t, n, strerror(errno));
                return -1;
            }
            total_nodes++;
        }
    }

    printf("[INFO] Successfully saved %d nodes to BPF map\n", total_nodes);
    return 0;
}

/*==================== Testing Functions ====================*/
int predict_tree_userspace(const DecisionTree *tree, const data_point *dp) {
    int idx = 0;
    int depth = 0;
    
    while (depth < MAX_TREE_DEPTH) { // Prevent infinite loops
        if (idx < 0 || idx >= tree->node_count) return 0;
        
        const Node *node = &tree->nodes[idx];
        if (node->is_leaf) return node->label;
        
        if (node->feature_idx < 0 || node->feature_idx >= MAX_FEATURES) return 0;
        
        if (dp->features[node->feature_idx] <= (__u32)node->split_value)
            idx = node->left_idx;
        else
            idx = node->right_idx;
            
        depth++;
    }
    return 0;
}

int predict_forest_userspace(const RandomForest *rf, const data_point *dp) {
    int votes0 = 0, votes1 = 0;
    
    for (__u32 t = 0; t < rf->n_trees && t < MAX_TREES; t++) {
        int pred = predict_tree_userspace(&rf->trees[t], dp);
        if (pred == 0) votes0++; 
        else votes1++;
    }
    return (votes1 > votes0) ? 1 : 0;
}

void test_forest_accuracy(RandomForest *rf, data_point *test_data, int test_count) {
    int correct = 0;
    int total = 0;
    
    for (int i = 0; i < test_count; i++) {
        int predicted = predict_forest_userspace(rf, &test_data[i]);
        int actual = test_data[i].label;
        
        if (predicted == actual) correct++;
        total++;
        
        if (i < 10) { // Print first few predictions
            printf("Test %d: predicted=%d, actual=%d %s\n", 
                   i, predicted, actual, (predicted == actual) ? "v" : "x");
        }
    }
    
    printf("[INFO] Accuracy: %d/%d = %.2f%%\n", correct, total, 
           (total > 0) ? (double)correct / total * 100.0 : 0.0);
}

/*==================== MAIN ====================*/
int main(int argc, char **argv) {
    srand(time(NULL));
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd_nodes, map_fd_params;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ = "Train RandomForest and load into XDP BPF maps\n";
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

    // Open BPF maps
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

    // Load dataset
    data_point train_dataset[TRAINING_SET];
    int train_count = read_csv_dataset1("/home/dongtv/dtuan/metric_results/data_portmap_fixed1.csv",
                                       train_dataset, TRAINING_SET);
    if (train_count < 1) {
        fprintf(stderr, "[ERROR] Training dataset empty or invalid\n");
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d training samples\n", train_count);

    // Initialize RandomForest parameters
    RandomForest rf = {0};
    struct forest_params params = {
        .n_trees = MAX_TREES,
        .max_depth = MAX_TREE_DEPTH, // Reasonable depth
        .sample_size = (train_count > MAX_SAMPLES_PER_NODE) ? MAX_SAMPLES_PER_NODE : train_count,
        .min_samples_split = MIN_SPLIT_SAMPLES
    };

    // Train RandomForest
    printf("[INFO] Starting RandomForest training...\n");
    train_random_forest(&rf, train_dataset, train_count, &params);
    printf("[INFO] RandomForest trained with %u trees\n", rf.n_trees);

    // Save to BPF maps (reindex each tree locally before saving)
    if (save_forest_to_map(map_fd_nodes, &rf) != 0) {
        fprintf(stderr, "[ERROR] Failed to update xdp_randforest_nodes\n");
        return EXIT_FAILURE;
    }

    __u32 key = 0;
    if (bpf_map_update_elem(map_fd_params, &key, &params, BPF_ANY) != 0) {
        fprintf(stderr, "[ERROR] Failed to update xdp_randforest_params: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    data_point test_dataset[MAX_FLOW_SAVED];
    int test_count = read_csv_dataset1("/home/dongtv/dtuan/metric_results/test_portmap_fixed.csv",
                                       test_dataset, MAX_FLOW_SAVED);
    if (test_count < 1) {
        fprintf(stderr, "[ERROR] Testing dataset empty or invalid\n");
        return EXIT_FAILURE;
    }
    printf("[INFO] Loaded %d testing samples\n", test_count);

    test_forest_accuracy(&rf, test_dataset, MAX_FLOW_SAVED);

    printf("[INFO] Successfully updated BPF maps\n");
    printf("[INFO] Forest params: n_trees=%u, max_depth=%u, sample_size=%u, min_samples_split=%u\n",
           params.n_trees, params.max_depth, params.sample_size, params.min_samples_split);

    // Close map file descriptors
    close(map_fd);
    close(map_fd_nodes);
    close(map_fd_params);

    return EXIT_SUCCESS;
}
