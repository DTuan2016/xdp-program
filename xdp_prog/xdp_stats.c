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
    {{"help", no_argument, NULL, 'h'}, "Show help", NULL, false},
    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)", NULL, false},
    {{"load-csv", no_argument, NULL, 'c'}, "Load RandomForest from default CSV", NULL, false},
    {{0, 0, NULL, 0}, NULL, NULL, false}
};
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

// void min_max_scale_fixed(data_point *dataset, int n_samples, int n_feature, struct forest_params *params){
//     fixed min_vals[n_feature];
//     fixed max_vals[n_feature];

//     for(int j = 0; j < n_feature; j++){
//         min_vals[j] = UINT32_MAX;
//         max_vals[j] = 0;
//     }

//     for (int i = 0; i < n_samples; i++) {
//         for (int j = 0; j < n_feature; j++) {
//             fixed val = dataset[i].features[j];
//             if (val < min_vals[j]) min_vals[j] = val;
//             if (val > max_vals[j]) max_vals[j] = val;
//         }
//     }

//     for(int i = 0; i < n_feature; i++){
//         params->min_vals[i] = min_vals[i];
//         params->max_vals[i] = max_vals[i];
//     }

//     for (int i = 0; i < n_samples; i++) {
//         for (int j = 0; j < n_feature; j++) {
//             __u32 val = dataset[i].features[j];
//             __u32 range = max_vals[j] - min_vals[j];
//             if (range > 0) {
//                 // scaled = (val - min) / range
//                 // => fixed = ((val - min) << 24) / range
//                 fixed scaled = fixed_div(fixed_sub(val, min_vals[j]), range);
//                 // fixed scaled = ((__s64)(val - min_vals[j]) << 24) / range;
//                 dataset[i].features[j] = scaled;
//             } else {
//                 dataset[i].features[j] = 0;
//             }
//         }
//     }
// }

// /*==================== CSV Reading ====================*/
// int read_csv_dataset1(const char *filename, data_point *dataset, int max_rows, struct forest_params *params) {
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
//         int idx;
//         int src_port, dst_port;
//         char src_ip[64];
//         char dst_ip[64];
//         double feature0, feature1, feature2, feature3, feature4;
//         int un_label, proto;
//         char label_str[32];  // label as string
        
//         int n = sscanf(line,
//                        "%d,%63[^,],%d,%63[^,],%d,%d,%lf,%lf,%lf,%lf,%lf,%d,%31s",
//                        &idx, src_ip, &src_port, dst_ip, &dst_port, &proto,
//                        &feature0, &feature1, &feature2,
//                        &feature3, &feature4, &un_label, label_str);

//         if (n != 13) continue;

//         /* Copy features */
//         dp.features[0] = fixed_from_float(log2(feature0 + 1.0));
//         dp.features[1] = fixed_from_float(log2(feature1 + 1.0));
//         dp.features[2] = fixed_from_float(log2(feature2 + 1.0));
//         dp.features[3] = fixed_from_float(log2(feature3 + 1.0));
//         dp.features[4] = fixed_from_float(log2(feature4 + 1.0));
        
//         /* Convert label string to int: BENIGN=1, else=0 */
//         if (strcmp(label_str, "BENIGN") == 0)
//             dp.label = 1;
//         else
//             dp.label = 0;

//         dataset[count++] = dp;
//     }
//     fclose(f);
//     min_max_scale_fixed(dataset, count, MAX_FEATURES, params);
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

/*==================== Decision Tree Training ====================*/
double getGiniImpurity(data_point *points, int num_points)
{
    if (num_points == 0)
        return 0.0;

    int count0 = 0, count1 = 0;
    for (int i = 0; i < num_points; i++)
    {
        if (points[i].label == 0)
            count0++;
        else
            count1++;
    }

    if (count0 == 0 || count1 == 0)
        return 0.0;

    double p0 = (double)count0 / num_points;
    double p1 = (double)count1 / num_points;

    return 1.0 - (p0 * p0 + p1 * p1);
}

/*==================== Majority voting ====================*/
int majority_label(data_point *points, int n)
{
    int count0 = 0, count1 = 0;

    for (int i = 0; i < n; i++)
    {
        if (points[i].label == 0)
            count0++;
        else
            count1++;
    }

    return (count1 > count0) ? 1 : 0;
}

/*==================== Find best split value ====================*/
void find_best_split(data_point *points, int num_points,
                     int *best_feature, fixed *best_threshold)
{
    double best_gain = -1.0;
    *best_feature = -1;
    *best_threshold = 0;

    double parent_impurity = getGiniImpurity(points, num_points);
    if (parent_impurity == 0.0)
        return;

    for (int f = 0; f < MAX_FEATURES; f++)
    {
        fixed *feature_values = malloc(sizeof(fixed) * num_points);
        if (!feature_values)
            continue;
        for (int i = 0; i < num_points; i++)
        {
            feature_values[i] = points[i].features[f];
        }

        for (int i = 0; i < num_points - 1; i++)
        {
            for (int j = 0; j < num_points - i - 1; j++)
            {
                if (feature_values[j] > feature_values[j + 1])
                {
                    fixed temp = feature_values[j];
                    feature_values[j] = feature_values[j + 1];
                    feature_values[j + 1] = temp;
                }
            }
        }

        for (int i = 0; i < num_points - 1; i++)
        {
            if (feature_values[i] == feature_values[i + 1])
            {
                continue;
            }
            fixed threshold = fixed_div(fixed_add(feature_values[i], feature_values[i + 1]), fixed_from_uint(2));

            // Count samples on each side
            int count_left = 0, count_right = 0;
            int left_label0 = 0, left_label1 = 0;
            int right_label0 = 0, right_label1 = 0;

            for (int j = 0; j < num_points; j++)
            {
                if (points[j].features[f] <= threshold)
                {
                    count_left++;
                    if (points[j].label == 0)
                        left_label0++;
                    else
                        left_label1++;
                }
                else
                {
                    count_right++;
                    if (points[j].label == 0)
                        right_label0++;
                    else
                        right_label1++;
                }
            }

            if (count_left == 0 || count_right == 0)
                continue;

            // Calculate Gini impurity for left and right
            double p_left_0 = (double)left_label0 / count_left;
            double p_left_1 = (double)left_label1 / count_left;
            double gini_left = 1.0 - (p_left_0 * p_left_0 + p_left_1 * p_left_1);

            double p_right_0 = (double)right_label0 / count_right;
            double p_right_1 = (double)right_label1 / count_right;
            double gini_right = 1.0 - (p_right_0 * p_right_0 + p_right_1 * p_right_1);

            double weighted_impurity = ((double)count_left / num_points) * gini_left +
                                       ((double)count_right / num_points) * gini_right;
            double gain = parent_impurity - weighted_impurity;

            if (gain > best_gain)
            {
                best_gain = gain;
                *best_feature = f;
                *best_threshold = threshold;
            }
        }
        free(feature_values);
    }
}

/*==================== Build Tree ====================*/
int build_tree(DecisionTree *tree, data_point *points, int n, int depth, int node_idx)
{
    if (node_idx >= MAX_NODE_PER_TREE || tree->node_count >= MAX_NODE_PER_TREE)
        return -1;

    Node *node = &tree->nodes[node_idx];
    tree->node_count = (node_idx + 1 > tree->node_count) ? node_idx + 1 : tree->node_count;

    int label0_count = 0, label1_count = 0;
    for (int i = 0; i < n; i++)
    {
        if (points[i].label == 0)
            label0_count++;
        else
            label1_count++;
    }

    // Create leaf node
    if (label0_count == 0 || label1_count == 0 ||
        depth >= tree->max_depth || n < tree->min_samples_split)
    {
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
    fixed best_threshold;
    find_best_split(points, n, &best_feature, &best_threshold);

    if (best_feature == -1)
    {
        // No good split found, create leaf
        node->is_leaf       = 1;
        node->label         = majority_label(points, n);
        node->left_idx      = -1;
        node->right_idx     = -1;
        node->feature_idx   = -1;
        node->split_value   = -1;
        return node_idx;
    }

    node->is_leaf           = 0;
    node->feature_idx       = best_feature;
    node->split_value       = best_threshold;

    // Split data
    int left_count = 0, right_count = 0;
    for (int i = 0; i < n; i++)
    {
        if (points[i].features[best_feature] <= best_threshold)
            left_count++;
        else
            right_count++;
    }

    if (left_count == 0 || right_count == 0)
    {
        // Failed split, create leaf
        node->is_leaf       = 1;
        node->label         = majority_label(points, n);
        node->left_idx      = -1;
        node->right_idx     = -1;
        node->split_value   = -1;
        return node_idx;
    }

    data_point *left  = malloc(left_count  * sizeof(data_point));
    data_point *right = malloc(right_count * sizeof(data_point));

    if (!left || !right)
    {
        free(left);
        free(right);
        return -1;
    }

    int li = 0, ri = 0;
    for (int i = 0; i < n; i++)
    {
        if (points[i].features[best_feature] <= best_threshold)
        {
            left[li++] = points[i];
        }
        else
        {
            right[ri++] = points[i];
        }
    }

    int left_node_idx = tree->node_count;
    if (left_node_idx >= MAX_NODE_PER_TREE)
    {
        free(left);
        free(right);
        return -1;
    }

    int left_ret = build_tree(tree, left, left_count, depth + 1, left_node_idx);
    if (left_ret < 0)
    {
        free(left);
        free(right);
        return -1;
    }

    /* get next free index AFTER left subtree was created */
    int right_node_idx = tree->node_count;
    if (right_node_idx >= MAX_NODE_PER_TREE)
    {
        free(left);
        free(right);
        return -1;
    }

    int right_ret = build_tree(tree, right, right_count, depth + 1, right_node_idx);
    if (right_ret < 0)
    {
        free(left);
        free(right);
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
                         int max_depth, int min_samples_split)
{
    tree->node_count = 0;
    tree->max_depth = max_depth;
    tree->min_samples_split = min_samples_split;

    // Initialize only used nodes area (safe)
    for (int i = 0; i < MAX_NODE_PER_TREE; i++)
    {
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
void bootstrap_sample(data_point *dataset, int num_points, data_point *sample, int sample_size)
{
    for (int i = 0; i < sample_size; i++)
    {
        int idx = rand() % num_points;
        sample[i] = dataset[idx];
    }
}

void train_random_forest(RandomForest *rf, data_point *dataset, int num_points,
                         struct forest_params *params)
{
    rf->n_trees = params->n_trees;
    rf->max_depth = params->max_depth;
    rf->sample_size = params->sample_size;

    printf("[INFO] Training %u trees with max_depth=%u, sample_size=%u\n",
           params->n_trees, params->max_depth, params->sample_size);

    for (__u32 t = 0; t < params->n_trees && t < MAX_TREES; t++)
    {
        printf("Training tree %u/%u...\n", t + 1, params->n_trees);

        data_point *sample = malloc(params->sample_size * sizeof(data_point));
        if (!sample)
        {
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

void reindex_tree(DecisionTree *tree)
{
    if (!tree)
        return;
    if (tree->node_count <= 1)
        return; // nothing to do

    int old_to_new[MAX_NODE_PER_TREE];
    for (int i = 0; i < MAX_NODE_PER_TREE; i++)
        old_to_new[i] = -1;

    Node *new_nodes = calloc(MAX_NODE_PER_TREE, sizeof(Node));
    if (!new_nodes)
        return;

    int queue[MAX_NODE_PER_TREE];
    int qh = 0, qt = 0;
    // assume root is at local index 0
    queue[qt++] = 0;
    old_to_new[0] = 0;
    int new_count = 0; // index of last assigned node in new_nodes

    while (qh < qt)
    {
        int old_idx     = queue[qh++];
        int new_idx     = old_to_new[old_idx];
        Node *old_node  = &tree->nodes[old_idx];
        Node *nnode     = &new_nodes[new_idx];

        // copy node content
        *nnode = *old_node;

        // process left child (if valid local index)
        if (old_node->left_idx >= 0)
        {
            int child_old = old_node->left_idx;
            if (child_old < 0 || child_old >= MAX_NODE_PER_TREE)
            {
                nnode->left_idx = -1;
            }
            else
            {
                if (old_to_new[child_old] == -1)
                {
                    new_count++;
                    old_to_new[child_old]   = new_count;
                    queue[qt++]             = child_old;
                }
                nnode->left_idx = old_to_new[child_old];
            }
        }
        else
        {
            nnode->left_idx = -1;
        }

        // process right child
        if (old_node->right_idx >= 0)
        {
            int child_old = old_node->right_idx;
            if (child_old < 0 || child_old >= MAX_NODE_PER_TREE)
            {
                nnode->right_idx = -1;
            }
            else
            {
                if (old_to_new[child_old] == -1)
                {
                    new_count++;
                    old_to_new[child_old]   = new_count;
                    queue[qt++]             = child_old;
                }
                nnode->right_idx = old_to_new[child_old];
            }
        }
        else
        {
            nnode->right_idx = -1;
        }
    }

    // copy back new_nodes into tree->nodes (only up to new_count+1)
    int final_count = new_count + 1;
    for (int i = 0; i < final_count; i++)
    {
        tree->nodes[i] = new_nodes[i];
    }
    // clear remaining nodes (optional)
    for (int i = final_count; i < MAX_NODE_PER_TREE; i++)
    {
        tree->nodes[i].is_leaf      = 1;
        tree->nodes[i].left_idx     = -1;
        tree->nodes[i].right_idx    = -1;
        tree->nodes[i].feature_idx  = -1;
        tree->nodes[i].split_value  = 0;
    }
    tree->node_count = final_count;
    free(new_nodes);
}

int dump_forest_to_csv(RandomForest *rf, const char *csv_path)
{
    if (!rf) return -1;

    FILE *fp = fopen(csv_path, "w");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open '%s' for writing: %s\n", csv_path, strerror(errno));
        return -1;
    }

    fprintf(fp, "global_idx,tree_idx,node_idx,left_idx,right_idx,split_value,feature_idx,is_leaf,label\n");

    int total_nodes = 0;

    for (__u32 t = 0; t < rf->n_trees && t < MAX_TREES; t++) {
        DecisionTree *tree = &rf->trees[t];
        reindex_tree(tree);

        for (int n = 0; n < tree->node_count && n < MAX_NODE_PER_TREE; n++) {
            __u32 key = t * MAX_NODE_PER_TREE + n;
            Node *src = &tree->nodes[n];

            __s32 left_idx = (src->left_idx >= 0) ? (__s32)(t * MAX_NODE_PER_TREE + src->left_idx) : -1;
            __s32 right_idx = (src->right_idx >= 0) ? (__s32)(t * MAX_NODE_PER_TREE + src->right_idx) : -1;

            fixed split_value = src->split_value; // Nếu dùng fixed-point thì scale ở đây
            fprintf(fp, "%u,%u,%d,%d,%d,%u,%d,%d,%d\n",
                    key, t, n, left_idx, right_idx,
                    split_value, src->feature_idx, src->is_leaf, src->label);
            total_nodes++;
        }
    }

    fclose(fp);
    printf("[INFO] Dumped %d nodes to %s\n", total_nodes, csv_path);
    return 0;
}

int load_csv_to_map(int map_fd, const char *csv_path)
{
    FILE *fp = fopen(csv_path, "r");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open '%s' for reading: %s\n", csv_path, strerror(errno));
        return -1;
    }

    char line[256];
    int total_nodes = 0;

    // Bỏ qua header (nếu có)
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "[WARN] Empty CSV file: %s\n", csv_path);
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        __u32 key;
        Node tmp = {0};

        int parsed = sscanf(line, "%u,%*u,%*d,%d,%d,%u,%d,%u,%d",
                            &key, &tmp.left_idx, &tmp.right_idx, &tmp.split_value,
                            &tmp.feature_idx, &tmp.is_leaf, &tmp.label);
        if (parsed < 7)
            continue;

        if (bpf_map_update_elem(map_fd, &key, &tmp, BPF_ANY) < 0) {
            fprintf(stderr, "[ERROR] Update map failed (key=%u): %s\n", key, strerror(errno));
            fclose(fp);
            return -1;
        }

        total_nodes++;
    }

    fclose(fp);
    printf("[INFO] Loaded %d nodes from %s into BPF map\n", total_nodes, csv_path);
    return total_nodes;
}

int save_forest_to_map(int map_fd, RandomForest *rf)
{
    if (!rf)
        return -1;

    printf("[INFO] Saving forest to BPF map...\n");
    int total_nodes = 0;

    for (__u32 t = 0; t < rf->n_trees && t < MAX_TREES; t++)
    {
        DecisionTree *tree = &rf->trees[t];

        reindex_tree(tree);

        for (int n = 0; n < tree->node_count && n < MAX_NODE_PER_TREE; n++)
        {
            __u32 key = t * MAX_NODE_PER_TREE + n;
            Node tmp = tree->nodes[n]; /* local copy */

            /* Convert child indices from local -> global */
            if (tmp.left_idx >= 0)
            {
                /* sanity check */
                if (tmp.left_idx >= tree->node_count)
                {
                    fprintf(stderr, "[WARN] Tree %u local left_idx %d out of range (node_count=%d). Setting -1\n",
                            t, tmp.left_idx, tree->node_count);
                    tmp.left_idx = -1;
                }
                else
                {
                    tmp.left_idx = (__s32)(t * MAX_NODE_PER_TREE + tmp.left_idx);
                }
            }
            if (tmp.right_idx >= 0)
            {
                if (tmp.right_idx >= tree->node_count)
                {
                    fprintf(stderr, "[WARN] Tree %u local right_idx %d out of range (node_count=%d). Setting -1\n",
                            t, tmp.right_idx, tree->node_count);
                    tmp.right_idx = -1;
                }
                else
                {
                    tmp.right_idx = (__s32)(t * MAX_NODE_PER_TREE + tmp.right_idx);
                }
            }

            if (bpf_map_update_elem(map_fd, &key, &tmp, BPF_ANY) < 0)
            {
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

int sync_forest_to_map(int map_fd, RandomForest *rf, const char *csv_path)
{
    if (!csv_path || map_fd < 0) {
        fprintf(stderr, "[ERROR] Invalid arguments to sync_forest_to_map()\n");
        return -1;
    }

    int ret = 0;

    /* =====================================================
     * CASE 1: TRAIN MODE - Có rf => dump + save
     * ===================================================== */
    if (rf != NULL) {
        printf("[INFO] [TRAIN MODE] Start syncing RandomForest...\n");

        // 1. Dump forest ra CSV
        ret = dump_forest_to_csv(rf, csv_path);
        if (ret < 0) {
            fprintf(stderr, "[ERROR] dump_forest_to_csv() failed\n");
            return -1;
        }

        // 2. Lưu trực tiếp forest vào BPF map
        ret = save_forest_to_map(map_fd, rf);
        if (ret < 0) {
            fprintf(stderr, "[ERROR] save_forest_to_map() failed\n");
            return -1;
        }

        printf("[INFO] [TRAIN MODE] Sync completed: %d nodes saved to map and CSV\n", ret);
        return ret;
    }

    /* =====================================================
     * CASE 2: LOAD MODE - Không có rf => chỉ đọc CSV
     * ===================================================== */
    printf("[INFO] [LOAD MODE] Loading nodes from CSV into BPF map...\n");

    ret = load_csv_to_map(map_fd, csv_path);
    if (ret < 0) {
        fprintf(stderr, "[ERROR] load_csv_to_map() failed\n");
        return -1;
    }

    printf("[INFO] [LOAD MODE] Loaded %d nodes into map from CSV\n", ret);
    return ret;
}

/*==================== Testing Functions ====================*/
int predict_tree_userspace(const DecisionTree *tree, const data_point *dp)
{
    int idx = 0;
    int depth = 0;

    while (depth < MAX_TREE_DEPTH)
    { // Prevent infinite loops
        if (idx < 0 || idx >= tree->node_count)
            return 0;

        const Node *node = &tree->nodes[idx];
        if (node->is_leaf)
            return node->label;

        if (node->feature_idx < 0 || node->feature_idx >= MAX_FEATURES)
            return 0;

        if (dp->features[node->feature_idx] <= (__u32)node->split_value)
            idx = node->left_idx;
        else
            idx = node->right_idx;

        depth++;
    }
    return 0;
}

int predict_forest_userspace(const RandomForest *rf, const data_point *dp)
{
    int votes0 = 0, votes1 = 0;

    for (__u32 t = 0; t < rf->n_trees && t < MAX_TREES; t++)
    {
        int pred = predict_tree_userspace(&rf->trees[t], dp);
        if (pred == 0)
            votes0++;
        else
            votes1++;
    }
    return (votes1 > votes0) ? 1 : 0;
}

void test_forest_accuracy(RandomForest *rf, data_point *test_data, int test_count)
{
    int correct = 0;
    int total = 0;

    for (int i = 0; i < test_count; i++)
    {
        int predicted = predict_forest_userspace(rf, &test_data[i]);
        int actual = test_data[i].label;

        if (predicted == actual)
            correct++;
        total++;

        if (i < 10)
        { // Print first few predictions
            printf("Test %d: predicted=%d, actual=%d %s\n",
                   i, predicted, actual, (predicted == actual) ? "v" : "x");
        }
    }

    printf("[INFO] Accuracy: %d/%d = %.2f%%\n", correct, total,
           (total > 0) ? (double)correct / total * 100.0 : 0.0);
}

struct forest_params read_params(const char *filename) {
    struct forest_params params = {0}; // initialize to 0
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[ERROR] fopen(%s): %s\n", filename, strerror(errno));
        return params; // return zeroed struct
    }

    char line[1024];
    char *token = NULL;

    // --- Skip header: "n_trees,max_depth,sample_size,min_samples_split"
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "[ERROR] Missing header in %s\n", filename);
        fclose(fp);
        return params;
    }

    // --- Read parameters line
    if (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%u,%u,%u,%u",
                   &params.n_trees,
                   &params.max_depth,
                   &params.sample_size,
                   &params.min_samples_split) != 4) {
            fprintf(stderr, "[WARN] Failed to parse main parameters\n");
        }
    } else {
        fprintf(stderr, "[ERROR] Missing parameter line in %s\n", filename);
        fclose(fp);
        return params;
    }

    // --- Skip blank line and "min_vals" header
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return params; } // blank
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return params; } // "min_vals"

    // --- Read min_vals
    if (fgets(line, sizeof(line), fp)) {
        token = strtok(line, ",");
        for (int i = 0; i < MAX_FEATURES && token; i++) {
            params.min_vals[i] = strtoul(token, NULL, 10);
            token = strtok(NULL, ",");
        }
    } else {
        fprintf(stderr, "[WARN] Missing min_vals in %s\n", filename);
    }
    
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return params; } // blank
    // --- Skip "max_vals" header
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "[WARN] Missing max_vals header in %s\n", filename);
        fclose(fp);
        return params;
    }

    // --- Read max_vals
    if (fgets(line, sizeof(line), fp)) {
        token = strtok(line, ",");
        for (int i = 0; i < MAX_FEATURES && token; i++) {
            params.max_vals[i] = strtoul(token, NULL, 10);
            token = strtok(NULL, ",");
        }
    } else {
        fprintf(stderr, "[WARN] Missing max_vals values in %s\n", filename);
    }

    fclose(fp);
    return params;
}

/*==================== MAIN ====================*/
int main(int argc, char **argv)
{
    srand(time(NULL));
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd, map_fd_nodes, map_fd_params;
    int len;

    struct config cfg = {.ifindex = -1, .do_unload = false};
    const char *__doc__ =
        "Train or Load RandomForest and sync into XDP BPF maps\n"
        "Usage:\n"
        "  --dev <iface>\n"
        "  [--load-csv] : load from fixed CSV path instead of training\n";

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
    if (map_fd < 0)
        return EXIT_FAIL_BPF;

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

    // ======== CỐ ĐỊNH ĐƯỜNG DẪN CSV ========
    const char *CSV_PATH = "/home/dongtv/dtuan/xdp-program/xdp_prog/forest_nodes.csv";

    // ======== KIỂM TRA FLAG --load-csv ========
    bool load_csv_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--load-csv") == 0) {
            load_csv_mode = true;
            break;
        }
    }

    // ======== MODE 1: LOAD FROM CSV ========
    if (load_csv_mode) {
        const char *filename = "/home/dongtv/dtuan/xdp-program/xdp_prog/params.csv";
        printf("[INFO] Loading RandomForest nodes from fixed path: %s\n", CSV_PATH);
        sync_forest_to_map(map_fd_nodes, NULL, CSV_PATH);
        struct forest_params p = read_params(filename);

        printf("[INFO] Params: trees=%u, depth=%u, sample=%u, min_split=%u\n",
            p.n_trees, p.max_depth, p.sample_size, p.min_samples_split);

        printf("[INFO] Min vals: ");
        for (int i = 0; i < MAX_FEATURES; i++) printf("%u ", p.min_vals[i]);
        printf("\n[INFO] Max vals: ");
        for (int i = 0; i < MAX_FEATURES; i++) printf("%u ", p.max_vals[i]);
        printf("\n");

        // Save params
        __u32 key = 0;
        if (bpf_map_update_elem(map_fd_params, &key, &p, BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] Failed to update xdp_randforest_params: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        printf("[INFO] Loaded model from CSV successfully.\n");

        close(map_fd);
        close(map_fd_nodes);
        close(map_fd_params);
        return EXIT_SUCCESS;
    }

    // ======== MODE 2: TRAIN FROM DATASET ========
    printf("[INFO] Training new RandomForest model...\n");

    // Load dataset
    data_point full_dataset[TRAINING_SET];
    struct forest_params params = {
        .n_trees = MAX_TREES,
        .max_depth = MAX_TREE_DEPTH,
        .sample_size = MAX_SAMPLES_PER_NODE,
        .min_samples_split = MIN_SPLIT_SAMPLES};

    int total_count = read_csv_dataset1(
        "/home/dongtv/dtuan/training_isolation/data.csv",
        full_dataset, TRAINING_SET);
    if (total_count < 1) {
        fprintf(stderr, "[ERROR] Dataset empty or invalid\n");
        return EXIT_FAILURE;
    }

    // Split 80/20
    int train_count = (int)(total_count * 0.8);
    int test_count = total_count - train_count;
    data_point *train_dataset = full_dataset;
    data_point *test_dataset  = &full_dataset[train_count];
    printf("[INFO] Split dataset: train=%d, test=%d (ratio 80/20)\n",
           train_count, test_count);

    // Init RandomForest
    RandomForest rf = {0};
    // Train
    train_random_forest(&rf, train_dataset, train_count, &params);
    printf("[INFO] RandomForest trained with %u trees\n", rf.n_trees);

    // Save to map + dump CSV
    sync_forest_to_map(map_fd_nodes, &rf, CSV_PATH);

    const char *filename = "/home/dongtv/dtuan/xdp-program/xdp_prog/params.csv";
    FILE *f = fopen(filename, "w");
    if(!f){
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(f, "n_trees,max_depth,sample_size,min_samples_split\n");
    fprintf(f, "%u,%u,%u,%u\n\n",
            params.n_trees, params.max_depth,
            params.sample_size, params.min_samples_split);

        // Dump min_vals
    fprintf(f, "min_vals\n");
    for (int i = 0; i < MAX_FEATURES; i++)
        fprintf(f, "%d%s", params.min_vals[i], (i == MAX_FEATURES-1) ? "\n" : ",");

    fprintf(f, "\n");
    // Dump max_vals
    fprintf(f, "max_vals\n");
    for (int i = 0; i < MAX_FEATURES; i++)
        fprintf(f, "%d%s", params.max_vals[i], (i == MAX_FEATURES-1) ? "\n" : ",");

    fclose(f);
    printf("[INFO] Dumped forest_params to %s\n", filename);
    // Save params
    __u32 key = 0;
    if (bpf_map_update_elem(map_fd_params, &key, &params, BPF_ANY) != 0) {
        fprintf(stderr, "[ERROR] Failed to update xdp_randforest_params: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Evaluate on test set
    printf("[INFO] Evaluating accuracy on test set...\n");
    test_forest_accuracy(&rf, test_dataset, test_count);

    printf("[INFO] Model + params successfully updated to BPF maps\n");

    printf("[INFO] Forest params: n_trees=%u, max_depth=%u, sample_size=%u, min_samples_split=%u\n",
           params.n_trees, params.max_depth, params.sample_size, params.min_samples_split);

    close(map_fd);
    close(map_fd_nodes);
    close(map_fd_params);
    return EXIT_SUCCESS;
}
