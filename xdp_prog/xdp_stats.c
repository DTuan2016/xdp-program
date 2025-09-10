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

void fit_tree(DecisionTree *tree, data_point *points, int num_points) {
    if (!tree) return;
    for (int i = 0; i < MAX_NODE_PER_TREE; i++) node_init_empty(&tree->nodes[i]);

    tree->node_count = 1;
    Node *root = &tree->nodes[0];
    node_init_empty(root);

    int tocopy = (num_points > MAX_SAMPLES_PER_NODE) ? MAX_SAMPLES_PER_NODE : num_points;
    for (int i = 0; i < tocopy; i++) {
        root->points[root->num_points++] = points[i];
    }
    build_tree(tree, 0, 0);
}

/*==================== FOREST ====================*/
static data_point *bootstrap_sample(data_point *points, int num_points, int sample_size) {
    if (num_points <= 0 || sample_size <= 0) return NULL;
    data_point *sample = calloc(sample_size, sizeof(data_point));
    if (!sample) return NULL;

    for (int i = 0; i < sample_size; i++) {
        int idx = rand() % num_points;
        sample[i] = points[idx];
    }
    return sample;
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

    while (1) {
        struct flow_key key = {}, next_key;
        data_point flows[TRAINING_SET];
        int flow_count = 0;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 && flow_count < TRAINING_SET) {
            data_point value;
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                flows[flow_count++] = value;
            }
            key = next_key;
        }

        if (flow_count < TRAINING_SET) {
            printf("[INFO] Current flows: %d (waiting for %d to train RandomForest)\n",
                   flow_count, TRAINING_SET);
            sleep(1);
            continue;
        }

        printf("\n=== Training RandomForest with %d flows ===\n", flow_count);

        data_point dataset[TRAINING_SET];
        memcpy(dataset, flows, sizeof(dataset));

        const __u32 n_trees     = MAX_TREES;
        const __u32 sample_size = (TRAINING_SET < 32) ? TRAINING_SET : 32;
        const __u32 max_depth   = 10;
        const __u32 min_samples_split = 2;

        RandomForest *forest = init_forest(n_trees, sample_size, max_depth, min_samples_split);
        if (!forest) {
            fprintf(stderr, "[ERROR] init_forest failed\n");
            sleep(1);
            continue;
        }

        fit_forest(forest, dataset, TRAINING_SET);

        Node *all_nodes = calloc(MAX_TREES * MAX_NODE_PER_TREE, sizeof(Node));
        if (!all_nodes) {
            perror("calloc all_nodes");
            free_forest(forest);
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
                    all_nodes[base + n].left_idx  = -1;
                    all_nodes[base + n].right_idx = -1;
                    all_nodes[base + n].size      = 0;
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
        break; /* only train once */
    }

    return EXIT_OK;
}
