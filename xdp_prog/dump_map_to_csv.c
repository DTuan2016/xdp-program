// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common_kern_user.h"

int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info);

const char *pin_basedir = "/sys/fs/bpf";
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ================= CSV PRINT ================= */
static void print_node_csv(FILE *f, __u32 key, const Node *node) {
    fprintf(f, "%u,%d,%d,%d,%d,%d,%d\n",
            key,
            node->left_idx,
            node->right_idx,
            node->feature_idx,
            node->split_value,
            node->is_leaf,
            0);
}

static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    struct in_addr ip_addr;
    ip_addr.s_addr = key->src_ip;
    fprintf(f, "%s,%u,%u,%u,%u,%u,%u,%u\n",
            inet_ntoa(ip_addr),
            key->src_port,
            dp->features[0],
            dp->features[1],
            dp->features[2],
            dp->features[3],
            dp->features[4],
            dp->label);
}

/* ================= DUMP MAPS ================= */
static void dump_nodes_to_csv(int map_fd, FILE *f) {
    __u32 key = 0, next_key;
    Node node;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &node) == 0) {
            print_node_csv(f, next_key, &node);
        }
        key = next_key;
    }
    fflush(f);
}

static void dump_flow_map_to_csv(int map_fd, FILE *f) {
    struct flow_key key, next_key;
    data_point dp;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &dp) == 0) {
            print_flow_csv(f, &next_key, &dp);
        }
        key = next_key;
    }
    fflush(f);
}

/* ================= MAIN ================= */
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <ifname> <nodes_out.csv> <flows_out.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *nodes_filename = argv[2];
    const char *flows_filename = argv[3];

    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);

    int map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_randforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_randforest_nodes\n");
        return EXIT_FAILURE;
    }

    int map_fd_flows = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd_flows < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_flow_tracking\n");
        return EXIT_FAILURE;
    }

    FILE *f_nodes = fopen(nodes_filename, "w");
    FILE *f_flows = fopen(flows_filename, "w");
    if (!f_nodes || !f_flows) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    /* Header CSV */
    fprintf(f_nodes, "Key,LeftIdx,RightIdx,FeatureIdx,SplitValue,IsLeaf,Reserved\n");
    fprintf(f_flows, "SrcIP,SrcPort,Feature0,Feature1,Feature2,Feature3,Feature4,Label\n");

    dump_nodes_to_csv(map_fd_nodes, f_nodes);
    dump_flow_map_to_csv(map_fd_flows, f_flows);

    fclose(f_nodes);
    fclose(f_flows);

    printf("Dumped xdp_randforest_nodes -> %s\n", nodes_filename);
    printf("Dumped xdp_flow_tracking -> %s\n", flows_filename);

    return EXIT_SUCCESS;
}
