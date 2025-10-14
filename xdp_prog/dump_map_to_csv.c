// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <limits.h>
#include <bpf/libbpf.h>

#include "common_kern_user.h"

/* Prototype */
int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info);

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* In ra node dưới dạng CSV */
static void print_node_csv(FILE *f, __u32 key, iTreeNode *node) {
    fprintf(f, "%u,%d,%d,%u,%d,%u,%u\n",
            key,
            node->left_idx,
            node->right_idx,
            node->feature_idx,
            node->split_value,
            node->num_points,
            node->is_leaf);
}

/* In ra flow dưới dạng CSV */
static void print_flow_csv(FILE *f, struct flow_key *key, data_point *dp) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr saddr = { .s_addr = key->src_ip };
    struct in_addr daddr = { .s_addr = key->dst_ip };

    inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

    fprintf(f, "%s,%u,%s,%u,%u,%f,%f,%f,%f,%f,%d\n",
        src_ip,
        key->src_port,
        dst_ip,
        key->dst_port,
        key->proto,
        fixed_to_float(dp->features[0]),
        fixed_to_float(dp->features[1]),
        fixed_to_float(dp->features[2]),
        fixed_to_float(dp->features[3]),
        fixed_to_float(dp->features[4]),
        dp->label
    );
}

/* Dump node map ra CSV */
static void dump_nodes_to_csv(int map_fd, FILE *f) {
    __u32 key = 0, next_key;
    iTreeNode value;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            print_node_csv(f, next_key, &value);
        }
        key = next_key;
    }
    fflush(f);
}

/* Dump flow map ra CSV */
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

int main(int argc, char **argv)
{
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd_nodes, map_fd_flows;
    int len;

    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <ifname> <nodes_csv> <flows_csv>\n"
            "Example: %s eth0 nodes.csv flows.csv\n",
            argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *nodes_csv = argv[2];
    const char *flows_csv = argv[3];

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAILURE;
    }

    map_fd_nodes = open_bpf_map_file(pin_dir, "xdp_isoforest_nodes", &info);
    if (map_fd_nodes < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_isoforest_nodes\n");
        return EXIT_FAILURE;
    }

    map_fd_flows = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd_flows < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_flow_tracking\n");
        return EXIT_FAILURE;
    }

    FILE *f_nodes = fopen(nodes_csv, "w");
    FILE *f_flows = fopen(flows_csv, "w");
    if (!f_nodes || !f_flows) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(f_nodes, "Key,LeftIdx,RightIdx,Feature,SplitValue,num_points,IsLeaf\n");
    fprintf(f_flows, "SrcIP,SrcPort,DstIP,DstPort,Proto,FlowDuration,FlowPktsPerSec,FlowBytesPerSec,FlowIATMean,PktLenMean,Label\n");

    dump_nodes_to_csv(map_fd_nodes, f_nodes);
    dump_flow_map_to_csv(map_fd_flows, f_flows);

    fclose(f_nodes);
    fclose(f_flows);

    printf("[INFO] Dumped nodes to %s\n", nodes_csv);
    printf("[INFO] Dumped flows to %s\n", flows_csv);
    return EXIT_SUCCESS;
}
