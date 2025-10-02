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
static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));
    fprintf(f, "%s,%u,%s,%u,%d,%u,%u,%u,%u,%u,%u\n",
            src_ip,
            key->src_port,
            dst_ip,
            key->dst_port,
            key->proto,
            dp->features[0],
            dp->features[1],
            dp->features[2],
            dp->features[3],
            dp->features[4],
            dp->label);
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
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <nodes_out.csv> <flows_out.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *flows_filename = argv[2];

    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);

    int map_fd_flows = open_bpf_map_file(pin_dir, "xdp_flow_tracking", &info);
    if (map_fd_flows < 0) {
        fprintf(stderr, "ERR: cannot open map xdp_flow_tracking\n");
        return EXIT_FAILURE;
    }
    FILE *f_flows = fopen(flows_filename, "w");
    if (!f_flows) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    /* Header CSV */
    fprintf(f_flows, "SrcIP,SrcPort,DstIP,DstPort,Proto,Feature0,Feature1,Feature2,Feature3,Feature4,Label\n");

    // dump_nodes_to_csv(map_fd_nodes, f_nodes);
    dump_flow_map_to_csv(map_fd_flows, f_flows);

    // fclose(f_nodes);
    fclose(f_flows);

    // printf("Dumped xdp_randforest_nodes -> %s\n", nodes_filename);
    printf("Dumped xdp_flow_tracking -> %s\n", flows_filename);

    return EXIT_SUCCESS;
}
