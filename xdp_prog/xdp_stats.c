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

static void print_flow_key(struct flow_key *key) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    printf("%s:%u", src_ip, ntohs(key->src_port));
}

static void print_data_point(data_point *dp) {
    printf("%-12llu | %-12u | %-12u | %-12u | %-12u |\n",
           dp->flow_duration,
           dp->flow_bytes_per_s,
           dp->flow_pkts_per_s,
           dp->pkts_len_mean,
           dp->flow_IAT_mean);
}

int main(int argc, char **argv)
{
    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    int map_fd;
    int len, err;

    struct config cfg = {
        .ifindex = -1,
        .do_unload = false,
    };

    const char *__doc__ = "Dump data_point from XDP BPF map\n";

    /* Parse command line args */
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
    if (map_fd < 0)
        return EXIT_FAIL_BPF;

    struct flow_key key, next_key;
    data_point value;

    while (1) {
        int stt = 1;
        printf("\n=== Flow Table ===\n");
        printf("%-4s | %-21s | %-12s | %-12s | %-12s | %-12s | %-12s |\n",
               "STT", "SrcIP:Port",
               "FlowDur(ns)", "flow_bytes_per_second", "flow_pkts_per_second", "MeanIAT(ns)",
                "pkts_len_mean");

        memset(&key, 0, sizeof(key));

        while ((err = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("%-4d | ", stt++);
                print_flow_key(&next_key);
                printf(" | ");
                print_data_point(&value);
                printf("\n");
            }
            key = next_key;
        }
        sleep(1); // dump mỗi giây
    }
    return EXIT_OK;
}
