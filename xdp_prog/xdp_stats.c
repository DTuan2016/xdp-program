/* SPDX-License-Identifier: GPL-2.0 */
// static const char *__doc__ = "XDP stats program\n"
// 	" - Finding xdp_stats_map via --dev name info\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include "common_kern_user.h"
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */
#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

static void print_flow_key(struct flow_key *key) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));
    // is_forward_init()
     printf("%s:%u -> %s:%u proto=%u",
           src_ip, ntohs(key->src_port),
           dst_ip, ntohs(key->dst_port),
           key->protocol);
}

static void print_flow_stats(struct flow_stats *value) {
    unsigned long long fwd_pkt = value->fwd_pkt_count;
    unsigned long long bwd_pkt = value->bwd_pkt_count;
    unsigned long long total_pkt = fwd_pkt + bwd_pkt;

    unsigned long long fwd_bytes = value->total_fwd_len;
    unsigned long long bwd_bytes = value->total_bwd_len;
    unsigned long long total_bytes = fwd_bytes + bwd_bytes;

    unsigned long long flow_duration = value->time_end_ns - value->time_start_ns;
    unsigned long long mean_iat = 0;
    if (total_pkt > 0)
        mean_iat = value->sum_iat_ns / total_pkt;

    printf("%-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-12llu | %-12llu | %-12llu\n",
           total_pkt,
           fwd_pkt,
           bwd_pkt,
           fwd_bytes,
           bwd_bytes,
           total_bytes,
           flow_duration,
           mean_iat);
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

    const char *__doc__ = "Dump flow tracking from XDP BPF map\n";

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
    struct flow_stats value;

    while (1) {
        int stt = 1;
        printf("\n=== Flow Table ===\n");
        printf("%-4s | %-21s | %-21s | %-5s | %-7s | %-7s | %-9s | %-10s | %-10s | %-12s | %-12s | %-12s \n",
               "STT", "SrcIP:Port", "DstIP:Port", "Proto",
               "FwdPkt", "BwdPkt", "TotalPkt",
               "FwdBytes", "BwdBytes", "TotalBytes", "FlowDur(ns)", "MeanIAT(ns)");

        memset(&key, 0, sizeof(key));

        while ((err = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("%-4d | ", stt++);
                print_flow_key(&next_key);
                printf(" | ");
                print_flow_stats(&value);
                printf("\n");
            }
            key = next_key;
        }

        sleep(1); // dump mỗi giây
    }

    return EXIT_OK;
}