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

// const char *pin_basedir = "/sys/fs/bpf";

#define MAP_PATH "/sys/fs/bpf/eno3/svm_map"


int main() {
    FILE *fp = fopen("/home/dongtv/userspace_test/weights.csv", "r");
    if (!fp) {
        perror("fopen weights.csv");
        return 1;
    }

    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        fclose(fp);
        return 1;
    }

    char line[64];
    int idx = 0;
    while (fgets(line, sizeof(line), fp)) {
        int value = atoi(line);   // đọc số nguyên từ CSV
        if (bpf_map_update_elem(map_fd, &idx, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to update map at key %d: %s\n",
                    idx, strerror(errno));
            fclose(fp);
            return 1;
        }
        printf("Updated key=%d, value=%d\n", idx, value);
        idx++;
    }

    fclose(fp);
    printf("Done. Updated %d entries into map.\n", idx);
    return 0;
}