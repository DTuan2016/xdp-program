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

// static const struct option_wrapper long_options[] = {
//     {{"help", no_argument, NULL, 'h'}, "Show help", false},
//     {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
//     {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},
//     {{0, 0, NULL, 0}}
// };

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAP_PATH "/sys/fs/bpf/eno3/svm_map"

// Đảm bảo định nghĩa svm_weight như sau:
// typedef struct {
//     __s32 value;   // fixed-point
//     __u8 is_neg;   // 1 nếu âm
// } svm_weight;

int main() {
    FILE *fp = fopen("/home/dongtv/userspace_test/model/svm_weight.csv", "r");
    if (!fp) {
        perror("fopen svm_weight.csv");
        return 1;
    }

    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        fclose(fp);
        return 1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "Empty CSV file\n");
        fclose(fp);
        return 1;
    }

    // CSV có dạng: w0,w1,w2,...,bias
    double features[MAX_FEATURES + 1] = {0};
    int count = 0;

    // Parse từng giá trị ngăn cách bởi dấu phẩy
    char *token = strtok(line, ",");
    while (token && count < MAX_FEATURES + 1) {
        features[count++] = atof(token);
        token = strtok(NULL, ",");
    }

    if (count == 0) {
        fprintf(stderr, "No values parsed from CSV\n");
        fclose(fp);
        return 1;
    }

    svm_weight weights[MAX_FEATURES + 1];

    for (int i = 0; i < count; i++) {
        weights[i].is_neg = (features[i] < 0) ? 1 : 0;
        weights[i].value = fixed_from_float(fabs(features[i]));
    }

    // Ghi từng phần tử vào BPF map
    for (int i = 0; i < count; i++) {
        if (bpf_map_update_elem(map_fd, &i, &weights[i], BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update index %d: %s\n", i, strerror(errno));
        } else {
            printf("[+] Updated map index %d: value=%d, neg=%d\n",
                   i, weights[i].value, weights[i].is_neg);
        }
    }

    fclose(fp);
    return 0;
}