/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
// #include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pinned_map_path>\n", argv[0]);
        return 1;
    }

    const char *map_path = argv[1];
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    __u32 key = 0;
	struct qsDataStruct qs_data = {0};
	memcpy(qs_data.num_leaves_per_tree, _qs_num_leaves_per_tree, sizeof(_qs_num_leaves_per_tree));
	memcpy(qs_data.leaves, _qs_leaves, sizeof(_qs_leaves));
	memcpy(qs_data.threshold, _qs_threshold, sizeof(_qs_threshold));
	memcpy(qs_data.tree_ids, _qs_tree_ids, sizeof(_qs_tree_ids));
	memcpy(qs_data.bitvectors, _qs_bitvectors, sizeof(_qs_bitvectors));
	memset(qs_data.v, 1, sizeof(qs_data.v));


    if (bpf_map_update_elem(map_fd, &key, &qs_data, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        close(map_fd);
        return 1;
    }

    printf("Updated pinned map at %s (key=%u)\n", map_path, key);
    close(map_fd);
    return 0;
}