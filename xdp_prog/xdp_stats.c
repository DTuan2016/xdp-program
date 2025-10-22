// /* SPDX-License-Identifier: GPL-2.0 */
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <errno.h>
// #include <getopt.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include <bpf/bpf.h>
// #include <linux/if_link.h>
// #include <locale.h>
// #include <unistd.h>
// #include <time.h>
// #include <net/if.h>
// #include <math.h>

// #include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

// #include "../common/common_params.h"
// #include "../common/common_user_bpf_xdp.h"
// #include "common_kern_user.h"

// // static const struct option_wrapper long_options[] = {
// //     {{"help", no_argument, NULL, 'h'}, "Show help", false},
// //     {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
// //     {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},
// //     {{0, 0, NULL, 0}}
// // };

// #ifndef PATH_MAX
// #define PATH_MAX 4096
// #endif

// #define MAP_PATH_SVM "/sys/fs/bpf/eno3/svm_map"
// // #define MAP_SCALE "/sys/fs/bpf/eno3/scale"
// int main(void)
// {
//     const char *weight_path = "/home/dongtv/userspace_test/model/svm_weight.csv";
//     const char *minmax_path = "/home/dongtv/userspace_test/model/minmax_params.csv";

//     FILE *fp_weight = fopen(weight_path, "r");
//     FILE *fp_minmax = fopen(minmax_path, "r");
//     if (!fp_weight || !fp_minmax) {
//         perror("fopen svm_weight.csv or minmax_params.csv");
//         return 1;
//     }

//     int map_fd = bpf_obj_get(MAP_PATH_SVM);
//     if (map_fd < 0) {
//         perror("bpf_obj_get svm_map");
//         fclose(fp_weight);
//         fclose(fp_minmax);
//         return 1;
//     }

//     svm_weight w_struct;
//     memset(&w_struct, 0, sizeof(w_struct));

//     /* ======== Đọc svm_weight.csv ======== */
//     char line[1024];
//     if (!fgets(line, sizeof(line), fp_weight)) {
//         fprintf(stderr, "Empty svm_weight.csv file\n");
//         fclose(fp_weight);
//         fclose(fp_minmax);
//         return 1;
//     }

//     char *token = strtok(line, ",");
//     int idx = 0;
//     while (token && idx < MAX_FEATURES + 1) {
//         double val = atof(token);
//         w_struct.is_neg[idx] = (val < 0) ? 1 : 0;
//         w_struct.value[idx] = fixed_from_float(fabs(val));
//         printf("Weight[%d] = %f (fixed=%d, neg=%d)\n",
//                idx, val, w_struct.value[idx], w_struct.is_neg[idx]);
//         token = strtok(NULL, ",");
//         idx++;
//     }

//     fclose(fp_weight);

//     /* ======== Đọc minmax_params.csv ======== */
//     if (!fgets(line, sizeof(line), fp_minmax)) {
//         fprintf(stderr, "Empty minmax_params.csv file\n");
//         fclose(fp_minmax);
//         return 1;
//     }

//     token = strtok(line, ",");
//     // int count = 0;
//     while (fgets(line, sizeof(line), fp_minmax)) {
//         int fidx;
//         double min_val, max_val;
//         if (sscanf(line, "%d,%lf,%lf", &fidx, &min_val, &max_val) == 3) {
//             if (fidx >= 0 && fidx < MAX_FEATURES) {
//                 w_struct.min_vals[fidx] = fixed_from_float(min_val);
//                 w_struct.max_vals[fidx] = fixed_from_float(max_val);
//                 printf("Feature %d: min=%f max=%f\n", fidx, min_val, max_val);
//             }
//         }
//     }
//     // fclose(fp_minmax);
//     fclose(fp_minmax);

//     /* ======== Debug log ======== */
//     for (int i = 0; i < MAX_FEATURES; i++) {
//         printf("Feature %d: min=%f max=%f weight=%f neg=%d\n",
//                i,
//                fixed_to_float(w_struct.min_vals[i]),
//                fixed_to_float(w_struct.max_vals[i]),
//                fixed_to_float(w_struct.value[i]),
//                w_struct.is_neg[i]);
//     }

//     /* ======== Ghi struct vào BPF map ======== */
//     int key = 0;
//     if (bpf_map_update_elem(map_fd, &key, &w_struct, BPF_ANY) != 0) {
//         fprintf(stderr, "Failed to update map: %s\n", strerror(errno));
//     } else {
//         printf("[+] Updated BPF map successfully!\n");
//     }

//     return 0;
// }

/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <math.h>

#include <bpf/libbpf.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// #define MAP_PATH_SVM "/sys/fs/bpf/eno3/svm_map"
#define MAP_PATH_SVM "/sys/fs/bpf/enp1s0f0/svm_map"

int main(void)
{
    // const char *weight_path = "/home/dongtv/userspace_test/model/svm_weight.csv";
    // const char *minmax_path = "/home/dongtv/userspace_test/model/minmax_params.csv";
    const char *weight_path = "/home/lanforge/xdp-program/svm_weight.csv";
    const char *minmax_path = "/home/lanforge/xdp-program/minmax_params.csv";

    FILE *fp_weight = fopen(weight_path, "r");
    FILE *fp_minmax = fopen(minmax_path, "r");
    if (!fp_weight || !fp_minmax) {
        perror("fopen svm_weight.csv or minmax_params.csv");
        return 1;
    }

    int map_fd = bpf_obj_get(MAP_PATH_SVM);
    if (map_fd < 0) {
        perror("bpf_obj_get svm_map");
        fclose(fp_weight);
        fclose(fp_minmax);
        return 1;
    }

    svm_weight w_struct;
    memset(&w_struct, 0, sizeof(w_struct));

    /* ======== Đọc svm_weight.csv ======== */
    char line[1024];
    if (!fgets(line, sizeof(line), fp_weight)) {
        fprintf(stderr, "Empty svm_weight.csv file\n");
        fclose(fp_weight);
        fclose(fp_minmax);
        return 1;
    }

    char *token = strtok(line, ",");
    int idx = 0;
    while (token && idx < MAX_FEATURES + 1) {
        double val = atof(token);
        w_struct.value[idx] = fixed_from_float(val); // giữ dấu
        token = strtok(NULL, ",");
        idx++;
    }
    fclose(fp_weight);

    /* ======== Đọc minmax_params.csv ======== */
    while (fgets(line, sizeof(line), fp_minmax)) {
        int fidx;
        double min_val, max_val;
        if (sscanf(line, "%d,%lf,%lf", &fidx, &min_val, &max_val) == 3) {
            if (fidx >= 0 && fidx < MAX_FEATURES) {
                if (min_val != 0){
                    min_val -= 5;
                }
                w_struct.min_vals[fidx] = fixed_from_float(min_val);
                w_struct.max_vals[fidx] = fixed_from_float(max_val);
            }
        }
    }
    fclose(fp_minmax);

    /* ======== Debug log ======== */
    for (int i = 0; i < MAX_FEATURES; i++) {
        printf("Feature %d: min=%f max=%f weight=%f\n",
               i,
               fixed_to_float(w_struct.min_vals[i]),
               fixed_to_float(w_struct.max_vals[i]),
               fixed_to_float(w_struct.value[i]));
    }
    printf("Bias: %f\n", fixed_to_float(w_struct.value[MAX_FEATURES]));

    /* ======== Ghi struct vào BPF map ======== */
    int key = 0;
    if (bpf_map_update_elem(map_fd, &key, &w_struct, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update map: %s\n", strerror(errno));
    } else {
        printf("[+] Updated BPF map successfully!\n");
    }

    return 0;
}
