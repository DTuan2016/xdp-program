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
    printf("%-12llu | %-12u | %-12u | %-12u | %-12u | %-12u | %-12f | %-12f\n",
           dp->last_seen - dp->start_ts,
           dp->total_pkts,
           dp->total_bytes,
           dp->flow_IAT_mean,
           dp->k_distance,
           dp->reach_dist[0], // in demo chỉ in 1 giá trị đầu
           (float)dp->lrd_value / SCALEEEEEE,
           (float)dp->lof_value / SCALEEEEEE);
}

/*==================== DISTANCE <EUCLIDEAN> ====================*/
static double distance (data_point *a, data_point *b){
    double f1 = (double)a->total_bytes - (double)b->total_bytes;
    double f2 = (double)a->total_pkts - (double)b->total_pkts;
    double f3 = (double)a->flow_IAT_mean - (double)b->flow_IAT_mean;
    double f4 = (double)(a->last_seen - a->start_ts) - (double)(b->last_seen - b->start_ts);
    return sqrt(f1*f1 + f2*f2 + f3*f3 + f4*f4);
}

/*==================== COMPUTE DISTANCE MATRIX ====================*/
static void compute_distance_matrix(data_point *data, int num_points, double dist[num_points][num_points]){
    for(int i = 0; i < num_points; i++){
        for(int j = 0; j < num_points; j++){
            dist[i][j] = (i == j) ? 0.0 : distance(&data[i], &data[j]);
        }
    }
}

/*==================== FIND KNN ====================*/
static void find_knn(data_point *data, int num_points, double dist[num_points][num_points], 
                                                        int neighbors[num_points][KNN]){
    for(int i = 0; i < num_points; i++){
        int idx[num_points];
        for(int j = 0; j < num_points; j++) idx[j] = j;
        
        for(int j = 0; j < num_points; j ++){
            for(int k = j + 1; k < num_points; k++){
                if(dist[i][idx[k]] < dist[i][idx[j]]){
                    int tmp = idx[j];
                    idx[j]  = idx[k];
                    idx[k]  = tmp;
                }
            }
        }
        for(int k = 0; k < KNN; k++){
            neighbors[i][k] = idx[k+1];
            if(k < (int)(sizeof(data[i].reach_dist) / sizeof(data[i].reach_dist[0]))){
                data[i].reach_dist[k] = (unsigned short)dist[i][neighbors[i][k]];
            }
        }
        data[i].k_distance = (unsigned short)dist[i][neighbors[i][KNN - 1]];
    }
}

/*==================== COMPUTE LRD ====================*/
static void compute_lrd(data_point *data, int num_points, double dist[num_points][num_points], 
                        int neighbors[num_points][KNN], double lrd[num_points]){
    for(int i = 0; i < num_points; i++){
        double sum_reach = 0;
        for(int k = 0; k < KNN; k++){
            int o = neighbors[i][k];
            double k_dist_o = dist[o][neighbors[o][KNN-1]];
            double reach = (k_dist_o > dist[i][o]) ? k_dist_o : dist[i][o];
            sum_reach += reach;
        }
        lrd[i] = (sum_reach > 0) ? (KNN / sum_reach) : 0.0;
        data[i].lrd_value = (unsigned short)(lrd[i] * SCALEEEEEE);
    }
}

/*==================== COMPUTE LOF ====================*/
static void compute_lof(data_point *data, int num_points, int neighbors[num_points][KNN], 
                                                        double lrd[num_points]){
    for(int i = 0; i < num_points; i++){
        double sum_ratio = 0.0; 
        for(int k = 0; k < KNN; k++){
            int o = neighbors[i][k];
            if(lrd[i] > 0){
                sum_ratio += lrd[o] / lrd[i];
            }
        }
        double lof = sum_ratio / KNN;
        data[i].lof_value = (unsigned short)(lof * SCALEEEEEE);
    }
}

/*==================== RUN WITH ALL DATA ====================*/
static void calculate_lof_for_data(data_point *data, int num_points){
    double dist[num_points][num_points];
    int neighbors[num_points][KNN];
    double lrd[num_points];
    
    compute_distance_matrix(data, num_points, dist);
    find_knn(data, num_points, dist, neighbors);
    compute_lrd(data, num_points, dist, neighbors, lrd);
    compute_lof(data, num_points, neighbors, lrd);
}

/*==================== MAIN PROCESS ====================*/
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
        data_point flows[MAX_FLOW_SAVED];
        struct flow_key keys[MAX_FLOW_SAVED];
        int flow_count = 0;

        memset(&key, 0, sizeof(key));

        // duyệt map và copy dữ liệu vào mảng flows[]
        while ((err = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                if (flow_count < MAX_FLOW_SAVED) {
                    flows[flow_count] = value;
                    keys[flow_count]  = next_key;
                    flow_count++;
                }
            }
            key = next_key;
        }

        if (flow_count >= MAX_FLOW_SAVED) {
            // đủ dữ liệu => tính toán LOF
            calculate_lof_for_data(flows, flow_count);

            printf("\n=== Flow Table with LOF ===\n");
            printf("%-4s | %-21s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
                   "STT", "SrcIP:Port",
                   "FlowDur(ns)", "TotalPkts", "TotalBytes", "MeanIAT(ns)",
                   "k-dist", "reach[0]", "lrd", "lof");

            for (int i = 0; i < flow_count; i++) {
                printf("%-4d | ", i+1);
                print_flow_key(&keys[i]);
                printf(" | ");
                print_data_point(&flows[i]);
                printf("\n");

                // optional: ghi lại LOF xuống map nếu muốn
                bpf_map_update_elem(map_fd, &keys[i], &flows[i], BPF_ANY);
            }
        } else {
            printf("\n[INFO] Current flows: %d (waiting for %d to compute LOF)\n",
                   flow_count, MAX_FLOW_SAVED);
        }

        sleep(1);
    }

    return EXIT_OK;
}