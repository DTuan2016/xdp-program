// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <bpf/xsk.h>

#include "common_kern_user.h"

static const int chunk_size = 4096;
static const int chunk_count = 4096;
static const int umem_len = chunk_size * chunk_count;
unsigned char[chunk_count][chunk_size] umem = malloc(umem_len);



int main(){
    return 0;
}