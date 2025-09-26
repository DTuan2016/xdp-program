#!/bin/bash
set -e

# Kiểm tra có truyền output file không
if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

OUT_FILE=$1

# Cleanup old maps/programs
sudo rm -f /sys/fs/bpf/xdp_isoforest_nodes
sudo rm -f /sys/fs/bpf/xdp_isoforest_params
sudo rm -f /sys/fs/bpf/xdp_isoforest_c
sudo rm -rf /sys/fs/bpf/test_xdp

sudo xdp-loader unload eno3 --all || true

# Load new program
sudo bpftool prog load xdp_prog/xdp_prog_kern.o /sys/fs/bpf/test_xdp type xdp

# Lấy ID của XDP program
PROG_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/test_xdp | awk 'NR==1 {print $1}' | cut -d: -f1)

echo "[INFO] Using program ID: $PROG_ID"

# Run test
sudo bpftool prog run id $PROG_ID \
    data_in ../test/data_in.bin \
    data_out - \
    repeat 10 | tail -n 1 >> "$OUT_FILE"

echo "[INFO] Done. Appended result to $OUT_FILE"
