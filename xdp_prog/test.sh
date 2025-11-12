MAX_TREE=$1
MAX_LEAVES=$2

sudo rm -rf /sys/fs/bpf/eno3

sudo xdp-loader unload eno3 --all

sudo python3 read_model_to_map.py --max_tree ${MAX_TREE} --max_leaves ${MAX_LEAVES}
