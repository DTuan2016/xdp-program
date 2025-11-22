IFACE=$1
MAX_TREE=$2
MAX_LEAVES=$3

sudo rm -rf /sys/fs/bpf/

sudo xdp-loader unload "$IFACE" --all

sudo python3 read_model_to_map.py --max_tree ${MAX_TREE} --max_leaves ${MAX_LEAVES} --iface "$IFACE" --model_folder "/home/dongtv/security_paper/rf/" --home_folder "/home/dongtv"
