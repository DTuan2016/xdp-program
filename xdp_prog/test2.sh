MAX_TREE=$1
MAX_LEAVES=$2

sudo rm -rf /sys/fs/bpf/eno3

sudo xdp-loader unload eno3 --all

python3 rf2qs.py --model ~/security_paper/rf/rf_${MAX_TREE}_${MAX_LEAVES}_model.pkl

sudo make

sudo ./xdp_loader -S --dev eno3 --progname xdp_anomaly_detector
