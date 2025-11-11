sudo make

sudo xdp-loader unload eth0 --all

sudo rm -rf /sys/fs/bpf/eth0

sudo ./xdp_loader -S --dev eth0 --progname xdp_anomaly_detector