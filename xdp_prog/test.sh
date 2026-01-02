
sudo rm -rf /sys/fs/bpf/

sudo xdp-loader unload eno3 --all

sudo ./xdp_loader -S --dev eno3 --prog xdp_anomaly_detector

sudo xdp-loader unload enp8s0f1 --all

sudo ./xdp_loader -S --dev enp8s0f1 --prog stats