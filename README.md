# XDP-based Network Anomaly Detection System

## 1. Setup dependencies:
We start by cloning this repository:
```bash
git clone --recurse-submodules https://github.com/DTuan2016/xdp-program
```

Note: If you missed the -recurse-submodules option in the previous step or you already cloned it earlier without the submodules you can use the following command:
```bash
git submodule update --init --recursive
```

### Dependencies:
On Debian and Ubuntu installations, install the dependencies like this:
```bash
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 m4
```
To install the 'perf' utility, run this:
```bash
sudo apt install linux-tools-$(uname -r)
```
### Kernel headers dependency:
```bash
sudo apt install linux-headers-$(uname -r)
```

### Extra tools:
Starting from Ubuntu 19.10, bpftool can be installed with:
```bash
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump
```

Install FlameGraph. You can see more instructions in this [Link](https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html):
```bash
cd ..
git clone https://github.com/brendangregg/FlameGraph
```
## 2. Description of this Reporitories:
Our work primarily focuses on addressing the question of how to deploy machine-learning-based alogorithms into the kernel so that they can be attached to network interface and perform inference directly at the data plane. The algorithms implemented in our system include:
- **Vallina** : A baseline variant that performs no inference, it simply recieves packets and forwards them unchanged.
- **Random Forest**: An implementation that performs real-time inference of a Random Forest classifier within the kernel context.
- **QuickXDP**: An optimized variant of Random Forest inference designed to achieve significantly higher throughput and low latency, thereby improving performance over the standard implementation.
- **SVM**: A kernel-level inference engine for Support Vector Machine (SVM) classification.
- **KNN_threshold**: This module implements inference based on a K-Nearest Neighbors (KNN) classifier using a threshold-based decision mechanism. The current implementation focuses primarily on functional correctness; performance optimizations have not yet been applied.
- **Supervised_LOF**: This component performs anomaly detection using a Supervised Local Outlier Factor (LOF) model. The LOF algorithm is trained offline, and the resulting model is subsequently deployed to the kernel for real-time inference.
- **Userscace**: This module aggregates features extracted from packet-level events and stores them in BPF maps. A userspace daemon periodically (every one second) retrieves these features and performs inference across multiple algorithms, enabling flexible integration of higher-level or computationally intensive models.

### I will include the usage instructions for each branch within its respective branch!