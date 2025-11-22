# Description of this Branch

## 1. Data Structures:
We use a hash-type map to track information of flows arriving at the network interface card (NIC). In this map, the `flow_key` serves as the key, `data_point` serves as the value, and `max_entries` is set to `MAX_FLOW_SAVED`
- **flow_key**: 
    + `src_ip`: Source IP address of the packet
    + `src_port`: Source port of the packet
    + `dst_ip`: Destination IP address of the packet
    + `dst_port`: Destination port of the packet
    + `proto`: Protocol of the packet
- **data_point**:
    + `start_ts`: Timestamp when the first packet of the flow arrives
    + `last_seen`: Timestamp of the last packet in the flow
    + `min_IAT`: Minimum inter-arrival time between two consecutive packets
    + `total_pkts`: Total number of packets in the flow
    + `max_pkt_len`: Maximum packet length within the flow
    + `min_pkt_len`: Minimum packet length within the flow
    + `features[MAX_FEATURES]`: Array storing features for easy inference
        + `FEATURE_FLOW_DURATION`: 0
        + `FEATURE_TOTAL_FWD_PACKET`: 1
        + `FEATURE_TOTAL_LENGTH_OF_FWD_PACKET`: 2
        + `FEATURE_FWD_PACKET_LENGTH_MAX`: 3
        + `FEATURE_FWD_PACKET_LENGTH_MIN`: 4
        + `FEATURE_FWD_IAT_MIN`: 5
    + `label`: Label of the flow

We also employ an array-type map to store the weights of SVM models. In this map, the index is represented by a `__u32` (typically 0), the value is stored in `svm_weight` and `max_entries` is set to 1.
- **svm_weight**:
    + `value[MAX_FEATURES + 1]`: An array containing the SVM weight coefficients corresponding to each feature, from feature 0 up to feature [MAX_FEATURES - 1] along with an additional element representing the bias term.
    + `is_neg[MAX_FEATURES + 1]`: An array of flags indicating whether the corresponding weight is negative.
    + `scale[MAX_FEATURES]`: An array of scaling factors applied to each feature. Each element represents the multiplier used to normalize the corresponding feature to a standard range, which ensures that all features contribute proportionally during SVM inference.
    + `min_vals[MAX_FEATURES]`: An array storing the minimum observed values of each feature. This is used in feature normalization to shift the range of feature values before scaling.
    + `max_vals[MAX_FEATURES]`: An array storing the maximum observed values of each feature. Combined with min_vals, it defines the original range of each feature, allowing proper linear scaling to the normalized domain.

We also use the array-type map to store `accounting` structure. It is used to collect latency and throughput statistices for network flows in the kernel/XDP program:
-  **accounting**:
    + `time_in`: Timestamp when a packet or flow is first observed.
    + `proc_time`: Accumulated processing time for the flow. Each packet contributes `time_out - time_in` to this value.
    + `total_pkts`: Total number of packets observed for this flow.
    + `total_bytes`: Total number of bytes observed for this flow.
This structure supports per-flow performance monitoring, enabling profiling and optimization of packet processing in real time.

## 2. Structures of code:
We have the following source files in the project:
- `xdp_prog_kern.c`: This file contains the XDP/eBPF kernel program that is attached to the network interface. It performs real-time packet processing, extracts flow-level features, and executes inference using pre-loaded models such as Linear SVM or other algorithms. The program also updates per-flow statistics and maintains BPF maps for communication with userspace.
- `read_model_to_map.py`: A Python script used to read pre-trained machine learning models (e.g., SVM) and their associated feature scaling parameters. The script converts the model data into a C-compatible header (`common_kern_user.h`) and initializes structures that can be loaded into the kernel via BPF maps.
- `xdp_loader.c`: This file implements a userspace loader and map initializer. It loads the compiled XDP program into the kernel, sets up the BPF maps (including SVM weights and flow statistics), and provides mechanisms for updating and monitoring maps from userspace.

The machine learning models and corresponding feature scalers were trained and generated using **Scikit-Learn** with the **CICDDoS 2019 dataset**. We use Linear SVM and svaed using (**"SVM-Linear"**, **"linear"**). This process ensures that the SVM weights and scaling parameters are compatible with the kernel-level inference workflow implemented in the XDP program.

## 3. Instructions:
Follow this instruction:

```bash
cd xdp_prog/
sudo python3 read_model_to_map.py --svm_model <Path of your svm model> --scaler <Path of your scaler>
sudo ./xdp_loader -S --dev {IFACE} --progname <Your progname/ xdp_anomaly_detector in this branch>
```