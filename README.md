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

We also employ an array-type map to store all nodes of Random Forest. In this map, the index is represented by a `__u32`, the value is stored in `Node` and `max_entries` is set to `MAX_NODE_PER_TREE * MAX_TREES`.
- `Node` is represents a single node within a decision tree used for RandomForest inferface in the kernel. Each field is defines as follows:
    + `left_idx`: Index of the left child node in the tree array.
    + `right_idx`: Index of the right child node in the tree array.
    + `split_value`: The threshold value (fixed-point) used to split the data for the associated feature.
    + `feature_idx`: Index of the feature used for splitting at this node.
    + `is_leaf`: Flag indicating whether the node is a leaf node (1 for leaf, 0 otherwise).
    + `label`: The class label assigned to the node if it is a leaf.
    + `tree_idx`: Identifier of the tree within the RandomForest ensemble to which this node belongs.
This structure enables efficient, kernel-level representation and traversal of decision trees for real-time packet classification and anomaly detector.

We also use the array-type map to store `accounting` structure. It is used to collect latency and throughput statistices for network flows in the kernel/XDP program:
-  **accounting**:
    + `time_in`: Timestamp when a packet or flow is first observed.
    + `proc_time`: Accumulated processing time for the flow. Each packet contributes `time_out - time_in` to this value.
    + `total_pkts`: Total number of packets observed for this flow.
    + `total_bytes`: Total number of bytes observed for this flow.
This structure supports per-flow performance monitoring, enabling profiling and optimization of packet processing in real time.

## 2. Structures of code:
We have the following source files in the project:
- `xdp_prog_kern.c`: This file contains the XDP/eBPF kernel program that is attached to the network interface. It performs real-time packet processing, extracts flow-level features, and executes inference using pre-loaded models RandomForest with `MAX_TREES` (10/20 trees) and `MAX_LEAVES` (8, 16, 32, 64 leaves). After load this XDP program to interface, it will DROP/PASS the packet in real time.
- `read_model_to_map.py`: A Python script used to read pre-trained machine learning models (e.g., SVM) and their associated feature scaling parameters. The script converts the model data into a C-compatible header (`common_kern_user.h`) and initializes structures that can be loaded into the kernel via BPF maps.
- `xdp_loader.c`: This file implements a userspace loader and map initializer. It loads the compiled XDP program into the kernel, sets up the BPF maps and provides mechanisms for updating and monitoring maps from userspace.

## 3. Instructions:
Follow this instruction:

```bash
cd xdp_prog/
sudo python3 read_model_to_map.py --max_tree ${MAX_TREE} --max_leaves ${MAX_LEAVES} --iface "$IFACE" --model_folder "/home/dongtv/security_paper/rf/" --home_folder "/home/dongtv"
```

## 4. Note:
The kernel has a strict **limitation**: floating-point arithmetic is not allowed. Therefore, we use fixed-point representation with 64-bit integers, where 16 bits are allocated for the fractional part and the remaining bits represent the integer part. Our Python code is also written to generate the common_kern_user.h file, which includes helper functions to perform calculations using this fixed-point format.