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
    + `label`: Label of the flow

- **feat_vec**:
    + `features[MAX_FEATURES]`: Array storing features for easy inference
        + `FEATURE_FLOW_DURATION`: 0
        + `FEATURE_TOTAL_FWD_PACKET`: 1
        + `FEATURE_TOTAL_LENGTH_OF_FWD_PACKET`: 2
        + `FEATURE_FWD_PACKET_LENGTH_MAX`: 3
        + `FEATURE_FWD_PACKET_LENGTH_MIN`: 4
        + `FEATURE_FWD_IAT_MIN`: 5

The `qs_forest` map is a BPF array map that stores the QuickScorer ensemble model in kernel space. It allows the XDP program to perform high-speed inference directly on incoming data without transferring the model to userspace.
- **qsDataStruct**: This structure represents the internal data used by the **QuickScorer** algorithm, which is an optimized decision tree inference method designed for high-speed evaluation. Each field is defined as follows:
    + `threshold[QS_NUM_NODES]`: An array storing the split thresholds for all nodes in all trees. Each value represents the decision boundary used to traverse the tree at that node.
    + `bitvectors[QS_NUM_NODES]`: An array of bitvectors representing the contribution of each node to the active leaves. These vectors allow the algorithm to quickly identify which leaves are still reachable as the input is evaluated.
    + `v[QS_NUM_NODES]`: An array containing precomputed values associated with each node, used to accelerate scoring by avoiding repeated computations during traversal.
    + `tree_ids[QS_NUM_NODES]`: An array mapping each node to its corresponding tree in the ensemble. This enables the QuickScorer to handle multiple trees efficiently.
    + `num_leaves_per_tree[QS_NUM_TREES]`: An array specifying the number of leaves for each tree, which is required for correctly computing the indices of leaf nodes in the `leaves` array.
    + `leaves[QS_NUM_LEAVES]`: An array representing the leaf nodes across all trees. Each element stores the output or score associated with that leaf, used to compute the final prediction for a given input.

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
- `read_model_to_map.py`: A Python script used to read pre-trained machine learning models and their associated feature scaling parameters. The script converts the model data into a C-compatible header (`common_kern_user.h`) and initializes structures that can be loaded into the kernel via BPF maps.
- `xdp_loader.c`: This file implements a userspace loader and map initializer. It loads the compiled XDP program into the kernel, sets up the BPF maps and provides mechanisms for updating and monitoring maps from userspace.

## 3. Instructions:
Follow this instruction:
### Run code
1. In xdp-program/xdp_prog, gen header file. Model in /home/haipt/security_paper/rf. Model name in format rf_{num tree}_{max leavec}.pkl
```
python3 rf2qs.py --model ~/security_paper/rf/rf_100_16_model.pkl
```
2. Rebuild
```
make
```

## 4. Note:
The kernel has a strict **limitation**: floating-point arithmetic is not allowed. Therefore, we use fixed-point representation with 64-bit integers, where 16 bits are allocated for the fractional part and the remaining bits represent the integer part. Our Python code is also written to generate the common_kern_user.h file, which includes helper functions to perform calculations using this fixed-point format.