import joblib
import pandas as pd
import os, sys
import argparse
import subprocess
from bcc import libbcc, BPF
from math import log2
import ctypes
def generate_common_header(output_path: str, max_tree : int, max_nodes : int, max_depth : int,  max_features: int = 6, fixed_shift: int = 16):
    """
    Generate common_kernel_user.h header file
    
    Args:
        output_path: Path to output header file
        max_features: Maximum number of features
        fixed_shift: Fixed-point shift bits
    """
    
    fixed_scale = 1 << fixed_shift
    
    header_content = f"""#ifndef COMMON_KERNEL_USER_H
#define COMMON_KERNEL_USER_H

#include <linux/types.h>

/* Fixed-point configuration */
#define FIXED_SHIFT         {fixed_shift}
#define FIXED_SCALE         {fixed_scale}
#define MAX_TREES           {max_tree}
#define MAX_NODE_PER_TREE   {max_nodes}
#define MAX_FEATURES        {max_features}
#define MAX_DEPTH           {max_depth}
#define TOTAL_NODES         {max_tree * max_nodes}
#define MAX_FLOW_SAVED      1000

#define QS_FEATURE_FLOW_DURATION                0
#define QS_FEATURE_TOTAL_FWD_PACKET             1
#define QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET   2
#define QS_FEATURE_FWD_PACKET_LENGTH_MAX        3
#define QS_FEATURE_FWD_PACKET_LENGTH_MIN        4
#define QS_FEATURE_FWD_IAT_MIN                  5

typedef __u64               fixed;

/* Latency statistics structure */
typedef struct {{
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u32 total_pkts;
    __u32 total_bytes;
}} accounting;

/* Flow key structure */
struct flow_key {{
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
}} __attribute__((packed));

/* Definition of a datapoint or a flow (accounting) */
typedef struct {{
    __u64   start_ts;             /* Timestamp of first packet */
    __u64   last_seen;            /* Timestamp of last packet */
    __u64   min_IAT;              /* Minimum Inter-Arrival Time */
    __u32   total_pkts;           /* Total packet count */
    __u32   max_pkt_len;          /* Maximum packet length */
    __u32   min_pkt_len;          /* Minimum packet length */
    __u32   total_bytes;          /* Total byte count */
    fixed   features[MAX_FEATURES];
    int     label;
}} data_point;

// /* Definition of feature vector to calculate RF */
// struct feat_vec {{
//     fixed features[MAX_FEATURES];
// }};

/* Definition of a Node of Decision Tree */
typedef struct {{
    int     left_idx;
    int     right_idx;
    fixed   split_value;
    int     feature_idx;
    __u32   is_leaf;
    int     label;
    int     tree_idx;
}} Node;

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{{
    return (__u64)(value * (double)FIXED_SCALE);
}}

/* Convert fixed-point to float */
static __always_inline double fixed_to_float(fixed value)
{{
    return (double)value / (double)FIXED_SCALE;
}}

static __always_inline fixed fixed_from_uint(__u64 value)
{{
    return value << FIXED_SHIFT;
}}

static __always_inline __u64 fixed_to_uint(fixed value)
{{
    return value >> FIXED_SHIFT;
}}

static __always_inline fixed fixed_add(fixed a, fixed b)
{{
    return a + b;
}}

static __always_inline fixed fixed_sub(fixed a, fixed b)
{{
    return (a > b) ? (a - b) : 0;
}}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{{
    /* Use 128-bit intermediate to prevent overflow */
    __u64 a_int = a >> FIXED_SHIFT;
    __u64 a_frac = a & ((1ULL << FIXED_SHIFT) - 1);
    __u64 b_int = b >> FIXED_SHIFT;
    __u64 b_frac = b & ((1ULL << FIXED_SHIFT) - 1);
    
    __u64 result_int = a_int * b_int;
    __u64 result_frac = (a_int * b_frac + a_frac * b_int) >> FIXED_SHIFT;
    __u64 result_frac_frac = (a_frac * b_frac) >> (FIXED_SHIFT * 2);
    
    return (result_int << FIXED_SHIFT) + result_frac + result_frac_frac;
}}

static __always_inline fixed fixed_div(fixed a, fixed b)
{{
    if (b == 0)
        return 0;
    
    /* Shift dividend left to maintain precision */
    __u64 shifted_a = a << FIXED_SHIFT;
    return shifted_a / b;
}}

static __always_inline fixed fixed_sqrt(fixed value)
{{
    if (value == 0)
        return 0;

    fixed x = value;
    fixed two = fixed_from_uint(2);
    
    // #pragma unroll
    for (int i = 0; i < 10; i++) {{
        fixed x_squared = fixed_div(value, x);
        x = fixed_div(fixed_add(x, x_squared), two);
    }}
    
    return x;
}}

static __always_inline fixed fixed_abs(fixed value)
{{
    /* For unsigned __u64, this is just the value itself */
    return value;
}}

static __always_inline int fixed_compare(fixed a, fixed b)
{{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}}


static __always_inline fixed fixed_log2(__u64 x)
{{
    if (x == 0)
        return 0;

    __u64 int_part = 0;
    __u64 tmp = x;
    
    while (tmp >>= 1)
        int_part++;

    __u64 base = 1ULL << int_part;
    __u64 remainder = x - base;

    __u64 frac = (remainder << FIXED_SHIFT) / base;
    
    return (int_part << FIXED_SHIFT) | frac;
}}

static __always_inline fixed fixed_ln(__u64 x)
{{
    if (x == 0)
        return 0;
    
    fixed log2_val = fixed_log2(x);
    fixed ln2 = 177;
    
    return fixed_mul(log2_val, ln2);
}}

static __always_inline fixed fixed_exp(fixed x)
{{
    fixed result = FIXED_SCALE; 
    fixed term = FIXED_SCALE;  
    
    // #pragma unroll
    for (int i = 1; i <= 6; i++) {{
        term = fixed_mul(term, x);
        term = fixed_div(term, fixed_from_uint(i));
        result = fixed_add(result, term);
    }}
    
    return result;
}}

static __always_inline fixed fixed_pow(fixed base, __u32 exp)
{{
    fixed result = FIXED_SCALE;
    
    // #pragma unroll
    for (__u32 i = 0; i < exp && i < 16; i++) {{
        result = fixed_mul(result, base);
    }}
    
    return result;
}}

#endif /*COMMON_KERN_USER_H*/
"""    
    with open(output_path, 'w') as f:
        f.write(header_content)
    
    print(f"[HEADER GEN] Generated {output_path}")
    print(f"[HEADER GEN] FIXED_SHIFT={fixed_shift}, FIXED_SCALE={fixed_scale}")
    print(f"[HEADER GEN] MAX_FEATURES={max_features}")


# Load model (.pkl) 
def dump_random_forest_to_csv(model_path="randforest.pkl", label_map=None):
    """
    Xuất toàn bộ node trong RandomForestClassifier ra CSV.
    - Nếu node là lá: label = class tương ứng (theo label_map)
    - Nếu node không phải lá: label = -1
    """
    import os, joblib, numpy as np, pandas as pd

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Không tìm thấy model tại {model_path}")

    model = joblib.load(model_path)
    if not hasattr(model, "estimators_"):
        raise ValueError("Model không có thuộc tính estimators_ — có thể chưa train xong hoặc không phải RandomForestClassifier.")
    class_labels = list(model.classes_)
    if label_map is None:
        label_map = {label: i for i, label in enumerate(class_labels)}

    rows = []
    for tree_idx, tree in enumerate(model.estimators_):
        t = tree.tree_
        for node_idx in range(t.node_count):
            left, right = t.children_left[node_idx], t.children_right[node_idx]
            is_leaf = int(left == -1 and right == -1)
            label = -1

            if is_leaf:
                value = t.value[node_idx].flatten()
                if value.sum() > 0:
                    label_name = class_labels[int(np.argmax(value))]
                    label = label_map.get(label_name, -1)

            rows.append({
                "tree_idx": tree_idx,
                "node_idx": node_idx,
                "feature_idx": int(t.feature[node_idx]),
                "split_value": float(t.threshold[node_idx]),
                "left_child": left,
                "right_child": right,
                "is_leaf": is_leaf,
                "label": label,
            })

    df = pd.DataFrame(rows)
    return df

SCALE_BITS = 16  # ví dụ: 2^16 = 65536
SCALE = 1 << SCALE_BITS

def float_to_fixed_u64(value: float, scale_bits: int = SCALE_BITS) -> int:
    """
    Chuyển float sang fixed-point dạng __u64, dùng cơ số 2^scale_bits.
    - Ví dụ: 1.5 -> 1.5 * 2^16 = 98304
    - clamp giá trị âm về 0
    """
    scaled = int(value * (1 << scale_bits))
    if scaled < 0:
        scaled = 0
    return scaled

def load_df_to_map(df: pd.DataFrame, MAP_PATH: str, MAX_TREE: int, MAX_LEAVES_PER_TREE: int):
    MAX_NODE_PER_TREE = 2 * MAX_LEAVES_PER_TREE - 1
    TOTAL_NODES = MAX_TREE * MAX_NODE_PER_TREE

    bpf_map_fd = libbcc.lib.bpf_obj_get(MAP_PATH.encode())
    if bpf_map_fd < 0:
        raise OSError(f"[LOAD TO MAPS] Failed to open pinned BPF map at {MAP_PATH}")

    print(f"[LOAD TO MAPS] Opened map: {MAP_PATH}")
    print(f"[LOAD TO MAPS] MAX_TREE={MAX_TREE}, MAX_LEAVES_PER_TREE={MAX_LEAVES_PER_TREE}, MAX_NODE_PER_TREE={MAX_NODE_PER_TREE}")
    print(f"[LOAD TO MAPS] TOTAL_NODES={TOTAL_NODES}")
    print(f"[LOAD TO MAPS] Using 2^{SCALE_BITS}-scaled fixed point ({SCALE})")

    # Reset index để đảm bảo index liên tục từ 0
    df = df.reset_index(drop=True)
    
    # Tính toán tree_idx dựa trên vị trí của node
    # Giả sử mỗi cây có MAX_NODE_PER_TREE nodes liên tiếp
    df['tree_idx'] = df.index // MAX_NODE_PER_TREE
    df['local_idx'] = df.index % MAX_NODE_PER_TREE
    
    print(f"[LOAD TO MAPS] Total nodes in DataFrame: {len(df)}")
    print(f"[LOAD TO MAPS] Trees populated: {df['tree_idx'].max() + 1 if len(df) > 0 else 0}")

    # Nhóm df theo tree_idx
    grouped = df.groupby("tree_idx")

    for tree_id in range(MAX_TREE):
        df_tree = grouped.get_group(tree_id) if tree_id in grouped.groups else None
        
        for local_idx in range(MAX_NODE_PER_TREE):
            global_idx = tree_id * MAX_NODE_PER_TREE + local_idx
            key = global_idx.to_bytes(4, "little", signed=True)

            try:
                if df_tree is not None and local_idx in df_tree['local_idx'].values:
                    # Lấy node tương ứng với local_idx
                    row = df_tree[df_tree['local_idx'] == local_idx].iloc[0]
                    
                    split_val = float_to_fixed_u64(float(row["split_value"]), SCALE_BITS)
                    left_idx = int(row["left_child"])
                    right_idx = int(row["right_child"])

                    # Chuyển đổi left/right_idx từ local sang global
                    if left_idx != -1:
                        left_idx += tree_id * MAX_NODE_PER_TREE
                    if right_idx != -1:
                        right_idx += tree_id * MAX_NODE_PER_TREE

                    val = (
                        left_idx.to_bytes(4, "little", signed=True) +
                        right_idx.to_bytes(4, "little", signed=True) +
                        split_val.to_bytes(8, "little", signed=False) +
                        int(row["feature_idx"]).to_bytes(4, "little", signed=True) +
                        int(row["is_leaf"]).to_bytes(4, "little", signed=True) +
                        int(row["label"]).to_bytes(4, "little", signed=True) +
                        int(tree_id).to_bytes(4, "little", signed=True)  # Sử dụng tree_id thay vì row["tree_idx"]
                    )
                else:
                    # Node trống → fill zero
                    val = (
                        (0).to_bytes(4, "little", signed=True) +  # left_idx
                        (0).to_bytes(4, "little", signed=True) +  # right_idx
                        (0).to_bytes(8, "little", signed=False) + # split_value
                        (0).to_bytes(4, "little", signed=True) +  # feature_idx
                        (0).to_bytes(4, "little", signed=True) + # is_leaf
                        (0).to_bytes(4, "little", signed=True) +  # label
                        int(tree_id).to_bytes(4, "little", signed=True)
                    )

                ret = libbcc.lib.bpf_update_elem(bpf_map_fd, key, val, 0)
                if ret != 0:
                    print(f"[LOAD TO MAPS] Failed to insert node {global_idx} (tree={tree_id}, local={local_idx}, ret={ret})")

            except Exception as e:
                print(f"[LOAD TO MAPS] Node {global_idx} (tree={tree_id}, local={local_idx}) skipped: {e}")

    print("[LOAD TO MAPS] All trees inserted, missing nodes filled with zero.")

def run(cmd):
    """Chạy lệnh shell và in log rõ ràng"""
    print(f"\n[RUN] {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"Lỗi khi chạy: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    # --- Parse arguments ---
    parser = argparse.ArgumentParser(description="Load RandomForest model into XDP program")
    parser.add_argument("--max_tree", type=int, required=True, help="Number of trees in RandomForest")
    parser.add_argument("--max_leaves", type=int, required=True, help="Maximum leaves per tree")
    parser.add_argument("--iface", type=str, required=True, help="Network interface to attach XDP program")
    parser.add_argument("--model_folder", type=str, required=True, help="Path to folder containing RandomForest model")
    parser.add_argument("--home_folder", type=str, required=True, help="Path of home folder")
    args = parser.parse_args()
    IFACE = args.iface
    MAP_DIR = f"/sys/fs/bpf/{IFACE}"
    MAP_NAME = "xdp_randforest_nodes"
    MAP_PATH = f"{MAP_DIR}/{MAP_NAME}"
    MAX_TREE = args.max_tree
    MAX_LEAVES = args.max_leaves
    MAX_NODE_PER_TREE = 2 * MAX_LEAVES - 1
    MAX_DEPTH = int(log2(MAX_NODE_PER_TREE)) + 1
    HOME_FOLDER=args.home_folder
    MODEL_PATH = os.path.join(args.model_folder, f"rf_{MAX_TREE}_{MAX_LEAVES}_model.pkl")

    generate_common_header(f"{HOME_FOLDER}/dtuan/xdp-program/xdp_prog/common_kern_user.h", MAX_TREE, MAX_NODE_PER_TREE, MAX_DEPTH, 6, 16)
    
    print("\n=== Biên dịch chương trình XDP ===")
    run("sudo make")
    
    os.chdir(f"{HOME_FOLDER}/dtuan/xdp-program/xdp_prog")
    print("\n==== Load chương trình XDP mới ===")
    run(f"sudo ./xdp_loader --dev {IFACE} -S --progname xdp_anomaly_detector")
    
    load_df_to_map(dump_random_forest_to_csv(MODEL_PATH), MAP_PATH, MAX_TREE, MAX_LEAVES)