import argparse
import pickle
import joblib
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict, Set

fixed_functions = """

static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

static __always_inline __u64 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
} \n
"""

flow_struct = """
/* Latency statistics structure */
typedef struct {
    __u64 time_in;
    __u64 time_out;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u32 total_pkts;
    __u32 total_bytes;
} accounting;

struct flow_key {
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
} __attribute__((packed));

typedef struct {
    __u64   start_ts;             /* Timestamp of first packet */
    __u64   last_seen;            /* Timestamp of last packet */
    __u64   min_IAT;              /* Minimum Inter-Arrival Time */
    __u32   total_pkts;           /* Total packet count*/
    __u32   max_pkt_len;          /* Maximum packet length */
    __u32   min_pkt_len;          /* Minimum packet length */
    __u32   total_bytes;          /* Total byte count*/

    int   label;
} data_point; \n
"""

def offset_marcos(offsets, leaves_per_tree: List[int]=None) -> str:
    k = 0
    offsets_lines = "\n".join(
        f"#define QS_OFFSETS_{i} {val}" for i, val in enumerate(offsets)
    )

    lines = []
    acc = 0
    for i, val in enumerate(leaves_per_tree):
        lines.append(f"#define QS_LEAF_BASE_{i} {acc}")
        acc += val
    offsets_leaf = "\n".join(lines)
    
    lines = []
    for i, val in enumerate(leaves_per_tree):
        lines.append(f"#define QS_NUM_LEAVES_{i} {val}")
    offsets_leaf += "\n" + "\n".join(lines)
    macro_qs_feature = r"""#define QS_FEATURE(IDX, START, END) do {                              \
    fixed feat_value = fv.features[IDX];                             \
    for (int i = (START); i < (END); i++) {                          \
        if (feat_value < tree->threshold[i]) {                       \
            __u16 h = tree->tree_ids[i];                             \
            if (h >= QS_NUM_TREES) return 0;                         \
            tree->v[h] &= tree->bitvectors[i];                       \
        } else break;                                                \
    }                                                                \
} while (0)
"""
    marco_qs_block = r"""#define QS_VOTE_BLOCK(H) do {                 \
    BITVECTOR_TYPE exit_leaf_idx = (BITVECTOR_TYPE)(__u8)msb_index(tree->v[H]);         \
    if (exit_leaf_idx >= QS_NUM_LEAVES_##H) return 0;                 \
    BITVECTOR_TYPE l = QS_LEAF_BASE_##H + exit_leaf_idx;              \
    if (l >= QS_NUM_LEAVES) return 0;                                 \
    votes += tree->leaves[l];                                         \
} while (0)
"""
    function = f"""
{offsets_lines}

{offsets_leaf}

{marco_qs_block}

{macro_qs_feature}
"""
    return function

def load_model(path: str):
    p = Path(path)
    try:
        return joblib.load(p)
    except Exception:
        with p.open("rb") as f:
            return pickle.load(f)

def ceil_pow2(x: int) -> int:
    if x <= 1:
        return 1
    x -= 1
    x |= x >> 1
    x |= x >> 2
    x |= x >> 4
    x |= x >> 8
    x |= x >> 16
    x |= x >> 32
    x |= x >> 64
    return x + 1

def walk_leaves(tree) -> Tuple[List[int], Dict[int,int]]:
    children_left = tree.children_left
    children_right = tree.children_right

    leaves_order = []
    stack = [0]
    while stack:
        nid = stack.pop()
        left = children_left[nid]
        right = children_right[nid]
        if left == -1 and right == -1:
            leaves_order.append(nid)
        else:
            if right != -1:
                stack.append(right)
            if left != -1:
                stack.append(left)
    leaf_index_of_node = {nid: idx for idx, nid in enumerate(leaves_order)}
    return leaves_order, leaf_index_of_node

def leaves_to_masked(tree, nid: int) -> List[int]:
    children_left = tree.children_left
    children_right = tree.children_right

    left_branch = children_left[nid]

    res: List[int] = []
    stack = [left_branch]
    while stack:
        u = stack.pop()
        l = children_left[u]; r = children_right[u]
        if l == -1 and r == -1:
            res.append(u)
        else:
            if r != -1:
                stack.append(r)
            if l != -1:
                stack.append(l)
    return res

def bitvector_for_node(tree, nid: int, leaf_index_of_node: Dict[int,int], max_leaves_pow2: int) -> int:
    leaves_nodes = leaves_to_masked(tree, nid)
    bits = list("1" * len(leaf_index_of_node))
    for ln in leaves_nodes:
        li = leaf_index_of_node[ln]
        if li >= max_leaves_pow2:
            raise RuntimeError("leaf index exceeds max_leaves_pow2")
        bits[li] = "0"
    if len(bits) < max_leaves_pow2:
        bits += [0] * (max_leaves_pow2 - len(bits))
    return bits

def is_internal(tree, nid: int) -> bool:
    return tree.children_left[nid] != -1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="Path to scikit-learn RandomForestClassifier (joblib/pickle)")
    ap.add_argument("--fixed-shift", type=int, default=8, help="Number bits for fractional part of fixed-point representation")
    args = ap.parse_args()

    rf = load_model(args.model)

    if not hasattr(rf, "estimators_"):
        raise ValueError("Model has no estimators_. Expect a fitted RandomForestClassifier.")
    n_trees = len(rf.estimators_)
    n_features = getattr(rf, "n_features_in_", None)
    if n_features is None:
        raise ValueError("Cannot determine n_features_in_ from model.")
    classes_ = getattr(rf, "classes_", None)
    if classes_ is None:
        raise ValueError("Cannot determine classes_ from model.")

    tree_leaf_orders: List[List[int]] = []
    tree_leaf_index_maps: List[Dict[int,int]] = []
    per_tree_leaf_class_id: List[List[int]] = []

    max_leaves = 0
    num_leaves = []
    for est in rf.estimators_:
        tree = est.tree_
        leaves_order, leaf_index_of_node = walk_leaves(tree)
        tree_leaf_orders.append(leaves_order)
        tree_leaf_index_maps.append(leaf_index_of_node)
        num_leaves.append(len(leaves_order))
        max_leaves = max(max_leaves, len(leaves_order))

        v = tree.value
        class_ids = []
        for nid in leaves_order:
            counts = v[nid, 0, :]
            cid = int(np.argmax(counts))
            class_ids.append(cid)
        per_tree_leaf_class_id.append(class_ids)

    max_leaves_pow2 = ceil_pow2(max_leaves)

    thresholds_all: List[float] = []
    bitvectors_all: List[List[str]] = []
    tree_ids_all: List[int] = []
    offsets: List[int] = []

    current_offset = 0
    for f in range(n_features):
        offsets.append(current_offset)
        triples_for_f = []
        for t_id, est in enumerate(rf.estimators_):
            tr = est.tree_
            feat = tr.feature
            thr = tr.threshold
            for nid in range(tr.node_count):
                if not is_internal(tr, nid):
                    continue
                if feat[nid] == f:
                    bits = bitvector_for_node(tr, nid, tree_leaf_index_maps[t_id], max_leaves_pow2)
                    triple = (thr[nid], bits, t_id)
                    triples_for_f.append(triple)
                    current_offset += 1
        # Sort triples by threshold ascending
        triples_for_f.sort(key=lambda x: x[0])
        for thr, bits, t_id in triples_for_f:
            thresholds_all.append(thr)
            bitvectors_all.append(bits)
            tree_ids_all.append(t_id)

    offsets.append(current_offset)  # end offset
    num_nodes = len(thresholds_all)

    leaves_flat: List[int] = []
    for t_id in range(n_trees):
        vals = per_tree_leaf_class_id[t_id]
        pad = max_leaves_pow2 - len(vals)
        if pad < 0:
            raise RuntimeError("pad < 0, unexpected")
        leaves_flat.extend(vals)
        if pad:
            leaves_flat.extend([0] * pad)

    # Decide BITVECTOR_TYPE
    if max_leaves_pow2 <= 8:
        bit_type = "__u8"
        msb_builtin = "__builtin_clzll((__u64)x) - 56;"
    elif max_leaves_pow2 <= 16:
        bit_type = "__u16"
        msb_builtin = "__builtin_clzll((__u64)x) - 48;"
    elif max_leaves_pow2 <= 32:
        bit_type = "__u32"
        msb_builtin = "__builtin_clzll((__u64)x) - 32;"
    elif max_leaves_pow2 <= 64:
        bit_type = "__u64"
        msb_builtin = "__builtin_clzll(x);"
        

    out = Path("common_kern_user.h")
    guard = "__COMMON_KERN_USER_H"
    FIXED_SHIFT = args.fixed_shift

    with out.open("w", encoding="utf-8") as h:
        h.write(f"#ifndef {guard}\n#define {guard}\n\n")
        h.write("#include <stdint.h>\n#include <linux/types.h>\n\n")

        h.write("#define TRAINING_SET         10000""\n")
        h.write("#define MAX_FLOW_SAVED       2000""\n\n")

        # Macros about sizes
        h.write(f"#define QS_NUM_TREES {n_trees}\n")
        h.write(f"#define MAX_FEATURES {n_features} \n")
        h.write(f"#define QS_NUM_NODES {num_nodes}\n")
        h.write(f"#define QS_NUM_LEAVES {sum(num_leaves)}\n\n")

        # Marcros about feature indices
        h.write("#define QS_FEATURE_FLOW_DURATION 0\n")
        h.write("#define QS_FEATURE_TOTAL_FWD_PACKET 1\n")
        h.write("#define QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET 2\n")
        h.write("#define QS_FEATURE_FWD_PACKET_LENGTH_MAX 3\n")
        h.write("#define QS_FEATURE_FWD_PACKET_LENGTH_MIN 4\n")
        h.write("#define QS_FEATURE_FWD_IAT_MIN 5\n\n")

        # # Fixed-point typedef
        h.write(f"#define FIXED_SHIFT {FIXED_SHIFT}\n")
        h.write(f"#define FIXED_SCALE (1ULL << FIXED_SHIFT)\n")
        h.write(f"typedef __u64 fixed;\n\n")

        # BITVECTOR_TYPE typedef
        h.write(f"typedef {bit_type} BITVECTOR_TYPE;\n\n")
        h.write(f"static __always_inline BITVECTOR_TYPE msb_index(BITVECTOR_TYPE x) {{\n")
        h.write(f"     return {msb_builtin}\n")
        h.write("}\n\n")
        
        # h.write(f"static __always_inline BITVECTOR_TYPE msb_index(BITVECTOR_TYPE x) {{\n")
        # h.write(f"    if (!x)\n")
        # h.write(f"        return 63;\n\n")
        # h.write(f"    __u32 i = 0;\n")
        # h.write(f"    for (int bit = 0; bit < 64; bit++) {{\n")
        # h.write(f"        if (x & (1ULL << (63 - bit))) {{\n")
        # h.write(f"            i = bit;\n")
        # h.write(f"            break;\n")
        # h.write(f"        }}\n")
        # h.write(f"    }}\n")
        # h.write(f"    return i;\n")
        # h.write(f"}}\n")
        
        h.write(flow_struct)
        # Struct with fixed-size arrays
        h.write("/*\n")
        h.write(" Layout rules:\n")
        h.write(" - Internal nodes are grouped by feature id in ascending order.\n")
        h.write(" - For feature f, its nodes occupy range [QS_OFFSETS_f, QS_OFFSETS_f+1) in the thresholds array.\n")
        h.write(" - bitvectors mark (LSB=leaf0) the set of leaves in that tree reachable from the node.\n")
        h.write(" - leaves array is laid out as [tree0 | tree1 | ...], each block is num_leaves[h] entries with h the tree id.\n")
        h.write("   If a tree has fewer leaves, the remainder of its block is zero-padded.\n")
        h.write(" - Each leaves entry is a uint8 class id (argmax at the leaf).\n")
        h.write("*/\n")
        h.write("struct feat_vec {\n")
        h.write("    fixed features[MAX_FEATURES];\n")
        h.write("};\n\n")
        h.write("struct qsDataStruct{\n")
        h.write("    fixed threshold[QS_NUM_NODES];\n")
        h.write("    BITVECTOR_TYPE bitvectors[QS_NUM_NODES];\n")
        h.write("    BITVECTOR_TYPE v[QS_NUM_TREES];\n")
        h.write("    __u16 tree_ids[QS_NUM_NODES];\n")
        h.write("    __u8  num_leaves_per_tree[QS_NUM_TREES];\n")
        h.write("    __u8  leaves[QS_NUM_LEAVES];\n")
        h.write("};\n\n")

        # Data arrays
        def fl_to_fp(float_num: float, q_f_bits: int) -> np.uint64:
            scale_factor = 2 ** q_f_bits
            scaled_value = float_num * scale_factor

            max_val = np.iinfo(np.uint64).max
            min_val = 0

            fixed_point_val = np.clip(np.round(scaled_value), min_val, max_val).astype(np.uint64)
            return f"{fixed_point_val}"

        h.write(f"static const fixed _qs_threshold[QS_NUM_NODES] = {{\n  ")
        h.write(", ".join(fl_to_fp(v, FIXED_SHIFT) for v in thresholds_all))
        h.write("\n};\n\n")

        # bitvectors
        h.write(f"static const BITVECTOR_TYPE _qs_bitvectors[QS_NUM_NODES] = {{\n  ")
        # print in hex for readability
        bv_hex = []
        for bits in bitvectors_all:
            v = int("".join(str(b) for b in bits), 2)
            if bit_type == "__u8":
                bv_hex.append(f"0x{v:02x}")
            elif bit_type == "__u16":
                bv_hex.append(f"0x{v:04x}")
            elif bit_type == "__u32":
                bv_hex.append(f"0x{v:08x}")
            elif bit_type == "__u64":
                bv_hex.append(f"0x{v:016x}ULL")

        h.write(", ".join(bv_hex))
        h.write("\n};\n\n")

        h.write(f"static const __u16 _qs_tree_ids[QS_NUM_NODES] = {{\n  ")
        h.write(", ".join(str(int(v)) for v in tree_ids_all))
        h.write("\n};\n\n")

        # leaves
        h.write(f"static const __u8 _qs_num_leaves_per_tree[QS_NUM_TREES] = {{\n  ")
        h.write(", ".join(str(int(v)) for v in num_leaves))
        h.write("\n};\n\n")

        h.write(f"static const __u8 _qs_leaves[QS_NUM_LEAVES] = {{\n")
        for t in range(n_trees):
            start = t * max_leaves_pow2
            chunk = leaves_flat[start:start+max_leaves_pow2]
            h.write("  /* tree %d */ " % t)
            h.write(", ".join(str(int(v)) for v in chunk))
            h.write(",\n")
        h.write("};\n\n")

       # Predict function
        h.write(offset_marcos(offsets, leaves_per_tree=num_leaves))
        h.write("\n")

        # XDP action compatibility
        h.write("#ifndef XDP_ACTION_MAX\n")
        h.write("#define XDP_ACTION_MAX (XDP_REDIRECT + 1)\n")
        h.write("#endif")

        # Fixed-point functions
        h.write(fixed_functions)
        h.write(f"#endif /* {guard} */\n")

    print(f"Wrote header: {out}  (trees={n_trees}, features={n_features}, nodes={num_nodes}, MAX_LEAVES_PER_TREE={max_leaves_pow2})")

if __name__ == "__main__":
    main()

