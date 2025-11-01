import joblib
import pandas as pd
import os, sys
import argparse
import subprocess
from bcc import libbcc, BPF
from math import log2
import ctypes

def generate_common_header(output_path : str):
    header_content = f"""/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <stdint.h>
#include <math.h>

#define MAX_FLOW_SAVED                       10000
#define MAX_FEATURES                         6
#define FEATURE_FLOW_DURATION                0
#define FEATURE_TOTAL_FWD_PACKET             1
#define FEATURE_TOTAL_LENGTH_OF_FWD_PACKET   2
#define FEATURE_FWD_PACKET_LENGTH_MAX        3
#define FEATURE_FWD_PACKET_LENGTH_MIN        4
#define FEATURE_FWD_IAT_MIN                  5

/* Define for fixed point Q48.16 */
#define FIXED_SHIFT                          16
#define FIXED_SCALE                          (1 << FIXED_SHIFT)
typedef __u64                                fixed;

/* Flow identification key */
struct flow_key {{
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
}} __attribute__((packed));

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

typedef struct svm_weight {{
    /*Cong 1 de tham bias*/
    fixed   value[MAX_FEATURES + 1]; 
    int     is_neg[MAX_FEATURES + 1];       
    fixed   scale[MAX_FEATURES];
}} svm_weight;

static __always_inline fixed fixed_from_float(double value)
{{
    return (__u64)(value * (double)FIXED_SCALE);
}}

static __always_inline double fixed_to_float(fixed value)
{{
    return (double)value / (double)FIXED_SCALE;
}}

static __always_inline fixed fixed_from_uint(__u64 value)
{{
    return value << FIXED_SHIFT;
}}

static __always_inline __u64 fixed_to_int(fixed value)
{{
    return value >> FIXED_SHIFT;
}}

static __always_inline fixed fixed_add(fixed a, fixed b)
{{
    return a + b;
}}

static __always_inline fixed fixed_sub(fixed a, fixed b)
{{
    return a - b;
}}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{{
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
    
    __u64 shifted_a = a << FIXED_SHIFT;
    return shifted_a / b;
}}
"""
    with open(output_path, "w") as f:
        f.write(header_content.strip() + "\n")

def dump_linear_svm_to_df(model_path="Linear.pkl", label_map=None):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Không tìm thấy model tại {model_path}")
    
    model = joblib.load(model_path)
    
    # Kiểm tra xem có phải Linear SVM không
    if not hasattr(model, "coef_") or not hasattr(model, "intercept_"):
        raise ValueError("[LOAD WEIGHT] Mô hình không phải Linear SVM / SGDClassifier hợp lệ (không có coef_ hoặc intercept_)")
    
    weights = model.coef_
    bias = model.intercept_
    
    print("[LOAD WEIGHT] Weights shape:", weights.shape)
    print("[LOAD WEIGHT] Bias:", bias)
    
    if weights.ndim == 1:
        weights = weights.reshape(1, -1)
        
    df = pd.DataFrame(weights, columns=[f"w{i}" for i in range(weights.shape[1])])
    df["bias"] = bias

    if label_map:
        df.insert(0, "label", [label_map.get(i, i) for i in range(len(df))])
    else:
        df.insert(0, "label", range(len(df)))
        
    return df

def dump_min_max_scaler(scaler_path: str):
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Không tìm thấy bộ scaler tại {scaler_path}")

    scaler = joblib.load(scaler_path)
    min_vals = scaler.data_min_
    max_vals = scaler.data_max_
    scale = scaler.scale_
    min_ = scaler.min_

    df_scaler = pd.DataFrame({
        "feature_index": range(len(min_vals)),
        "data_min": min_vals,
        "data_max": max_vals,
        "scale": scale,
        "min_": min_
    })
    print("[LOAD MIN MAX SCALE] Thông tin MinMaxScaler:")
    print(df_scaler.head())
    return df_scaler

def to_fixed_u64(value: float, fixed_shift=16) -> int:
    """Convert float to fixed-point (u64)"""
    return int(round(value * (1 << fixed_shift)))

def generate_svm_weights(df_weights : pd.DataFrame, df_scaler : pd.DataFrame, output_path, fixed_shift : int = 16):
    
    weight_values = []
    is_neg_values = []

    weight_cols = [c for c in df_weights.columns if c.startswith("w")]
    bias = df_weights["bias"].iloc[0] if "bias" in df_weights.columns else 0.0
    
    for c in weight_cols:
        val = float(df_weights[c].iloc[0])
        fixed_val = to_fixed_u64(val, fixed_shift)
        weight_values.append(f"{fixed_val}ULL")
        is_neg_values.append("1" if val < 0 else "0")

    # Thêm bias cuối cùng
    fixed_bias = to_fixed_u64(bias, fixed_shift)
    weight_values.append(f"{fixed_bias}ULL")
    is_neg_values.append("1" if bias < 0 else "0")
    # --- Xử lý scaler ---
    scale_values = [
        f"{to_fixed_u64(float(s), fixed_shift)}ULL"
        for s in df_scaler["scale"].tolist()
    ]

    # --- Sinh code ---
    c_code = f"""
const svm_weight svm_weights = {{
    .value = {{
        {", ".join(weight_values)}
    }},
    .is_neg = {{
        {", ".join(is_neg_values)}
    }},
    .scale = {{
        {", ".join(scale_values)}
    }},
}};
"""

    end_header = f"""
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
"""

    with open(output_path, "a") as f:
        f.write(c_code.strip() + "\n")
        f.write(end_header.strip() + "\n")

if __name__ == "__main__":
    df_weights = dump_linear_svm_to_df("/home/dongtv/security_paper/svm/models/SVM-Linear.pkl")
    print(df_weights.head())
    # df_weights.to_csv("svm_weights.csv", index=False)
    print("Đã xuất trọng số ra svm_weights.csv")
    
    df_scaler = dump_min_max_scaler("/home/dongtv/security_paper/svm/scalers/scaler_SVM-Linear.pkl")
    # df_scaler.to_csv("svm_scaler.csv")
    print("Đã xuất scaler ra svm_scaler.csv")
    
    generate_common_header("common_kern_user.h")
    generate_svm_weights(df_weights=df_weights, df_scaler=df_scaler, output_path="common_kern_user.h")