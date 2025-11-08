#!/bin/bash

# Device
DEV="eno3"

# Dải số lượng cây
TREE_LIST=(10 20 30 40 50 60 70 80 90 100)

# Dải số lượng lá
LEAF_LIST=(8 16 32 64)

# Đường dẫn model RF
MODEL_DIR=~/security_paper/rf

# Log output
LOG_DIR=./logs
mkdir -p "$LOG_DIR"

echo "[INFO] Starting QuickScorer test loop on device $DEV"
echo "==============================================="

for MAX_TREE in "${TREE_LIST[@]}"; do
  for MAX_LEAVES in "${LEAF_LIST[@]}"; do
    echo
    echo ">>> Testing configuration: ${MAX_TREE} trees, ${MAX_LEAVES} leaves"
    echo "---------------------------------------------------------------"

    # Gỡ chương trình XDP cũ
    sudo xdp-loader unload "$DEV" --all 2>/dev/null

    # Xóa map cũ
    sudo rm -rf /sys/fs/bpf/$DEV

    # Sinh model tương ứng
    MODEL_PATH="${MODEL_DIR}/rf_${MAX_TREE}_${MAX_LEAVES}_model.pkl"
    if [ ! -f "$MODEL_PATH" ]; then
      echo "[WARN] Model file not found: $MODEL_PATH"
      continue
    fi

    echo "[INFO] Generating QS tables from $MODEL_PATH"
    python3 rf2qs.py --model "$MODEL_PATH"
    if [ $? -ne 0 ]; then
      echo "[ERROR] rf2qs.py failed for ${MAX_TREE}-${MAX_LEAVES}"
      continue
    fi
    sudo make 
    # Load XDP
    echo "[INFO] Loading XDP program..."
    sudo ./xdp_loader -S --dev "$DEV" --progname xdp_anomaly_detector
    if [ $? -ne 0 ]; then
      echo "[ERROR] Failed to load XDP program for ${MAX_TREE}-${MAX_LEAVES}"
      continue
    fi

    echo "[OK] Loaded successfully (${MAX_TREE} trees, ${MAX_LEAVES} leaves)"
    echo "-----------------------------------------------"

    # Ghi log hoặc chờ 3s giữa mỗi lần
    sleep 3
  done
done

echo
echo "[DONE] All test combinations completed."
