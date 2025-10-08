# MÔ TẢ CODE XDP_STATS

## 1. Đọc CSV:
- Có 2 hàm đọc CSV nhưng hiện tại chỉ sử dụng hàm read_csv_dataset1()
- Input:
    + filename: Path của file CSV cần đọc.
    + *dataset: Kết quả đọc file CSV sẽ trả về đây.
    + max_rows: Muốn đọc bao nhiêu dòng trong file input.
- Hoạt động:
    + Đọc file csv có cấu trúc như sau: idx, src_ip, src_port, dst_ip, dst_port, proto, feature0..feature4, un_label, label_str.
    + Gán trực tiếp 5 feature vào dp.feature[0...4]
    + Convert `label_str` thành 0 (BENIGN), 1 (Else)

## 2. Hàm tính toán toán học c_factor(int n):
- Là công thức tính xấp xỉu của c(n) - expected path length trong BST với n nút:
- c(n) = 2*H(n-1) - 2*(n-1)/n
- c(n) dùng để chuẩn hóa độ sâu trung bình khi tính toán anomaly score.

## 3. Khởi tạo forest: init_forest():
- Gán các thông số của forest như: `n_trees, max_depth, sample_size = 0`
- Duyệt qua các cây trong rừng, duyệt qua các node trên cây, khởi tạo các giá trị.
- Chuẩn bị cấu trúc rỗng để train.

## 4. Xây dựng các cây: build_tree():
- Dùng để xây dựng các cây trong rừng. Đây là hàm đệ quy xây dựng iTree theo thuật toán Isolation Tree
- Input:
    + iTree *tree:
    + points
    + num_points
    + int depth
    + int node_idx

- Mô tả:
    + Khởi tạo node: set các trường mặc định, tree->nodes cập nhật.
    + Điều kiện dừng:
        + `num_points <= 1` ==> Leaf
        + `depth >= tree->max_depth` ==> Leaf
    + Chọn ngẫu nhiên feature
    + Tìm min/max giá trị của feature đó. Nếu như `min == max` --> Leaf (Không thể split)
    + Chọn split value: Chọn giá trị nguyên trong minv, maxv
    + Phân chia points:
        + Dùng 2 mảng left và right.
        + li và ri là chỉ số phần tử.
    + Cấp chỉ số cho left subtree, right subtree: left đặt tại `node_idx + 1`, right đặt tại `last_left + 1`
    + Xây các subtree bằng đệ quy.

## 5. Huấn luyện 1 tree / forest:
- train_isolation_tree: Reset `tree->num_nodes` và node defaults, rồi gọi build_tree().
- boostrap_sample (): Lấy sample có lặp
- train_isolation_forest():
    + Thiết lập `forest->n_trees, max_depth, sample_size`
    + Tạo tập data bằng bootstrap_sample()
    + Gọi train_isolation_tree
    + In số node của tree.
