## 2. void train_decision_tree(DecisionTree *tree, data_point *dataset, int num_points, int max_depth, int min_samples_split);
- Description: Initializes and trains a single Decision Tree on a dataset.
- Inputs:
+ tree: tree to train.
+ dataset: array of data_point.
+ num_points: number of samples.
+ max_depth: maximum depth allowed.
+ min_samples_split: minimum samples needed to continue splitting.
- Operations:
+ Sets tree metadata (max_depth, min_samples_split, node_count).
+ Calls build_tree() starting at depth 0.
## 3. void bootstrap_sample(data_point *dataset, int num_points, data_point *sample, int sample_size);
- Description: Generates a bootstrap sample for training a tree.
- Inputs:
+ dataset: original dataset.
+ num_points: number of samples in original dataset.
+ sample: array to fill with sampled points.
+ sample_size: number of samples to draw (usually ≤ num_points).
- Operations:
+ Randomly select sample_size points with replacement from dataset.
## 4. void train_random_forest(RandomForest *rf, data_point *dataset, int num_points, struct forest_params *params);
- Description: Trains a full Random Forest (multiple Decision Trees).
- Inputs:
+ rf: the Random Forest struct to fill.
+ dataset: full training dataset.
+ num_points: number of samples in dataset.
+ params: contains n_trees, sample_size, min_samples_split.
- Operations:
+ For each tree:\
    Generate a bootstrap sample.\
    Train a DecisionTree on that sample.\
    Store trained trees in rf->trees[].
## 5. int save_forest_to_map(int map_fd, RandomForest *rf);
- Description:

Writes the trained Random Forest into a BPF map so XDP can access it.

Inputs:

map_fd: file descriptor of the BPF map (obtained via bpf_obj_get() or bpf_create_map()).

rf: pointer to trained RandomForest.

Operations:

Uses bpf_map_update_elem() to write rf into the map.

Return: 0 if success, <0 if failed.

6. int predict_tree(const DecisionTree *tree, const data_point *dp);

Description:

Makes a prediction using a single Decision Tree.

Inputs:

tree: trained Decision Tree.

dp: single data_point to classify.

Operations:

Traverse the tree from root:

At each node, check the feature and threshold.

Move to left/right child until a leaf is reached.

Return: Predicted label (e.g., 0 or 1).

7. int predict_forest(const RandomForest *rf, const data_point *dp);

Description:

Makes a prediction using the entire Random Forest.

Inputs:

rf: trained Random Forest.

dp: single data_point to classify.

Operations:

For each tree in rf->trees[]:

Call predict_tree() to get a label.

Use majority vote across all trees to decide the final label.

Return: Predicted label (0 or 1).