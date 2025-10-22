static int push_leaf_right(struct btrfs_trans_handle *trans, struct btrfs_root *root, struct btrfs_path *path, int min_data_size, int data_size, int empty, u32 min_slot)
{
    struct extent_buffer *left = path->nodes[0];
    struct extent_buffer *right;
    struct extent_buffer *upper;
    int slot;
    int free_space;
    u32 left_nritems;
    int ret;
    if (!path->nodes[1])
    {
        return 1;
    }
    slot = path->slots[1];
    upper = path->nodes[1];
    if (slot >= btrfs_header_nritems(upper) - 1)
    {
        return 1;
    }
    btrfs_assert_tree_locked(path->nodes[1]);
    right = read_node_slot(root, upper, slot + 1);
    if (right == NULL)
    {
        return 1;
    }
    btrfs_tree_lock(right);
    btrfs_set_lock_blocking(right);
    free_space = btrfs_leaf_free_space(root, right);
    if (free_space < data_size)
    {
        out_unlock
    }
    ret = btrfs_cow_block(trans, root, right, upper, slot + 1, &right);
    if (ret)
    {
        out_unlock
    }
    free_space = btrfs_leaf_free_space(root, right);
    if (free_space < data_size)
    {
        out_unlock
    }
    left_nritems = btrfs_header_nritems(left);
    if (left_nritems == 0)
    {
        out_unlock
    }
    return __push_leaf_right(trans, root, path, min_data_size, empty, right, free_space, left_nritems, min_slot);
    out_unlock btrfs_tree_unlock(right);
    free_extent_buffer(right);
    return 1;
}