static int push_leaf_left(struct btrfs_trans_handle *trans, struct btrfs_root *root, struct btrfs_path *path, int min_data_size, int data_size, int empty, u32 max_slot)
{
    struct extent_buffer *right = path->nodes[0];
    struct extent_buffer *left;
    int slot;
    int free_space;
    u32 right_nritems;
    int ret = 0;
    slot = path->slots[1];
    if (slot == 0)
    {
        return 1;
    }
    if (!path->nodes[1])
    {
        return 1;
    }
    right_nritems = btrfs_header_nritems(right);
    if (right_nritems == 0)
    {
        return 1;
    }
    btrfs_assert_tree_locked(path->nodes[1]);
    left = read_node_slot(root, path->nodes[1], slot - 1);
    btrfs_tree_lock(left);
    btrfs_set_lock_blocking(left);
    free_space = btrfs_leaf_free_space(root, left);
    if (free_space < data_size)
    {
        ret = 1;
        out
    }
    ret = btrfs_cow_block(trans, root, left, path->nodes[1], slot - 1, &left);
    if (ret)
    {
        ret = 1;
        out
    }
    free_space = btrfs_leaf_free_space(root, left);
    if (free_space < data_size)
    {
        ret = 1;
        out
    }
    return __push_leaf_left(trans, root, path, min_data_size, empty, left, free_space, right_nritems, max_slot);
    out btrfs_tree_unlock(left);
    free_extent_buffer(left);
    return ret;
}