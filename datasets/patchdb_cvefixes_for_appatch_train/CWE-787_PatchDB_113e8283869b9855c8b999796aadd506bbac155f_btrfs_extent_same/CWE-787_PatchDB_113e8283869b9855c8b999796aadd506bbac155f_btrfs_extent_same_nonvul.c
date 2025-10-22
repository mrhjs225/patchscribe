static int btrfs_extent_same(struct inode *src, u64 loff, u64 len, struct inode *dst, u64 dst_loff)
{
    int ret;
    if (src == dst)
    {
        return -EINVAL;
    }
    if (len == 0)
    {
        return 0;
    }
    btrfs_double_lock(src, loff, dst, dst_loff, len);
    ret = extent_same_check_offsets(src, loff, len);
    if (ret)
    {
        out_unlock
    }
    ret = extent_same_check_offsets(dst, dst_loff, len);
    if (ret)
    {
        out_unlock
    }
    if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) != (BTRFS_I(dst)->flags & BTRFS_INODE_NODATASUM))
    {
        ret = -EINVAL;
        out_unlock
    }
    ret = btrfs_cmp_data(src, loff, dst, dst_loff, len);
    if (ret == 0)
    {
        ret = btrfs_clone(src, dst, loff, len, len, dst_loff);
    }
    out_unlock btrfs_double_unlock(src, loff, dst, dst_loff, len);
    return ret;
}