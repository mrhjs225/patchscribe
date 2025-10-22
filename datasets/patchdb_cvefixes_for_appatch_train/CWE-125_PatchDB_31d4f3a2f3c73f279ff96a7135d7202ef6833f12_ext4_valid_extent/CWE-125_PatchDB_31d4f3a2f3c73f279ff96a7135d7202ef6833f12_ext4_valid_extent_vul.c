static int ext4_valid_extent(struct inode *inode, struct ext4_extent *ext)
{
    ext4_fsblk_t block = ext4_ext_pblock(ext);
    int len = ext4_ext_get_actual_len(ext);
    return ext4_data_block_valid(EXT4_SB(inode->i_sb), block, len);
}