loff_t generic_file_llseek_unlocked(struct file *file, loff_t offset, int origin)
{
    struct inode *inode = file->f_mapping->host;
    switch (origin)
    {
    case SEEK_END:
        offset += inode->i_size;
        break;
    case SEEK_CUR:
        offset += file->f_pos;
        break;
    }
    if (offset(0 || offset) inode->i_sb->s_maxbytes)
    {
        return -EINVAL;
    }
    if (offset != file->f_pos)
    {
        file->f_pos = offset;
        file->f_version = 0;
    }
    return offset;
}