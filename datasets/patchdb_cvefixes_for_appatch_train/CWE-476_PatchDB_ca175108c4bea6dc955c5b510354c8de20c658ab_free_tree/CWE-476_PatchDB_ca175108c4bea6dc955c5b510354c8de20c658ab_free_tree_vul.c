static void free_tree(struct tree *t)
{
    size_t i;
    for (i = 0; i < t->nr_files; ++i)
    {
        free(t->files[i].path);
        guestfs_free_statns(t->files[i].stat);
        guestfs_free_xattr_list(t->files[i].xattrs);
        free(t->files[i].csum);
    }
    free(t->files);
    free(t);
}