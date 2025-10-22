char *kobject_get_path(struct kobject *kobj, gfp_t gfp_mask)
{
    char *path;
    int len;
    len = get_kobj_path_length(kobj);
    path = kmalloc(len, gfp_mask);
    if (!path)
    {
        return NULL;
    }
    memset(path, 0x00, len);
    fill_kobj_path(kobj, path, len);
    return path;
}