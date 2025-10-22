R_API char *r_cons_hud_path(const char *path, int dir)
{
    char *tmp = NULL, *ret = NULL;
    RList *files;
    while (*path == ' ')
    {
        path++;
    }
    if (!path || !*path)
    {
        tmp = strdup("./");
    }
    else
    {
        tmp = strdup(path);
    }
    files = r_sys_dir(tmp);
    if (files)
    {
        ret = r_cons_hud(files, tmp);
        if (ret)
        {
            tmp = r_str_concat(tmp, "/");
            tmp = r_str_concat(tmp, ret);
            ret = r_file_abspath(tmp);
            free(tmp);
            tmp = ret;
            if (r_file_is_directory(tmp))
            {
                ret = r_cons_hud_path(tmp, dir);
                free(tmp);
                tmp = ret;
            }
        }
    }
    else
    {
        eprintf("No files found\n");
    }
    if (!ret)
    {
        free(tmp);
        return NULL;
    }
    return tmp;
}