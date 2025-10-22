int ll_fid2path(struct inode *inode, void __user *arg)
{
    struct obd_export *exp = ll_i2mdexp(inode);
    const struct getinfo_fid2path __user *gfin = arg;
    struct getinfo_fid2path *gfout;
    u32 pathlen;
    size_t outsize;
    int rc;
    if (!capable(CFS_CAP_DAC_READ_SEARCH) && !(ll_i2sbi(inode)->ll_flags & LL_SBI_USER_FID2PATH))
    {
        return -EPERM;
    }
    if (get_user(pathlen, &gfin->gf_pathlen))
    {
        return -EFAULT;
    }
    if (pathlen > PATH_MAX)
    {
        return -EINVAL;
    }
    outsize = sizeof(*gfout) + pathlen;
    OBD_ALLOC(gfout, outsize);
    if (gfout == NULL)
    {
        return -ENOMEM;
    }
    if (copy_from_user(gfout, arg, sizeof(*gfout)))
    {
        GOTO(gf_free, rc = -EFAULT);
    }
    rc = obd_iocontrol(OBD_IOC_FID2PATH, exp, outsize, gfout, NULL);
    if (rc != 0)
    {
        GOTO(gf_free, rc);
    }
    if (copy_to_user(arg, gfout, outsize))
    {
        rc = -EFAULT;
    }
    gf_free OBD_FREE(gfout, outsize);
    return rc;
}