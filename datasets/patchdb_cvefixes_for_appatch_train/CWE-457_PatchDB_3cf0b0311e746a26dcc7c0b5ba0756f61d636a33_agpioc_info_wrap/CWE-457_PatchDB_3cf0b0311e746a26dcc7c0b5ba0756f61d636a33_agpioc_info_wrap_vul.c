static int agpioc_info_wrap(struct agp_file_private *priv, void __user *arg)
{
    struct agp_info userinfo;
    struct agp_kern_info kerninfo;
    agp_copy_info(agp_bridge, &kerninfo);
    userinfo.version.major = kerninfo.version.major;
    userinfo.version.minor = kerninfo.version.minor;
    userinfo.bridge_id = kerninfo.device->vendor | (kerninfo.device->device << 16);
    userinfo.agp_mode = kerninfo.mode;
    userinfo.aper_base = kerninfo.aper_base;
    userinfo.aper_size = kerninfo.aper_size;
    userinfo.pg_total = userinfo.pg_system = kerninfo.max_memory;
    userinfo.pg_used = kerninfo.current_memory;
    if (copy_to_user(arg, &userinfo, sizeof(agp_info)))
    {
        return -EFAULT;
    }
    return 0;
}