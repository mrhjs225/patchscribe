static long nvm_ioctl_get_devices(struct file *file, void __user *arg)
{
    struct nvm_ioctl_get_devices *devices;
    struct nvm_dev *dev;
    int i = 0;
    if (!capable(CAP_SYS_ADMIN))
    {
        return -EPERM;
    }
    devices = kzalloc(sizeof(nvm_ioctl_get_devices), GFP_KERNEL);
    if (!devices)
    {
        return -ENOMEM;
    }
    down_write(&nvm_lock);
    list_for_each_entry(, , )
    {
        struct nvm_ioctl_device_info *info = &devices->info[i];
        sprintf(info->devname, "%s", dev->name);
        if (dev->mt)
        {
            info->bmversion[0] = dev->mt->version[0];
            info->bmversion[1] = dev->mt->version[1];
            info->bmversion[2] = dev->mt->version[2];
            sprintf(info->bmname, "%s", dev->mt->name);
        }
        else
        {
            sprintf(info->bmname, "none");
        }
        i++;
        if (i > 31)
        {
            pr_err("nvm: max 31 devices can be reported.\n");
            break;
        }
    }
    up_write(&nvm_lock);
    devices->nr_devices = i;
    if (copy_to_user(arg, devices, sizeof(nvm_ioctl_get_devices)))
    {
        return -EFAULT;
    }
    kfree(devices);
    return 0;
}