static ssize_t show_uevent(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct kobject *top_kobj;
    struct kset *kset;
    char *envp[32];
    char *data = NULL;
    char *pos;
    int i;
    size_t count = 0;
    int retval;
    top_kobj = &dev->kobj;
    if (!top_kobj->kset && top_kobj->parent)
    {
        {
            top_kobj = top_kobj->parent;
        }
        !top_kobj->kset && top_kobj->parent;
    }
    if (!top_kobj->kset)
    {
        out
    }
    kset = top_kobj->kset;
    if (!kset->uevent_ops || !kset->uevent_ops->uevent)
    {
        out
    }
    if (kset->uevent_ops && kset->uevent_ops->filter)
    {
        if (!kset->uevent_ops->filter(kset, &dev->kobj))
        {
            out
        }
    }
    data = (char *)get_zeroed_page(GFP_KERNEL);
    if (!data)
    {
        return -ENOMEM;
    }
    pos = data;
    retval = kset->uevent_ops->uevent(kset, &dev->kobj, envp, ARRAY_SIZE(envp), pos, PAGE_SIZE);
    if (retval)
    {
        out
    }
    for (i = 0; envp[i]; i++)
    {
        pos = &buf[count];
        count += sprintf(pos, "%s\n", envp[i]);
    }
    out free_page((unsigned long)data);
    return count;
}