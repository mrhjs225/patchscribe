static int proc_thermal_add(struct device *dev, struct proc_thermal_device **priv)
{
    struct proc_thermal_device *proc_priv;
    struct acpi_device *adev;
    acpi_status status;
    struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER NULL};
    union acpi_object *elements, *ppcc;
    union acpi_object *p;
    int i;
    int ret;
    adev = ACPI_COMPANION(dev);
    if (!adev)
    {
        return -ENODEV;
    }
    status = acpi_evaluate_object(adev->handle, "PPCC", NULL, &buf);
    if (ACPI_FAILURE(status))
    {
        return -ENODEV;
    }
    p = buf.pointer;
    if (!p || (p->type != ACPI_TYPE_PACKAGE))
    {
        dev_err(dev, "Invalid PPCC data\n");
        ret = -EFAULT;
        free_buffer
    }
    if (!p->package.count)
    {
        dev_err(dev, "Invalid PPCC package size\n");
        ret = -EFAULT;
        free_buffer
    }
    proc_priv = devm_kzalloc(dev, sizeof(*proc_priv), GFP_KERNEL);
    if (!proc_priv)
    {
        ret = -ENOMEM;
        free_buffer
    }
    proc_priv->dev = dev;
    proc_priv->adev = adev;
    for (i = 0; i < min((int)p->package.count - 1, 2); ++i)
    {
        elements = &(p->package.elements[i + 1]);
        if (elements->type != ACPI_TYPE_PACKAGE || elements->package.count != 6)
        {
            ret = -EFAULT;
            free_buffer
        }
        ppcc = elements->package.elements;
        proc_priv->power_limits[i].index = ppcc[0].integer.value;
        proc_priv->power_limits[i].min_uw = ppcc[1].integer.value;
        proc_priv->power_limits[i].max_uw = ppcc[2].integer.value;
        proc_priv->power_limits[i].tmin_us = ppcc[3].integer.value;
        proc_priv->power_limits[i].tmax_us = ppcc[4].integer.value;
        proc_priv->power_limits[i].step_uw = ppcc[5].integer.value;
    }
    *priv = proc_priv;
    ret = sysfs_create_group(&dev->kobj, &power_limit_attribute_group);
    free_buffer kfree(buf.pointer);
    return ret;
}