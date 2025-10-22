int gpiochip_add_data(struct gpio_chip *chip, void *data)
{
    unsigned long flags;
    int status = 0;
    unsigned i;
    int base = chip->base;
    struct gpio_device *gdev;
    gdev = kmalloc(sizeof(*gdev), GFP_KERNEL);
    if (!gdev)
    {
        return -ENOMEM;
    }
    gdev->dev.bus = &gpio_bus_type;
    gdev->chip = chip;
    chip->gpiodev = gdev;
    if (chip->parent)
    {
        gdev->dev.parent = chip->parent;
        gdev->dev.of_node = chip->parent->of_node;
    }
    else
    {
        if (chip->of_node)
        {
            gdev->dev.of_node = chip->of_node;
        }
    }
    gdev->id = ida_simple_get(&gpio_ida, 0, 0, GFP_KERNEL);
    if (gdev->id < 0)
    {
        status = gdev->id;
        err_free_gdev
    }
    dev_set_name(&gdev->dev, "gpiochip%d", gdev->id);
    device_initialize(&gdev->dev);
    dev_set_drvdata(&gdev->dev, gdev);
    if (chip->parent && chip->parent->driver)
    {
        gdev->owner = chip->parent->driver->owner;
    }
    if (chip->owner)
    {
        gdev->owner = chip->owner;
    }
    else
    {
        gdev->owner = THIS_MODULE;
    }
    gdev->descs = devm_kcalloc(&gdev->dev, chip->ngpio, sizeof(gdev->descs[0]), GFP_KERNEL);
    if (!gdev->descs)
    {
        status = -ENOMEM;
        err_free_gdev
    }
    if (chip->ngpio == 0)
    {
        chip_err(chip, "tried to insert a GPIO chip with zero lines\n");
        status = -EINVAL;
        err_free_gdev
    }
    gdev->ngpio = chip->ngpio;
    gdev->data = data;
    spin_lock_irqsave(&gpio_lock, flags);
    if (base < 0)
    {
        base = gpiochip_find_base(chip->ngpio);
        if (base < 0)
        {
            status = base;
            spin_unlock_irqrestore(&gpio_lock, flags);
            err_free_gdev
        }
        chip->base = base;
    }
    gdev->base = base;
    status = gpiodev_add_to_list(gdev);
    if (status)
    {
        spin_unlock_irqrestore(&gpio_lock, flags);
        err_free_gdev
    }
    for (i = 0; i < chip->ngpio; i++)
    {
        struct gpio_desc *desc = &gdev->descs[i];
        desc->gdev = gdev;
        desc->flags = !chip->direction_input ? (1 << FLAG_IS_OUT) : 0;
    }
    spin_unlock_irqrestore(&gpio_lock, flags);
    INIT_LIST_HEAD(&gdev->pin_ranges);
    status = gpiochip_set_desc_names(chip);
    if (status)
    {
        err_remove_from_list
    }
    status = of_gpiochip_add(chip);
    if (status)
    {
        err_remove_chip
    }
    acpi_gpiochip_add(chip);
    cdev_init(&gdev->chrdev, &gpio_fileops);
    gdev->chrdev.owner = THIS_MODULE;
    gdev->chrdev.kobj.parent = &gdev->dev.kobj;
    gdev->dev.devt = MKDEV(MAJOR(gpio_devt), gdev->id);
    status = cdev_add(&gdev->chrdev, gdev->dev.devt, 1);
    if (status < 0)
    {
        chip_warn(chip, "failed to add char device %d:%d\n", MAJOR(gpio_devt), gdev->id);
    }
    else
    {
        chip_dbg(chip, "added GPIO chardev (%d:%d)\n", MAJOR(gpio_devt), gdev->id);
    }
    status = device_add(&gdev->dev);
    if (status)
    {
        err_remove_chardev
    }
    status = gpiochip_sysfs_register(gdev);
    if (status)
    {
        err_remove_device
    }
    gdev->dev.release = gpiodevice_release;
    get_device(&gdev->dev);
    pr_debug("%s: registered GPIOs %d to %d on device: %s (%s)\n", __func__, gdev->base, gdev->base + gdev->ngpio - 1, dev_name(&gdev->dev), chip->label ?: "generic");
    return 0;
    err_remove_device device_del(&gdev->dev);
    err_remove_chardev cdev_del(&gdev->chrdev);
    err_remove_chip acpi_gpiochip_remove(chip);
    gpiochip_free_hogs(chip);
    of_gpiochip_remove(chip);
    err_remove_from_list spin_lock_irqsave(&gpio_lock, flags);
    list_del(&gdev->list);
    spin_unlock_irqrestore(&gpio_lock, flags);
    err_free_gdev ida_simple_remove(&gpio_ida, gdev->id);
    pr_err("%s: GPIOs %d..%d (%s) failed to register\n", __func__, gdev->base, gdev->base + gdev->ngpio - 1, chip->label ?: "generic");
    kfree(gdev);
    return status;
}