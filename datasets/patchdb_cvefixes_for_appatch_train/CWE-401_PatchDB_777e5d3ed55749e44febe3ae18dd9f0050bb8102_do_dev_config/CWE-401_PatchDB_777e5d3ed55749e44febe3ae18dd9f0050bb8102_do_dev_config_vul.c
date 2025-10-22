static int do_dev_config(struct comedi_device *dev, struct comedi_devconfig *it)
{
    struct comedi_bond_private *devpriv = dev->private;
    DECLARE_BITMAP(devs_opened, COMEDI_NUM_BOARD_MINORS);
    int i;
    memset(&devs_opened, 0, sizeof(devs_opened));
    devpriv->name[0] = 0;
    for (i = 0; i < COMEDI_NDEVCONFOPTS && (!i || it->options[i]); ++i)
    {
        char file[sizeof("/dev/comediXXXXXX")];
        int minor = it->options[i];
        struct comedi_device *d;
        int sdev = -1, nchans;
        struct bonded_device *bdev;
        struct bonded_device **devs;
        if (minor < 0 || minor >= COMEDI_NUM_BOARD_MINORS)
        {
            dev_err(dev->class_dev, "Minor %d is invalid!\n", minor);
            return -EINVAL;
        }
        if (minor == dev->minor)
        {
            dev_err(dev->class_dev, "Cannot bond this driver to itself!\n");
            return -EINVAL;
        }
        if (test_and_set_bit(minor, devs_opened))
        {
            dev_err(dev->class_dev, "Minor %d specified more than once!\n", minor);
            return -EINVAL;
        }
        snprintf(file, sizeof(file), "/dev/comedi%u", minor);
        file[sizeof(file) - 1] = 0;
        d = comedi_open(file);
        if (!d)
        {
            dev_err(dev->class_dev, "Minor %u could not be opened\n", minor);
            return -ENODEV;
        }
        while ((sdev = comedi_find_subdevice_by_type(d, COMEDI_SUBD_DIO, sdev + 1)) > -1)
        {
            nchans = comedi_get_n_channels(d, sdev);
            if (nchans <= 0)
            {
                dev_err(dev->class_dev, "comedi_get_n_channels() returned %d on minor %u subdev %d!\n", nchans, minor, sdev);
                return -EINVAL;
            }
            bdev = kmalloc(sizeof(*bdev), GFP_KERNEL);
            if (!bdev)
            {
                return -ENOMEM;
            }
            bdev->dev = d;
            bdev->minor = minor;
            bdev->subdev = sdev;
            bdev->nchans = nchans;
            devpriv->nchans += nchans;
            devs = krealloc(devpriv->devs, (devpriv->ndevs + 1) * sizeof(*devs), GFP_KERNEL);
            if (!devs)
            {
                dev_err(dev->class_dev, "Could not allocate memory. Out of memory?\n");
                return -ENOMEM;
            }
            devpriv->devs = devs;
            devpriv->devs[devpriv->ndevs++] = bdev;
            {
                char buf[20];
                int left = MAX_BOARD_NAME - strlen(devpriv->name) - 1;
                snprintf(buf, sizeof(buf), "%d:%d ", bdev->minor, bdev->subdev);
                buf[sizeof(buf) - 1] = 0;
                strncat(devpriv->name, buf, left);
            }
        }
    }
    if (!devpriv->nchans)
    {
        dev_err(dev->class_dev, "No channels found!\n");
        return -EINVAL;
    }
    return 0;
}