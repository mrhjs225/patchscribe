static int idetape_blkdev_ioctl(ide_drive_t *drive, unsigned int cmd, unsigned long arg)
{
    idetape_tape_t *tape = drive->driver_data;
    void __user *argp = (void __user *)arg;
    idetape_config
    {
        int dsc_rw_frequency;
        int dsc_media_access_frequency;
        int nr_stages;
    }
    , config debug_log(DBG_PROCS, "Enter %s\n", __func__);
    switch (cmd)
    {
    case 0x0340:
        if (copy_from_user(&config, argp, sizeof(config)))
        {
            return -EFAULT;
        }
        tape->best_dsc_rw_freq = config.dsc_rw_frequency;
        break;
    case 0x0350:
        config.dsc_rw_frequency = (int)tape->best_dsc_rw_freq;
        config.nr_stages = 1;
        if (copy_to_user(argp, &config, sizeof(config)))
        {
            return -EFAULT;
        }
        break;
    default:
        return -EIO;
    }
    return 0;
}