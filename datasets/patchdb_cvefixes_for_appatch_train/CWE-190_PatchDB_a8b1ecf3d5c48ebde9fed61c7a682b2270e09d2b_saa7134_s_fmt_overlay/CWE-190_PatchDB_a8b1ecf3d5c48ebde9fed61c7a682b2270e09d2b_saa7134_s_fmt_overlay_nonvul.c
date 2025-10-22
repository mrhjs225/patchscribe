static int saa7134_s_fmt_overlay(struct file *file, void *priv, struct v4l2_format *f)
{
    struct saa7134_fh *fh = priv;
    struct saa7134_dev *dev = fh->dev;
    int err;
    unsigned long flags;
    if (saa7134_no_overlay > 0)
    {
        printk(KERN_ERR "V4L2_BUF_TYPE_VIDEO_OVERLAY: no_overlay\n");
        return -EINVAL;
    }
    err = verify_preview(dev, &f->fmt.win);
    if (0 != err)
    {
        return err;
    }
    mutex_lock(&dev->lock);
    fh->win = f->fmt.win;
    fh->nclips = f->fmt.win.clipcount;
    if (fh->nclips > 8)
    {
        fh->nclips = 8;
    }
    if (copy_from_user(fh->clips, f->fmt.win.clips, sizeof(v4l2_clip) * fh->nclips))
    {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }
    if (res_check(fh, RESOURCE_OVERLAY))
    {
        spin_lock_irqsave(&dev->slock, flags);
        stop_preview(dev, fh);
        start_preview(dev, fh);
        spin_unlock_irqrestore(&dev->slock, flags);
    }
    mutex_unlock(&dev->lock);
    return 0;
}