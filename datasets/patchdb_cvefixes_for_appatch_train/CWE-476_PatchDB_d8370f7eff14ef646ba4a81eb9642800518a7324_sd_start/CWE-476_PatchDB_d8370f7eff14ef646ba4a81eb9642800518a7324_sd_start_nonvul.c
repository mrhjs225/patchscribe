static int sd_start(struct gspca_dev *gspca_dev)
{
    struct sd *dev = (sd *)gspca_dev;
    int ret;
    dev->jpeg_hdr = kmalloc(JPEG_HDR_SZ, GFP_KERNEL);
    if (dev->jpeg_hdr == NULL)
    {
        return -ENOMEM;
    }
    jpeg_define(dev->jpeg_hdr, gspca_dev->height, gspca_dev->width, 0x21);
    jpeg_set_qual(dev->jpeg_hdr, dev->quality);
    PDEBUG(D_STREAM, "Start streaming at 320x240");
    ret = jlj_start(gspca_dev);
    if (ret < 0)
    {
        PDEBUG(D_ERR, "Start streaming command failed");
        return ret;
    }
    dev->work_thread = create_singlethread_workqueue(MODULE_NAME);
    queue_work(dev->work_thread, &dev->work_struct);
    return 0;
}