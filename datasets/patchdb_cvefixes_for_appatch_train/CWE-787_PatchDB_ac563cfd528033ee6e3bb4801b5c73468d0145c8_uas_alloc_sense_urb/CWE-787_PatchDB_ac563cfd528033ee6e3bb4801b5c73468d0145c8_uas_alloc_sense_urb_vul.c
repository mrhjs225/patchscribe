static struct urb *uas_alloc_sense_urb(struct uas_dev_info *devinfo, gfp_t gfp, struct scsi_cmnd *cmnd, u16 stream_id)
{
    struct usb_device *udev = devinfo->udev;
    struct urb *urb = usb_alloc_urb(0, gfp);
    struct sense_iu *iu;
    if (!urb)
    {
        out
    }
    iu = kmalloc(sizeof(*iu), gfp);
    if (!iu)
    {
        free
    }
    usb_fill_bulk_urb(urb, udev, devinfo->status_pipe, iu, sizeof(*iu), uas_stat_cmplt, cmnd->device);
    urb->stream_id = stream_id;
    urb->transfer_flags |= URB_FREE_BUFFER;
    out return urb;
    free usb_free_urb(urb);
    return NULL;
}