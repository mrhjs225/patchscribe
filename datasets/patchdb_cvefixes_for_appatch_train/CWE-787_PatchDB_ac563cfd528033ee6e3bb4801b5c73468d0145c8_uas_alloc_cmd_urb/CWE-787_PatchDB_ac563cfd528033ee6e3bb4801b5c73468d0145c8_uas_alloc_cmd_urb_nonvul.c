static struct urb *uas_alloc_cmd_urb(struct uas_dev_info *devinfo, gfp_t gfp, struct scsi_cmnd *cmnd, u16 stream_id)
{
    struct usb_device *udev = devinfo->udev;
    struct scsi_device *sdev = cmnd->device;
    struct urb *urb = usb_alloc_urb(0, gfp);
    struct command_iu *iu;
    int len;
    if (!urb)
    {
        out
    }
    len = cmnd->cmd_len - 16;
    if (len < 0)
    {
        len = 0;
    }
    len = ALIGN(len, 4);
    iu = kzalloc(sizeof(*iu) + len, gfp);
    if (!iu)
    {
        free
    }
    iu->iu_id = IU_ID_COMMAND;
    iu->tag = cpu_to_be16(stream_id);
    if (sdev->ordered_tags && (cmnd->request->cmd_flags & REQ_HARDBARRIER))
    {
        iu->prio_attr = UAS_ORDERED_TAG;
    }
    else
    {
        iu->prio_attr = UAS_SIMPLE_TAG;
    }
    iu->len = len;
    int_to_scsilun(sdev->lun, &iu->lun);
    memcpy(iu->cdb, cmnd->cmnd, cmnd->cmd_len);
    usb_fill_bulk_urb(urb, udev, devinfo->cmd_pipe, iu, sizeof(*iu) + len, usb_free_urb, NULL);
    urb->transfer_flags |= URB_FREE_BUFFER;
    out return urb;
    free usb_free_urb(urb);
    return NULL;
}