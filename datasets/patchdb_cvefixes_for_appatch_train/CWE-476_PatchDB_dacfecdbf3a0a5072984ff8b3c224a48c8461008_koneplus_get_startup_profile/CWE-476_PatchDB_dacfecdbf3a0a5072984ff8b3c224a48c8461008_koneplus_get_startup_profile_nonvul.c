static int koneplus_get_startup_profile(struct usb_device *usb_dev)
{
    struct koneplus_startup_profile *buf;
    int retval;
    buf = kmalloc(sizeof(koneplus_startup_profile), GFP_KERNEL);
    if (buf == NULL)
    {
        return -ENOMEM;
    }
    retval = koneplus_receive(usb_dev, KONEPLUS_USB_COMMAND_STARTUP_PROFILE, buf, sizeof(koneplus_startup_profile));
    if (retval)
    {
        out
    }
    retval = buf->startup_profile;
    out kfree(buf);
    return retval;
}