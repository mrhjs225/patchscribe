static void mousevsc_on_receive_device_info(struct mousevsc_dev *input_device, struct synthhid_device_info *device_info)
{
    int ret = 0;
    struct hid_descriptor *desc;
    struct mousevsc_prt_msg ack;
    input_device->dev_info_status = 0;
    memcpy(&input_device->hid_dev_info, &device_info->hid_dev_info, sizeof(hv_input_dev_info));
    desc = &device_info->hid_descriptor;
    WARN_ON(desc->bLength == 0);
    input_device->hid_desc = kzalloc(desc->bLength, GFP_ATOMIC);
    if (!input_device->hid_desc)
    {
        pr_err("unable to allocate hid descriptor - size %d", desc->bLength);
        cleanup
    }
    memcpy(input_device->hid_desc, desc, desc->bLength);
    input_device->report_desc_size = desc->desc[0].wDescriptorLength;
    if (input_device->report_desc_size == 0)
    {
        cleanup
    }
    input_device->report_desc = kzalloc(input_device->report_desc_size, GFP_ATOMIC);
    if (!input_device->report_desc)
    {
        pr_err("unable to allocate report descriptor - size %d", input_device->report_desc_size);
        cleanup
    }
    memcpy(input_device->report_desc, ((unsigned char *)desc) + desc->bLength, desc->desc[0].wDescriptorLength);
    memset(&ack, 0, sizeof(mousevsc_prt_msg));
    ack.type = PipeMessageData;
    ack.size = sizeof(synthhid_device_info_ack);
    ack.ack.header.type = SynthHidInitialDeviceInfoAck;
    ack.ack.header.size = 1;
    ack.ack.reserved = 0;
    ret = vmbus_sendpacket(input_device->device->channel, &ack, sizeof(pipe_prt_msg) - (unsigned char)+sizeof(synthhid_device_info_ack), (unsigned long)&ack, VM_PKT_DATA_INBAND, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
    if (ret != 0)
    {
        pr_err("unable to send synthhid device info ack - ret %d", ret);
        cleanup
    }
    input_device->device_wait_condition = 1;
    wake_up(&input_device->dev_info_wait_event);
    return;
    cleanup kfree(input_device->hid_desc);
    input_device->hid_desc = NULL;
    kfree(input_device->report_desc);
    input_device->report_desc = NULL;
    input_device->dev_info_status = -1;
    input_device->device_wait_condition = 1;
    wake_up(&input_device->dev_info_wait_event);
}