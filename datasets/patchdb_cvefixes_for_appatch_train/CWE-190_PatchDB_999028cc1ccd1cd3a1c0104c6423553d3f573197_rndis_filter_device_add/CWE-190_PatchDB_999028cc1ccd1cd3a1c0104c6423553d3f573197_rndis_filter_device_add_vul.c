int rndis_filter_device_add(struct hv_device *dev, void *additional_info)
{
    int ret;
    struct netvsc_device *net_device;
    struct rndis_device *rndis_device;
    struct netvsc_device_info *device_info = additional_info;
    struct ndis_offload_params offloads;
    struct nvsp_message *init_packet;
    int t;
    struct ndis_recv_scale_cap rsscap;
    u32 rsscap_size = sizeof(ndis_recv_scale_cap);
    u32 mtu, size;
    rndis_device = get_rndis_device();
    if (!rndis_device)
    {
        return -ENODEV;
    }
    ret = netvsc_device_add(dev, additional_info);
    if (ret != 0)
    {
        kfree(rndis_device);
        return ret;
    }
    net_device = hv_get_drvdata(dev);
    net_device->num_chn = 1;
    net_device->extension = rndis_device;
    rndis_device->net_dev = net_device;
    ret = rndis_filter_init_device(rndis_device);
    if (ret != 0)
    {
        rndis_filter_device_remove(dev);
        return ret;
    }
    size = sizeof(u32);
    ret = rndis_filter_query_device(rndis_device, RNDIS_OID_GEN_MAXIMUM_FRAME_SIZE, &mtu, &size);
    if (ret == 0 && size == sizeof(u32))
    {
        net_device->ndev->mtu = mtu;
    }
    ret = rndis_filter_query_device_mac(rndis_device);
    if (ret != 0)
    {
        rndis_filter_device_remove(dev);
        return ret;
    }
    memcpy(device_info->mac_adr, rndis_device->hw_mac_adr, ETH_ALEN);
    memset(&offloads, 0, sizeof(ndis_offload_params));
    offloads.ip_v4_csum = NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED;
    offloads.tcp_ip_v4_csum = NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED;
    offloads.udp_ip_v4_csum = NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED;
    offloads.tcp_ip_v6_csum = NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED;
    offloads.udp_ip_v6_csum = NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED;
    offloads.lso_v2_ipv4 = NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED;
    ret = rndis_filter_set_offload_params(dev, &offloads);
    if (ret)
    {
        err_dev_remv
    }
    rndis_filter_query_device_link_status(rndis_device);
    device_info->link_state = rndis_device->link_state;
    dev_info(&dev->device, "Device MAC %pM link state %s\n", rndis_device->hw_mac_adr, device_info->link_state ? "down" : "up");
    if (net_device->nvsp_version < NVSP_PROTOCOL_VERSION_5)
    {
        return 0;
    }
    memset(&rsscap, 0, rsscap_size);
    ret = rndis_filter_query_device(rndis_device, OID_GEN_RECEIVE_SCALE_CAPABILITIES, &rsscap, &rsscap_size);
    if (ret || rsscap.num_recv_que < 2)
    {
        out
    }
    net_device->num_chn = (num_online_cpus() < rsscap.num_recv_que) ? num_online_cpus() : rsscap.num_recv_que;
    if (net_device->num_chn == 1)
    {
        out
    }
    net_device->sub_cb_buf = vzalloc((net_device->num_chn - 1) * NETVSC_PACKET_SIZE);
    if (!net_device->sub_cb_buf)
    {
        net_device->num_chn = 1;
        dev_info(&dev->device, "No memory for subchannels.\n");
        out
    }
    vmbus_set_sc_create_callback(dev->channel, netvsc_sc_open);
    init_packet = &net_device->channel_init_pkt;
    memset(init_packet, 0, sizeof(nvsp_message));
    init_packet->hdr.msg_type = NVSP_MSG5_TYPE_SUBCHANNEL;
    init_packet->msg.v5_msg.subchn_req.op = NVSP_SUBCHANNEL_ALLOCATE;
    init_packet->msg.v5_msg.subchn_req.num_subchannels = net_device->num_chn - 1;
    ret = vmbus_sendpacket(dev->channel, init_packet, sizeof(nvsp_message), (unsigned long)init_packet, VM_PKT_DATA_INBAND, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
    if (ret)
    {
        out
    }
    t = wait_for_completion_timeout(&net_device->channel_init_wait, 5 * HZ);
    if (t == 0)
    {
        ret = -ETIMEDOUT;
        out
    }
    if (init_packet->msg.v5_msg.subchn_comp.status != NVSP_STAT_SUCCESS)
    {
        ret = -ENODEV;
        out
    }
    net_device->num_chn = 1 + init_packet->msg.v5_msg.subchn_comp.num_subchannels;
    vmbus_are_subchannels_present(dev->channel);
    ret = rndis_filter_set_rss_param(rndis_device, net_device->num_chn);
    out if (ret) { net_device->num_chn = 1; }
    return 0;
    err_dev_remv rndis_filter_device_remove(dev);
    return ret;
}