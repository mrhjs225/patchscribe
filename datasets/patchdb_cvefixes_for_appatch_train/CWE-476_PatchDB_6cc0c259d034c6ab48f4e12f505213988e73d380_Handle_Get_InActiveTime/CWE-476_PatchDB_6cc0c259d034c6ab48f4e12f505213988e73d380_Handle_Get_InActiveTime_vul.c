static s32 Handle_Get_InActiveTime(struct wilc_vif *vif, struct sta_inactive_t *strHostIfStaInactiveT)
{
    s32 result = 0;
    u8 *stamac;
    struct wid wid;
    struct host_if_drv *hif_drv = vif->hif_drv;
    wid.id = (u16)WID_SET_STA_MAC_INACTIVE_TIME;
    wid.type = WID_STR;
    wid.size = ETH_ALEN;
    wid.val = kmalloc(wid.size, GFP_KERNEL);
    stamac = wid.val;
    ether_addr_copy(stamac, strHostIfStaInactiveT->mac);
    result = wilc_send_config_pkt(vif, SET_CFG, &wid, 1, wilc_get_vif_idx(vif));
    if (result)
    {
        netdev_err(vif->ndev, "Failed to SET incative time\n");
        return -EFAULT;
    }
    wid.id = (u16)WID_GET_INACTIVE_TIME;
    wid.type = WID_INT;
    wid.val = (s8 *)&inactive_time;
    wid.size = sizeof(u32);
    result = wilc_send_config_pkt(vif, GET_CFG, &wid, 1, wilc_get_vif_idx(vif));
    if (result)
    {
        netdev_err(vif->ndev, "Failed to get incative time\n");
        return -EFAULT;
    }
    complete(&hif_drv->comp_inactive_time);
    return result;
}