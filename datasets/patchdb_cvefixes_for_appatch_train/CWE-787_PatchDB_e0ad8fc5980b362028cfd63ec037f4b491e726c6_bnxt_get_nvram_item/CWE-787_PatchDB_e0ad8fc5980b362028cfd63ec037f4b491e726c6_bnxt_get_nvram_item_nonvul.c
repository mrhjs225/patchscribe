static int bnxt_get_nvram_item(struct net_device *dev, u32 index, u32 offset, u32 length, u8 *data)
{
    struct bnxt *bp = netdev_priv(dev);
    int rc;
    u8 *buf;
    dma_addr_t dma_handle;
    struct hwrm_nvm_read_input req = {0};
    if (!length)
    {
        return -EINVAL;
    }
    buf = dma_alloc_coherent(&bp->pdev->dev, length, &dma_handle, GFP_KERNEL);
    if (!buf)
    {
        netdev_err(dev, "dma_alloc_coherent failure, length = %u\n", (unsigned)length);
        return -ENOMEM;
    }
    bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_READ, -1, -1);
    req.host_dest_addr = cpu_to_le64(dma_handle);
    req.dir_idx = cpu_to_le16(index);
    req.offset = cpu_to_le32(offset);
    req.len = cpu_to_le32(length);
    rc = hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT);
    if (rc == 0)
    {
        memcpy(data, buf, length);
    }
    dma_free_coherent(&bp->pdev->dev, length, buf, dma_handle);
    return rc;
}