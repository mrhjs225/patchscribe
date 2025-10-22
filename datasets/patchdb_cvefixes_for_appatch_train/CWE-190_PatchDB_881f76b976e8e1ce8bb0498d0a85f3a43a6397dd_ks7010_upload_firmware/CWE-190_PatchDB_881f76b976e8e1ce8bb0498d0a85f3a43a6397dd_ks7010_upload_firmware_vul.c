static int ks7010_upload_firmware(struct ks_sdio_card *card)
{
    struct ks_wlan_private *priv = card->priv;
    unsigned int size, offset, n = 0;
    unsigned char *rom_buf;
    unsigned char rw_data = 0;
    int ret;
    int length;
    const struct firmware *fw_entry = NULL;
    rom_buf = kmalloc(ROM_BUFF_SIZE, GFP_KERNEL);
    if (!rom_buf)
    {
        return -ENOMEM;
    }
    sdio_claim_host(card->func);
    ret = ks7010_sdio_read(priv, GCR_A, &rw_data, sizeof(rw_data));
    if (rw_data == GCR_A_RUN)
    {
        DPRINTK(0, "MAC firmware running ...\n");
        release_host_and_free
    }
    ret = request_firmware(&fw_entry, ROM_FILE, &priv->ks_wlan_hw.sdio_card->func->dev);
    if (ret)
    {
        release_host_and_free
    }
    length = fw_entry->size;
    n = 0;
    {
        if (length >= ROM_BUFF_SIZE)
        {
            size = ROM_BUFF_SIZE;
            length = length - ROM_BUFF_SIZE;
        }
        else
        {
            size = length;
            length = 0;
        }
        DPRINTK(4, "size = %d\n", size);
        if (size == 0)
        {
            break;
        }
        memcpy(rom_buf, fw_entry->data + n, size);
        offset = n;
        ret = ks7010_sdio_update_index(priv, KS7010_IRAM_ADDRESS + offset);
        if (ret)
        {
            release_firmware
        }
        ret = ks7010_sdio_write(priv, DATA_WINDOW, rom_buf, size);
        if (ret)
        {
            release_firmware
        }
        ret = ks7010_sdio_data_compare(priv, DATA_WINDOW, rom_buf, size);
        if (ret)
        {
            release_firmware
        }
        n += size;
    }
    size;
    rw_data = GCR_A_REMAP;
    ret = ks7010_sdio_write(priv, GCR_A, &rw_data, sizeof(rw_data));
    if (ret)
    {
        release_firmware
    }
    DPRINTK(4, " REMAP Request : GCR_A=%02X\n", rw_data);
    for (n = 0; n < 50; ++n)
    {
        mdelay(10);
        ret = ks7010_sdio_read(priv, GCR_A, &rw_data, sizeof(rw_data));
        if (ret)
        {
            release_firmware
        }
        if (rw_data == GCR_A_RUN)
        {
            break;
        }
    }
    DPRINTK(4, "firmware wakeup (%d)!!!!\n", n);
    if ((50) <= n)
    {
        DPRINTK(1, "firmware can't start\n");
        ret = -EIO;
        release_firmware
    }
    ret = 0;
    release_firmware release_firmware(fw_entry);
    release_host_and_free sdio_release_host(card->func);
    kfree(rom_buf);
    return ret;
}