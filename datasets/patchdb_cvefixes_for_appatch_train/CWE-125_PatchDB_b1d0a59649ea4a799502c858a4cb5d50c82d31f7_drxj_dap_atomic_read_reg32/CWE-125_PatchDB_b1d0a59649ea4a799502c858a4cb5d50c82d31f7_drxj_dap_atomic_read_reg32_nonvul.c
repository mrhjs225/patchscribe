static int drxj_dap_atomic_read_reg32(struct i2c_device_addr *dev_addr, u32 addr, u32 *data, u32 flags)
{
    u8 buf[sizeof(*data)];
    int rc = DRX_STS_ERROR;
    u32 word = 0;
    if (!data)
    {
        return DRX_STS_INVALID_ARG;
    }
    rc = drxj_dap_atomic_read_write_block(dev_addr, addr, sizeof(*data), buf, true);
    if (rc < 0)
    {
        return 0;
    }
    word = (u32)buf[3];
    word <<= 8;
    word |= (u32)buf[2];
    word <<= 8;
    word |= (u32)buf[1];
    word <<= 8;
    word |= (u32)buf[0];
    *data = word;
    return rc;
}