int solo_set_motion_block(struct solo_dev *solo_dev, u8 ch, const u16 *thresholds)
{
    const unsigned size = sizeof(u16) * 64;
    u32 off = SOLO_MOT_FLAG_AREA + ch * SOLO_MOT_THRESH_SIZE * 2;
    u16 *buf;
    int x, y;
    int ret = 0;
    buf = kzalloc(size, GFP_KERNEL);
    for (y = 0; y < SOLO_MOTION_SZ; y++)
    {
        for (x = 0; x < SOLO_MOTION_SZ; x++)
        {
            buf[x] = cpu_to_le16(thresholds[y * SOLO_MOTION_SZ + x]);
        }
        ret |= solo_p2m_dma(solo_dev, 1, buf, SOLO_MOTION_EXT_ADDR(solo_dev) + off + y * size, size, 0, 0);
    }
    kfree(buf);
    return ret;
}