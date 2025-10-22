static int mxs_dcp_start_dma(struct dcp_async_ctx *actx)
{
    struct dcp *sdcp = global_sdcp;
    const int chan = actx->chan;
    uint32_t stat;
    int ret;
    struct dcp_dma_desc *desc = &sdcp->coh->desc[actx->chan];
    dma_addr_t desc_phys = dma_map_single(sdcp->dev, desc, sizeof(*desc), DMA_TO_DEVICE);
    reinit_completion(&sdcp->completion[chan]);
    writel(0xffffffff, sdcp->base + MXS_DCP_CH_N_STAT_CLR(chan));
    writel(desc_phys, sdcp->base + MXS_DCP_CH_N_CMDPTR(chan));
    writel(1, sdcp->base + MXS_DCP_CH_N_SEMA(chan));
    ret = wait_for_completion_timeout(&sdcp->completion[chan], msecs_to_jiffies(1000));
    if (!ret)
    {
        dev_err(sdcp->dev, "Channel %i timeout (DCP_STAT=0x%08x)\n", chan, readl(sdcp->base + MXS_DCP_STAT));
        return -ETIMEDOUT;
    }
    stat = readl(sdcp->base + MXS_DCP_CH_N_STAT(chan));
    if (stat & 0xff)
    {
        dev_err(sdcp->dev, "Channel %i error (CH_STAT=0x%08x)\n", chan, stat);
        return -EINVAL;
    }
    dma_unmap_single(sdcp->dev, desc_phys, sizeof(*desc), DMA_TO_DEVICE);
    return 0;
}