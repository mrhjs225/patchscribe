static int mv643xx_eth_shared_probe(struct platform_device *pdev)
{
    static int mv643xx_eth_version_printed;
    struct mv643xx_eth_shared_platform_data *pd = pdev->dev.platform_data;
    struct mv643xx_eth_shared_private *msp;
    struct resource *res;
    int ret;
    if (!mv643xx_eth_version_printed++)
    {
        printk(KERN_NOTICE "MV-643xx 10/100/1000 ethernet "
                           "driver version %s\n",
               mv643xx_eth_driver_version);
    }
    ret = -EINVAL;
    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (res == NULL)
    {
        out
    }
    ret = -ENOMEM;
    msp = kzalloc(sizeof(*msp), GFP_KERNEL);
    if (msp == NULL)
    {
        out
    }
    msp->base = ioremap(res->start, res->end - res->start + 1);
    if (msp->base == NULL)
    {
        out_free
    }
    if (pd == NULL || pd->shared_smi == NULL)
    {
        msp->smi_bus = mdiobus_alloc();
        if (msp->smi_bus == NULL)
        {
            out_unmap
        }
        msp->smi_bus->priv = msp;
        msp->smi_bus->name = "mv643xx_eth smi";
        msp->smi_bus->read = smi_bus_read;
        msp->smi_bus->write = smi_bus_write, snprintf(msp->smi_bus->id, MII_BUS_ID_SIZE, "%d", pdev->id);
        msp->smi_bus->parent = &pdev->dev;
        msp->smi_bus->phy_mask = 0xffffffff;
        if (mdiobus_register(msp->smi_bus) < 0)
        {
            out_free_mii_bus
        }
        msp->smi = msp;
    }
    else
    {
        msp->smi = platform_get_drvdata(pd->shared_smi);
    }
    msp->err_interrupt = NO_IRQ;
    init_waitqueue_head(&msp->smi_busy_wait);
    res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
    if (res != NULL)
    {
        int err;
        err = request_irq(res->start, mv643xx_eth_err_irq, IRQF_SHARED, "mv643xx_eth", msp);
        if (!err)
        {
            writel(ERR_INT_SMI_DONE, msp->base + ERR_INT_MASK);
            msp->err_interrupt = res->start;
        }
    }
    if (pd != NULL && pd->dram != NULL)
    {
        mv643xx_eth_conf_mbus_windows(msp, pd->dram);
    }
    msp->t_clk = (pd != NULL && pd->t_clk != 0) ? pd->t_clk : 133000000;
    msp->tx_csum_limit = pd->tx_csum_limit ? pd->tx_csum_limit : 9 * 1024;
    infer_hw_params(msp);
    platform_set_drvdata(pdev, msp);
    return 0;
    out_free_mii_bus mdiobus_free(msp->smi_bus);
    out_unmap iounmap(msp->base);
    out_free kfree(msp);
    out return ret;
}