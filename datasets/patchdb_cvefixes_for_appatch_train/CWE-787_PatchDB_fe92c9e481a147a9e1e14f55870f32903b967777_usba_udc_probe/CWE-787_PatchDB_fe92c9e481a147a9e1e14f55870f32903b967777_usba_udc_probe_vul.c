static int __init usba_udc_probe(struct platform_device *pdev)
{
    struct usba_platform_data *pdata = pdev->dev.platform_data;
    struct resource *regs, *fifo;
    struct clk *pclk, *hclk;
    struct usba_udc *udc = &the_udc;
    int irq, ret, i;
    regs = platform_get_resource(pdev, IORESOURCE_MEM, CTRL_IOMEM_ID);
    fifo = platform_get_resource(pdev, IORESOURCE_MEM, FIFO_IOMEM_ID);
    if (!regs || !fifo || !pdata)
    {
        return -ENXIO;
    }
    irq = platform_get_irq(pdev, 0);
    if (irq < 0)
    {
        return irq;
    }
    pclk = clk_get(&pdev->dev, "pclk");
    if (IS_ERR(pclk))
    {
        return PTR_ERR(pclk);
    }
    hclk = clk_get(&pdev->dev, "hclk");
    if (IS_ERR(hclk))
    {
        ret = PTR_ERR(hclk);
        err_get_hclk
    }
    spin_lock_init(&udc->lock);
    udc->pdev = pdev;
    udc->pclk = pclk;
    udc->hclk = hclk;
    udc->vbus_pin = -ENODEV;
    ret = -ENOMEM;
    udc->regs = ioremap(regs->start, regs->end - regs->start + 1);
    if (!udc->regs)
    {
        dev_err(&pdev->dev, "Unable to map I/O memory, aborting.\n");
        err_map_regs
    }
    dev_info(&pdev->dev, "MMIO registers at 0x%08lx mapped at %p\n", (unsigned long)regs->start, udc->regs);
    udc->fifo = ioremap(fifo->start, fifo->end - fifo->start + 1);
    if (!udc->fifo)
    {
        dev_err(&pdev->dev, "Unable to map FIFO, aborting.\n");
        err_map_fifo
    }
    dev_info(&pdev->dev, "FIFO at 0x%08lx mapped at %p\n", (unsigned long)fifo->start, udc->fifo);
    device_initialize(&udc->gadget.dev);
    udc->gadget.dev.parent = &pdev->dev;
    udc->gadget.dev.dma_mask = pdev->dev.dma_mask;
    platform_set_drvdata(pdev, udc);
    clk_enable(pclk);
    toggle_bias(0);
    usba_writel(udc, CTRL, USBA_DISABLE_MASK);
    clk_disable(pclk);
    usba_ep = kmalloc(sizeof(usba_ep) * pdata->num_ep, GFP_KERNEL);
    if (!usba_ep)
    {
        err_alloc_ep
    }
    the_udc.gadget.ep0 = &usba_ep[0].ep;
    INIT_LIST_HEAD(&usba_ep[0].ep.ep_list);
    usba_ep[0].ep_regs = udc->regs + USBA_EPT_BASE(0);
    usba_ep[0].dma_regs = udc->regs + USBA_DMA_BASE(0);
    usba_ep[0].fifo = udc->fifo + USBA_FIFO_BASE(0);
    usba_ep[0].ep.ops = &usba_ep_ops;
    usba_ep[0].ep.name = pdata->ep[0].name;
    usba_ep[0].ep.maxpacket = pdata->ep[0].fifo_size;
    usba_ep[0].udc = &the_udc;
    INIT_LIST_HEAD(&usba_ep[0].queue);
    usba_ep[0].fifo_size = pdata->ep[0].fifo_size;
    usba_ep[0].nr_banks = pdata->ep[0].nr_banks;
    usba_ep[0].index = pdata->ep[0].index;
    usba_ep[0].can_dma = pdata->ep[0].can_dma;
    usba_ep[0].can_isoc = pdata->ep[0].can_isoc;
    for (i = 1; i < pdata->num_ep; i++)
    {
        struct usba_ep *ep = &usba_ep[i];
        ep->ep_regs = udc->regs + USBA_EPT_BASE(i);
        ep->dma_regs = udc->regs + USBA_DMA_BASE(i);
        ep->fifo = udc->fifo + USBA_FIFO_BASE(i);
        ep->ep.ops = &usba_ep_ops;
        ep->ep.name = pdata->ep[i].name;
        ep->ep.maxpacket = pdata->ep[i].fifo_size;
        ep->udc = &the_udc;
        INIT_LIST_HEAD(&ep->queue);
        ep->fifo_size = pdata->ep[i].fifo_size;
        ep->nr_banks = pdata->ep[i].nr_banks;
        ep->index = pdata->ep[i].index;
        ep->can_dma = pdata->ep[i].can_dma;
        ep->can_isoc = pdata->ep[i].can_isoc;
        list_add_tail(&ep->ep.ep_list, &udc->gadget.ep_list);
    }
    ret = request_irq(irq, usba_udc_irq, 0, "atmel_usba_udc", udc);
    if (ret)
    {
        dev_err(&pdev->dev, "Cannot request irq %d (error %d)\n", irq, ret);
        err_request_irq
    }
    udc->irq = irq;
    ret = device_add(&udc->gadget.dev);
    if (ret)
    {
        dev_dbg(&pdev->dev, "Could not add gadget: %d\n", ret);
        err_device_add
    }
    if (gpio_is_valid(pdata->vbus_pin))
    {
        if (!gpio_request(pdata->vbus_pin, "atmel_usba_udc"))
        {
            udc->vbus_pin = pdata->vbus_pin;
            ret = request_irq(gpio_to_irq(udc->vbus_pin), usba_vbus_irq, 0, "atmel_usba_udc", udc);
            if (ret)
            {
                gpio_free(udc->vbus_pin);
                udc->vbus_pin = -ENODEV;
                dev_warn(&udc->pdev->dev, "failed to request vbus irq; "
                                          "assuming always on\n");
            }
            else
            {
                disable_irq(gpio_to_irq(udc->vbus_pin));
            }
        }
    }
    usba_init_debugfs(udc);
    for (i = 1; i < pdata->num_ep; i++)
    {
        usba_ep_init_debugfs(udc, &usba_ep[i]);
    }
    return 0;
    err_device_add free_irq(irq, udc);
    err_request_irq kfree(usba_ep);
    err_alloc_ep iounmap(udc->fifo);
    err_map_fifo iounmap(udc->regs);
    err_map_regs clk_put(hclk);
    err_get_hclk clk_put(pclk);
    platform_set_drvdata(pdev, NULL);
    return ret;
}