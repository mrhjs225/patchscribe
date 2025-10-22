static int of_platform_serial_probe(struct platform_device *ofdev)
{
    const struct of_device_id *match;
    struct of_serial_info *info;
    struct uart_port port;
    int port_type;
    int ret;
    match = of_match_device(of_platform_serial_table, &ofdev->dev);
    if (!match)
    {
        return -EINVAL;
    }
    if (of_find_property(ofdev->dev.of_node, "used-by-rtas", NULL))
    {
        return -EBUSY;
    }
    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (info == NULL)
    {
        return -ENOMEM;
    }
    port_type = (unsigned long)match->data;
    ret = of_platform_serial_setup(ofdev, port_type, &port, info);
    if (ret)
    {
        out
    }
    switch (port_type)
    {
    case PORT_8250 ... PORT_MAX_8250:
    {
        struct uart_8250_port port8250;
        memset(&port8250, 0, sizeof(port8250));
        port.type = port_type;
        port8250.port = port;
        if (port.fifosize)
        {
            port8250.capabilities = UART_CAP_FIFO;
        }
        if (of_property_read_bool(ofdev->dev.of_node, "auto-flow-control"))
        {
            port8250.capabilities |= UART_CAP_AFE;
        }
        ret = serial8250_register_8250_port(&port8250);
        break;
    }
    case PORT_NWPSERIAL:
        ret = nwpserial_register_port(&port);
        break;
    default:
    case PORT_UNKNOWN:
        dev_info(&ofdev->dev, "Unknown serial port found, ignored\n");
        ret = -ENODEV;
        break;
    }
    if (ret < 0)
    {
        out
    }
    info->type = port_type;
    info->line = ret;
    platform_set_drvdata(ofdev, info);
    return 0;
    out kfree(info);
    irq_dispose_mapping(port.irq);
    return ret;
}