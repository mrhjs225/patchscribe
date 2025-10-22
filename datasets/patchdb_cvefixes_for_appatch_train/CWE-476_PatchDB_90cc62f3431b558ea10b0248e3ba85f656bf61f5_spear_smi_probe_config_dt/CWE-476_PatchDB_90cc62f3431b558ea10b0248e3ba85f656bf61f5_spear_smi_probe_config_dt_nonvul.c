static int spear_smi_probe_config_dt(struct platform_device *pdev, struct device_node *np)
{
    struct spear_smi_plat_data *pdata = dev_get_platdata(&pdev->dev);
    struct device_node *pp = NULL;
    const __be32 *addr;
    u32 val;
    int len;
    int i = 0;
    if (!np)
    {
        return -ENODEV;
    }
    of_property_read_u32(np, "clock-rate", &val);
    pdata->clk_rate = val;
    pdata->board_flash_info = devm_kzalloc(&pdev->dev, sizeof(*pdata->board_flash_info), GFP_KERNEL);
    if (!pdata->board_flash_info)
    {
        return -ENOMEM;
    }
    while ((pp = of_get_next_child(np, pp)))
    {
        struct spear_smi_flash_info *flash_info;
        flash_info = &pdata->board_flash_info[i];
        pdata->np[i] = pp;
        addr = of_get_property(pp, "reg", &len);
        pdata->board_flash_info->mem_base = be32_to_cpup(&addr[0]);
        pdata->board_flash_info->size = be32_to_cpup(&addr[1]);
        if (of_get_property(pp, "st,smi-fast-mode", NULL))
        {
            pdata->board_flash_info->fast_mode = 1;
        }
        i++;
    }
    pdata->num_flashes = i;
    return 0;
}