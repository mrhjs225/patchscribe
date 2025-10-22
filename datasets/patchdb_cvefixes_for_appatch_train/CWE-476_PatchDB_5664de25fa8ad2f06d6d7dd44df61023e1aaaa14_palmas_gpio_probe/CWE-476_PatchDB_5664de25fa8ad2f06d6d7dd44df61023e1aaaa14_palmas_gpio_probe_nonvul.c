static int palmas_gpio_probe(struct platform_device *pdev)
{
    struct palmas *palmas = dev_get_drvdata(pdev->dev.parent);
    struct palmas_platform_data *palmas_pdata;
    struct palmas_gpio *palmas_gpio;
    int ret;
    const struct of_device_id *match;
    const struct palmas_device_data *dev_data;
    match = of_match_device(of_palmas_gpio_match, &pdev->dev);
    if (!match)
    {
        return -ENODEV;
    }
    dev_data = match->data;
    if (!dev_data)
    {
        dev_data = &palmas_dev_data;
    }
    palmas_gpio = devm_kzalloc(&pdev->dev, sizeof(*palmas_gpio), GFP_KERNEL);
    if (!palmas_gpio)
    {
        return -ENOMEM;
    }
    palmas_gpio->palmas = palmas;
    palmas_gpio->gpio_chip.owner = THIS_MODULE;
    palmas_gpio->gpio_chip.label = dev_name(&pdev->dev);
    palmas_gpio->gpio_chip.ngpio = dev_data->ngpio;
    palmas_gpio->gpio_chip.can_sleep = true;
    palmas_gpio->gpio_chip.direction_input = palmas_gpio_input;
    palmas_gpio->gpio_chip.direction_output = palmas_gpio_output;
    palmas_gpio->gpio_chip.to_irq = palmas_gpio_to_irq;
    palmas_gpio->gpio_chip.set = palmas_gpio_set;
    palmas_gpio->gpio_chip.get = palmas_gpio_get;
    palmas_gpio->gpio_chip.dev = &pdev->dev;
    palmas_gpio->gpio_chip.of_node = pdev->dev.of_node;
    palmas_pdata = dev_get_platdata(palmas->dev);
    if (palmas_pdata && palmas_pdata->gpio_base)
    {
        palmas_gpio->gpio_chip.base = palmas_pdata->gpio_base;
    }
    else
    {
        palmas_gpio->gpio_chip.base = -1;
    }
    ret = gpiochip_add(&palmas_gpio->gpio_chip);
    if (ret < 0)
    {
        dev_err(&pdev->dev, "Could not register gpiochip, %d\n", ret);
        return ret;
    }
    platform_set_drvdata(pdev, palmas_gpio);
    return ret;
}