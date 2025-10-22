static int ds2760_battery_remove(struct platform_device *pdev)
{
    struct ds2760_device_info *di = platform_get_drvdata(pdev);
    cancel_rearming_delayed_workqueue(di->monitor_wqueue, &di->monitor_work);
    cancel_rearming_delayed_workqueue(di->monitor_wqueue, &di->set_charged_work);
    destroy_workqueue(di->monitor_wqueue);
    power_supply_unregister(&di->bat);
    return 0;
}