int acpi_bus_generate_proc_event4(const char *device_class, const char *bus_id, u8 type, int data)
{
    struct acpi_bus_event *event;
    unsigned long flags = 0;
    if (!event_is_open)
    {
        return 0;
    }
    event = kzalloc(sizeof(acpi_bus_event), GFP_ATOMIC);
    if (!event)
    {
        return -ENOMEM;
    }
    strcpy(event->device_class, device_class);
    strcpy(event->bus_id, bus_id);
    event->type = type;
    event->data = data;
    spin_lock_irqsave(&acpi_bus_event_lock, flags);
    list_add_tail(&event->node, &acpi_bus_event_list);
    spin_unlock_irqrestore(&acpi_bus_event_lock, flags);
    wake_up_interruptible(&acpi_bus_event_queue);
    return 0;
}