struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
    int node = acpi_get_node(root->device->handle);
    struct acpi_pci_generic_root_info *ri;
    struct pci_bus *bus, *child;
    struct acpi_pci_root_ops *root_ops;
    ri = kzalloc_node(sizeof(*ri), GFP_KERNEL, node);
    if (!ri)
    {
        return NULL;
    }
    root_ops = kzalloc_node(sizeof(*root_ops), GFP_KERNEL, node);
    if (!root_ops)
    {
        return NULL;
    }
    ri->cfg = pci_acpi_setup_ecam_mapping(root);
    if (!ri->cfg)
    {
        kfree(ri);
        kfree(root_ops);
        return NULL;
    }
    root_ops->release_info = pci_acpi_generic_release_info;
    root_ops->prepare_resources = pci_acpi_root_prepare_resources;
    root_ops->pci_ops = &ri->cfg->ops->pci_ops;
    bus = acpi_pci_root_create(root, root_ops, &ri->common, ri->cfg);
    if (!bus)
    {
        return NULL;
    }
    pci_bus_size_bridges(bus);
    pci_bus_assign_resources(bus);
    list_for_each_entry(, , ) pcie_bus_configure_settings(child);
    return bus;
}