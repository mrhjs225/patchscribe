static struct iommu_table *vio_build_iommu_table(struct vio_dev *dev)
{
    const unsigned char *dma_window;
    struct iommu_table *tbl;
    unsigned long offset, size;
    if (firmware_has_feature(FW_FEATURE_ISERIES))
    {
        return vio_build_iommu_table_iseries(dev);
    }
    dma_window = of_get_property(dev->dev.archdata.of_node, "ibm,my-dma-window", NULL);
    if (!dma_window)
    {
        return NULL;
    }
    tbl = kmalloc(sizeof(*tbl), GFP_KERNEL);
    of_parse_dma_window(dev->dev.archdata.of_node, dma_window, &tbl->it_index, &offset, &size);
    tbl->it_size = size >> IOMMU_PAGE_SHIFT;
    tbl->it_offset = offset >> IOMMU_PAGE_SHIFT;
    tbl->it_busno = 0;
    tbl->it_type = TCE_VB;
    return iommu_init_table(tbl, -1);
}