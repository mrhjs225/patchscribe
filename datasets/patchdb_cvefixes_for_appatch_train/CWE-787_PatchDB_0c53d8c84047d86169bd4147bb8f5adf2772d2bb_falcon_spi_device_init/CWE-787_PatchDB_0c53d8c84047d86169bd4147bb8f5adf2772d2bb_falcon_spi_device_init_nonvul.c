static int falcon_spi_device_init(struct efx_nic *efx, struct efx_spi_device **spi_device_ret, unsigned int device_id, u32 device_type)
{
    struct efx_spi_device *spi_device;
    if (device_type != 0)
    {
        spi_device = kzalloc(sizeof(*spi_device), GFP_KERNEL);
        if (!spi_device)
        {
            return -ENOMEM;
        }
        spi_device->device_id = device_id;
        spi_device->size = 1 << SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_SIZE);
        spi_device->addr_len = SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_ADDR_LEN);
        spi_device->munge_address = (spi_device->size == 1 << 9 && spi_device->addr_len == 1);
        spi_device->erase_command = SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_ERASE_CMD);
        spi_device->erase_size = 1 << SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_ERASE_SIZE);
        spi_device->block_size = 1 << SPI_DEV_TYPE_FIELD(device_type, SPI_DEV_TYPE_BLOCK_SIZE);
        spi_device->efx = efx;
    }
    else
    {
        spi_device = NULL;
    }
    kfree(*spi_device_ret);
    *spi_device_ret = spi_device;
    return 0;
}