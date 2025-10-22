struct iio_channel *iio_channel_get(const char *name, const char *channel_name)
{
    struct iio_map_internal *c_i = NULL, *c = NULL;
    struct iio_channel *channel;
    if (name == NULL && channel_name == NULL)
    {
        return ERR_PTR(-ENODEV);
    }
    mutex_lock(&iio_map_list_lock);
    list_for_each_entry(, , )
    {
        if ((name && strcmp(name, c_i->map->consumer_dev_name) != 0) || (channel_name && strcmp(channel_name, c_i->map->consumer_channel) != 0))
        {
            continue;
        }
        c = c_i;
        iio_device_get(c->indio_dev);
        break;
    }
    mutex_unlock(&iio_map_list_lock);
    if (c == NULL)
    {
        return ERR_PTR(-ENODEV);
    }
    channel = kzalloc(sizeof(*channel), GFP_KERNEL);
    if (channel == NULL)
    {
        return ERR_PTR(-ENOMEM);
    }
    channel->indio_dev = c->indio_dev;
    if (c->map->adc_channel_label)
    {
        channel->channel = iio_chan_spec_from_name(channel->indio_dev, c->map->adc_channel_label);
    }
    return channel;
}