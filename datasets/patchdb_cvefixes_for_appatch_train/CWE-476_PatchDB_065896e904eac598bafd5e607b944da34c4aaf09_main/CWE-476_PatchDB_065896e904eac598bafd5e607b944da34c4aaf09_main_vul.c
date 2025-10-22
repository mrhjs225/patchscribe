int main(int argc, char **argv)
{
    unsigned long num_loops = 2;
    unsigned long timedelay = 1000000;
    unsigned long buf_len = 128;
    int ret, c, i, j, toread;
    FILE *fp_ev;
    int fp;
    int num_channels;
    char *trigger_name = NULL, *device_name = NULL;
    char *dev_dir_name, *buf_dir_name;
    int datardytrigger = 1;
    char *data;
    size_t read_size;
    struct iio_event_data dat;
    int dev_num, trig_num;
    char *buffer_access, *buffer_event;
    int scan_size;
    int noevents = 0;
    char *dummy;
    struct iio_channel_info *infoarray;
    while ((c = getopt(argc, argv, "l:w:c:et:n:")) != -1)
    {
        switch (c)
        {
        case 'n':
            device_name = optarg;
            break;
        case 't':
            trigger_name = optarg;
            datardytrigger = 0;
            break;
        case 'e':
            noevents = 1;
            break;
        case 'c':
            num_loops = strtoul(optarg, &dummy, 10);
            break;
        case 'w':
            timedelay = strtoul(optarg, &dummy, 10);
            break;
        case 'l':
            buf_len = strtoul(optarg, &dummy, 10);
            break;
        case '?':
            return -1;
        }
    }
    dev_num = find_type_by_name(device_name, "device");
    if (dev_num < 0)
    {
        printf("Failed to find the %s\n", device_name);
        ret = -ENODEV;
        error_ret
    }
    printf("iio device number being used is %d\n", dev_num);
    asprintf(&dev_dir_name, "%sdevice%d", iio_dir, dev_num);
    if (trigger_name == NULL)
    {
        ret = asprintf(&trigger_name, "%s-dev%d", device_name, dev_num);
        if (ret < 0)
        {
            ret = -ENOMEM;
            error_ret
        }
    }
    trig_num = find_type_by_name(trigger_name, "trigger");
    if (trig_num < 0)
    {
        printf("Failed to find the trigger %s\n", trigger_name);
        ret = -ENODEV;
        error_free_triggername
    }
    printf("iio trigger number being used is %d\n", trig_num);
    ret = build_channel_array(dev_dir_name, &infoarray, &num_channels);
    if (ret)
    {
        printf("Problem reading scan element information \n");
        error_free_triggername
    }
    ret = asprintf(&buf_dir_name, "%sdevice%d:buffer0", iio_dir, dev_num);
    if (ret < 0)
    {
        ret = -ENOMEM;
        error_free_triggername
    }
    printf("%s %s\n", dev_dir_name, trigger_name);
    ret = write_sysfs_string_and_verify("trigger/current_trigger", dev_dir_name, trigger_name);
    if (ret < 0)
    {
        printf("Failed to write current_trigger file\n");
        error_free_buf_dir_name
    }
    ret = write_sysfs_int("length", buf_dir_name, buf_len);
    if (ret < 0)
    {
        error_free_buf_dir_name
    }
    ret = write_sysfs_int("enable", buf_dir_name, 1);
    if (ret < 0)
    {
        error_free_buf_dir_name
    }
    scan_size = size_from_channelarray(infoarray, num_channels);
    data = malloc(scan_size * buf_len);
    if (!data)
    {
        ret = -ENOMEM;
        error_free_buf_dir_name
    }
    ret = asprintf(&buffer_access, "/dev/device%d:buffer0:access0", dev_num);
    if (ret < 0)
    {
        ret = -ENOMEM;
        error_free_data
    }
    ret = asprintf(&buffer_event, "/dev/device%d:buffer0:event0", dev_num);
    if (ret < 0)
    {
        ret = -ENOMEM;
        error_free_buffer_access
    }
    fp = open(buffer_access, O_RDONLY | O_NONBLOCK);
    if (fp == -1)
    {
        printf("Failed to open %s\n", buffer_access);
        ret = -errno;
        error_free_buffer_event
    }
    fp_ev = fopen(buffer_event, "rb");
    if (fp_ev == NULL)
    {
        printf("Failed to open %s\n", buffer_event);
        ret = -errno;
        error_close_buffer_access
    }
    for (j = 0; j < num_loops; j++)
    {
        if (!noevents)
        {
            read_size = fread(&dat, 1, sizeof(iio_event_data), fp_ev);
            switch (dat.id)
            {
            case IIO_EVENT_CODE_RING_100_FULL:
                toread = buf_len;
                break;
            case IIO_EVENT_CODE_RING_75_FULL:
                toread = buf_len * 3 / 4;
                break;
            case IIO_EVENT_CODE_RING_50_FULL:
                toread = buf_len / 2;
                break;
            default:
                printf("Unexpecteded event code\n");
                continue;
            }
        }
        else
        {
            usleep(timedelay);
            toread = 64;
        }
        read_size = read(fp, data, toread * scan_size);
        if (read_size == -EAGAIN)
        {
            printf("nothing available\n");
            continue;
        }
        for (i = 0; i < read_size / scan_size; i++)
        {
            process_scan(data + scan_size * i, infoarray, num_channels);
        }
    }
    ret = write_sysfs_int("enable", buf_dir_name, 0);
    if (ret < 0)
    {
        error_close_buffer_event
    }
    write_sysfs_string("trigger/current_trigger", dev_dir_name, "NULL");
    error_close_buffer_event fclose(fp_ev);
    error_close_buffer_access close(fp);
    error_free_data free(data);
    error_free_buffer_access free(buffer_access);
    error_free_buffer_event free(buffer_event);
    error_free_buf_dir_name free(buf_dir_name);
    error_free_triggername if (datardytrigger) { free(trigger_name); }
    error_ret return ret;
}