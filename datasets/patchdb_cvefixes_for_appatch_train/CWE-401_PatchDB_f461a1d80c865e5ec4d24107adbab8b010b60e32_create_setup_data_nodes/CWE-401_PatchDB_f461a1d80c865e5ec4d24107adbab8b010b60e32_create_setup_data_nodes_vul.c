static int __init create_setup_data_nodes(struct dentry *parent)
{
    struct setup_data_node *node;
    struct setup_data *data;
    int error, no = 0;
    struct dentry *d;
    struct page *pg;
    u64 pa_data;
    d = debugfs_create_dir("setup_data", parent);
    if (!d)
    {
        error = -ENOMEM;
        err_return
    }
    pa_data = boot_params.hdr.setup_data;
    while (pa_data)
    {
        node = kmalloc(sizeof(*node), GFP_KERNEL);
        if (!node)
        {
            error = -ENOMEM;
            err_dir
        }
        pg = pfn_to_page((pa_data + sizeof(*data) - 1) >> PAGE_SHIFT);
        if (PageHighMem(pg))
        {
            data = ioremap_cache(pa_data, sizeof(*data));
            if (!data)
            {
                error = -ENXIO;
                err_dir
            }
        }
        else
        {
            data = __va(pa_data);
        }
        node->paddr = pa_data;
        node->type = data->type;
        node->len = data->len;
        error = create_setup_data_node(d, no, node);
        pa_data = data->next;
        if (PageHighMem(pg))
        {
            iounmap(data);
        }
        if (error)
        {
            err_dir
        }
        no++;
    }
    return 0;
    err_dir debugfs_remove(d);
    err_return return error;
}