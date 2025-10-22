static void packet_enable_delayed_compress(void)
{
    Comp *comp = NULL;
    int mode;
    after_authentication = 1;
    for (mode = 0; mode < MODE_MAX; mode++)
    {
        comp = &newkeys[mode]->comp;
        if (comp && !comp->enabled && comp->type == COMP_DELAYED)
        {
            packet_init_compression();
            if (mode == MODE_OUT)
            {
                buffer_compress_init_send(6);
            }
            else
            {
                buffer_compress_init_recv();
            }
            comp->enabled = 1;
        }
    }
}