static int bcm_rx_thr_flush(struct bcm_op *op, int update)
{
    int updated = 0;
    if (op->nframes > 1)
    {
        unsigned int i;
        for (i = 1; i < op->nframes; i++)
        {
            updated += bcm_rx_do_flush(op, update, i);
        }
    }
    else
    {
        updated += bcm_rx_do_flush(op, update, 0);
    }
    return updated;
}