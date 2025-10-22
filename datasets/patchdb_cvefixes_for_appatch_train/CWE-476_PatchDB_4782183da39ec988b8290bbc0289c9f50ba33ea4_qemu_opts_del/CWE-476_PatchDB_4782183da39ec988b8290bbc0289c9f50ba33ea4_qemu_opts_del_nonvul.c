void qemu_opts_del(QemuOpts *opts)
{
    QemuOpt *opt;
    if (opts == NULL)
    {
        return;
    }
    for (;;)
    {
        opt = QTAILQ_FIRST(&opts->head);
        if (opt == NULL)
        {
            break;
        }
        qemu_opt_del(opt);
    }
    QTAILQ_REMOVE(&opts->list->head, opts, next);
    g_free(opts->id);
    g_free(opts);
}