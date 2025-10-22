void kiblnd_fmr_pool_unmap(kib_fmr_t *fmr, int status)
{
    LIST_HEAD(zombies);
    kib_fmr_pool_t *fpo = fmr->fmr_pool;
    kib_fmr_poolset_t *fps = fpo->fpo_owner;
    unsigned long now = cfs_time_current();
    kib_fmr_pool_t *tmp;
    int rc;
    rc = ib_fmr_pool_unmap(fmr->fmr_pfmr);
    LASSERT(rc == 0);
    if (status != 0)
    {
        rc = ib_flush_fmr_pool(fpo->fpo_fmr_pool);
        LASSERT(rc == 0);
    }
    fmr->fmr_pool = NULL;
    fmr->fmr_pfmr = NULL;
    spin_lock(&fps->fps_lock);
    fpo->fpo_map_count--;
    list_for_each_entry_safe(, , , )
    {
        if (fps->fps_pool_list.next == &fpo->fpo_list)
        {
            continue;
        }
        if (kiblnd_fmr_pool_is_idle(fpo, now))
        {
            list_move(&fpo->fpo_list, &zombies);
            fps->fps_version++;
        }
    }
    spin_unlock(&fps->fps_lock);
    if (!list_empty(&zombies))
    {
        kiblnd_destroy_fmr_pool_list(&zombies);
    }
}