int sptlrpc_enc_pool_get_pages(struct ptlrpc_bulk_desc *desc)
{
    wait_queue_t waitlink;
    unsigned long this_idle = -1;
    cfs_time_t tick = 0;
    long now;
    int p_idx, g_idx;
    int i;
    LASSERT(desc->bd_iov_count > 0);
    LASSERT(desc->bd_iov_count <= page_pools.epp_max_pages);
    if (desc->bd_enc_iov != NULL)
    {
        return 0;
    }
    OBD_ALLOC(desc->bd_enc_iov, desc->bd_iov_count * sizeof(*desc->bd_enc_iov));
    if (desc->bd_enc_iov == NULL)
    {
        return -ENOMEM;
    }
    spin_lock(&page_pools.epp_lock);
    page_pools.epp_st_access++;
    again if (unlikely(page_pools.epp_free_pages < desc->bd_iov_count))
    {
        if (tick == 0)
        {
            tick = cfs_time_current();
        }
        now = cfs_time_current_sec();
        page_pools.epp_st_missings++;
        page_pools.epp_pages_short += desc->bd_iov_count;
        if (enc_pools_should_grow(desc->bd_iov_count, now))
        {
            page_pools.epp_growing = 1;
            spin_unlock(&page_pools.epp_lock);
            enc_pools_add_pages(page_pools.epp_pages_short / 2);
            spin_lock(&page_pools.epp_lock);
            page_pools.epp_growing = 0;
            enc_pools_wakeup();
        }
        else
        {
            if (++page_pools.epp_waitqlen > page_pools.epp_st_max_wqlen)
            {
                page_pools.epp_st_max_wqlen = page_pools.epp_waitqlen;
            }
            set_current_state(TASK_UNINTERRUPTIBLE);
            init_waitqueue_entry(&waitlink, current);
            add_wait_queue(&page_pools.epp_waitq, &waitlink);
            spin_unlock(&page_pools.epp_lock);
            schedule();
            remove_wait_queue(&page_pools.epp_waitq, &waitlink);
            LASSERT(page_pools.epp_waitqlen > 0);
            spin_lock(&page_pools.epp_lock);
            page_pools.epp_waitqlen--;
        }
        LASSERT(page_pools.epp_pages_short >= desc->bd_iov_count);
        page_pools.epp_pages_short -= desc->bd_iov_count;
        this_idle = 0;
        again
    }
    if (unlikely(tick != 0))
    {
        tick = cfs_time_current() - tick;
        if (tick > page_pools.epp_st_max_wait)
        {
            page_pools.epp_st_max_wait = tick;
        }
    }
    page_pools.epp_free_pages -= desc->bd_iov_count;
    p_idx = page_pools.epp_free_pages / PAGES_PER_POOL;
    g_idx = page_pools.epp_free_pages % PAGES_PER_POOL;
    for (i = 0; i < desc->bd_iov_count; i++)
    {
        LASSERT(page_pools.epp_pools[p_idx][g_idx] != NULL);
        desc->bd_enc_iov[i].kiov_page = page_pools.epp_pools[p_idx][g_idx];
        page_pools.epp_pools[p_idx][g_idx] = NULL;
        if (++g_idx == PAGES_PER_POOL)
        {
            p_idx++;
            g_idx = 0;
        }
    }
    if (page_pools.epp_free_pages < page_pools.epp_st_lowfree)
    {
        page_pools.epp_st_lowfree = page_pools.epp_free_pages;
    }
    if (this_idle == -1)
    {
        this_idle = page_pools.epp_free_pages * IDLE_IDX_MAX / page_pools.epp_total_pages;
    }
    page_pools.epp_idle_idx = (page_pools.epp_idle_idx * IDLE_IDX_WEIGHT + this_idle) / (IDLE_IDX_WEIGHT + 1);
    page_pools.epp_last_access = cfs_time_current_sec();
    spin_unlock(&page_pools.epp_lock);
    return 0;
}