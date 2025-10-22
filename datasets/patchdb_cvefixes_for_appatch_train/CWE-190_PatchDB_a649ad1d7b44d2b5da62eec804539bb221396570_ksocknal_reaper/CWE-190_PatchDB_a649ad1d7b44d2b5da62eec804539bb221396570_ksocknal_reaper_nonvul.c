int ksocknal_reaper(void *arg)
{
    wait_queue_t wait;
    ksock_conn_t *conn;
    ksock_sched_t *sched;
    struct list_head enomem_conns;
    int nenomem_conns;
    cfs_duration_t timeout;
    int i;
    int peer_index = 0;
    unsigned long deadline = cfs_time_current();
    cfs_block_allsigs();
    INIT_LIST_HEAD(&enomem_conns);
    init_waitqueue_entry(&wait, current);
    spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);
    while (!ksocknal_data.ksnd_shuttingdown)
    {
        if (!list_empty(&ksocknal_data.ksnd_deathrow_conns))
        {
            conn = list_entry(ksocknal_data.ksnd_deathrow_conns.next, ksock_conn_t, ksnc_list);
            list_del(&conn->ksnc_list);
            spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
            ksocknal_terminate_conn(conn);
            ksocknal_conn_decref(conn);
            spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);
            continue;
        }
        if (!list_empty(&ksocknal_data.ksnd_zombie_conns))
        {
            conn = list_entry(ksocknal_data.ksnd_zombie_conns.next, ksock_conn_t, ksnc_list);
            list_del(&conn->ksnc_list);
            spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
            ksocknal_destroy_conn(conn);
            spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);
            continue;
        }
        if (!list_empty(&ksocknal_data.ksnd_enomem_conns))
        {
            list_add(&enomem_conns, &ksocknal_data.ksnd_enomem_conns);
            list_del_init(&ksocknal_data.ksnd_enomem_conns);
        }
        spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
        nenomem_conns = 0;
        while (!list_empty(&enomem_conns))
        {
            conn = list_entry(enomem_conns.next, ksock_conn_t, ksnc_tx_list);
            list_del(&conn->ksnc_tx_list);
            sched = conn->ksnc_scheduler;
            spin_lock_bh(&sched->kss_lock);
            LASSERT(conn->ksnc_tx_scheduled);
            conn->ksnc_tx_ready = 1;
            list_add_tail(&conn->ksnc_tx_list, &sched->kss_tx_conns);
            wake_up(&sched->kss_waitq);
            spin_unlock_bh(&sched->kss_lock);
            nenomem_conns++;
        }
        while ((timeout = cfs_time_sub(deadline, cfs_time_current())) <= 0)
        {
            const int n = 4;
            const int p = 1;
            int chunk = ksocknal_data.ksnd_peer_hash_size;
            if (*ksocknal_tunables.ksnd_timeout > n * p)
            {
                chunk = (chunk * n * p) / *ksocknal_tunables.ksnd_timeout;
            }
            if (chunk == 0)
            {
                chunk = 1;
            }
            for (i = 0; i < chunk; i++)
            {
                ksocknal_check_peer_timeouts(peer_index);
                peer_index = (peer_index + 1) % ksocknal_data.ksnd_peer_hash_size;
            }
            deadline = cfs_time_add(deadline, cfs_time_seconds(p));
        }
        if (nenomem_conns != 0)
        {
            timeout = SOCKNAL_ENOMEM_RETRY;
        }
        ksocknal_data.ksnd_reaper_waketime = cfs_time_add(cfs_time_current(), timeout);
        set_current_state(TASK_INTERRUPTIBLE);
        add_wait_queue(&ksocknal_data.ksnd_reaper_waitq, &wait);
        if (!ksocknal_data.ksnd_shuttingdown && list_empty(&ksocknal_data.ksnd_deathrow_conns) && list_empty(&ksocknal_data.ksnd_zombie_conns))
        {
            schedule_timeout(timeout);
        }
        set_current_state(TASK_RUNNING);
        remove_wait_queue(&ksocknal_data.ksnd_reaper_waitq, &wait);
        spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);
    }
    spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
    ksocknal_thread_fini();
    return 0;
}