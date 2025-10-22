static int ptlrpc_pinger_main(void *arg)
{
    struct ptlrpc_thread *thread = (ptlrpc_thread *)arg;
    thread_set_flags(thread, SVC_RUNNING);
    wake_up(&thread->t_ctl_waitq);
    while (1)
    {
        cfs_time_t this_ping = cfs_time_current();
        struct l_wait_info lwi;
        cfs_duration_t time_to_next_wake;
        struct timeout_item *item;
        struct list_head *iter;
        mutex_lock(&pinger_mutex);
        list_for_each_entry(, , ) { item->ti_cb(item, item->ti_cb_data); }
        list_for_each(, )
        {
            struct obd_import *imp = list_entry(iter, obd_import, imp_pinger_chain);
            ptlrpc_pinger_process_import(imp, this_ping);
            if (imp->imp_pingable && imp->imp_next_ping && cfs_time_after(imp->imp_next_ping, cfs_time_add(this_ping, cfs_time_seconds(PING_INTERVAL))))
            {
                ptlrpc_update_next_ping(imp, 0);
            }
        }
        mutex_unlock(&pinger_mutex);
        obd_update_maxusage();
        time_to_next_wake = pinger_check_timeout(this_ping);
        CDEBUG(D_INFO, "next wakeup in " CFS_DURATION_T " (" CFS_TIME_T ")\n", time_to_next_wake, cfs_time_add(this_ping, cfs_time_seconds(PING_INTERVAL)));
        if (time_to_next_wake > 0)
        {
            lwi = LWI_TIMEOUT(max_t(cfs_duration_t, time_to_next_wake, cfs_time_seconds(1)), NULL, NULL);
            l_wait_event(thread->t_ctl_waitq, thread_is_stopping(thread) || thread_is_event(thread), &lwi);
            if (thread_test_and_clear_flags(thread, SVC_STOPPING))
            {
                break;
            }
            else
            {
                thread_test_and_clear_flags(thread, SVC_EVENT);
            }
        }
    }
    thread_set_flags(thread, SVC_STOPPED);
    wake_up(&thread->t_ctl_waitq);
    CDEBUG(D_NET, "pinger thread exiting, process %d\n", current_pid());
    return 0;
}