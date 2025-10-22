int lstcon_rpc_pinger_start(void)
{
    stt_timer_t *ptimer;
    int rc;
    LASSERT(list_empty(&console_session.ses_rpc_freelist));
    LASSERT(atomic_read(&console_session.ses_rpc_counter) == 0);
    rc = lstcon_rpc_trans_prep(NULL, LST_TRANS_SESPING, &console_session.ses_ping);
    if (rc != 0)
    {
        CERROR("Failed to create console pinger\n");
        return rc;
    }
    ptimer = &console_session.ses_ping_timer;
    ptimer->stt_expires = (cfs_time_t)(cfs_time_current_sec() + LST_PING_INTERVAL);
    stt_add_timer(ptimer);
    return 0;
}