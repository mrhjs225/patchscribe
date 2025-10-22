int ldlm_expired_completion_wait(void *data)
{
    struct lock_wait_data *lwd = data;
    struct ldlm_lock *lock = lwd->lwd_lock;
    struct obd_import *imp;
    struct obd_device *obd;
    if (lock->l_conn_export == NULL)
    {
        static unsigned long next_dump = 0, last_dump = 0;
        LCONSOLE_WARN("lock timed out (enqueued at " CFS_TIME_T ", " CFS_DURATION_T "s ago)\n", lock->l_last_activity, cfs_time_sub(cfs_time_current_sec(), lock->l_last_activity));
        LDLM_DEBUG(lock, "lock timed out (enqueued at " CFS_TIME_T ", " CFS_DURATION_T "s ago); not entering recovery in "
                         "server code, just going back to sleep",
                   lock->l_last_activity, cfs_time_sub(cfs_time_current_sec(), lock->l_last_activity));
        if (cfs_time_after(cfs_time_current(), next_dump))
        {
            last_dump = next_dump;
            next_dump = cfs_time_shift(300);
            ldlm_namespace_dump(D_DLMTRACE, ldlm_lock_to_ns(lock));
            if (last_dump == 0)
            {
                libcfs_debug_dumplog();
            }
        }
        return 0;
    }
    obd = lock->l_conn_export->exp_obd;
    imp = obd->u.cli.cl_import;
    ptlrpc_fail_import(imp, lwd->lwd_conn_cnt);
    LDLM_ERROR(lock, "lock timed out (enqueued at " CFS_TIME_T ", " CFS_DURATION_T "s ago), entering recovery for %s@%s", lock->l_last_activity, cfs_time_sub(cfs_time_current_sec(), lock->l_last_activity), obd2cli_tgt(obd), imp->imp_connection->c_remote_uuid.uuid);
    return 0;
}